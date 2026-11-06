package main

import (
	"bytes"
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/binary"
	json "encoding/json/v2"
	"math/big"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"filippo.io/passkey"
)

const testRP = "drawbridge.example.com"

func testJSON(t *testing.T, value any) []byte {
	t.Helper()
	b, err := json.Marshal(value)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func testECKey(t *testing.T) *ecdsa.PrivateKey {
	t.Helper()
	k, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	return k
}

func testOldRecord(t *testing.T, key crypto.PublicKey, algorithm int) oldRecord {
	t.Helper()
	der, err := x509.MarshalPKIXPublicKey(key)
	if err != nil {
		t.Fatal(err)
	}
	return oldRecord{
		CredentialID: bytes.Repeat([]byte{0xab}, 32), UserID: bytes.Repeat([]byte{0xcd}, 32),
		UserName: "Alice@example.com", UserDisplayName: "Alice Carroll",
		AuthenticatorID: "fbfc3007-154e-4ecc-8c0b-6e020557d7bd", AuthenticatorName: "iCloud Keychain",
		PublicKey: der, Algorithm: algorithm,
	}
}

func TestConvertedRecordsAuthenticate(t *testing.T) {
	for _, name := range []string{"ES256", "RSA2048", "RSA4096"} {
		t.Run(name, func(t *testing.T) {
			var key crypto.Signer
			algorithm := -7
			if name == "ES256" {
				key = testECKey(t)
			} else {
				bits := 2048
				if name == "RSA4096" {
					bits = 4096
				}
				var err error
				key, err = rsa.GenerateKey(rand.Reader, bits)
				if err != nil {
					t.Fatal(err)
				}
				algorithm = -257
			}
			old := testOldRecord(t, key.Public(), algorithm)
			converted, err := convert(testJSON(t, old), testRP)
			if err != nil {
				t.Fatal(err)
			}
			var got newRecord
			if err := json.Unmarshal(converted, &got, json.RejectUnknownMembers(true)); err != nil {
				t.Fatal(err)
			}
			if !bytes.Equal(got.UserID, old.UserID) || got.UserName != old.UserName ||
				got.UserDisplayName != old.UserDisplayName || got.AuthenticatorID != old.AuthenticatorID ||
				got.AuthenticatorName != old.AuthenticatorName {
				t.Fatalf("changed enrollment metadata: %+v", got)
			}
			id, err := passkey.AAGUID(got.Passkey)
			if err != nil || id != [16]byte{0xfb, 0xfc, 0x30, 0x07, 0x15, 0x4e, 0x4e, 0xcc, 0x8c, 0x0b, 0x6e, 0x02, 0x05, 0x57, 0xd7, 0xbd} {
				t.Fatalf("incorrect AAGUID: %x, %v", id, err)
			}
			rp, err := passkey.NewRelyingParty(testRP, "https://"+testRP, passkey.Options{})
			if err != nil {
				t.Fatal(err)
			}
			// Include a synced passkey assertion: the reconstructed record lacks BE/BS,
			// but this must not stop an existing synced credential from logging in.
			for _, flags := range []byte{0x05, 0x1d, 0x01, 0x04, 0x00} {
				request, options, err := rp.NewLogin(passkey.LoginOptions{})
				if err != nil {
					t.Fatal(err)
				}
				var o struct {
					Challenge string `json:"challenge"`
				}
				if err := json.Unmarshal(options, &o); err != nil {
					t.Fatal(err)
				}
				clientData := testJSON(t, map[string]any{
					"type": "webauthn.get", "origin": "https://" + testRP, "challenge": o.Challenge,
				})
				rpHash := sha256.Sum256([]byte(testRP))
				ad := binary.BigEndian.AppendUint32(append(rpHash[:], flags), 7)
				cdHash := sha256.Sum256(clientData)
				digest := sha256.Sum256(append(bytes.Clone(ad), cdHash[:]...))
				sig, err := key.Sign(rand.Reader, digest[:], crypto.SHA256)
				if err != nil {
					t.Fatal(err)
				}
				response, err := passkey.ParseResponse(testJSON(t, map[string]any{
					"rawId": base64.RawURLEncoding.EncodeToString(old.CredentialID),
					"response": map[string]any{
						"clientDataJSON":    base64.RawURLEncoding.EncodeToString(clientData),
						"authenticatorData": base64.RawURLEncoding.EncodeToString(ad),
						"signature":         base64.RawURLEncoding.EncodeToString(sig),
						"userHandle":        base64.RawURLEncoding.EncodeToString(old.UserID),
					},
				}))
				var result *passkey.LoginResult
				if err == nil {
					if response.UnauthenticatedUserID() != string(got.UserID) {
						t.Fatal("converted user ID no longer matches the authenticator")
					}
					result, err = rp.Login(response, request, []string{got.Passkey})
				}
				if flags == 0x05 || flags == 0x1d {
					if err != nil || result.Matched != 0 || result.BackedUp != (flags == 0x1d) {
						t.Fatalf("converted credential login flags=%02x: %+v, %v", flags, result, err)
					}
				} else if err == nil {
					t.Fatalf("converted credential bypassed UP/UV: flags=%02x", flags)
				}
			}
		})
	}
}

func TestRejectUnsupportedOrMalformedRecords(t *testing.T) {
	key := testECKey(t)
	ed, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	for _, algorithm := range []int{-8, -35, -36, -258, -259} {
		old := testOldRecord(t, ed, algorithm)
		if _, err := convert(testJSON(t, old), testRP); err == nil || !strings.Contains(err.Error(), "re-enrollment required") {
			t.Fatalf("unsupported algorithm %d: %v", algorithm, err)
		}
	}
	for name, change := range map[string]func(*oldRecord){
		"wrong_key_type":      func(r *oldRecord) { r.Algorithm = -257 },
		"bad_key":             func(r *oldRecord) { r.PublicKey = []byte("bad DER") },
		"bad_aaguid":          func(r *oldRecord) { r.AuthenticatorID = strings.Repeat("z", 36) },
		"empty_user":          func(r *oldRecord) { r.UserName = "" },
		"missing_user_id":     func(r *oldRecord) { r.UserID = nil },
		"long_user_id":        func(r *oldRecord) { r.UserID = make([]byte, 65) },
		"short_credential_id": func(r *oldRecord) { r.CredentialID = make([]byte, 15) },
		"long_credential_id":  func(r *oldRecord) { r.CredentialID = make([]byte, 1024) },
	} {
		t.Run(name, func(t *testing.T) {
			old := testOldRecord(t, key.Public(), -7)
			change(&old)
			if _, err := convert(testJSON(t, old), testRP); err == nil {
				t.Fatal("accepted invalid record")
			}
		})
	}
	weakRSA := &rsa.PublicKey{N: new(big.Int).Lsh(big.NewInt(1), 1023), E: 65537}
	if _, err := convert(testJSON(t, testOldRecord(t, weakRSA, -257)), testRP); err == nil {
		t.Fatal("accepted RSA key smaller than 2048 bits")
	}
	valid := testJSON(t, testOldRecord(t, key.Public(), -7))
	converted, err := convert(valid, testRP)
	if err != nil {
		t.Fatal(err)
	}
	for _, invalid := range [][]byte{
		converted, // Do not accidentally convert already migrated records.
		append([]byte(`{"algorithm":-7,`), valid[1:]...),
		append([]byte(`{"unexpected":true,`), valid[1:]...),
		append(bytes.Clone(valid), []byte(`{}`)...),
	} {
		if _, err := convert(invalid, testRP); err == nil {
			t.Fatal("accepted invalid JSON or an already converted record")
		}
	}
}

func TestBatchConversionPreservesFiles(t *testing.T) {
	dir := t.TempDir()
	old := testOldRecord(t, testECKey(t).Public(), -7)
	valid := testJSON(t, old)
	old.Algorithm = -8
	unsupported := testJSON(t, old)
	inputs := map[string][]byte{"valid.json": valid, "unsupported.json": unsupported, "broken.json": []byte("{")}
	for name, b := range inputs {
		if err := os.WriteFile(filepath.Join(dir, name), b, 0o600); err != nil {
			t.Fatal(err)
		}
	}
	outDir := filepath.Join(dir, "converted")
	args := []string{"-rp-id", testRP, "-out", outDir,
		filepath.Join(dir, "unsupported.json"), filepath.Join(dir, "valid.json"), filepath.Join(dir, "broken.json")}
	var stdout, stderr bytes.Buffer
	if code := run(args, &stdout, &stderr); code != 1 || !strings.Contains(stdout.String(), "1 converted; 2 failed") ||
		!strings.Contains(stderr.String(), "unsupported.json") || !strings.Contains(stderr.String(), "re-enrollment required") ||
		!strings.Contains(stderr.String(), "broken.json") {
		t.Fatalf("unexpected batch result: code=%d stdout=%s stderr=%s", code, &stdout, &stderr)
	}
	entries, err := os.ReadDir(outDir)
	if err != nil || len(entries) != 1 || entries[0].Name() != "valid.json" {
		t.Fatalf("unexpected output files: %v, %v", entries, err)
	}
	for name, original := range inputs {
		b, err := os.ReadFile(filepath.Join(dir, name))
		if err != nil || !bytes.Equal(b, original) {
			t.Fatalf("original %s changed: %v", name, err)
		}
	}
	output := filepath.Join(outDir, "valid.json")
	before, err := os.ReadFile(output)
	if err != nil {
		t.Fatal(err)
	}
	// Reusing the output directory, or colliding output filenames, must not overwrite.
	if code := run(args, &stdout, &stderr); code != 1 {
		t.Fatal("accepted an existing output directory")
	}
	if err := convertFile(filepath.Join(dir, "valid.json"), output, "another.example.com"); err == nil {
		t.Fatal("overwrote an existing file")
	}
	after, err := os.ReadFile(output)
	if err != nil || !bytes.Equal(before, after) {
		t.Fatalf("converted file changed: %v", err)
	}
	if runtime.GOOS != "windows" {
		info, err := os.Stat(output)
		if err != nil || info.Mode().Perm() != 0o600 {
			t.Fatalf("output permissions: %v, %v", info, err)
		}
	}
}
