// drawbridge-convert-enrollment converts records produced by Drawbridge's old
// go-passkeys enrollment handler. Run it from the repository root with:
//
//	go run ./scripts/drawbridge-convert-enrollment -rp-id drawbridge.example.com -out converted creds/*.json
package main

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"encoding/json/jsontext"
	json "encoding/json/v2"
	"errors"
	"flag"
	"fmt"
	"io"
	"math/big"
	"os"
	"path/filepath"
	"strings"

	"filippo.io/passkey"
)

func main() {
	os.Exit(run(os.Args[1:], os.Stdout, os.Stderr))
}

func run(args []string, stdout, stderr io.Writer) int {
	flags := flag.NewFlagSet("drawbridge-convert-enrollment", flag.ContinueOnError)
	flags.SetOutput(stderr)
	rpID := flags.String("rp-id", "", "original domain_drawbridge (a hostname, without https://)")
	outDir := flags.String("out", "", "new output directory; must not already exist")
	flags.Usage = func() {
		fmt.Fprintln(stderr, "Usage: drawbridge-convert-enrollment -rp-id HOST -out DIR OLD.json ...")
		fmt.Fprintln(stderr, "Convert only records produced by Drawbridge's old enrollment handler, which required user verification.")
		flags.PrintDefaults()
	}
	if err := flags.Parse(args); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return 0
		}
		return 2
	}
	if *rpID == "" || *outDir == "" || flags.NArg() == 0 {
		flags.Usage()
		return 2
	}
	if _, err := passkey.NewRelyingParty(*rpID, "https://"+*rpID, passkey.Options{}); err != nil {
		fmt.Fprintln(stderr, err)
		return 2
	}
	if err := os.Mkdir(*outDir, 0o700); err != nil {
		fmt.Fprintf(stderr, "create output directory: %v\n", err)
		return 1
	}
	converted, failed := 0, 0
	for _, input := range flags.Args() {
		output := filepath.Join(*outDir, filepath.Base(input))
		if err := convertFile(input, output, *rpID); err != nil {
			fmt.Fprintf(stderr, "%s: %v\n", input, err)
			failed++
			continue
		}
		fmt.Fprintf(stdout, "%s -> %s\n", input, output)
		converted++
	}
	fmt.Fprintf(stdout, "%d converted; %d failed. Original files were not changed.\n", converted, failed)
	if failed > 0 {
		return 1
	}
	return 0
}

func convertFile(input, output, rpID string) error {
	if filepath.Ext(input) != ".json" {
		return errors.New("expected a .json enrollment file")
	}
	b, err := os.ReadFile(input)
	if err != nil {
		return err
	}
	b, err = convert(b, rpID)
	if err != nil {
		return err
	}
	f, err := os.OpenFile(output, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		return err
	}
	_, err = f.Write(b)
	if err = errors.Join(err, f.Close()); err != nil {
		os.Remove(output)
		return err
	}
	return nil
}

type oldRecord struct {
	CredentialID      []byte `json:"credential_id"`
	UserID            []byte `json:"user_id"`
	UserName          string `json:"user_name"`
	UserDisplayName   string `json:"user_display_name"`
	AuthenticatorID   string `json:"authenticator_id"`
	AuthenticatorName string `json:"authenticator_name,omitempty"`
	PublicKey         []byte `json:"public_key"`
	Algorithm         int    `json:"algorithm"`
}

type newRecord struct {
	UserID            []byte `json:"user_id"`
	UserName          string `json:"user_name"`
	UserDisplayName   string `json:"user_display_name"`
	AuthenticatorID   string `json:"authenticator_id"`
	AuthenticatorName string `json:"authenticator_name,omitempty"`
	Passkey           string `json:"passkey"`
}

func convert(input []byte, rpID string) ([]byte, error) {
	var old oldRecord
	if err := json.Unmarshal(input, &old, json.RejectUnknownMembers(true)); err != nil {
		return nil, fmt.Errorf("decode old enrollment: %w", err)
	}
	if old.UserName == "" || len(old.UserID) == 0 || len(old.UserID) > 64 {
		return nil, errors.New("invalid credential user")
	}
	if len(old.CredentialID) < 16 || len(old.CredentialID) > 1023 {
		return nil, errors.New("credential ID must be 16–1023 bytes; re-enrollment required")
	}
	id := old.AuthenticatorID
	if len(id) != 36 || id[8] != '-' || id[13] != '-' || id[18] != '-' || id[23] != '-' {
		return nil, errors.New("invalid authenticator_id (expected an AAGUID)")
	}
	aaguid, err := hex.DecodeString(strings.ReplaceAll(id, "-", ""))
	if err != nil || len(aaguid) != 16 {
		return nil, errors.New("invalid authenticator_id (expected an AAGUID)")
	}
	key, err := x509.ParsePKIXPublicKey(old.PublicKey)
	if err != nil {
		return nil, fmt.Errorf("parse public_key: %w", err)
	}
	var cose []byte
	switch old.Algorithm {
	case -7: // ES256: {1: 2, 3: -7, -1: 1, -2: x, -3: y}.
		pub, ok := key.(*ecdsa.PublicKey)
		if !ok || pub.Curve != elliptic.P256() {
			return nil, errors.New("ES256 requires a P-256 public key")
		}
		cose = []byte{0xa5, 0x01, 0x02, 0x03, 0x26, 0x20, 0x01, 0x21}
		cose = appendCBORBytes(cose, pub.X.FillBytes(make([]byte, 32)))
		cose = append(cose, 0x22)
		cose = appendCBORBytes(cose, pub.Y.FillBytes(make([]byte, 32)))
	case -257: // RS256: {1: 3, 3: -257, -1: n, -2: e}.
		pub, ok := key.(*rsa.PublicKey)
		if !ok {
			return nil, errors.New("RS256 requires an RSA public key")
		}
		if pub.N.BitLen() < 2048 || pub.N.BitLen() > 4096 {
			return nil, errors.New("RSA key must be 2048–4096 bits; re-enrollment required")
		}
		cose = []byte{0xa4, 0x01, 0x03, 0x03, 0x39, 0x01, 0x00, 0x20}
		cose = appendCBORBytes(cose, pub.N.Bytes())
		cose = append(cose, 0x21)
		cose = appendCBORBytes(cose, big.NewInt(int64(pub.E)).Bytes())
	default:
		return nil, fmt.Errorf("algorithm %d is unsupported; re-enrollment required", old.Algorithm)
	}

	// Reconstruct https://c2sp.org/passkey-record from the retained fields.
	// Only AT and UV are known: the old enrollment handler required UV, but did
	// not retain UP, backup flags, extensions, transports, or the signature counter.
	// Leave those flags/counter zero and omit extensions/transports. The current
	// library does not require their original values to verify a login.
	rpHash := sha256.Sum256([]byte(rpID))
	ad := append(rpHash[:], 0x44) // AT | UV.
	ad = binary.BigEndian.AppendUint32(ad, 0)
	ad = append(ad, aaguid...)
	ad = binary.BigEndian.AppendUint16(ad, uint16(len(old.CredentialID)))
	ad = append(ad, old.CredentialID...)
	ad = append(ad, cose...)
	record := "$webauthn$v=1$" + base64.RawStdEncoding.EncodeToString(ad)
	if _, err := passkey.AAGUID(record); err != nil {
		return nil, fmt.Errorf("converted record rejected by passkey library: %w", err)
	}
	b, err := json.Marshal(newRecord{
		UserID: old.UserID, UserName: old.UserName, UserDisplayName: old.UserDisplayName,
		AuthenticatorID: strings.ToLower(id), AuthenticatorName: old.AuthenticatorName,
		Passkey: record,
	}, jsontext.WithIndent("  "))
	if err != nil {
		return nil, err
	}
	return append(b, '\n'), nil
}

// appendCBORBytes encodes public-key components, which are at most 512 bytes.
func appendCBORBytes(dst, b []byte) []byte {
	switch {
	case len(b) < 24:
		dst = append(dst, 0x40|byte(len(b)))
	case len(b) <= 255:
		dst = append(dst, 0x58, byte(len(b)))
	default:
		dst = binary.BigEndian.AppendUint16(append(dst, 0x59), uint16(len(b)))
	}
	return append(dst, b...)
}
