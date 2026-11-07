package main

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	crand "crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"encoding/json/jsontext"
	json "encoding/json/v2"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"

	"pgregory.net/rapid"
)

func TestKeyEncodeDecodeRoundtrip(t *testing.T) {
	rapid.Check(t, func(t *rapid.T) {
		var key [keySize]byte
		keyBytes := rapid.SliceOfN(rapid.Byte(), keySize, keySize).Draw(t, "key")
		copy(key[:], keyBytes)

		s := keyEncode(key)
		k, err := keyDecode(s)
		if err != nil {
			t.Fatalf("failed to decode key: %v", err)
		}
		if k != key {
			t.Fatalf("decoded key mismatch: %x vs %x", k, key)
		}
	})
}

func TestCookieEncodeDecodeRoundtrip(t *testing.T) {
	rapid.Check(t, func(t *rapid.T) {
		var key [keySize]byte
		keyBytes := rapid.SliceOfN(rapid.Byte(), keySize, keySize).Draw(t, "key")
		copy(key[:], keyBytes)

		name := rapid.String().Draw(t, "name")
		data := rapid.Make[sessionCookieData]().Draw(t, "cookie")
		cookie, err := cookieEncode(name, &data, key)
		if err != nil {
			t.Fatalf("failed to encode cookie: %v", err)
		}
		t.Logf("cookie: %v", cookie)

		decoded, err := cookieDecode[sessionCookieData](name, cookie, key)
		if err != nil {
			t.Fatalf("failed to decode cookie: %v", err)
		}
		if !reflect.DeepEqual(decoded, &data) {
			t.Fatalf("decoded cookie mismatch: %#v vs %#v", decoded, &data)
		}
	})
}

func mustParseURL(t *testing.T, s string) *url.URL {
	t.Helper()
	u, err := url.Parse(s)
	if err != nil {
		t.Fatalf("failed to parse URL %q: %v", s, err)
	}
	return u
}

func writeTestCredential(t *testing.T, dir string, username string) {
	t.Helper()

	a := newTestAuthenticator(t)
	cred := credentialRecord{
		UserID:          userIDFromUsername(username),
		UserName:        username,
		UserDisplayName: "Test User",
		Passkey:         "$webauthn$v=1$" + base64.RawStdEncoding.EncodeToString(a.authData("drawbridge.example.com", 0x05, true)),
	}

	path := filepath.Join(dir, "cred.json")
	f, err := os.Create(path)
	if err != nil {
		t.Fatalf("failed to create credential file: %v", err)
	}
	if err := json.MarshalWrite(f, &cred, jsontext.WithIndent("  ")); err != nil {
		f.Close()
		t.Fatalf("failed to write credential record: %v", err)
	}
	if _, err := io.WriteString(f, "\n"); err != nil {
		f.Close()
		t.Fatalf("failed to finish credential record: %v", err)
	}
	if err := f.Close(); err != nil {
		t.Fatalf("failed to close credential file: %v", err)
	}
}

func newTestHandler(t *testing.T, upstreamURL string, allowedUsersByHost map[string][]string) (*handler, *config) {
	t.Helper()

	credsDir := t.TempDir()
	writeTestCredential(t, credsDir, "hello@example.com")

	var key [keySize]byte
	if _, err := crand.Read(key[:]); err != nil {
		t.Fatalf("failed to generate key: %v", err)
	}

	cfg := &config{
		key:              key,
		CredentialsDir:   credsDir,
		DomainRoot:       "example.com",
		DomainDrawbridge: "drawbridge.example.com",
		Domains:          map[string]*configDomain{},
	}

	upstreamParsed := mustParseURL(t, upstreamURL)
	for host, allowed := range allowedUsersByHost {
		allowedSet := make(map[string]struct{}, len(allowed))
		for _, u := range allowed {
			allowedSet[strings.ToLower(u)] = struct{}{}
		}
		cfg.Domains[host] = &configDomain{
			ProxyToURL:   upstreamParsed.String(),
			proxyToURL:   upstreamParsed,
			AllowedUsers: allowed,
			allowedUsers: allowedSet,
		}
	}

	h, err := newHandler(discardLogger(), cfg)
	if err != nil {
		t.Fatalf("failed to create handler: %v", err)
	}
	return h, cfg
}

func discardLogger() *slog.Logger {
	// Keep logs out of test output; handler logging is not under test.
	return slog.New(slog.NewTextHandler(io.Discard, nil))
}

func addValidSessionCookie(t *testing.T, req *http.Request, cfg *config, username string) {
	t.Helper()
	session := &sessionCookieData{
		SessionID: "test-session-id",
		Username:  username,
		Domain:    cfg.DomainRoot,
		Issued:    uint32(time.Now().Add(-1 * time.Minute).Unix()),
		Expires:   uint32(time.Now().Add(1 * time.Hour).Unix()),
	}
	value, err := cookieEncode(cookieNameSession, session, cfg.key)
	if err != nil {
		t.Fatalf("failed to encode session cookie: %v", err)
	}
	req.AddCookie(&http.Cookie{
		Name:  cookieNameSession,
		Value: value,
	})
}

// A software authenticator for exercising the HTTP flow with real signatures.
type testAuthenticator struct {
	key *ecdsa.PrivateKey
	id  []byte
}

func newTestAuthenticator(t *testing.T) *testAuthenticator {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), crand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	id := make([]byte, 32)
	crand.Read(id)
	return &testAuthenticator{key: key, id: id}
}

func (a *testAuthenticator) authData(rpID string, flags byte, registration bool) []byte {
	rpHash := sha256.Sum256([]byte(rpID))
	if registration {
		flags |= 0x40 // Attested credential data.
	}
	b := append(rpHash[:], flags)
	b = binary.BigEndian.AppendUint32(b, 0)
	if registration {
		// Apple Passwords' AAGUID exercises the authenticator display-name table.
		b = append(b, 0xfb, 0xfc, 0x30, 0x07, 0x15, 0x4e, 0x4e, 0xcc, 0x8c, 0x0b, 0x6e, 0x02, 0x05, 0x57, 0xd7, 0xbd)
		b = binary.BigEndian.AppendUint16(b, uint16(len(a.id)))
		b = append(b, a.id...)
		// Canonical COSE EC2 key: {1: 2, 3: -7, -1: 1, -2: x, -3: y}.
		b = append(b, 0xa5, 0x01, 0x02, 0x03, 0x26, 0x20, 0x01, 0x21, 0x58, 0x20)
		b = append(b, a.key.X.FillBytes(make([]byte, 32))...)
		b = append(b, 0x22, 0x58, 0x20)
		b = append(b, a.key.Y.FillBytes(make([]byte, 32))...)
	}
	return b
}

func testJSON(t *testing.T, v any) jsontext.Value {
	t.Helper()
	b, err := json.Marshal(v)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func (a *testAuthenticator) registration(t *testing.T, rpID, challenge string) map[string]any {
	t.Helper()
	ad := a.authData(rpID, 0x05, true)
	cd := testJSON(t, map[string]any{
		"type": "webauthn.create", "origin": "https://" + rpID, "challenge": challenge,
	})
	return map[string]any{
		"id": base64.RawURLEncoding.EncodeToString(a.id), "rawId": base64.RawURLEncoding.EncodeToString(a.id),
		"type": "public-key", "authenticatorAttachment": "platform",
		"clientExtensionResults": map[string]any{"credProps": map[string]any{"rk": true}},
		"response": map[string]any{
			"clientDataJSON":    base64.RawURLEncoding.EncodeToString(cd),
			"authenticatorData": base64.RawURLEncoding.EncodeToString(ad),
			"transports":        []string{"internal"},
		},
	}
}

func (a *testAuthenticator) assertion(t *testing.T, rpID, origin, challenge string, userID []byte, flags byte) map[string]any {
	t.Helper()
	cd := testJSON(t, map[string]any{"type": "webauthn.get", "origin": origin, "challenge": challenge})
	ad := a.authData(rpID, flags, false)
	cdHash := sha256.Sum256(cd)
	digest := sha256.Sum256(append(append([]byte{}, ad...), cdHash[:]...))
	sig, err := ecdsa.SignASN1(crand.Reader, a.key, digest[:])
	if err != nil {
		t.Fatal(err)
	}
	return map[string]any{
		"id": base64.RawURLEncoding.EncodeToString(a.id), "rawId": base64.RawURLEncoding.EncodeToString(a.id),
		"type": "public-key", "authenticatorAttachment": "platform", "clientExtensionResults": map[string]any{},
		"response": map[string]any{
			"clientDataJSON":    base64.RawURLEncoding.EncodeToString(cd),
			"authenticatorData": base64.RawURLEncoding.EncodeToString(ad),
			"signature":         base64.RawURLEncoding.EncodeToString(sig),
			"userHandle":        base64.RawURLEncoding.EncodeToString(userID),
		},
	}
}

func passkeyPost(t *testing.T, h *handler, path string, body any, cookie *http.Cookie) *httptest.ResponseRecorder {
	t.Helper()
	r := httptest.NewRequest(http.MethodPost, "https://"+h.cfg.DomainDrawbridge+path, bytes.NewReader(testJSON(t, body)))
	r.Header.Set(headerContentType, contentTypeJSON)
	if cookie != nil {
		r.AddCookie(cookie)
	}
	w := httptest.NewRecorder()
	h.ServeHTTP(w, r)
	return w
}

func passkeyBegin(t *testing.T, h *handler, path string, body any) (string, *http.Cookie) {
	t.Helper()
	w := passkeyPost(t, h, path, body, nil)
	if w.Code != http.StatusOK {
		t.Fatalf("begin failed: %s", w.Body)
	}
	var options struct {
		Challenge string `json:"challenge"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &options); err != nil {
		t.Fatal(err)
	}
	if options.Challenge == "" || w.Header().Get(headerCacheControl) != cacheNoStore {
		t.Fatalf("invalid or cacheable options: %s", w.Body)
	}
	for _, c := range w.Result().Cookies() {
		if c.Name == cookieNameChallenge {
			return options.Challenge, c
		}
	}
	t.Fatal("missing challenge cookie")
	return "", nil
}

func TestPasskeyEnrollmentAndLogin(t *testing.T) {
	h, cfg := newTestHandler(t, "http://127.0.0.1:1", map[string][]string{"example.com": {"alice@example.com"}})
	a := newTestAuthenticator(t)
	begin := map[string]any{"username": "Alice@example.com", "displayname": "Alice Carroll"}
	challenge, cookie := passkeyBegin(t, h, pathAttestationBegin, begin)
	w := passkeyPost(t, h, pathAttestationFinish, a.registration(t, cfg.DomainDrawbridge, challenge), cookie)
	if w.Code != http.StatusOK {
		t.Fatalf("registration failed: %s", w.Body)
	}
	cred, err := loadCredentialRecord(bytes.NewReader(w.Body.Bytes()))
	if err != nil {
		t.Fatal(err)
	}
	if cred.UserName != "Alice@example.com" || cred.UserDisplayName != "Alice Carroll" || cred.AuthenticatorName != "Apple Passwords" ||
		cred.AuthenticatorID != "fbfc3007-154e-4ecc-8c0b-6e020557d7bd" || !bytes.Equal(cred.UserID, userIDFromUsername(cred.UserName)) {
		t.Fatalf("wrong enrollment metadata: %+v", cred)
	}
	for _, c := range w.Result().Cookies() {
		if c.Name == cookieNameSession {
			t.Fatal("enrollment granted a session before administrator approval")
		}
	}
	enrollment := bytes.Clone(w.Body.Bytes())
	login := func() *httptest.ResponseRecorder {
		challenge, cookie := passkeyBegin(t, h, pathAssertionBegin, map[string]any{})
		return passkeyPost(t, h, pathAssertionFinish, map[string]any{
			"credential": a.assertion(t, cfg.DomainDrawbridge, "https://"+cfg.DomainDrawbridge, challenge, cred.UserID, 0x05),
			"next":       "https://example.com/welcome",
		}, cookie)
	}
	if w := login(); w.Code != http.StatusUnauthorized {
		t.Fatalf("login succeeded before administrator approval: %d", w.Code)
	}

	// Exercise the real administrator command against the JSON the employee received.
	cfg.KeyFile = filepath.Join(t.TempDir(), "key")
	if err := os.WriteFile(cfg.KeyFile, []byte(keyEncode(cfg.key)), 0o600); err != nil {
		t.Fatal(err)
	}
	configFile := filepath.Join(t.TempDir(), "config.json")
	if err := os.WriteFile(configFile, testJSON(t, cfg), 0o600); err != nil {
		t.Fatal(err)
	}
	inputFile := filepath.Join(t.TempDir(), "enrollment.json")
	if err := os.WriteFile(inputFile, enrollment, 0o600); err != nil {
		t.Fatal(err)
	}
	input, err := os.Open(inputFile)
	if err != nil {
		t.Fatal(err)
	}
	defer input.Close()
	stdin := os.Stdin
	os.Stdin = input
	defer func() { os.Stdin = stdin }()
	if err := credEnroll(configFile); err != nil {
		t.Fatal(err)
	}
	h.reloadCredentials()

	w = passkeyPost(t, h, pathAttestationBegin, begin, nil)
	var options struct {
		User struct {
			ID string `json:"id"`
		} `json:"user"`
		Exclude []struct {
			ID string `json:"id"`
		} `json:"excludeCredentials"`
		Selection struct {
			ResidentKey      string `json:"residentKey"`
			UserVerification string `json:"userVerification"`
		} `json:"authenticatorSelection"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &options); err != nil {
		t.Fatal(err)
	}
	if options.User.ID != base64.RawURLEncoding.EncodeToString(cred.UserID) ||
		len(options.Exclude) != 1 || options.Exclude[0].ID != base64.RawURLEncoding.EncodeToString(a.id) ||
		options.Selection.ResidentKey != "required" || options.Selection.UserVerification != "required" {
		t.Fatalf("wrong registration options: %s", w.Body)
	}
	w = login()
	if w.Code != http.StatusOK || !strings.Contains(w.Body.String(), "https://example.com/welcome") {
		t.Fatalf("login failed: %d %s", w.Code, w.Body)
	}
	var sessionCookie *http.Cookie
	for _, c := range w.Result().Cookies() {
		if c.Name == cookieNameSession {
			sessionCookie = c
		}
	}
	if sessionCookie == nil {
		t.Fatal("login did not issue a session cookie")
	}
	session, err := cookieDecode[sessionCookieData](cookieNameSession, sessionCookie.Value, cfg.key)
	if err != nil || session.Username != "alice@example.com" {
		t.Fatalf("incorrect signed-in user: %+v, %v", session, err)
	}
	// Removing the installed record and reloading revokes login and existing sessions.
	id := sha256.Sum256([]byte(cred.Passkey))
	filename := "alice@example.com-" + base64.RawURLEncoding.EncodeToString(id[:]) + ".json"
	if err := os.Remove(filepath.Join(cfg.CredentialsDir, filename)); err != nil {
		t.Fatal(err)
	}
	h.reloadCredentials()
	if w := login(); w.Code != http.StatusUnauthorized {
		t.Fatal("removed credential can still log in")
	}
	r := httptest.NewRequest(http.MethodGet, "https://example.com/", nil)
	r.AddCookie(sessionCookie)
	if h.authenticate(discardLogger(), r) != nil {
		t.Fatal("removed user's session is still accepted")
	}
}

func TestPasskeyLogin(t *testing.T) {
	h, cfg := newTestHandler(t, "http://127.0.0.1:1", nil)
	a := newTestAuthenticator(t)
	userID := userIDFromUsername("alice@example.com")
	// Put the signing credential second to exercise passing all of a user's
	// records to the library and handling a nonzero matched index.
	for _, authenticator := range []*testAuthenticator{newTestAuthenticator(t), a} {
		record := "$webauthn$v=1$" + base64.RawStdEncoding.EncodeToString(authenticator.authData(cfg.DomainDrawbridge, 5, true))
		h.credentials["alice@example.com"] = append(h.credentials["alice@example.com"],
			&credentialRecord{UserName: "alice@example.com", UserID: userID, Passkey: record})
	}
	for _, name := range []string{"valid_second_passkey", "no_presence", "no_verification", "wrong_origin", "wrong_rp", "wrong_challenge", "wrong_user", "missing_user", "wrong_key", "tampered_cookie", "expired_cookie"} {
		t.Run(name, func(t *testing.T) {
			challenge, cookie := passkeyBegin(t, h, pathAssertionBegin, map[string]any{})
			rpID, origin, uid, flags, signer := cfg.DomainDrawbridge, "https://"+cfg.DomainDrawbridge, userID, byte(5), a
			switch name {
			case "no_presence":
				flags = 4
			case "no_verification":
				flags = 1
			case "wrong_origin":
				origin = "https://other.example.com"
			case "wrong_rp":
				rpID = "other.example.com"
			case "wrong_challenge":
				challenge, _ = passkeyBegin(t, h, pathAssertionBegin, map[string]any{})
			case "wrong_user":
				uid = userIDFromUsername("hello@example.com")
			case "missing_user":
				uid = nil
			case "wrong_key":
				signer = newTestAuthenticator(t)
				signer.id = a.id
			case "tampered_cookie":
				cookie.Value += "x"
			case "expired_cookie":
				c, err := cookieDecode[challengeCookieData](cookieNameChallenge, cookie.Value, cfg.key)
				if err != nil {
					t.Fatal(err)
				}
				c.Expires = uint32(time.Now().Add(-time.Minute).Unix())
				cookie.Value, err = cookieEncode(cookieNameChallenge, c, cfg.key)
				if err != nil {
					t.Fatal(err)
				}
			}
			w := passkeyPost(t, h, pathAssertionFinish, map[string]any{
				"credential": signer.assertion(t, rpID, origin, challenge, uid, flags),
				"next":       "https://attacker.example/",
			}, cookie)
			if name == "valid_second_passkey" {
				if w.Code != http.StatusOK || strings.Contains(w.Body.String(), "attacker.example") {
					t.Fatalf("valid login or safe redirect failed: %d %s", w.Code, w.Body)
				}
			} else {
				if w.Code != http.StatusUnauthorized && w.Code != http.StatusBadRequest {
					t.Fatalf("invalid assertion accepted: %d %s", w.Code, w.Body)
				}
				for _, c := range w.Result().Cookies() {
					if c.Name == cookieNameSession {
						t.Fatal("failed login issued a session")
					}
				}
			}
		})
	}
}

func TestDrawbridgeLoginServesHTMLAndHSTS(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Fatalf("unexpected upstream request to %q", r.URL.String())
	}))
	t.Cleanup(upstream.Close)

	h, cfg := newTestHandler(t, upstream.URL, map[string][]string{
		"example.com": {"hello@example.com"},
	})

	req := httptest.NewRequest(http.MethodGet, "https://"+cfg.DomainDrawbridge+pathLogin, nil)
	req.Host = cfg.DomainDrawbridge
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, req)
	res := rr.Result()
	t.Cleanup(func() { _ = res.Body.Close() })

	if res.StatusCode != http.StatusOK {
		t.Fatalf("unexpected status: %v", res.Status)
	}
	if got := res.Header.Get(headerHSTS); got != hstsValue {
		t.Fatalf("unexpected HSTS header: %q", got)
	}
	body, _ := io.ReadAll(res.Body)
	if !bytes.Contains(body, []byte("Drawbridge Login")) {
		t.Fatalf("unexpected body, missing login marker")
	}
}

func TestDrawbridgeIndex(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Fatalf("unexpected upstream request to %q", r.URL.String())
	}))
	t.Cleanup(upstream.Close)

	h, cfg := newTestHandler(t, upstream.URL, map[string][]string{
		"a.example.com": {"hello@example.com"},
		"c.example.com": {"other@example.com"},
	})

	t.Run("signed_out", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, "https://"+cfg.DomainDrawbridge+pathIndex, nil)
		req.Host = cfg.DomainDrawbridge
		rr := httptest.NewRecorder()
		h.ServeHTTP(rr, req)
		res := rr.Result()
		t.Cleanup(func() { _ = res.Body.Close() })

		if res.StatusCode != http.StatusOK {
			t.Fatalf("unexpected status: %v", res.Status)
		}
		if got := res.Header.Get(headerHSTS); got != hstsValue {
			t.Fatalf("unexpected HSTS header: %q", got)
		}
		body, _ := io.ReadAll(res.Body)
		if !bytes.Contains(body, []byte("<title>Drawbridge</title>")) {
			t.Fatalf("unexpected body, missing title marker")
		}
		if !bytes.Contains(body, []byte("href=\"/enroll\"")) {
			t.Fatalf("unexpected body, missing enroll link")
		}
		if !bytes.Contains(body, []byte("href=\"/login\"")) {
			t.Fatalf("unexpected body, missing login link")
		}
		if !bytes.Contains(body, []byte("href=\"/logout\"")) {
			t.Fatalf("unexpected body, missing logout link")
		}
	})

	t.Run("signed_in", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, "https://"+cfg.DomainDrawbridge+pathIndex, nil)
		req.Host = cfg.DomainDrawbridge
		addValidSessionCookie(t, req, cfg, "hello@example.com")
		rr := httptest.NewRecorder()
		h.ServeHTTP(rr, req)
		res := rr.Result()
		t.Cleanup(func() { _ = res.Body.Close() })

		if res.StatusCode != http.StatusOK {
			t.Fatalf("unexpected status: %v", res.Status)
		}
		body, _ := io.ReadAll(res.Body)
		if !bytes.Contains(body, []byte("hello@example.com")) {
			t.Fatalf("unexpected body, missing username marker")
		}
		if !bytes.Contains(body, []byte("a.example.com")) {
			t.Fatalf("unexpected body, missing authorized service marker")
		}
		if bytes.Contains(body, []byte("c.example.com")) {
			t.Fatalf("unexpected body, found unauthorized service marker")
		}
	})
}

func TestUnauthenticatedSafeRequestRedirectsToLogin(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Fatalf("unexpected upstream request to %q", r.URL.String())
	}))
	t.Cleanup(upstream.Close)

	h, cfg := newTestHandler(t, upstream.URL, map[string][]string{
		"example.com": {"hello@example.com"},
	})

	req := httptest.NewRequest(http.MethodGet, "https://example.com/foo?bar=baz", nil)
	req.Host = "example.com"
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, req)
	res := rr.Result()
	t.Cleanup(func() { _ = res.Body.Close() })

	if res.StatusCode != http.StatusSeeOther {
		t.Fatalf("unexpected status: %v", res.Status)
	}
	if got := res.Header.Get(headerHSTS); got != hstsValue {
		t.Fatalf("unexpected HSTS header: %q", got)
	}

	loc := res.Header.Get("Location")
	u, err := url.Parse(loc)
	if err != nil {
		t.Fatalf("failed to parse Location %q: %v", loc, err)
	}
	if u.Scheme != "https" || u.Host != cfg.DomainDrawbridge || u.Path != pathLogin {
		t.Fatalf("unexpected redirect location: %q", loc)
	}
	if next := u.Query().Get("next"); next != "https://example.com/foo?bar=baz" {
		t.Fatalf("unexpected next param: %q", next)
	}

	var cleared bool
	for _, v := range res.Header.Values(headerSetCookie) {
		if strings.Contains(v, cookieNameSession+"=") && strings.Contains(v, "Max-Age=0") {
			cleared = true
		}
	}
	if !cleared {
		t.Fatalf("expected session cookie to be cleared, got Set-Cookie=%q", res.Header.Values(headerSetCookie))
	}
}

func TestUnauthenticatedUnsafeRequestReturnsUnauthorized(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Fatalf("unexpected upstream request to %q", r.URL.String())
	}))
	t.Cleanup(upstream.Close)

	h, _ := newTestHandler(t, upstream.URL, map[string][]string{
		"example.com": {"hello@example.com"},
	})

	req := httptest.NewRequest(http.MethodPost, "https://example.com/api", strings.NewReader("{}"))
	req.Host = "example.com"
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, req)
	res := rr.Result()
	t.Cleanup(func() { _ = res.Body.Close() })

	if res.StatusCode != http.StatusUnauthorized {
		t.Fatalf("unexpected status: %v", res.Status)
	}
	if got := res.Header.Get(headerHSTS); got != hstsValue {
		t.Fatalf("unexpected HSTS header: %q", got)
	}

	var cleared bool
	for _, v := range res.Header.Values(headerSetCookie) {
		if strings.Contains(v, cookieNameSession+"=") && strings.Contains(v, "Max-Age=0") {
			cleared = true
		}
	}
	if !cleared {
		t.Fatalf("expected session cookie to be cleared, got Set-Cookie=%q", res.Header.Values(headerSetCookie))
	}
}

func TestAuthorizedButNotAllowedReturns404(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Fatalf("unexpected upstream request to %q", r.URL.String())
	}))
	t.Cleanup(upstream.Close)

	h, cfg := newTestHandler(t, upstream.URL, map[string][]string{
		"private.example.com": {"other@example.com"},
	})

	req := httptest.NewRequest(http.MethodGet, "https://private.example.com/", nil)
	req.Host = "private.example.com"
	addValidSessionCookie(t, req, cfg, "hello@example.com")
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, req)
	res := rr.Result()
	t.Cleanup(func() { _ = res.Body.Close() })

	if res.StatusCode != http.StatusNotFound {
		t.Fatalf("unexpected status: %v", res.Status)
	}
	if got := res.Header.Get(headerHSTS); got != hstsValue {
		t.Fatalf("unexpected HSTS header: %q", got)
	}
	if got := res.Header.Values(headerSetCookie); len(got) != 0 {
		t.Fatalf("did not expect Set-Cookie, got %q", got)
	}
}

func TestProxyAddsHeadersAndStripsCookiesAndHeaders(t *testing.T) {
	type upstreamReq struct {
		UserHeader      string
		RequestIDHeader string
		CookieNames     []string
		Path            string
	}
	gotCh := make(chan upstreamReq, 1)

	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var names []string
		for _, c := range r.Cookies() {
			names = append(names, c.Name)
		}
		gotCh <- upstreamReq{
			UserHeader:      r.Header.Get(headerUser),
			RequestIDHeader: r.Header.Get(headerRequestID),
			CookieNames:     names,
			Path:            r.URL.Path,
		}

		w.Header().Set(headerUser, "evil")
		w.Header().Set(headerRequestID, "evil")
		http.SetCookie(w, &http.Cookie{Name: cookieNameSession, Value: "evil", Path: "/"})
		http.SetCookie(w, &http.Cookie{Name: "app", Value: "ok", Path: "/"})
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("ok"))
	}))
	t.Cleanup(upstream.Close)

	h, cfg := newTestHandler(t, upstream.URL, map[string][]string{
		"example.com": {"hello@example.com"},
	})

	req := httptest.NewRequest(http.MethodGet, "https://example.com/hello", nil)
	req.Host = "example.com"
	req.Header.Set(headerUser, "client-spoof")
	req.Header.Set(headerRequestID, "client-spoof")
	addValidSessionCookie(t, req, cfg, "hello@example.com")
	req.AddCookie(&http.Cookie{Name: "app", Value: "1"})

	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, req)
	res := rr.Result()
	t.Cleanup(func() { _ = res.Body.Close() })

	if res.StatusCode != http.StatusOK {
		t.Fatalf("unexpected status: %v", res.Status)
	}
	if got := res.Header.Get(headerHSTS); got != hstsValue {
		t.Fatalf("unexpected HSTS header: %q", got)
	}
	if got := res.Header.Get(headerUser); got != "" {
		t.Fatalf("expected %q to be stripped from response, got %q", headerUser, got)
	}
	if got := res.Header.Get(headerRequestID); got != "" {
		t.Fatalf("expected %q to be stripped from response, got %q", headerRequestID, got)
	}
	body, _ := io.ReadAll(res.Body)
	if string(body) != "ok" {
		t.Fatalf("unexpected body: %q", string(body))
	}

	var appCookie bool
	for _, v := range res.Header.Values(headerSetCookie) {
		if strings.HasPrefix(v, "app=") {
			appCookie = true
		}
		if strings.Contains(v, cookieNameSession+"=") || strings.Contains(v, cookieNameChallenge+"=") {
			t.Fatalf("expected Drawbridge cookies to be stripped from response, got Set-Cookie=%q", res.Header.Values(headerSetCookie))
		}
	}
	if !appCookie {
		t.Fatalf("expected upstream app cookie to pass through, got Set-Cookie=%q", res.Header.Values(headerSetCookie))
	}

	up := <-gotCh
	if up.Path != "/hello" {
		t.Fatalf("unexpected upstream path: %q", up.Path)
	}
	if up.UserHeader != "hello@example.com" {
		t.Fatalf("unexpected upstream %q: %q", headerUser, up.UserHeader)
	}
	if strings.TrimSpace(up.RequestIDHeader) == "" {
		t.Fatalf("expected non-empty upstream %q", headerRequestID)
	}
	for _, n := range up.CookieNames {
		if n == cookieNameSession || n == cookieNameChallenge {
			t.Fatalf("expected Drawbridge cookies to be stripped from proxied request, got cookies=%v", up.CookieNames)
		}
	}
	var sawApp bool
	for _, n := range up.CookieNames {
		if n == "app" {
			sawApp = true
		}
	}
	if !sawApp {
		t.Fatalf("expected app cookie to be forwarded, got cookies=%v", up.CookieNames)
	}
}

func TestUnknownDomainReturns404(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Fatalf("unexpected upstream request to %q", r.URL.String())
	}))
	t.Cleanup(upstream.Close)

	h, _ := newTestHandler(t, upstream.URL, map[string][]string{
		"example.com": {"hello@example.com"},
	})

	req := httptest.NewRequest(http.MethodGet, "https://unknown.example.com/", nil)
	req.Host = "unknown.example.com"
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, req)
	res := rr.Result()
	t.Cleanup(func() { _ = res.Body.Close() })

	if res.StatusCode != http.StatusNotFound {
		t.Fatalf("unexpected status: %v", res.Status)
	}
	if got := res.Header.Get(headerHSTS); got != hstsValue {
		t.Fatalf("unexpected HSTS header: %q", got)
	}
}
