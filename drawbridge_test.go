package main

import (
	"bytes"
	"crypto/ed25519"
	crand "crypto/rand"
	"crypto/x509"
	"encoding/json"
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

	"github.com/go-passkeys/go-passkeys/webauthn"
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

	pub, _, err := ed25519.GenerateKey(crand.Reader)
	if err != nil {
		t.Fatalf("failed to generate key: %v", err)
	}
	pkix, err := x509.MarshalPKIXPublicKey(pub)
	if err != nil {
		t.Fatalf("failed to marshal public key: %v", err)
	}

	cred := credentialRecord{
		CredentialID:    []byte("test-credential-id"),
		UserID:          userIDFromUsername(username),
		UserName:        username,
		UserDisplayName: "Test User",
		AuthenticatorID: "test-authenticator",
		PublicKey:       pkix,
		Algorithm:       int(webauthn.EdDSA),
	}

	path := filepath.Join(dir, "cred.json")
	f, err := os.Create(path)
	if err != nil {
		t.Fatalf("failed to create credential file: %v", err)
	}
	enc := json.NewEncoder(f)
	enc.SetIndent("", "  ")
	enc.SetEscapeHTML(false)
	if err := enc.Encode(&cred); err != nil {
		f.Close()
		t.Fatalf("failed to write credential record: %v", err)
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

	h := newHandler(discardLogger(), cfg)
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
