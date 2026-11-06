package main

import (
	"bufio"
	"bytes"
	"crypto/hmac"
	crand "crypto/rand"
	"crypto/sha256"
	_ "embed"
	"encoding/base64"
	"encoding/json/jsontext"
	json "encoding/json/v2"
	"errors"
	"flag"
	"fmt"
	"html/template"
	"io"
	"log/slog"
	"maps"
	"math/rand/v2"
	"net"
	"net/http"
	"net/http/httputil"
	"net/url"
	"os"
	"os/signal"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"

	"filippo.io/passkey"
	"golang.org/x/crypto/acme/autocert"
)

const (
	idSize      = 16
	keySize     = 32
	copyBufSize = 32 * 1024

	httpsAddr                = "0.0.0.0:443"
	httpReadHeaderTimeout    = 5 * time.Second
	httpIdleTimeout          = 1 * time.Minute
	httpInternalReadTimeout  = 1 * time.Second
	httpInternalWriteTimeout = 5 * time.Second
	httpMaxHeaderBytes       = copyBufSize // Conservative, to limit DoS potential somewhat.
	httpSmallBodyBytes       = copyBufSize

	pathIndex             = "/"
	pathEnroll            = "/enroll"
	pathLogin             = "/login"
	pathLogout            = "/logout"
	pathAttestationBegin  = "/attestation/begin"
	pathAttestationFinish = "/attestation/finish"
	pathAssertionBegin    = "/assertion/begin"
	pathAssertionFinish   = "/assertion/finish"

	cacheNoStore        = "no-store"
	contentTypeTextHTML = "text/html"
	contentTypeJSON     = "application/json"
	hstsValue           = "max-age=31536000; includeSubDomains"
	robotsNone          = "noindex, nofollow"

	headerAllow         = "Allow"
	headerCacheControl  = "Cache-Control"
	headerContentLength = "Content-Length"
	headerContentType   = "Content-Type"
	headerCookie        = "Cookie"
	headerOrigin        = "Origin"
	headerSetCookie     = "Set-Cookie"
	headerHSTS          = "Strict-Transport-Security"
	headerRobots        = "X-Robots-Tag"

	headerRequestID = "X-Drawbridge-Request-ID"
	headerUser      = "X-Drawbridge-User"

	cookieNameSession   = "drawbridge_session"
	cookieNameChallenge = "drawbridge_challenge"

	cookieTTLChallenge  = 30 * time.Minute
	cookieTTLSessionMin = 7 * 24 * time.Hour
	cookieTTLSessionMax = 14 * 24 * time.Hour
)

var (
	safeMethods = []string{http.MethodGet, http.MethodHead}
	ourHeaders  = []string{headerRequestID, headerUser}
	ourCookies  = []string{cookieNameSession, cookieNameChallenge}

	copyBufPool = newFixedBufferPool(copyBufSize)

	//go:embed drawbridge_index.html
	contentIndex string
	//go:embed drawbridge_enroll.html
	contentEnroll []byte
	//go:embed drawbridge_login.html
	contentLogin []byte
	//go:embed drawbridge_logout.html
	contentLogout []byte

	tmplIndex *template.Template
)

func init() {
	tmplIndex = template.Must(template.New("index").Option("missingkey=error").Parse(contentIndex))
}

type fixedBufferPool struct {
	size int
	ch   chan []byte
}

func newFixedBufferPool(size int) *fixedBufferPool {
	const capacity = 64
	return &fixedBufferPool{
		size: size,
		ch:   make(chan []byte, capacity),
	}
}

func (p *fixedBufferPool) Get() []byte {
	select {
	case buf := <-p.ch:
		return buf
	default:
		return make([]byte, p.size)
	}
}

func (p *fixedBufferPool) Put(buf []byte) {
	if cap(buf) == p.size {
		select {
		case p.ch <- buf[:p.size]:
		default:
		}
	}
}

type config struct {
	KeyFile string `json:"key_file"`
	key     [keySize]byte

	CredentialsDir string `json:"credentials_dir"`

	TLSCertFile string `json:"tls_cert_file"`
	TLSKeyFile  string `json:"tls_key_file"`

	DomainRoot       string                   `json:"domain_root"`
	DomainDrawbridge string                   `json:"domain_drawbridge"`
	Domains          map[string]*configDomain `json:"domains"`
}

type configDomain struct {
	ProxyToURL string `json:"proxy_to_url"`
	proxyToURL *url.URL

	AllowedUsers []string `json:"allowed_users"`
	allowedUsers map[string]struct{}
}

func configLoad(path string) (*config, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("failed to read config: %w", err)
	}

	var cfg config
	err = json.Unmarshal(data, &cfg, json.RejectUnknownMembers(true))
	if err != nil {
		return nil, fmt.Errorf("failed to parse config: %w", err)
	}

	keyData, err := os.ReadFile(cfg.KeyFile)
	if err != nil {
		return nil, fmt.Errorf("failed to read key file %q: %w", cfg.KeyFile, err)
	}
	key, err := keyDecode(string(bytes.TrimSpace(keyData)))
	if err != nil {
		return nil, fmt.Errorf("failed to decode key: %w", err)
	}
	cfg.key = key

	if cfg.CredentialsDir == "" {
		return nil, fmt.Errorf("empty credentials dir")
	}

	if cfg.DomainRoot == "" {
		return nil, fmt.Errorf("no \"domain_root\" specified")
	}
	if cfg.DomainDrawbridge == "" {
		return nil, fmt.Errorf("no \"domain_drawbridge\" specified")
	}
	if !hostSameOrSubdomain(cfg.DomainDrawbridge, cfg.DomainRoot) {
		return nil, fmt.Errorf("drawbridge domain %q is not a subdomain of root %q", cfg.DomainDrawbridge, cfg.DomainRoot)
	}
	if len(cfg.Domains) == 0 {
		return nil, fmt.Errorf("no \"domains\" specified")
	}
	for d, dc := range cfg.Domains {
		if !hostSameOrSubdomain(d, cfg.DomainRoot) {
			return nil, fmt.Errorf("domain %q is not a subdomain of root %q", d, cfg.DomainRoot)
		}

		u, err := url.Parse(dc.ProxyToURL)
		if err != nil {
			return nil, fmt.Errorf("failed to parse \"proxy_to_url\" for domain %q (%q): %w", d, dc.ProxyToURL, err)
		}
		if u.Scheme != "http" && u.Scheme != "https" {
			return nil, fmt.Errorf("non-HTTP(S) \"proxy_to_url\" for domain %q: %q", d, dc.ProxyToURL)
		}
		dc.proxyToURL = u
		dc.allowedUsers = make(map[string]struct{}, len(dc.AllowedUsers))
		for _, u := range dc.AllowedUsers {
			dc.allowedUsers[strings.ToLower(u)] = struct{}{}
		}
	}

	return &cfg, nil
}

type sessionCookieData struct {
	SessionID string `json:"sid"`
	Username  string `json:"sub"`
	Domain    string `json:"aud"`
	Issued    uint32 `json:"iat"`
	Expires   uint32 `json:"exp"`
}

type challengeCookieData struct {
	Type        string `json:"typ"`
	Challenge   string `json:"chal,omitempty"`
	Request     []byte `json:"req,omitempty"`
	UserID      []byte `json:"uid,omitempty"`
	Username    string `json:"name,omitempty"`
	DisplayName string `json:"disp,omitempty"`
	Domain      string `json:"aud"`
	Issued      uint32 `json:"iat"`
	Expires     uint32 `json:"exp"`
}

func cookieEncode[T any](name string, data *T, key [keySize]byte) (string, error) {
	dataBytes, err := json.Marshal(data)
	if err != nil {
		return "", fmt.Errorf("failed to encode cookie data to JSON: %w", err)
	}
	dataEnc := base64.RawURLEncoding.EncodeToString(dataBytes)
	h := hmac.New(sha256.New, key[:])
	h.Write([]byte(name + "=" + dataEnc))
	macBytes := h.Sum(nil)
	macEnc := base64.RawURLEncoding.EncodeToString(macBytes)
	cookie := fmt.Sprintf("%s.%s", dataEnc, macEnc)
	return cookie, nil
}

func cookieDecode[T any](name string, cookie string, key [keySize]byte) (*T, error) {
	parts := strings.Split(cookie, ".")
	if len(parts) != 2 {
		return nil, fmt.Errorf("wrong cookie format: %v parts instead of expected 2", len(parts))
	}
	dataEnc, macEnc := parts[0], parts[1]
	macBytes, err := base64.RawURLEncoding.Strict().DecodeString(macEnc)
	if err != nil {
		return nil, fmt.Errorf("failed to decode cookie MAC: %w", err)
	}
	h := hmac.New(sha256.New, key[:])
	h.Write([]byte(name + "=" + dataEnc))
	expectedMacBytes := h.Sum(nil)
	if !hmac.Equal(macBytes, expectedMacBytes) {
		return nil, fmt.Errorf("invalid cookie MAC")
	}
	dataBytes, err := base64.RawURLEncoding.Strict().DecodeString(dataEnc)
	if err != nil {
		return nil, fmt.Errorf("failed to decode cookie data: %w", err)
	}
	var data T
	err = json.Unmarshal(dataBytes, &data)
	if err != nil {
		return nil, fmt.Errorf("failed to unmarshal cookie data: %w", err)
	}
	return &data, nil
}

type handler struct {
	log *slog.Logger
	cfg *config
	rp  *passkey.RelyingParty

	rngMu sync.Mutex
	rng   *rand.ChaCha8

	credentialsMu sync.RWMutex
	credentials   map[string][]*credentialRecord
}

func newHandler(log *slog.Logger, cfg *config) (*handler, error) {
	rp, err := passkey.NewRelyingParty(cfg.DomainDrawbridge, "https://"+cfg.DomainDrawbridge,
		passkey.Options{Timeout: cookieTTLChallenge})
	if err != nil {
		return nil, fmt.Errorf("failed to configure passkeys: %w", err)
	}

	var seed [32]byte
	crand.Read(seed[:])

	h := &handler{
		log: log,
		cfg: cfg,
		rp:  rp,
		rng: rand.NewChaCha8(seed),
	}
	h.reloadCredentials()

	return h, nil
}

func (h *handler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	// Strip all Drawbridge headers.
	for _, header := range ourHeaders {
		r.Header.Del(header)
	}

	id := h.requestID()
	host := strings.ToLower(hostStripPort(r.Host))
	rw := &responseWriter{w: w}
	log := h.log.With(
		"request_id", id,
		"remote_addr", r.RemoteAddr,
		"method", r.Method,
		"host", host,
		"path", r.URL.Path,
	)
	defer func(start time.Time) {
		status := rw.status
		if status == 0 {
			status = http.StatusOK
		}
		log.Debug("request finished",
			"status", status,
			"size", rw.size,
			"duration", time.Since(start),
		)
	}(time.Now())

	// Only set the HSTS header unconditionally since Drawbridge promises to always enforce HTTPS.
	rw.Header().Set(headerHSTS, hstsValue)

	if host == h.cfg.DomainDrawbridge {
		rw.Header().Set(headerRobots, robotsNone)

		rc := http.NewResponseController(w)
		_ = rc.SetReadDeadline(time.Now().Add(httpInternalReadTimeout))
		defer rc.SetReadDeadline(time.Time{})
		_ = rc.SetWriteDeadline(time.Now().Add(httpInternalWriteTimeout))
		defer rc.SetWriteDeadline(time.Time{})

		switch r.URL.Path {
		case pathIndex:
			if checkMethod(rw, r, http.MethodGet) {
				h.handleIndex(log, rw, r)
			}
		case pathEnroll:
			if checkMethod(rw, r, http.MethodGet) {
				httpWrite(log, rw, contentTypeTextHTML, contentEnroll)
			}
		case pathLogin:
			if checkMethod(rw, r, http.MethodGet) {
				httpWrite(log, rw, contentTypeTextHTML, contentLogin)
			}
		case pathLogout:
			switch r.Method {
			case http.MethodGet:
				httpWrite(log, rw, contentTypeTextHTML, contentLogout)
			case http.MethodPost:
				h.handleLogout(log, rw, r)
			default:
				rw.Header().Set(headerAllow, strings.Join([]string{http.MethodGet, http.MethodPost}, ", "))
				httpError(rw, http.StatusMethodNotAllowed)
			}
		case pathAttestationBegin:
			if checkMethod(rw, r, http.MethodPost) {
				h.handleAttestationBegin(log, rw, r)
			}
		case pathAttestationFinish:
			if checkMethod(rw, r, http.MethodPost) {
				h.handleAttestationFinish(log, rw, r)
			}
		case pathAssertionBegin:
			if checkMethod(rw, r, http.MethodPost) {
				h.handleAssertionBegin(log, rw)
			}
		case pathAssertionFinish:
			if checkMethod(rw, r, http.MethodPost) {
				h.handleAssertionFinish(log, rw, r)
			}
		default:
			http.NotFound(rw, r)
		}
		return
	}

	domain, ok := h.cfg.Domains[host]
	if !ok {
		http.NotFound(rw, r)
		return
	}

	session := h.authenticate(log, r)
	if session == nil {
		// Clear our session cookie.
		httpHeaderSetCookieEmpty(rw, cookieNameSession, h.cfg.DomainRoot)
		if slices.Contains(safeMethods, r.Method) {
			loginURL := (&url.URL{
				Scheme: "https",
				Host:   h.cfg.DomainDrawbridge,
				Path:   pathLogin,
				RawQuery: "next=" + url.QueryEscape((&url.URL{
					Scheme:   "https",
					Host:     host,
					Path:     r.URL.Path,
					RawQuery: r.URL.RawQuery,
				}).String()),
			}).String()
			http.Redirect(rw, r, loginURL, http.StatusSeeOther)
		} else {
			httpError(rw, http.StatusUnauthorized)
		}
		return
	}

	if !h.authorize(session.Username, host) {
		// Return 404 to disallow domain enumeration.
		http.NotFound(rw, r)
		return
	}

	proxy := httputil.ReverseProxy{
		Rewrite: func(r *httputil.ProxyRequest) {
			r.SetURL(domain.proxyToURL)
			r.Out.Host = host
			r.SetXForwarded()
			// Set Drawbridge headers.
			r.Out.Header.Set(headerRequestID, id)
			r.Out.Header.Set(headerUser, session.Username)
			// Strip all Drawbridge cookies.
			r.Out.Header.Del(headerCookie)
			for _, cookie := range r.In.Cookies() {
				if !slices.Contains(ourCookies, cookie.Name) {
					r.Out.AddCookie(cookie)
				}
			}
		},
		ModifyResponse: func(r *http.Response) error {
			// Strip all Drawbridge headers.
			for _, header := range ourHeaders {
				r.Header.Del(header)
			}
			// Strip all Drawbridge set-cookies.
			cookies := r.Cookies()
			r.Header.Del(headerSetCookie)
			for _, cookie := range cookies {
				if !slices.Contains(ourCookies, cookie.Name) {
					r.Header.Add(headerSetCookie, cookie.String())
				}
			}
			return nil
		},
		BufferPool: copyBufPool,
	}
	proxy.ServeHTTP(rw, r)
}

func (h *handler) handleIndex(log *slog.Logger, w http.ResponseWriter, r *http.Request) {
	type templateData struct {
		SignedIn bool
		Username string
		Services []string
	}

	data := templateData{}
	if session := h.authenticate(log, r); session != nil {
		data.SignedIn = true
		data.Username = session.Username
		for host := range h.cfg.Domains {
			if h.authorize(session.Username, host) {
				data.Services = append(data.Services, host)
			}
		}
		slices.Sort(data.Services)
	}

	var buf bytes.Buffer
	if err := tmplIndex.Execute(&buf, &data); err != nil {
		log.Error("failed to execute index template", "err", err)
		httpError(w, http.StatusInternalServerError)
		return
	}
	w.Header().Set(headerCacheControl, cacheNoStore)
	httpWrite(log, w, contentTypeTextHTML, buf.Bytes())
}

func (h *handler) handleLogout(log *slog.Logger, w http.ResponseWriter, r *http.Request) {
	origin := r.Header.Get(headerOrigin)
	if origin != "" && origin != "https://"+h.cfg.DomainDrawbridge {
		log.Warn("logout blocked: cross-site request", "origin", origin)
		httpError(w, http.StatusForbidden)
		return
	}
	httpHeaderSetCookieEmpty(w, cookieNameSession, h.cfg.DomainRoot)
	http.Redirect(w, r, "https://"+h.cfg.DomainDrawbridge+pathLogin, http.StatusSeeOther)
}

func (h *handler) handleAttestationBegin(log *slog.Logger, w http.ResponseWriter, r *http.Request) {
	type attestationBeginRequest struct {
		Username    string `json:"username"`
		DisplayName string `json:"displayname"`
	}

	var req attestationBeginRequest
	if !readSmallJSON(w, r, &req) {
		return
	}
	log.Info("attestation begin", "username", req.Username, "display_name", req.DisplayName)
	userID := userIDFromUsername(req.Username)
	options, err := h.rp.NewRegistration(
		passkey.User{ID: string(userID), Name: req.Username},
		passkey.RegistrationOptions{ExcludeCredentials: h.passkeysForUsername(strings.ToLower(req.Username))})
	if err != nil {
		log.Warn("invalid registration options", "err", err)
		httpError(w, http.StatusBadRequest)
		return
	}
	var creation struct {
		Challenge string `json:"challenge"`
	}
	if err := json.Unmarshal(options, &creation); err != nil || creation.Challenge == "" {
		log.Error("invalid registration challenge", "err", err)
		httpError(w, http.StatusInternalServerError)
		return
	}
	cookieData := &challengeCookieData{
		Type:        "attestation",
		Challenge:   creation.Challenge,
		UserID:      userID,
		Username:    req.Username,
		DisplayName: req.DisplayName,
		Domain:      h.cfg.DomainDrawbridge,
		Issued:      uint32(time.Now().Unix()),
		Expires:     uint32(time.Now().Add(cookieTTLChallenge).Unix()),
	}
	if !httpHeaderSetCookieValue(log, w, cookieNameChallenge, cookieData, h.cfg.DomainDrawbridge, cookieTTLChallenge, h.cfg.key, http.SameSiteStrictMode) {
		return
	}
	w.Header().Set(headerCacheControl, cacheNoStore)
	httpWrite(log, w, contentTypeJSON, options)
}

type credentialRecord struct {
	UserID            []byte `json:"user_id"`
	UserName          string `json:"user_name"`
	UserDisplayName   string `json:"user_display_name"`
	AuthenticatorID   string `json:"authenticator_id"`
	AuthenticatorName string `json:"authenticator_name,omitempty"`
	Passkey           string `json:"passkey"`
}

func loadCredentialRecord(r io.Reader) (*credentialRecord, error) {
	var cred credentialRecord
	err := json.UnmarshalRead(r, &cred, json.RejectUnknownMembers(true))
	if err != nil {
		return nil, fmt.Errorf("failed to decode credential record: %w", err)
	}
	if cred.UserName == "" || len(cred.UserID) == 0 || len(cred.UserID) > 64 {
		return nil, fmt.Errorf("invalid credential user")
	}
	cred.AuthenticatorID, err = passkeyAuthenticatorID(cred.Passkey)
	if err != nil {
		return nil, err
	}
	cred.AuthenticatorName = authenticatorNames[cred.AuthenticatorID]
	return &cred, nil
}

func passkeyAuthenticatorID(record string) (string, error) {
	aaguid, err := passkey.AAGUID(record)
	if err != nil {
		return "", fmt.Errorf("invalid passkey record: %w", err)
	}
	return fmt.Sprintf("%x-%x-%x-%x-%x", aaguid[:4], aaguid[4:6], aaguid[6:8], aaguid[8:10], aaguid[10:]), nil
}

func (h *handler) handleAttestationFinish(log *slog.Logger, w http.ResponseWriter, r *http.Request) {
	var response jsontext.Value
	if !readSmallJSON(w, r, &response) {
		return
	}
	challenge := httpCookieValidateChallenge(log, w, r, "attestation", h.cfg.DomainDrawbridge, h.cfg.key)
	if challenge == nil {
		return
	}
	var registration struct {
		Response struct {
			ClientDataJSON string `json:"clientDataJSON"`
		} `json:"response"`
	}
	// Match the library's case-insensitive field lookup (until it switches to encoding/json/v2).
	if err := json.Unmarshal(response, &registration, json.MatchCaseInsensitiveNames(true)); err != nil {
		log.Warn("invalid registration response", "err", err)
		httpError(w, http.StatusUnauthorized)
		return
	}
	clientDataJSON, err := base64.RawURLEncoding.Strict().DecodeString(registration.Response.ClientDataJSON)
	var clientData struct {
		Challenge string `json:"challenge"`
	}
	if err != nil || json.Unmarshal(clientDataJSON, &clientData, json.MatchCaseInsensitiveNames(true)) != nil ||
		challenge.Challenge == "" || clientData.Challenge != challenge.Challenge {
		log.Warn("attestation challenge mismatch")
		httpError(w, http.StatusUnauthorized)
		return
	}
	record, err := h.rp.Register(response)
	if err != nil {
		log.Warn("attestation failed", "err", err)
		httpError(w, http.StatusUnauthorized)
		return
	}
	authenticatorID, err := passkeyAuthenticatorID(record)
	if err != nil {
		log.Warn("attestation failed", "err", err)
		httpError(w, http.StatusUnauthorized)
		return
	}
	resp := credentialRecord{
		UserID:            challenge.UserID,
		UserName:          challenge.Username,
		UserDisplayName:   challenge.DisplayName,
		AuthenticatorID:   authenticatorID,
		AuthenticatorName: authenticatorNames[authenticatorID],
		Passkey:           record,
	}
	log.Info("attestation finish",
		"username", resp.UserName,
		"display_name", resp.UserDisplayName,
		"authenticator_id", resp.AuthenticatorID,
		"authenticator_name", resp.AuthenticatorName)
	httpHeaderSetCookieEmpty(w, cookieNameChallenge, h.cfg.DomainDrawbridge)
	writeJSON(log, w, resp)
}

func (h *handler) handleAssertionBegin(log *slog.Logger, w http.ResponseWriter) {
	request, options, err := h.rp.NewLogin(passkey.LoginOptions{})
	if err != nil {
		log.Error("failed to create login options", "err", err)
		httpError(w, http.StatusInternalServerError)
		return
	}
	cookieData := &challengeCookieData{
		Type:    "assertion",
		Request: request,
		Domain:  h.cfg.DomainDrawbridge,
		Issued:  uint32(time.Now().Unix()),
		Expires: uint32(time.Now().Add(cookieTTLChallenge).Unix()),
	}
	if !httpHeaderSetCookieValue(log, w, cookieNameChallenge, cookieData, h.cfg.DomainDrawbridge, cookieTTLChallenge, h.cfg.key, http.SameSiteStrictMode) {
		return
	}
	w.Header().Set(headerCacheControl, cacheNoStore)
	httpWrite(log, w, contentTypeJSON, options)
}

func (h *handler) handleAssertionFinish(log *slog.Logger, w http.ResponseWriter, r *http.Request) {
	type assertionFinishRequest struct {
		Credential jsontext.Value `json:"credential"`
		Next       string         `json:"next"`
	}

	var req assertionFinishRequest
	if !readSmallJSON(w, r, &req) {
		return
	}
	challenge := httpCookieValidateChallenge(log, w, r, "assertion", h.cfg.DomainDrawbridge, h.cfg.key)
	if challenge == nil {
		return
	}
	response, err := passkey.ParseResponse(req.Credential)
	if err != nil {
		log.Warn("assertion failed", "err", err)
		httpError(w, http.StatusUnauthorized)
		return
	}
	// The user handle is only a lookup hint until Login verifies the assertion.
	creds := h.credentialsForUserID(response.UnauthenticatedUserID())
	if len(creds) == 0 {
		log.Warn("assertion failed: no matching credential")
		httpError(w, http.StatusUnauthorized)
		return
	}

	passkeys := make([]string, len(creds))
	for i, cred := range creds {
		passkeys[i] = cred.Passkey
	}
	result, err := h.rp.Login(response, challenge.Request, passkeys)
	if err != nil {
		log.Warn("assertion failed", "err", err)
		httpError(w, http.StatusUnauthorized)
		return
	}
	cred := creds[result.Matched]

	ttl := h.sessionTTL()
	session := &sessionCookieData{
		SessionID: h.sessionID(),
		Username:  strings.ToLower(cred.UserName),
		Domain:    h.cfg.DomainRoot,
		Issued:    uint32(time.Now().Unix()),
		Expires:   uint32(time.Now().Add(ttl).Unix()),
	}
	if !httpHeaderSetCookieValue(log, w, cookieNameSession, session, h.cfg.DomainRoot, ttl, h.cfg.key, http.SameSiteLaxMode) {
		return
	}
	httpHeaderSetCookieEmpty(w, cookieNameChallenge, h.cfg.DomainDrawbridge)

	redirectTo := "https://" + h.cfg.DomainRoot + "/"
	if h.validNextURL(req.Next) {
		redirectTo = req.Next
	}
	resp := map[string]any{
		"redirect_to": redirectTo,
	}
	writeJSON(log, w, resp)
}

func (h *handler) authenticate(log *slog.Logger, r *http.Request) *sessionCookieData {
	sessCookie, err := r.Cookie(cookieNameSession)
	if err != nil {
		log.Debug("session cookie missing")
		return nil
	}
	err = sessCookie.Valid()
	if err != nil {
		log.Debug("session cookie validation error", "err", err)
		return nil
	}
	session, err := cookieDecode[sessionCookieData](cookieNameSession, sessCookie.Value, h.cfg.key)
	if err != nil {
		log.Debug("session cookie decoding error", "err", err)
		return nil
	}
	if session.Domain != h.cfg.DomainRoot {
		log.Debug("session cookie for wrong domain", "cookie_domain", session.Domain, "domain", h.cfg.DomainRoot)
		return nil
	}
	expires := time.Unix(int64(session.Expires), 0)
	if expires.Before(time.Now()) {
		log.Debug("session cookie expired", "exp", expires)
		return nil
	}
	if !h.hasCredentialsForUsername(session.Username) {
		log.Debug("credentials for session username not found", "username", session.Username)
		return nil
	}
	return session
}

func (h *handler) authorize(username string, domain string) bool {
	dc, ok := h.cfg.Domains[domain]
	if !ok {
		return false
	}
	_, ok = dc.allowedUsers[username]
	return ok
}

func (h *handler) hasCredentialsForUsername(username string) bool {
	h.credentialsMu.RLock()
	defer h.credentialsMu.RUnlock()

	return len(h.credentials[username]) > 0
}

func (h *handler) passkeysForUsername(username string) []string {
	h.credentialsMu.RLock()
	defer h.credentialsMu.RUnlock()

	var records []string
	for _, cred := range h.credentials[username] {
		records = append(records, cred.Passkey)
	}
	return records
}

func (h *handler) credentialsForUserID(userID string) []*credentialRecord {
	h.credentialsMu.RLock()
	defer h.credentialsMu.RUnlock()

	// O(N), which is acceptable given the use case.
	var records []*credentialRecord
	for _, creds := range h.credentials {
		for _, cred := range creds {
			if string(cred.UserID) == userID {
				records = append(records, cred)
			}
		}
	}
	return records
}

func (h *handler) validNextURL(next string) bool {
	u, err := url.Parse(next)
	if err != nil {
		return false
	}
	return u.Scheme == "https" && h.cfg.Domains[u.Host] != nil
}

func (h *handler) requestID() string {
	h.rngMu.Lock()
	defer h.rngMu.Unlock()

	var id [idSize]byte
	h.rng.Read(id[:])

	return base64.RawURLEncoding.EncodeToString(id[:])
}

func (h *handler) sessionID() string {
	var id [idSize]byte
	crand.Read(id[:])
	return base64.RawURLEncoding.EncodeToString(id[:])
}

func (h *handler) sessionTTL() time.Duration {
	h.rngMu.Lock()
	defer h.rngMu.Unlock()

	rng := rand.New(h.rng)
	return cookieTTLSessionMin + time.Duration(rng.Int64N(int64(cookieTTLSessionMax-cookieTTLSessionMin)))
}

func (h *handler) reloadCredentials() {
	entries, err := os.ReadDir(h.cfg.CredentialsDir)
	if err != nil {
		h.log.Warn("failed to read all credential dir entries", "dir", h.cfg.CredentialsDir, "entries", len(entries), "err", err)
	}

	creds := make(map[string][]*credentialRecord, len(entries))
	n := 0
	for _, ent := range entries {
		if ent.IsDir() {
			continue
		}
		if filepath.Ext(ent.Name()) != ".json" {
			continue
		}
		path := filepath.Join(h.cfg.CredentialsDir, ent.Name())
		f, err := os.Open(path)
		if err != nil {
			h.log.Warn("failed to open credential record file, ignoring", "path", path, "err", err)
			continue
		}
		cred, err := loadCredentialRecord(f)
		f.Close()
		if err != nil {
			h.log.Warn("failed to load credential record, ignoring", "path", path, "err", err)
			continue
		}
		name := strings.ToLower(cred.UserName)
		creds[name] = append(creds[name], cred)
		n += 1
	}

	h.credentialsMu.Lock()
	h.credentials = creds
	h.credentialsMu.Unlock()

	h.log.Info("credential records reloaded", "records", n)
}

func hostStripPort(host string) string {
	if strings.IndexByte(host, ':') == -1 {
		return host
	}
	h, _, err := net.SplitHostPort(host)
	if err != nil {
		return host
	}
	return h
}

func hostSameOrSubdomain(host string, domain string) bool {
	return host == domain || strings.HasSuffix(host, "."+domain)
}

func userIDFromUsername(username string) []byte {
	h := sha256.Sum256([]byte(strings.ToLower(username)))
	return h[:]
}

func keyEncode(key [keySize]byte) string {
	return base64.RawURLEncoding.EncodeToString(key[:])
}

func keyDecode(s string) ([keySize]byte, error) {
	var key [keySize]byte
	k, err := base64.RawURLEncoding.Strict().DecodeString(s)
	if err != nil {
		return key, err
	}
	if len(k) != keySize {
		return key, fmt.Errorf("invalid key size %v instead of %v", len(k), keySize)
	}
	copy(key[:], k)
	return key, nil
}

func credEnroll(configPath string) error {
	if configPath == "" {
		return fmt.Errorf("config file not specified")
	}
	cfg, err := configLoad(configPath)
	if err != nil {
		return fmt.Errorf("failed to load config file %q: %w", configPath, err)
	}

	cred, err := loadCredentialRecord(os.Stdin)
	if err != nil {
		return fmt.Errorf("failed to load credential record: %w", err)
	}

	err = os.MkdirAll(cfg.CredentialsDir, 0o755)
	if err != nil {
		return fmt.Errorf("failed to create credentials dir %q: %w", cfg.CredentialsDir, err)
	}

	f, err := os.CreateTemp(cfg.CredentialsDir, "")
	if err != nil {
		return fmt.Errorf("failed to create temporary credential file in %q: %w", cfg.CredentialsDir, err)
	}
	defer f.Close()

	err = json.MarshalWrite(f, cred, jsontext.WithIndent("  "))
	if err != nil {
		return fmt.Errorf("failed to encode credential record to %q: %w", f.Name(), err)
	}
	if _, err := io.WriteString(f, "\n"); err != nil {
		return fmt.Errorf("failed to finish credential record %q: %w", f.Name(), err)
	}

	id := sha256.Sum256([]byte(cred.Passkey))
	name := fmt.Sprintf("%s-%s.json", strings.ToLower(cred.UserName), base64.RawURLEncoding.EncodeToString(id[:]))
	filename := filepath.Join(cfg.CredentialsDir, simpleEscapeFilename(name))
	err = os.Rename(f.Name(), filename)
	if err != nil {
		return fmt.Errorf("failed to move credential record to from %q to %q: %w", f.Name(), filename, err)
	}

	fmt.Printf("credential written to %q\n", filename)
	fmt.Printf("send SIGHUP to drawbridge service process to re-scan the credentials directory\n")

	return nil
}

func keyGen() error {
	var key [keySize]byte
	crand.Read(key[:])
	fmt.Println(keyEncode(key))
	return nil
}

func runProxy(log *slog.Logger, configPath string) error {
	if configPath == "" {
		return fmt.Errorf("config file not specified")
	}
	cfg, err := configLoad(configPath)
	if err != nil {
		return fmt.Errorf("failed to load config file %q: %w", configPath, err)
	}

	h, err := newHandler(log, cfg)
	if err != nil {
		return err
	}
	sigs := make(chan os.Signal, 1)
	signal.Notify(sigs, syscall.SIGHUP)
	defer signal.Stop(sigs)
	go func() {
		for range sigs {
			h.reloadCredentials()
		}
	}()

	acme := cfg.TLSCertFile == "" && cfg.TLSKeyFile == ""
	var ln net.Listener
	domains := slices.AppendSeq([]string{cfg.DomainDrawbridge}, maps.Keys(cfg.Domains))
	if acme {
		ln = autocert.NewListener(domains...)
	} else {
		ln, err = net.Listen("tcp", httpsAddr)
		if err != nil {
			return fmt.Errorf("failed to listen TCP on %q: %w", httpsAddr, err)
		}
	}
	defer ln.Close()

	log.Info("starting to serve HTTPS", "acme", acme, "addr", ln.Addr().String(), "domains", domains)
	srv := &http.Server{
		Handler:                      h,
		ReadHeaderTimeout:            httpReadHeaderTimeout,
		IdleTimeout:                  httpIdleTimeout,
		MaxHeaderBytes:               httpMaxHeaderBytes,
		DisableGeneralOptionsHandler: true,
	}
	if acme {
		err = srv.Serve(ln)
	} else {
		err = srv.ServeTLS(ln, cfg.TLSCertFile, cfg.TLSKeyFile)
	}
	log.Debug("done serving HTTPS", "err", err)

	return err
}

func main() {
	var (
		enroll     = flag.Bool("enroll", false, "read new credential JSON from stdin, enroll it and exit")
		keygen     = flag.Bool("keygen", false, "generate new secret key, write it to stdout and exit")
		configPath = flag.String("config", "", "path to the config file")
	)
	flag.Parse()

	log := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{
		Level: slog.LevelDebug,
	}))

	var err error
	switch {
	case *enroll:
		err = credEnroll(*configPath)
	case *keygen:
		err = keyGen()
	default:
		err = runProxy(log, *configPath)
	}
	if err != nil {
		log.Error("drawbridge failed", "err", err)
		os.Exit(1)
	}
}

func simpleEscapeFilename(s string) string {
	specialChars := "/|\\:;<>\"'!?*"
	for _, c := range specialChars {
		s = strings.ReplaceAll(s, string(c), "_")
	}
	return s
}

func checkMethod(w http.ResponseWriter, r *http.Request, method string) bool {
	if r.Method != method {
		w.Header().Set(headerAllow, method)
		httpError(w, http.StatusMethodNotAllowed)
		return false
	}
	return true
}

func readSmallJSON(w http.ResponseWriter, r *http.Request, v any) bool {
	rd := http.MaxBytesReader(w, r.Body, httpSmallBodyBytes)
	err := json.UnmarshalRead(rd, v, json.RejectUnknownMembers(true))
	if err != nil {
		if _, ok := errors.AsType[*http.MaxBytesError](err); ok {
			httpError(w, http.StatusRequestEntityTooLarge)
		} else {
			httpError(w, http.StatusBadRequest)
		}
		return false
	}
	return true
}

func writeJSON(log *slog.Logger, w http.ResponseWriter, v any) {
	data, err := json.Marshal(v)
	if err != nil {
		log.Error("JSON encoding failed", "err", err)
		httpError(w, http.StatusInternalServerError)
		return
	}
	httpWrite(log, w, contentTypeJSON, data)
}

func httpCookieValidateChallenge(log *slog.Logger, w http.ResponseWriter, r *http.Request, typ string, domain string, key [keySize]byte) *challengeCookieData {
	cookie, err := r.Cookie(cookieNameChallenge)
	if err != nil {
		log.Debug("challenge cookie missing")
		httpError(w, http.StatusBadRequest)
		return nil
	}
	err = cookie.Valid()
	if err != nil {
		log.Debug("challenge cookie validation error", "err", err)
		httpError(w, http.StatusBadRequest)
		return nil
	}
	challenge, err := cookieDecode[challengeCookieData](cookieNameChallenge, cookie.Value, key)
	if err != nil {
		log.Debug("challenge cookie decoding error", "err", err)
		httpError(w, http.StatusBadRequest)
		return nil
	}
	if challenge.Type != typ {
		log.Debug("challenge cookie of unexpected type", "type", challenge.Type)
		httpError(w, http.StatusBadRequest)
		return nil
	}
	if challenge.Domain != domain {
		log.Debug("challenge cookie for wrong domain", "cookie_domain", challenge.Domain, "domain", domain)
		httpError(w, http.StatusBadRequest)
		return nil
	}
	expires := time.Unix(int64(challenge.Expires), 0)
	if expires.Before(time.Now()) {
		log.Debug("challenge cookie expired", "exp", expires)
		httpError(w, http.StatusBadRequest)
		return nil
	}
	return challenge
}

func httpHeaderSetCookieValue[T any](log *slog.Logger, w http.ResponseWriter, name string, data *T, domain string, ttl time.Duration, key [keySize]byte, sameSite http.SameSite) bool {
	value, err := cookieEncode(name, data, key)
	if err != nil {
		log.Error("cookie encoding failed", "err", err)
		httpError(w, http.StatusInternalServerError)
		return false
	}
	cookie := http.Cookie{
		Name:     name,
		Value:    value,
		Domain:   domain,
		Path:     "/",
		Expires:  time.Now().Add(ttl),
		Secure:   true,
		HttpOnly: true,
		SameSite: sameSite,
	}
	w.Header().Add(headerSetCookie, cookie.String())
	return true
}

func httpHeaderSetCookieEmpty(w http.ResponseWriter, name string, domain string) {
	emptyCookie := http.Cookie{
		Name:     name,
		Value:    "",
		Domain:   domain,
		Path:     "/",
		Expires:  time.Unix(0, 0),
		MaxAge:   -1,
		Secure:   true,
		HttpOnly: true,
	}
	w.Header().Add(headerSetCookie, emptyCookie.String())
}

func httpWrite(log *slog.Logger, w http.ResponseWriter, contentType string, data []byte) {
	w.Header().Set(headerContentType, contentType)
	w.Header().Set(headerContentLength, strconv.Itoa(len(data)))
	_, err := w.Write(data)
	if err != nil {
		log.Warn("HTTP write failed", "err", err)
	}
}

func httpError(w http.ResponseWriter, status int) {
	error := fmt.Sprintf("%d %s", status, http.StatusText(status))
	http.Error(w, error, status)
}

type responseWriter struct {
	w      http.ResponseWriter
	status int
	size   int64
}

func (rw *responseWriter) Header() http.Header {
	return rw.w.Header()
}

func (rw *responseWriter) WriteHeader(statusCode int) {
	if rw.status != 0 {
		return
	}
	rw.status = statusCode
	rw.w.WriteHeader(statusCode)
}

func (rw *responseWriter) Write(p []byte) (int, error) {
	if rw.status == 0 {
		rw.WriteHeader(http.StatusOK)
	}
	n, err := rw.w.Write(p)
	rw.size += int64(n)
	return n, err
}

func (rw *responseWriter) Unwrap() http.ResponseWriter {
	return rw.w
}

func (rw *responseWriter) Flush() {
	f, ok := rw.w.(http.Flusher)
	if !ok {
		return
	}
	f.Flush()
}

func (rw *responseWriter) Hijack() (net.Conn, *bufio.ReadWriter, error) {
	h, ok := rw.w.(http.Hijacker)
	if !ok {
		return nil, nil, http.ErrNotSupported
	}
	// Note: we don't properly account response size for hijacked connections.
	return h.Hijack()
}

func (rw *responseWriter) Push(target string, opts *http.PushOptions) error {
	p, ok := rw.w.(http.Pusher)
	if !ok {
		return http.ErrNotSupported
	}
	return p.Push(target, opts)
}

func (rw *responseWriter) ReadFrom(r io.Reader) (int64, error) {
	if rw.status == 0 {
		rw.WriteHeader(http.StatusOK)
	}
	if rf, ok := rw.w.(io.ReaderFrom); ok {
		n, err := rf.ReadFrom(r)
		rw.size += n
		return n, err
	} else {
		buf := copyBufPool.Get()
		defer copyBufPool.Put(buf)
		n, err := io.CopyBuffer(rw.w, r, buf)
		rw.size += n
		return n, err
	}
}
