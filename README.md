# Drawbridge

Drawbridge is a reverse proxy that enables safe, authenticated access to internal HTTP services
(issue trackers, source code hosting, monitoring dashboards, admin panels) without a VPN.

Drawbridge enforces, for all exposed services:

- mandatory transport security (TLS with optional ACME),
- mandatory user authentication (WebAuthn),
- mandatory service access checks.

Drawbridge is intentionally conservative and minimalistic in all aspects – its main design
goal is to ensure the above guarantees *while having smallest possible total audit surface*.
You are expected to be able to manually vet all Drawbridge dependencies and manually review
all Drawbridge source code – [`drawbridge.go`](./drawbridge.go).

To align with this goal, Drawbridge relies on manual user registration and does not provide
any authorization besides service/subdomain access checks. Drawbridge is designed
to be Internet-facing, with no additional reverse proxies in front of it.

Drawbridge is not:

- a general identity provider (no SSO/OIDC/SAML),
- a user lifecycle system (no automatic provisioning/deprovisioning),
- a full-featured policy engine (no RBAC, groups, conditional access).

## Configuration

Drawbridge reads a single JSON config file (see [`drawbridge.json`](./drawbridge.json) for a complete example).

All fields are required unless noted.

- `key_file`: Path to the Drawbridge secret key (as produced by `-keygen`).
- `credentials_dir`: Directory containing enrolled credential record JSON files.
- `tls_cert_file`, `tls_key_file` (optional): If both are set, Drawbridge serves TLS using these files. If both
  are empty, Drawbridge uses ACME (`autocert`).
- `domain_root`: Root domain for all proxied hosts. Also used as the cookie domain for the session cookie.
- `domain_drawbridge`: Hostname for the Drawbridge UI/auth endpoints. Must be the same as or a subdomain of
  `domain_root`.
- `domains`: Map of hostname -> domain config. Each hostname must be the same as or a subdomain of
  `domain_root`.
- `domains[hostname].proxy_to_url`: Upstream URL to proxy to (must be `http` or `https`).
- `domains[hostname].allowed_users`: List of allowed user identifiers (typically emails) for this host.
  Matching is case-insensitive.

## How it works

Drawbridge serves HTTPS on TCP port `443` and routes purely on `Host`:

- `domain_drawbridge` serves the minimal UI/API endpoints for login, logout, and enrollment.
- Each configured app hostname proxies to its `proxy_to_url` after authentication + authorization.
- Unauthenticated `GET`/`HEAD` to app hosts are redirected to the login page; other methods get `401`.
- Authorization is a per-host allowlist (`allowed_users`); disallowed users get `404` to avoid domain
  enumeration.

Authentication is WebAuthn. Successful login sets a `drawbridge_session` cookie on `domain_root`
that is HMAC-signed but not encrypted: the browser can read it, but cannot forge it. Sessions are otherwise
stateless; credential records live as JSON files under `credentials_dir` and can be reloaded on `SIGHUP`.

For authorized requests, Drawbridge adds `X-Drawbridge-Request-ID` and `X-Drawbridge-User` and
strips its own headers/cookies in both directions to reduce spoofing/leakage risk.

## Quickstart

### 1) Build

Requires Go 1.25+.

```sh
go build -o drawbridge .
```

### 2) Pick domains and DNS

You need:

- a root domain that will host your internal apps (`example.com`)
- a dedicated Drawbridge host under that root (`drawbridge.example.com`)
- one or more app hosts under that root (`src.example.com`, `msg.example.com`, ...)

Point all of those DNS names to the Drawbridge server IP (you can use a wildcard DNS record).
Drawbridge routes purely on `Host`.

### 3) Generate the Drawbridge secret key

Drawbridge uses a single secret key to HMAC-sign its session cookies.

```sh
./drawbridge -keygen > skey
chmod 600 skey
```

### 4) Write a config file

Start from `drawbridge.json` and update:

- your domain names
- each app’s `proxy_to_url` and `allowed_users`
- `tls_cert_file`/`tls_key_file` (or omit both to use ACME)

Make sure `credentials_dir` exists and is writable by the Drawbridge process.

### 5) Run Drawbridge

Drawbridge serves HTTPS on TCP port `443`, so you need privileges/capabilities to bind to 443.

```sh
sudo ./drawbridge -config drawbridge.json
```

Use [`drawbridge.service`](./drawbridge.service) to run Drawbridge in production with systemd.

### 6) Enroll a WebAuthn credential

1. Visit Drawbridge enroll page (`https://drawbridge.example.com/enroll`)
2. Follow the browser prompts; the page will produce enrollment JSON
3. As an administrator, save it to a file and pass it to `-enroll`:

```sh
./drawbridge -enroll -config drawbridge.json < enrollment.json
```

`-enroll` performs basic validation and writes the credential record into `credentials_dir` under a stable,
filesystem-safe name (`<lower(username)>-<base64url(credential_id)>.json`). You can also skip `-enroll` and
place a `*.json` credential record file into `credentials_dir` yourself.

Send `SIGHUP` to the running Drawbridge process to reload credentials without restarting. (Config
changes require a restart.)

### 7) Sign in and use proxied apps

Visit any configured app domain (`https://src.example.com/`); Drawbridge will redirect
unauthenticated safe requests to the login page (`https://<domain_drawbridge>/login`).

## Known issues

- WebAuthn does not work in some webviews (use a standalone browser instead).
- Chrome may try to load `/manifest.json` in the background without sending cookies, which triggers a redirect
  to the login page. This appears to be a Chrome issue.

## Contributing

We welcome feedback – bug reports, issues, proposals – but do not accept non-trivial
pull requests without prior discussion.

## License

Drawbridge is licensed under the [Mozilla Public License Version 2.0](./LICENSE).
