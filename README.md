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

Drawbridge is configured via a single JSON file (see [`drawbridge.json`](./drawbridge.json) for a complete example).

### Top-level fields

- `key_file` (string, required): Path to the Drawbridge secret key (as produced by `-keygen`).
- `credentials_dir` (string, required): Directory containing enrolled credential record files.
- `tls_cert_file`, `tls_key_file` (string, optional): If both are set, Drawbridge serves TLS using
  these files. If both are empty, Drawbridge uses ACME (`autocert`).
- `domain_root` (string, required): The root domain for your internal services. This is also the
  cookie domain for the session cookie.
- `domain_drawbridge` (string, required): The Drawbridge UI/authentication hostname. Must be the
  same as or a subdomain of `domain_root`.
- `domains` (object, required): Map of hostname -> domain config (see below). Each hostname must
  be the same as or a subdomain of `domain_root`.

### Per-domain fields (`domains["host"]`)

- `proxy_to_url` (string, required): Upstream URL to proxy to (must be `http` or `https`).
- `allowed_users` (array of strings, required): List of allowed user identifiers (typically
  emails) for this host. Matching is case-insensitive.

## How it works

Drawbridge serves HTTPS and routes purely on `Host`:

- `domain_drawbridge` serves the minimal UI/API endpoints for login, logout, and enrollment.
- each configured app hostname proxies to its `proxy_to_url` after authz.
- unauthenticated `GET`/`HEAD` to app hosts are redirected to the login page; other methods get
  `401`.
- authorization is a per-host allowlist (`allowed_users`); disallowed users get `404` to avoid
  domain enumeration.

Authentication is WebAuthn. Successful login sets a `drawbridge_session` cookie on `domain_root`
that is MACed (HMAC) but not encrypted: the browser can read it, but cannot forge it. Sessions are
otherwise stateless; credential records live as JSON files under `credentials_dir` and are
reloaded on `SIGHUP`.

For authorized requests, Drawbridge adds `X-Drawbridge-Request-ID` and `X-Drawbridge-User` and
strips its own headers/cookies in both directions to reduce spoofing/leakage risk.


## Quickstart

### 1) Build

Requires Go 1.25.

```sh
go build -o drawbridge .
```

### 2) Pick domains + DNS

You need:

- a root domain that will host your internal apps (`example.com`)
- a dedicated Drawbridge host under that root (`drawbridge.example.com`)
- one or more app hosts under that root (`src.example.com`, `msg.example.com`, ...)

Point all of those DNS names to the Drawbridge server IP (you can use a wildcard DNS record).
Drawbridge routes purely on `Host`.

### 3) Generate the Drawbridge secret key

Drawbridge uses a single secret key to MAC (HMAC) its cookies.

```sh
./drawbridge -keygen > skey
chmod 600 skey
```

### 4) Write a config file

Start from `drawbridge.json` and edit:

- your real domain names
- each app’s `proxy_to_url`
- each app’s `allowed_users`
- either provide `tls_cert_file`/`tls_key_file` or omit them to use ACME

Make sure `credentials_dir` exists and is writable by the Drawbridge process.

### 5) Run Drawbridge

Drawbridge serves HTTPS on TCP port `443`, so you need privileges/capabilities to bind to 443.

```sh
sudo ./drawbridge -config drawbridge.json
```

Use [`drawbridge.service`](./drawbridge.service) to run Drawbridge in production with systemd.

### 6) Enroll a WebAuthn credential

1. Visit Drawbridge enroll page (`https://drawbridge.example.com/enroll`)
2. Follow the browser prompts; the page will produce a JSON “enrollment blob”
3. As an administrator, save that blob to a file and pass it to `-enroll`:

```sh
./drawbridge -enroll -config drawbridge.json < enrollment.json
```

`-enroll` only performs basic validation of the credential record JSON and writes it into
`credentials_dir` under a stable, filesystem-safe name (`<lower(username)>-<base64url(credential_id)>.json`).
You can skip `-enroll` and place a `*.json` credential record file into `credentials_dir` yourself.

Send `SIGHUP` to the running Drawbridge process to reload credentials without restarting. (Config
changes require a restart.)

### 7) Sign in and use proxied apps

Visit any configured app domain (`https://src.example.com/`); Drawbridge will redirect
unauthenticated safe requests to the login page (`https://<domain_drawbridge>/login`).

## Known issues

- WebAuthn does not work in some webviews (use a standalone browser instead).
- Chrome tries to load `/manifest.json` in the background without sending the cookies,
  which does not work (results in a redirect to login page). Seems like a Chrome issue.

## Contributing

We welcome feedback – bug reports, issues, proposals – but do not accept non-trivial
pull requests without prior discussion.

## License

Drawbridge is licensed under the [Mozilla Public License Version 2.0](./LICENSE).
