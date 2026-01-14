# TODO

- consider reloading (parts of?) config on SIGHUP, at least to update allowed users
- fork/vendor `go-passkeys` or ensure all PRs have landed
- migrate to `encoding/json/v2` once it is out (additionally, ensure no unknown fields + no trailing data)
- `autocert.NewListener` caches certs under an OS cache/temp dir; `autocert.Manager` with an explicit dir could be better
- consider custom ACME server support
- consider serving a list of user-accessible services & Drawbridge pages on `https://<domain_drawbridge>/`

## Known issues

- WebAuthn does not work in some webviews (use a standalone browser instead)
- Chrome tries to load `/manifest.json` in the background without sending the cookies,
  which does not work (results in a redirect to login page). Seems like a Chrome issue.
