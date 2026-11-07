# TODO

- consider reloading (parts of?) config on SIGHUP, at least to update allowed users
- `autocert.NewListener` caches certs under an OS cache/temp dir; `autocert.Manager` with an explicit dir could be better
- consider custom ACME server support
