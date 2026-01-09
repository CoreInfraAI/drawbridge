module github.com/CoreInfraAI/drawbridge

go 1.25.5

require (
	github.com/go-passkeys/go-passkeys v0.4.2-0.20251212170742-2852eb57c748
	golang.org/x/crypto v0.46.0
)

// test-only
require pgregory.net/rapid v1.2.0

require (
	golang.org/x/net v0.48.0 // indirect
	golang.org/x/text v0.32.0 // indirect
)

replace github.com/go-passkeys/go-passkeys => github.com/flyingmutant/go-passkeys v0.0.0-20260109202745-7585cf57fe48
