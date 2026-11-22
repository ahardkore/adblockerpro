# Contributing to adblockerpro

Issues and pull requests are welcome. This project is a single static binary
— the ground rules are deliberately simple.

## Ground rules

- **Zero dependencies.** The resolver is Go 1.22, standard library only. If
  you are about to add an import, check why the stdlib does not cover it,
  and weigh the dependency on a device running for years on an SD card.
- **No runtime dependencies either.** A fresh install must need nothing but
  the binary and the systemd unit. If your change needs something new, put
  it behind a feature flag or a separate deploy target.
- **Fail loudly.** Silently skipping or truncating configuration is a bug
  in this project, not a convenience. Prefer an error or a log line that
  names the offending entry.
- **Secrets stay owner-only.** Any file that can carry credentials is
  written 0600 with `O_EXCL`-aware atomic renames. Do not regress this.
- **Keep the dashboard honest.** The UI must never show a wrong number. If
  a feature is approximate, say so on screen.

## Development loop

```bash
make test       # unit tests, with the race detector
make vet        # static analysis
make run        # DNS on :5353, dashboard on :8080, no root needed
```

The dashboard is plain HTML/CSS/JS in `web/static`, embedded into the binary
with `go:embed` — no build step, no node_modules. Edit it in place.

A few files you may want to read before filing an issue:

- `internal/server/dns.go` — the per-query decision path (UDP pool,
  coalescing, prefetch, stale-serving)
- `internal/history/store.go` — the append-only daily shards; understand the
  magic header before touching the format
- `internal/api/features.go` — backup/restore, schedules, Devices, metrics
- `internal/blocklist/` — the engine + updater; `SetRules` and `Set` cost a
  compile, do not call them per-query

## Tests

Add a test for every behavior change in `internal/`. Tests stay in the same
package as the code under test (`package stats`, not `stats_test`), use
`t.TempDir()` for files, and must not touch the network. `go test ./...`
must pass with `-race`.

The existing 13 test files cover the core paths; the gaps are the API,
config, devices, stats, tlsutil and abpctl surfaces. Pull requests that
close a gap are welcome and welcome a companion test.

## Pull requests

- One issue per PR; title the PR with the issue it fixes.
- `make test` and `make vet` green; no `go:embed` edits without a reason.
- Do not change the README safety claims or the safety promises in this
  file without a discussion first. The product's promise is "safe by
  default" — that is worth protecting.
