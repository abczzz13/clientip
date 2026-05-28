# Contributing

Thanks for taking the time to contribute.

## Project Layout

- The root module, `github.com/abczzz13/clientip`, is dependency-light and contains the resolver, parsers, trust validation, middleware, and public API docs.
- The optional Prometheus adapter module lives in `observe/prometheus` and is tested both from the workspace and as an external consumer with `GOWORK=off`.
- `Justfile` is the canonical local task runner entrypoint. Run `just --list` to see available tasks.

## Development Requirements

- Minimum supported Go for both modules is `1.21`.
- CI also runs maintainer tooling on Go `1.26.x` because some pinned tools require a newer toolchain.
- Keep changes focused and include tests where behavior changes.
- Public API changes should update godocs, examples, README guidance, and `CHANGELOG.md` when relevant.

## Installing Tools

These maintainer tools are pinned or used by CI and may require Go `1.26.x`:

```bash
go install github.com/just/just@latest
go install github.com/golangci/golangci-lint/v2/cmd/golangci-lint@v2.8.0
go install golang.org/x/vuln/cmd/govulncheck@v1.1.4
go install github.com/rhysd/actionlint/cmd/actionlint@v1.7.10
go install mvdan.cc/gofumpt@latest
go install golang.org/x/tools/cmd/goimports@latest
```

## Running tests

```bash
just test
```

To run one test pattern across both modules:

```bash
just test TestResolve
```

## Race tests

```bash
just race
```

## Linting

```bash
just lint
```

## Formatting

```bash
just fmt
```

## Coverage

```bash
just coverage
```

## Security checks

```bash
just security
```

## CI parity

```bash
just ci
```

## Adapter Workspace Mode

The Prometheus adapter normally runs as an external consumer so it does not accidentally depend on workspace-only state:

```bash
GOWORK=off go -C observe/prometheus test ./...
```

For local development against unpublished root-module changes, opt into workspace mode:

```bash
CLIENTIP_ADAPTER_GOWORK=auto just test
```

## Testing Expectations

- Parser changes should include malformed-input, boundary, and fuzz-relevant cases.
- Trust-chain changes should cover immediate-peer trust, trusted suffix selection, and min/max trusted proxy validation.
- Source changes should cover missing source fallback, terminal errors, duplicate header-line behavior, and context cancellation.
- Middleware changes should verify pass-through behavior and `FromContext` retrieval.
- Adapter changes should include consumer-mode tests with `GOWORK=off`.

## Documentation Expectations

- Every exported identifier needs a useful godoc comment that explains when to use it and any security implications.
- Examples should compile as Go examples where practical.
- README changes should stay user-facing and concise; detailed contributor guidance belongs here.
- Public behavior changes should update `CHANGELOG.md` under `[Unreleased]`.

## Pull Requests

- Describe the trust-boundary impact of the change, even when it is "none".
- Keep unrelated formatting or refactors out of behavior changes.
- Include tests or explain why tests are not applicable.
- Run `just ci` before requesting review when the required tools are available.
