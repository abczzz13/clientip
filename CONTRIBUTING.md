# Contributing

Thanks for taking the time to contribute.

## Development
- Minimum supported Go for the core module is `1.21`.
- Some maintainer tooling currently uses a newer Go toolchain (`1.26+`) in CI.
- Keep changes focused and include tests where applicable.

## Running tests
```bash
just test
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

## Installing tools
These maintainer tools are pinned and may require Go `1.24+`.

```bash
go install github.com/just/just@latest
go install github.com/golangci/golangci-lint/v2/cmd/golangci-lint@v2.8.0
go install golang.org/x/vuln/cmd/govulncheck@v1.1.4
go install github.com/rhysd/actionlint/cmd/actionlint@v1.7.10
go install mvdan.cc/gofumpt@latest
go install golang.org/x/tools/cmd/goimports@latest
```
