# Contributing

Thanks for taking the time to contribute.

## Development
- Use the Go version listed in `go.mod`.
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
```bash
go install github.com/just/just@latest
go install github.com/golangci/golangci-lint/v2/cmd/golangci-lint@v2.8.0
go install golang.org/x/vuln/cmd/govulncheck@v1.1.4
go install github.com/rhysd/actionlint/cmd/actionlint@v1.7.10
go install mvdan.cc/gofumpt@latest
go install golang.org/x/tools/cmd/goimports@latest
```
