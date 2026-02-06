set dotenv-load := false
set ignore-comments := true

default:
  @just --list

ci: test race coverage lint tidy-check actionlint

fmt:
  gofumpt -extra -w .
  goimports -w .

lint:
  golangci-lint run

test pattern="" *args:
  @echo {{ if pattern == "" { "Running full test suite with shuffle..." } else { if pattern == "--" { "Running full test suite with shuffle..." } else { "Running tests matching pattern: " + pattern } } }}
  @go test -v -p 1 -count=1 ./... {{ if pattern == "" { "-shuffle=on" } else { if pattern == "--" { "-shuffle=on" } else { "-run \"" + pattern + "\"" } } }} {{args}}

race:
  go test -race ./...

coverage:
  go test -coverprofile=coverage.out ./...
  go tool cover -func=coverage.out

vet:
  go vet ./...

tidy-check:
  go mod tidy
  git diff --exit-code -- go.mod go.sum

security:
  govulncheck ./...

actionlint:
  actionlint
