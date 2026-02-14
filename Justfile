set dotenv-load := false
set ignore-comments := true

adapter_gowork := env_var_or_default("CLIENTIP_ADAPTER_GOWORK", "off")

default:
  @just --list

ci: test race coverage lint tidy-check actionlint

fmt:
  gofumpt -extra -w .
  goimports -w .

lint:
  golangci-lint run
  cd prometheus && GOWORK={{adapter_gowork}} golangci-lint run --config ../.golangci.yml

test pattern="" *args:
  @echo {{ if pattern == "" { "Running full test suite with shuffle..." } else { if pattern == "--" { "Running full test suite with shuffle..." } else { "Running tests matching pattern: " + pattern } } }}
  @go test -v -p 1 -count=1 ./... {{ if pattern == "" { "-shuffle=on" } else { if pattern == "--" { "-shuffle=on" } else { "-run \"" + pattern + "\"" } } }} {{args}}
  @GOWORK={{adapter_gowork}} go -C prometheus test -v -p 1 -count=1 ./... {{ if pattern == "" { "-shuffle=on" } else { if pattern == "--" { "-shuffle=on" } else { "-run \"" + pattern + "\"" } } }} {{args}}

bench pattern="." *args:
  @echo "Running benchmarks matching pattern: {{pattern}}"
  @go test -run '^$' -bench "{{pattern}}" -benchmem -count=1 ./... {{args}}
  @GOWORK={{adapter_gowork}} go -C prometheus test -run '^$' -bench "{{pattern}}" -benchmem -count=1 ./... {{args}}

bench-all *args:
  @just bench "." {{args}}

bench-save name pattern="." count="6" *args:
  @mkdir -p .bench
  @bash -eo pipefail -c 'outfile="$1"; echo "Saving benchmark sample to $outfile"; go test -run "^$" -bench "{{pattern}}" -benchmem -count={{count}} ./... {{args}} | tee "$outfile"; GOWORK={{adapter_gowork}} go -C prometheus test -run "^$" -bench "{{pattern}}" -benchmem -count={{count}} ./... {{args}} | tee -a "$outfile"' _ ".bench/{{name}}.txt"

bench-compare-saved before after:
  @just bench-compare ".bench/{{before}}.txt" ".bench/{{after}}.txt"

bench-compare before after:
  @if command -v benchstat >/dev/null 2>&1; then benchstat "{{before}}" "{{after}}"; else go run golang.org/x/perf/cmd/benchstat@latest "{{before}}" "{{after}}"; fi

race:
  go test -race ./...
  GOWORK={{adapter_gowork}} go -C prometheus test -race ./...

coverage:
  go test -coverprofile=coverage.out ./...
  GOWORK={{adapter_gowork}} go -C prometheus test -coverprofile=../coverage-prometheus.out ./...
  go tool cover -func=coverage.out
  GOWORK={{adapter_gowork}} go -C prometheus tool cover -func=../coverage-prometheus.out

vet:
  go vet ./...
  GOWORK={{adapter_gowork}} go -C prometheus vet ./...

tidy-check:
  before="$(git status --porcelain -- go.mod go.sum)"; go mod tidy; after="$(git status --porcelain -- go.mod go.sum)"; test "$before" = "$after"
  before="$(git status --porcelain -- prometheus/go.mod prometheus/go.sum)"; GOWORK={{adapter_gowork}} go -C prometheus mod tidy; after="$(git status --porcelain -- prometheus/go.mod prometheus/go.sum)"; test "$before" = "$after"

security:
  govulncheck ./...
  cd prometheus && GOWORK={{adapter_gowork}} govulncheck ./...

actionlint:
  actionlint
