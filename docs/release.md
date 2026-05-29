# Release Checklist

## Tags

This repository contains two Go modules:

- root module: `github.com/abczzz13/clientip`
- Prometheus adapter module: `github.com/abczzz13/clientip/observe/prometheus`

Tag the root module with normal semantic-version tags:

```bash
git tag -a vX.Y.Z -m "release: vX.Y.Z"
git push origin vX.Y.Z
```

Tag the nested Prometheus adapter module with a path-prefixed tag:

```bash
git tag -a observe/prometheus/vX.Y.Z -m "release(prometheus): vX.Y.Z"
git push origin observe/prometheus/vX.Y.Z
```

The older `prometheus/v0.0.x` tags belong to the previous adapter module path and should be left in place for historical users. Do not reuse or move published tags.

## Before Tagging

1. Ensure `CHANGELOG.md` has a dated release section.
2. Run `just ci` locally when the required tools are installed.
3. Confirm GitHub Actions are green on `main`.
4. Confirm `go list -m -versions github.com/abczzz13/clientip` includes the intended root version after tagging.
5. Confirm `go list -m -versions github.com/abczzz13/clientip/observe/prometheus` includes the intended adapter version after tagging.

## v0.1 Compatibility Posture

Starting with `v0.1.0`, public APIs should preserve compatibility according to Semantic Versioning. Breaking API changes should wait for an appropriate SemVer boundary and should be clearly documented in the changelog.
