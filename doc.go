// Package clientip provides secure client IP extraction from HTTP requests with
// support for proxy chains, trusted proxy validation, and multiple header sources.
//
// # Features
//
//   - Security-first design with protection against IP spoofing and header injection
//   - Flexible proxy configuration with min/max proxy ranges
//   - Multiple source support: X-Forwarded-For, X-Real-IP, RemoteAddr, custom headers
//   - Optional observability with context-aware logging and pluggable metrics
//   - Type-safe using modern Go netip.Addr
//
// # Basic Usage
//
// Simple extraction without proxy configuration:
//
//	extractor, err := clientip.New()
//	if err != nil {
//	    log.Fatal(err)
//	}
//
//	result := extractor.ExtractIP(req)
//	if result.Valid() {
//	    fmt.Printf("Client IP: %s from %s\n", result.IP, result.Source)
//	}
//
// # Behind Reverse Proxy
//
// Configure trusted proxy CIDRs with flexible min/max proxy count:
//
//	cidrs, _ := clientip.ParseCIDRs("10.0.0.0/8", "172.16.0.0/12")
//	extractor, err := clientip.New(
//	    clientip.TrustedProxies(cidrs, 1, 2),  // Expect 1-2 trusted proxies
//	    clientip.AllowPrivateIPs(false),
//	)
//
// # Custom Headers
//
// Support for cloud providers and custom proxy headers:
//
//	extractor, _ := clientip.New(
//	    clientip.Priority(
//	        "CF-Connecting-IP",                   // Cloudflare
//	        clientip.SourceXForwardedFor,
//	        clientip.SourceRemoteAddr,
//	    ),
//	)
//
// # Observability
//
// Add logging and metrics for production monitoring:
// (Prometheus adapter package: github.com/abczzz13/clientip/prometheus)
// The logger receives req.Context(), allowing trace/span IDs to flow through.
//
//	import clientipprom "github.com/abczzz13/clientip/prometheus"
//
//	extractor, err := clientip.New(
//	    clientip.TrustedProxies(cidrs, 1, 3),
//	    clientip.WithLogger(slog.Default()),
//	    clientipprom.WithMetrics(),
//	)
//
// # Security Considerations
//
// The package includes several security features:
//
//   - Detection of multiple X-Forwarded-For headers (possible spoofing)
//   - Immediate proxy trust enforcement before honoring X-Forwarded-For
//   - Validation of proxy counts (min/max enforcement)
//   - Chain length limits to prevent DoS
//   - Rejection of invalid/implausible IPs (loopback, multicast, etc.)
//   - Optional private IP filtering
//   - Strict fail-closed behavior by default (SecurityModeStrict)
//
// # Security Modes
//
// Security behavior can be configured per extractor:
//
//   - SecurityModeStrict (default): fail closed on security-significant errors.
//   - SecurityModeLax: allow fallback to lower-priority sources.
//
// Example:
//
//	extractor, _ := clientip.New(
//	    clientip.WithSecurityMode(clientip.SecurityModeLax),
//	)
//
// # Thread Safety
//
// Extractor instances are safe for concurrent use. They are typically created
// once at application startup and reused across all requests.
package clientip
