// Package clientip provides secure client IP extraction from HTTP requests and
// framework-agnostic request inputs with support for proxy chains, trusted
// proxy validation, and multiple header sources.
//
// # Features
//
//   - Security-first design with protection against IP spoofing and header injection
//   - Flexible proxy configuration with min/max trusted proxy ranges in proxy chains
//   - Multiple source support: Forwarded, X-Forwarded-For, X-Real-IP, RemoteAddr, custom headers
//   - Framework-friendly RequestInput API for non-net/http integrations
//   - Typed source configuration via Source constants and HeaderSource(...)
//   - Safe defaults: RemoteAddr-only unless header sources are explicitly configured
//   - Deployment presets for common topologies (direct, loopback proxy, VM proxy)
//   - Per-call policy overrides via CallOption builders such as WithCallSecurityMode
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
//	extraction, err := extractor.Extract(req)
//	if err != nil {
//	    log.Printf("extract failed: %v", err)
//	    return
//	}
//
//	fmt.Printf("Client IP: %s from %s\n", extraction.IP, extraction.Source)
//
// Framework-agnostic input is available via ExtractFrom:
//
//	extraction, err := extractor.ExtractFrom(clientip.RequestInput{
//	    Context:    ctx,
//	    RemoteAddr: remoteAddr,
//	    Path:       path,
//	    Headers:    headerProvider,
//	})
//
// Call options work with both Extract and ExtractFrom:
//
//	extraction, err := extractor.ExtractFrom(input,
//	    clientip.WithCallSourcePriority(
//	        clientip.HeaderSource("CF-Connecting-IP"),
//	        clientip.SourceRemoteAddr,
//	    ),
//	)
//
// # Behind Reverse Proxy
//
// Configure trusted proxy prefixes with flexible min/max proxy count:
//
//	cidrs, _ := clientip.ParseCIDRs("10.0.0.0/8", "172.16.0.0/12")
//	extractor, err := clientip.New(
//	    clientip.WithTrustedProxyPrefixes(cidrs...), // Trust upstream proxy ranges
//	    clientip.WithMinTrustedProxies(0),         // Count trusted proxies present in proxy headers
//	    clientip.WithMaxTrustedProxies(2),
//	    clientip.WithSourcePriority(clientip.SourceXForwardedFor, clientip.SourceRemoteAddr),
//	    clientip.WithChainSelection(clientip.RightmostUntrustedIP),
//	    clientip.WithAllowPrivateIPs(false),
//	)
//
// # Custom Headers
//
// Support for cloud providers and custom proxy headers:
//
//	extractor, _ := clientip.New(
//	    clientip.WithTrustedLoopbackProxy(),
//	    clientip.WithSourcePriority(
//	        clientip.HeaderSource("CF-Connecting-IP"), // Cloudflare
//	        clientip.SourceXForwardedFor,
//	        clientip.SourceRemoteAddr,
//	    ),
//	)
//
// Header sources require trusted upstream proxy ranges. Use
// WithTrustedProxyPrefixes(with ParseCIDRs for string inputs) or helper options like
// WithTrustedLoopbackProxy, WithTrustedPrivateProxyRanges,
// WithTrustedLocalProxyDefaults, or WithTrustedProxyAddrs.
//
// Presets are available for common setups:
//
//	extractor, _ := clientip.New(clientip.PresetVMReverseProxy())
//
// # Observability
//
// Add logging and metrics for production monitoring:
// (Prometheus adapter package: github.com/abczzz13/clientip/prometheus)
// The logger receives req.Context(), allowing trace/span IDs to flow through.
//
//	import clientipprom "github.com/abczzz13/clientip/prometheus"
//
//	metrics, _ := clientipprom.New()
//
//	extractor, err := clientip.New(
//	    clientip.WithTrustedProxyPrefixes(cidrs...),
//	    clientip.WithMinTrustedProxies(0),
//	    clientip.WithMaxTrustedProxies(3),
//	    clientip.WithSourcePriority(clientip.SourceXForwardedFor, clientip.SourceRemoteAddr),
//	    clientip.WithLogger(slog.Default()),
//	    clientip.WithMetrics(metrics),
//	)
//
// # Security Considerations
//
// The package includes several security features:
//
//   - Detection of malformed Forwarded headers and duplicate single-IP header values
//   - Immediate proxy trust enforcement before honoring Forwarded/X-Forwarded-For
//   - Validation of proxy counts (min/max enforcement)
//   - Chain length limits to prevent DoS
//   - Rejection of invalid/implausible IPs (loopback, multicast, etc.)
//   - Optional private IP filtering and explicit reserved CIDR allowlisting
//   - Strict fail-closed behavior by default (SecurityModeStrict)
//
// # Security Anti-Patterns
//
//   - Do not combine multiple competing header sources for security decisions.
//   - Do not use SecurityModeLax for ACL/risk/authz enforcement paths.
//   - Do not trust broad proxy CIDRs unless they are truly controlled by your edge.
//
// # Security Modes
//
// Security behavior can be configured per extractor:
//
//   - SecurityModeStrict (default): fail closed on security-significant errors and invalid present source values.
//   - SecurityModeLax: allow fallback to lower-priority sources for those errors.
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
