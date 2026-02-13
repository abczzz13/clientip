package clientip

// PresetDirectConnection configures extraction for direct client-to-app
// traffic.
//
// This preset extracts from RemoteAddr only.
func PresetDirectConnection() Option {
	return Priority(SourceRemoteAddr)
}

// PresetLoopbackReverseProxy configures extraction for apps behind a reverse
// proxy on the same host (for example NGINX on localhost).
//
// It trusts loopback proxy CIDRs and uses X-Forwarded-For with RemoteAddr
// fallback.
func PresetLoopbackReverseProxy() Option {
	return func(c *config) error {
		return applyOptions(c,
			TrustLoopbackProxy(),
			Priority(SourceXForwardedFor, SourceRemoteAddr),
		)
	}
}

// PresetVMReverseProxy configures extraction for apps behind a reverse proxy
// in a typical VM or private-network setup.
//
// It trusts loopback and private proxy CIDRs and uses X-Forwarded-For with
// RemoteAddr fallback.
func PresetVMReverseProxy() Option {
	return func(c *config) error {
		return applyOptions(c,
			TrustLocalProxyDefaults(),
			Priority(SourceXForwardedFor, SourceRemoteAddr),
		)
	}
}

// PresetPreferredHeaderThenXFFLax configures extraction to prefer a single
// custom header, then fall back to X-Forwarded-For and RemoteAddr.
//
// It also enables SecurityModeLax so invalid values in the preferred header
// can fall through to lower-priority sources.
//
// Header-based sources still require trusted proxy CIDRs.
func PresetPreferredHeaderThenXFFLax(header string) Option {
	return func(c *config) error {
		return applyOptions(c,
			Priority(header, SourceXForwardedFor, SourceRemoteAddr),
			WithSecurityMode(SecurityModeLax),
		)
	}
}
