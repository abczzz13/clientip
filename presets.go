package clientip

// PresetDirectConnection configures strict extraction for direct client-to-app
// traffic.
//
// This preset extracts from RemoteAddr only.
func PresetDirectConnection() Option {
	return optionFunc(func(c *options) {
		c.Sources = []Source{builtinSource(sourceRemoteAddr)}
	})
}

// PresetLoopbackReverseProxy configures extraction for apps behind a reverse
// proxy on the same host (for example NGINX on localhost).
//
// It trusts loopback proxy CIDRs and prioritizes X-Forwarded-For before
// RemoteAddr within the extractor's strict source order.
func PresetLoopbackReverseProxy() Option {
	return optionFunc(func(c *options) {
		c.TrustedProxyPrefixes = LoopbackProxyPrefixes()
		c.Sources = []Source{builtinSource(sourceXForwardedFor), builtinSource(sourceRemoteAddr)}
	})
}

// PresetVMReverseProxy configures extraction for apps behind a reverse proxy
// in a typical VM or private-network setup.
//
// It trusts loopback and private proxy CIDRs and prioritizes X-Forwarded-For
// before RemoteAddr within the extractor's strict source order.
func PresetVMReverseProxy() Option {
	return optionFunc(func(c *options) {
		c.TrustedProxyPrefixes = LocalProxyPrefixes()
		c.Sources = []Source{builtinSource(sourceXForwardedFor), builtinSource(sourceRemoteAddr)}
	})
}
