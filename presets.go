package clientip

// PresetDirectConnection configures strict extraction for direct client-to-app
// traffic.
//
// This preset extracts from RemoteAddr only.
func PresetDirectConnection() Config {
	cfg := DefaultConfig()
	cfg.Sources = []Source{builtinSource(sourceRemoteAddr)}
	return cfg
}

// PresetLoopbackReverseProxy configures extraction for apps behind a reverse
// proxy on the same host (for example NGINX on localhost).
//
// It trusts loopback proxy CIDRs and prioritizes X-Forwarded-For before
// RemoteAddr within the extractor's strict source order.
func PresetLoopbackReverseProxy() Config {
	cfg := DefaultConfig()
	cfg.TrustedProxyPrefixes = LoopbackProxyPrefixes()
	cfg.Sources = []Source{builtinSource(sourceXForwardedFor), builtinSource(sourceRemoteAddr)}
	return cfg
}

// PresetVMReverseProxy configures extraction for apps behind a reverse proxy
// in a typical VM or private-network setup.
//
// It trusts loopback and private proxy CIDRs and prioritizes X-Forwarded-For
// before RemoteAddr within the extractor's strict source order.
func PresetVMReverseProxy() Config {
	cfg := DefaultConfig()
	cfg.TrustedProxyPrefixes = LocalProxyPrefixes()
	cfg.Sources = []Source{builtinSource(sourceXForwardedFor), builtinSource(sourceRemoteAddr)}
	return cfg
}
