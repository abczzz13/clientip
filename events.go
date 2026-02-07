package clientip

const (
	securityEventMultipleHeaders       = "multiple_headers"
	securityEventChainTooLong          = "chain_too_long"
	securityEventUntrustedProxy        = "untrusted_proxy"
	securityEventNoTrustedProxies      = "no_trusted_proxies"
	securityEventTooFewTrustedProxies  = "too_few_trusted_proxies"
	securityEventTooManyTrustedProxies = "too_many_trusted_proxies"
	securityEventInvalidIP             = "invalid_ip"
	securityEventReservedIP            = "reserved_ip"
	securityEventPrivateIP             = "private_ip"
	securityEventMalformedForwarded    = "malformed_forwarded"
)
