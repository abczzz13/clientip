# Trusted Proxy Configuration

This guide expands on the README's deployment examples.

## Core Rule

Only trust proxy ranges that can actually connect to your application. A broad provider range is usually too large to be a trust boundary.

Forwarding headers are HTTP headers. They become meaningful only when the immediate peer is a trusted proxy that sets, appends, or sanitizes them according to your deployment contract.

## Recommended Workflow

1. Fetch ranges from the provider's official source.
2. Filter to the product, region, VPC, subnet, load balancer, CDN edge, or proxy fleet that can actually reach your service.
3. Store the filtered CIDR strings in your application configuration.
4. Parse them with `clientip.ParseCIDRs`.
5. Pass the resulting prefixes to `clientip.WithTrustedProxies`.
6. Refresh ranges on your deploy or configuration-management schedule.

```go
trustedProxyCIDRs := []string{
    // Replace these documentation prefixes with your filtered proxy CIDRs.
    "203.0.113.0/24",
    "2001:db8:1234::/48",
}

trustedProxies, err := clientip.ParseCIDRs(trustedProxyCIDRs...)
if err != nil {
    log.Fatal(err)
}

resolver, err := clientip.New(
    clientip.WithTrustedProxies(trustedProxies...),
    clientip.WithSources(clientip.SourceXForwardedFor, clientip.SourceRemoteAddr),
)
```

## Common Provider Range Sources

Use these as starting points before product/service/region filtering:

- AWS: `https://ip-ranges.amazonaws.com/ip-ranges.json`
- Azure: `https://www.microsoft.com/download/details.aspx?id=56519`
- Google Cloud: `https://www.gstatic.com/ipranges/cloud.json`
- Google Cloud default domains: `https://www.gstatic.com/ipranges/goog.json`
- Cloudflare: `https://www.cloudflare.com/ips-v4` and `https://www.cloudflare.com/ips-v6`
- Fastly: `https://api.fastly.com/public-ip-list`

Do not treat broad cloud-provider feeds as ready-to-use trusted proxy lists. Some feeds describe public service ranges and may not represent the immediate proxy peers that connect to your application.

## CDN Single-IP Headers

Single-IP headers such as `CF-Connecting-IP`, `True-Client-IP`, or `Fastly-Client-IP` are trusted only when the connecting peer is verified as the expected CDN or edge proxy.

```go
resolver, err := clientip.New(
    clientip.WithTrustedProxies(trustedCDNPrefixes...),
    clientip.WithSources(clientip.HeaderSource("CF-Connecting-IP"), clientip.SourceRemoteAddr),
)
```

If the origin is reachable directly, clients can spoof these headers. Block direct origin access with firewall rules, security groups, private networking, or equivalent network policy.

## Load Balancers And X-Forwarded-For

ALBs and reverse proxies commonly append to `X-Forwarded-For`. Trust the narrowest ingress range that can reach your targets, such as explicit proxy addresses or load-balancer target subnets protected by security groups.

```go
resolver, err := clientip.New(
    clientip.WithTrustedProxies(trustedIngressPrefixes...),
    clientip.WithSources(clientip.SourceXForwardedFor, clientip.SourceRemoteAddr),
)
```

Published cloud public-service ranges are usually not the right trust boundary for private load-balancer-to-target traffic.

## Count-Only Trust

`clientip` intentionally does not support count-only proxy trust. `WithMinTrustedProxies` and `WithMaxTrustedProxies` validate how many CIDR-trusted hops were observed; they do not make a header source trusted without `WithTrustedProxies` and a trusted immediate peer.
