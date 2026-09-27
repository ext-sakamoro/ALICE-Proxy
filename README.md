**English** | [日本語](README_JP.md)

# ALICE-Proxy

L7 reverse proxy engine for the ALICE ecosystem. Provides routing, load balancing, header/path rewriting, circuit breaker, rate limiting, and health tracking -- all in pure Rust.

## Features

- **Routing** -- Path matching (exact, prefix, wildcard, regex), host matching, method matching
- **Load Balancing** -- Round-robin, random, least-connections, IP-hash strategies with weighted upstreams
- **Header Rewriting** -- Set, append, remove headers; chained rewrite rules for requests and responses
- **Path Rewriting** -- Strip prefix, add prefix, regex replace
- **Circuit Breaker** -- Configurable failure threshold, timeout, half-open probing with per-upstream registry
- **Rate Limiting** -- Token bucket algorithm with configurable capacity and refill rate
- **Health Tracking** -- Per-upstream health status (Healthy / Degraded / Unhealthy)
- **Request/Response Transform** -- Body size limits, method override, status rewriting, CORS injection
- **Retry Policy** -- Configurable max retries with retryable status codes

## Architecture

```
Request --> Router (path + host + method matching)
              |
              v
         Route --> LoadBalancer (round-robin / hash / least-conn)
              |
              v
         RequestTransform --> HeaderRewrite --> PathRewrite
              |
              v
         CircuitBreaker --> Upstream selection
              |
              v
         ResponseTransform --> Response
```

## License

`AGPL-3.0 OR LicenseRef-Commercial` — dual-licensed. Pick either.

| Option | Terms | Use it when |
|--------|-------|-------------|
| **AGPL-3.0** | [LICENSE-AGPL](LICENSE-AGPL) — free, no reporting obligation | Your project is itself AGPL-compatible open source, or you are only using it internally |
| **Commercial License** | [LICENSE-COMMERCIAL.md](LICENSE-COMMERCIAL.md) — paid, removes the copyleft | Closed-source product, proprietary SaaS, edge / firmware distribution, plugin redistribution, or a platform NDA that forbids source disclosure |

AGPL is a strong copyleft: a product, firmware image, or service that links
`alice-proxy` and is distributed or served to users must be released under the AGPL
as well. That is intentional for the open ecosystem, and the Commercial
License exists for the cases where it is not something you are able to do.

Commercial licence enquiries: <contact@extoria.co.jp>
