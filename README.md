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

AGPL-3.0
