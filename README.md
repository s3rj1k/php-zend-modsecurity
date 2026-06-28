# php-waf

A PHP extension (`waf`) that embeds **libmodsecurity** into the PHP request
lifecycle by hooking Zend Engine internals (`zend_execute_ex`) and the SAPI
output path (`sapi_module.ub_write`). ModSecurity request/response phases run
from inside PHP FPM, with no separate WAF proxy.

## Benchmarks

oha overhead across 3 scenarios, 10 iterations each, 50 connections. Baseline =
`disabled` (extension loaded but inactive). `enabled-norules` loads the engine
with no rules. `enabled-rules` loads the engine + the custom rule set.

### Unrestricted (saturation)

Measures throughput. The WAF cost shows up as lost requests per second.

| Scenario | Avg RPS | RPS Δ% | Slowest (ms) | Slowest Δ% | Fastest (ms) | Fastest Δ% | Average (ms) | Average Δ% |
|----------|---------|--------|--------------|------------|--------------|-----------|--------------|-----------|
| disabled | 8820.99 | +0.0% | 116.545 | +0.0% | 0.231 | +0.0% | 5.078 | +0.0% |
| enabled-norules | 6760.18 | -23.4% | 129.344 | +11.0% | 0.294 | +27.3% | 6.662 | +31.2% |
| enabled-rules | 4397.19 | -50.2% | 216.355 | +85.6% | 0.441 | +90.9% | 10.254 | +101.9% |

### 4000 req/s (fixed offered load)

Rate capped at 4000 req/s, isolating per request latency overhead.

| Scenario | Avg RPS | RPS Δ% | Slowest (ms) | Slowest Δ% | Fastest (ms) | Fastest Δ% | Average (ms) | Average Δ% |
|----------|---------|--------|--------------|------------|--------------|-----------|--------------|-----------|
| disabled | 3999.65 | +0.0% | 3.935 | +0.0% | 0.246 | +0.0% | 0.565 | +0.0% |
| enabled-norules | 3999.66 | +0.0% | 4.746 | +20.6% | 0.311 | +26.4% | 0.684 | +21.1% |
| enabled-rules | 3999.69 | +0.0% | 126.007 | +3102.2% | 0.346 | +40.7% | 1.656 | +193.1% |

