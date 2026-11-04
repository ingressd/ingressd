# Spike 05 — Coraza / OWASP CRS performance

## Question
How much throughput and latency does the WAF cost on the VM size we plan to use (1–2 vCPU, 1–2 GB), at paranoia levels 1 and 2?

## Setup
On the target VM (or an identical size):
```bash
make build-edge
bin/ingressd-edge run --config test/perf/Caddyfile --adapter caddyfile
```
Ports: `8080` no WAF, `8081` CRS PL1, `8082` CRS PL2.

Install [k6](https://k6.io/docs/get-started/installation/) on a **separate** machine in the same region (running the load generator on the edge itself skews results).

## Run
For each target, raise `RATE` until a threshold fails:
```bash
TARGET=http://<vm>:8080 RATE=1000 k6 run test/perf/waf.js
TARGET=http://<vm>:8081 RATE=1000 k6 run test/perf/waf.js
TARGET=http://<vm>:8082 RATE=1000 k6 run test/perf/waf.js
```
Also note memory use (`ps -o rss= -C ingressd-edge`) at idle and under load.

## Record

| Target | Max sustained req/s (p95 < 50 ms, <1% errors) | p95 at 500 req/s | RSS idle / load |
|---|---|---|---|
| No WAF | | | |
| CRS PL1 | | | |
| CRS PL2 | | | |

VM: provider, size, CPU model.

## Decision to make
- Is 2 vCPU enough for the plan's target of ~2k req/s with WAF PL1?
- Should response-body inspection stay off by default? (Plan says yes.)

## Result
_Pending._
