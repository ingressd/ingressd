// k6 load test for the WAF baseline (docs/spikes/05-coraza-perf.md).
//   TARGET=http://127.0.0.1:8081 RATE=1000 k6 run test/perf/waf.js
import http from 'k6/http';
import { check } from 'k6';

const target = __ENV.TARGET || 'http://127.0.0.1:8080';

export const options = {
  scenarios: {
    steady: {
      executor: 'constant-arrival-rate',
      rate: Number(__ENV.RATE || 1000),
      timeUnit: '1s',
      duration: __ENV.DURATION || '60s',
      preAllocatedVUs: 200,
      maxVUs: 1000,
    },
  },
  thresholds: {
    http_req_failed: ['rate<0.01'],
    http_req_duration: ['p(95)<50'],
  },
};

export default function () {
  const res = http.get(`${target}/search?q=ingressd&page=2`, {
    headers: { 'User-Agent': 'Mozilla/5.0 (ingressd-perf)', Accept: 'text/html' },
  });
  check(res, { 'status 200': (r) => r.status === 200 });
}
