// SPDX-License-Identifier: Apache-2.0

package edgechallenge

import (
	"crypto/rand"
	"html/template"
)

var randRead = rand.Read

type pageData struct {
	Token       string
	Difficulty  int
	Return      string
	Action      string
	UnderAttack bool
}

// The page is self-contained: inline CSS and JS, no external requests.
var pageTmpl = template.Must(template.New("challenge").Parse(`<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<meta name="robots" content="noindex">
<title>Checking your browser</title>
<style>
body{font-family:system-ui,-apple-system,"Segoe UI",sans-serif;background:#f6f7f9;color:#1d2330;margin:0;display:flex;min-height:100vh;align-items:center;justify-content:center}
main{max-width:32rem;padding:2rem;background:#fff;border-radius:12px;box-shadow:0 1px 4px rgba(0,0,0,.08)}
h1{font-size:1.4rem;margin:0 0 1rem}
p{line-height:1.5}
button{font:inherit;padding:.5rem 1rem;border-radius:6px;border:1px solid #445;background:#fff;cursor:pointer}
@media (prefers-color-scheme:dark){body{background:#14171c;color:#e4e7ec}main{background:#1d2128}button{background:#1d2128;color:inherit;border-color:#889}}
</style>
</head>
<body>
<main>
<h1>Checking your browser</h1>
{{if .UnderAttack}}<p>This site is under heavy load from automated traffic, so every visitor is checked.</p>{{end}}
<p id="he-status" role="status" aria-live="polite">Your browser is doing a short calculation to show it is not a bot. This usually takes a few seconds and needs no action from you.</p>
<noscript><p><strong>JavaScript is required.</strong> This check runs a small calculation in your browser and cannot work with JavaScript turned off. Please enable JavaScript and reload the page, or contact the site owner if you cannot.</p></noscript>
<form id="he-form" method="POST" action="{{.Action}}" data-difficulty="{{.Difficulty}}">
<input type="hidden" name="token" value="{{.Token}}">
<input type="hidden" name="nonce" value="">
<input type="hidden" name="return" value="{{.Return}}">
<noscript><button type="submit" disabled>Continue</button></noscript>
</form>
</main>
<script>
(async function () {
  var f = document.getElementById("he-form"), status = document.getElementById("he-status");
  var token = f.elements.token.value, bits = parseInt(f.getAttribute("data-difficulty"), 10);
  if (!(window.crypto && crypto.subtle && window.TextEncoder)) {
    status.textContent = "Your browser cannot run this check (it needs a secure HTTPS connection and a current browser).";
    return;
  }
  function ok(h) {
    var n = bits, i = 0;
    for (; n >= 8; n -= 8, i++) if (h[i] !== 0) return false;
    return n === 0 || (h[i] >> (8 - n)) === 0;
  }
  var enc = new TextEncoder(), batch = 1024, start = 0, t0 = Date.now();
  for (;;) {
    var jobs = [];
    for (var i = 0; i < batch; i++) jobs.push(crypto.subtle.digest("SHA-256", enc.encode(token + (start + i))));
    var res = await Promise.all(jobs);
    for (var j = 0; j < batch; j++) {
      if (ok(new Uint8Array(res[j]))) {
        f.elements.nonce.value = String(start + j);
        status.textContent = "Done, continuing to the site…";
        f.submit();
        return;
      }
    }
    start += batch;
    if (Date.now() - t0 > 8000 && start % (batch * 64) === 0) status.textContent = "Still checking… thanks for your patience.";
  }
})();
</script>
</body>
</html>
`))
