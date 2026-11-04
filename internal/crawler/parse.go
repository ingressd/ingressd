// SPDX-License-Identifier: Apache-2.0

package crawler

import (
	"bytes"
	"encoding/xml"
	"regexp"
	"strings"

	"golang.org/x/net/html"
)

// linkAttrs are the attributes that reference pages or assets.
var linkAttrs = map[string]bool{"href": true, "src": true, "poster": true, "data-src": true}

// htmlLinks returns every page/asset reference in an HTML document: href,
// src, srcset, poster, inline style url()s and <style> blocks.
func htmlLinks(body []byte) []string {
	var out []string
	z := html.NewTokenizer(bytes.NewReader(body))
	inStyle := false
	for {
		switch z.Next() {
		case html.ErrorToken:
			return out
		case html.TextToken:
			if inStyle {
				out = append(out, cssLinks(string(z.Text()))...)
			}
		case html.EndTagToken:
			if name, _ := z.TagName(); string(name) == "style" {
				inStyle = false
			}
		case html.StartTagToken, html.SelfClosingTagToken:
			name, hasAttr := z.TagName()
			tag := string(name)
			if tag == "style" {
				inStyle = true
			}
			var rel string
			var refs []string
			for hasAttr {
				var k, v []byte
				k, v, hasAttr = z.TagAttr()
				key, val := string(k), string(v)
				switch {
				case linkAttrs[key]:
					refs = append(refs, val)
				case key == "srcset" || key == "imagesrcset":
					refs = append(refs, srcset(val)...)
				case key == "style":
					refs = append(refs, cssLinks(val)...)
				case key == "rel":
					rel = strings.ToLower(val)
				}
			}
			// Skip links that are not part of the page (e.g. rel=nofollow
			// on <a> is still crawlable; only drop non-resource <link>s).
			if tag == "link" && rel != "" && !linkRelWanted(rel) {
				continue
			}
			out = append(out, refs...)
		}
	}
}

func linkRelWanted(rel string) bool {
	for _, r := range strings.Fields(rel) {
		switch r {
		case "stylesheet", "icon", "apple-touch-icon", "preload", "prefetch", "modulepreload", "manifest", "mask-icon", "shortcut":
			return true
		}
	}
	return false
}

func srcset(v string) []string {
	var out []string
	for _, part := range strings.Split(v, ",") {
		if f := strings.Fields(part); len(f) > 0 {
			out = append(out, f[0])
		}
	}
	return out
}

var (
	cssURLRe    = regexp.MustCompile(`url\(\s*['"]?([^'")]+?)['"]?\s*\)`)
	cssImportRe = regexp.MustCompile(`@import\s+['"]([^'"]+)['"]`)
)

// cssLinks returns url(...) and @import references in CSS.
func cssLinks(css string) []string {
	var out []string
	for _, m := range cssURLRe.FindAllStringSubmatch(css, -1) {
		if !strings.HasPrefix(m[1], "data:") {
			out = append(out, m[1])
		}
	}
	for _, m := range cssImportRe.FindAllStringSubmatch(css, -1) {
		out = append(out, m[1])
	}
	return out
}

// parseSitemap returns the <loc>s of a sitemap, and whether it is a
// sitemap index (whose locs are further sitemaps).
func parseSitemap(b []byte) (locs []string, index bool) {
	var doc struct {
		XMLName xml.Name
		URLs    []struct {
			Loc string `xml:"loc"`
		} `xml:"url"`
		Sitemaps []struct {
			Loc string `xml:"loc"`
		} `xml:"sitemap"`
	}
	if xml.Unmarshal(b, &doc) != nil {
		return nil, false
	}
	for _, u := range doc.URLs {
		locs = append(locs, strings.TrimSpace(u.Loc))
	}
	for _, s := range doc.Sitemaps {
		locs = append(locs, strings.TrimSpace(s.Loc))
	}
	return locs, doc.XMLName.Local == "sitemapindex"
}

// robots holds the robots.txt rules that apply to the crawler.
type robots struct {
	rules    []robotsRule
	sitemaps []string
}

type robotsRule struct {
	allow  bool
	prefix string
}

// parseRobots keeps the rules of the most specific group: "ingressd" if
// present, else "*".
func parseRobots(txt string) robots {
	var r robots
	groups := map[string][]robotsRule{}
	var agents []string
	lastWasAgent := false
	for _, line := range strings.Split(txt, "\n") {
		if i := strings.IndexByte(line, '#'); i >= 0 {
			line = line[:i]
		}
		k, v, ok := strings.Cut(line, ":")
		if !ok {
			continue
		}
		k, v = strings.ToLower(strings.TrimSpace(k)), strings.TrimSpace(v)
		switch k {
		case "user-agent":
			if !lastWasAgent {
				agents = nil
			}
			agents = append(agents, strings.ToLower(v))
			lastWasAgent = true
			continue
		case "allow", "disallow":
			for _, a := range agents {
				if v == "" && k == "disallow" {
					groups[a] = append(groups[a], robotsRule{allow: true, prefix: "/"})
					continue
				}
				groups[a] = append(groups[a], robotsRule{allow: k == "allow", prefix: v})
			}
		case "sitemap":
			r.sitemaps = append(r.sitemaps, v)
		}
		lastWasAgent = false
	}
	for a, rules := range groups {
		if strings.Contains(a, "ingressd") {
			r.rules = rules
			return r
		}
	}
	r.rules = groups["*"]
	return r
}

// allowed applies the longest matching rule (allow wins ties).
func (r robots) allowed(path string) bool {
	best, allow := -1, true
	for _, rule := range r.rules {
		if strings.HasPrefix(path, rule.prefix) && len(rule.prefix) >= best {
			if len(rule.prefix) > best || rule.allow {
				allow = rule.allow
			}
			best = len(rule.prefix)
		}
	}
	return allow
}
