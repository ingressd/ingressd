// SPDX-License-Identifier: Apache-2.0

// Package mailtheme is the one layout every ingressd email uses: the node's
// access-portal codes and the panel's own mail (sign-in codes, invites).
//
// It follows the website's design system (website/src/styles.css): the dark
// ground and surface, a single signal accent, square corners, Archivo for
// text and JetBrains Mono for labels and codes. Email clients cannot load
// the self-hosted fonts, so both fall back to system stacks.
//
// An email is described as data (Email) rather than free-form HTML so that
// every message gets the same structure, and the plain-text alternative is
// generated from the same fields.
package mailtheme

import (
	"bytes"
	htmltemplate "html/template"
	"math"
	"net/url"
	"regexp"
	"strconv"
	"strings"
	"text/template"
)

// Theme is the brand an email is sent under.
type Theme struct {
	Name    string // wordmark and footer, e.g. "ingressd"
	LogoURL string // optional https:// image shown instead of the wordmark
	Accent  string // #rgb or #rrggbb; the website's signal orange by default
	URL     string // optional link shown in the footer
}

// Ingressd is the house theme.
var Ingressd = Theme{Name: "ingressd", Accent: Signal, URL: "https://ingressd.com"}

// Website tokens (dark theme, the site's default).
const (
	Signal  = "#ff6b2c"
	ground  = "#0a0e14"
	surface = "#10161f"
	raised  = "#172030"
	line    = "#232e3d"
	control = "#5b6b80"
	ink     = "#e9eef4"
	muted   = "#8d99a8"
)

// Email is one message. Every field except Subject and Title is optional;
// sections render in the order they are declared.
type Email struct {
	Subject   string
	Preheader string   // inbox preview text, hidden in the body
	Eyebrow   string   // small uppercase label above the title
	Title     string   // heading
	Intro     []string // paragraphs under the heading
	CodeLabel string   // label for Code; the text part reads "<CodeLabel>: <Code>"
	Code      string   // one-time code, shown large in mono
	Action    *Action  // primary button
	Details   []Detail // label/value rows
	Outro     []string // small muted paragraphs at the end
}

// Action is a button linking somewhere.
type Action struct{ Label, URL string }

// Detail is one label/value row.
type Detail struct{ Label, Value string }

// Render returns the plain-text and HTML bodies of e under theme t.
func (e Email) Render(t Theme) (text, html string, err error) {
	t = t.withDefaults()
	d := page{Email: e, Theme: t, OnAccent: OnAccent(t.Accent), Link: linkText(t.URL), Mark: markRows}
	var tb, hb bytes.Buffer
	if err := textTmpl.Execute(&tb, d); err != nil {
		return "", "", err
	}
	if err := htmlTmpl.Execute(&hb, d); err != nil {
		return "", "", err
	}
	return tb.String(), hb.String(), nil
}

type page struct {
	Email
	Theme    Theme
	OnAccent string // text colour on the accent
	Link     string // Theme.URL without the scheme
	Mark     []markRow
}

// mark is the ingressd mark (three connections converging on one origin) at
// 16 by 12 pixels. Email clients cannot show SVG and an image would have to
// be fetched from somewhere, so the layout draws it from table cells in the
// accent colour instead.
var mark = []string{
	"#####...........",
	"######..........",
	"....###.........",
	".....###...#####",
	"......###..#####",
	"################",
	"################",
	"......###..#####",
	".....###...#####",
	"....###.........",
	"######..........",
	"#####...........",
}

// markRow is a run of identical pixel rows, H pixels tall, split into runs
// of on (accent) and off pixels.
type markRow struct {
	H    int
	Runs []markRun
}

type markRun struct {
	W  int
	On bool
}

var markRows = func() []markRow {
	var rows []markRow
	for i, line := range mark {
		if i > 0 && line == mark[i-1] {
			rows[len(rows)-1].H++
			continue
		}
		var runs []markRun
		for j := 0; j < len(line); j++ {
			on := line[j] == '#'
			if n := len(runs); n > 0 && runs[n-1].On == on {
				runs[n-1].W++
			} else {
				runs = append(runs, markRun{W: 1, On: on})
			}
		}
		rows = append(rows, markRow{H: 1, Runs: runs})
	}
	return rows
}()

var hexRe = regexp.MustCompile(`^#([0-9a-fA-F]{3}|[0-9a-fA-F]{6})$`)

func (t Theme) withDefaults() Theme {
	if t.Name == "" {
		t.Name = Ingressd.Name
	}
	if !hexRe.MatchString(t.Accent) {
		t.Accent = Signal
	}
	return t
}

// OnAccent picks the website's ground or ink colour for text on an accent
// background, whichever contrasts more (dark text on the signal orange, as on
// the site's primary buttons).
func OnAccent(accent string) string {
	if !hexRe.MatchString(accent) {
		accent = Signal
	}
	l := luminance(accent)
	if (l+0.05)/(luminance(ground)+0.05) >= (luminance(ink)+0.05)/(l+0.05) {
		return ground
	}
	return ink
}

// luminance is the WCAG relative luminance of a #rgb or #rrggbb colour.
func luminance(hex string) float64 {
	h := hex[1:]
	if len(h) == 3 {
		h = string([]byte{h[0], h[0], h[1], h[1], h[2], h[2]})
	}
	var l float64
	for i, w := range []float64{0.2126, 0.7152, 0.0722} {
		v, _ := strconv.ParseUint(h[i*2:i*2+2], 16, 8)
		c := float64(v) / 255
		if c <= 0.03928 {
			c /= 12.92
		} else {
			c = math.Pow((c+0.055)/1.055, 2.4)
		}
		l += w * c
	}
	return l
}

func linkText(u string) string {
	p, err := url.Parse(u)
	if err != nil || p.Host == "" {
		return ""
	}
	return strings.TrimSuffix(p.Host+p.Path, "/")
}

var textTmpl = template.Must(template.New("text").Parse(`{{.Title}}
{{range .Intro}}
{{.}}
{{end}}{{if .Code}}
{{.CodeLabel}}: {{.Code}}
{{end}}{{with .Action}}
{{.Label}}: {{.URL}}
{{end}}{{if .Details}}
{{range .Details}}{{.Label}}: {{.Value}}
{{end}}{{end}}{{range .Outro}}
{{.}}
{{end}}
{{"-- "}}
{{.Theme.Name}}{{if .Theme.URL}} · {{.Theme.URL}}{{end}}
`))

// Style fragments shared by the layout. Inline styles only: most clients
// drop <style> blocks. Tables and bgcolor attributes keep Outlook in line.
var styles = strings.NewReplacer(
	"@sans", `font-family:Archivo,-apple-system,'Segoe UI',Roboto,Helvetica,Arial,sans-serif`,
	"@mono", `font-family:'JetBrains Mono',ui-monospace,SFMono-Regular,Menlo,Consolas,monospace`,
	"@label", `font-size:11px;line-height:1.6;font-weight:500;letter-spacing:0.08em;text-transform:uppercase;color:`+muted,
	"@ground", ground, "@surface", surface, "@raised", raised, "@line", line,
	"@control", control, "@ink", ink, "@muted", muted,
	"@kvpx", labelWidth+"px", "@kvw", labelWidth,
)

// labelWidth is the fixed width, in px (plus a 16px gutter), of the
// label column in the details table. It fits "REQUESTED FROM" (about 100px
// at 11px mono with the label letter-spacing). A fixed width, not a
// shrink-to-fit width:1%, keeps the labels readable in clients that drop
// white-space:nowrap or force break-word wrapping (iOS Mail collapsed the
// shrink-to-fit column to one letter wide). Labels also get &nbsp; between
// words, and a <style> media query stacks label over value on phones where
// it is supported.
const labelWidth = "112"

// funcs are the HTML template helpers.
var funcs = htmltemplate.FuncMap{
	// nbsp escapes s and joins its words with non-breaking spaces.
	"nbsp": func(s string) htmltemplate.HTML {
		return htmltemplate.HTML(strings.ReplaceAll(htmltemplate.HTMLEscapeString(s), " ", "&nbsp;")) //nolint:gosec // G203: s is escaped first; only &nbsp; is added
	},
}

var htmlTmpl = htmltemplate.Must(htmltemplate.New("html").Funcs(funcs).Parse(styles.Replace(`<!doctype html>
<html lang="en"><head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<meta name="color-scheme" content="dark">
<meta name="supported-color-schemes" content="dark">
<title>{{.Subject}}</title>
<style>
@media only screen and (max-width:480px){
.kv-label,.kv-value{display:block!important;width:auto!important;min-width:0!important}
.kv-label{padding:12px 0 0!important}
.kv-value{padding:2px 0 0!important}
}
</style>
</head>
<body style="margin:0;padding:0;background:@ground;color:@ink;-webkit-font-smoothing:antialiased;-webkit-text-size-adjust:100%;-ms-text-size-adjust:100%">
{{if .Preheader}}<div style="display:none;max-height:0;overflow:hidden;opacity:0;color:transparent">{{.Preheader}}</div>{{end}}
<table role="presentation" width="100%" cellpadding="0" cellspacing="0" border="0" bgcolor="@ground" style="background:@ground">
<tr><td align="center" style="padding:40px 16px">
<table role="presentation" width="100%" cellpadding="0" cellspacing="0" border="0" style="max-width:480px">
<tr><td style="padding:0 0 24px">
{{if .Theme.LogoURL}}<img src="{{.Theme.LogoURL}}" alt="{{.Theme.Name}}" height="28" style="display:block;height:28px;border:0">
{{else}}<table role="presentation" cellpadding="0" cellspacing="0" border="0"><tr>
<td style="vertical-align:middle">{{$accent := .Theme.Accent}}{{range .Mark}}{{$h := .H}}<table role="presentation" width="16" cellpadding="0" cellspacing="0" border="0" style="width:16px"><tr>
{{- range .Runs}}<td width="{{.W}}" height="{{$h}}"{{if .On}} bgcolor="{{$accent}}"{{end}} style="width:{{.W}}px;height:{{$h}}px;font-size:0;line-height:0;mso-line-height-rule:exactly">&nbsp;</td>{{end -}}
</tr></table>{{end}}</td>
<td style="padding-left:10px;vertical-align:middle;@sans;font-size:20px;line-height:1;font-weight:700;letter-spacing:-0.02em;color:@ink">{{.Theme.Name}}</td>
</tr></table>{{end}}
</td></tr>
<tr><td bgcolor="@surface" style="background:@surface;border:1px solid @line;border-top:3px solid {{.Theme.Accent}};padding:32px 28px">
{{if .Eyebrow}}<p style="margin:0 0 12px;@mono;@label">{{.Eyebrow}}</p>{{end}}
<h1 style="margin:0 0 16px;@sans;font-size:24px;line-height:1.2;font-weight:700;letter-spacing:-0.02em;color:@ink">{{.Title}}</h1>
{{range .Intro}}<p style="margin:0 0 16px;@sans;font-size:15px;line-height:1.55;color:@ink">{{.}}</p>
{{end}}{{if .Code}}{{if .CodeLabel}}<p style="margin:24px 0 8px;@mono;@label">{{.CodeLabel}}</p>{{end}}
<table role="presentation" width="100%" cellpadding="0" cellspacing="0" border="0"><tr>
<td bgcolor="@raised" style="background:@raised;border-left:3px solid {{.Theme.Accent}};padding:18px 20px;@mono;font-size:32px;line-height:1;font-weight:600;letter-spacing:0.2em;color:@ink">{{.Code}}</td>
</tr></table>
{{end}}{{with .Action}}<table role="presentation" cellpadding="0" cellspacing="0" border="0" style="margin:24px 0 0"><tr>
<td bgcolor="{{$.Theme.Accent}}" style="background:{{$.Theme.Accent}}"><a href="{{.URL}}" style="display:inline-block;padding:14px 20px;@sans;font-size:15px;line-height:1;font-weight:600;color:{{$.OnAccent}};text-decoration:none">{{.Label}}&nbsp;&nbsp;<span style="@mono;font-weight:400">&rarr;</span></a></td>
</tr></table>
{{end}}{{if .Details}}<table role="presentation" width="100%" cellpadding="0" cellspacing="0" border="0" style="margin:24px 0 0;border-top:1px solid @line;table-layout:fixed">
{{range .Details}}<tr><td class="kv-label" width="@kvw" style="width:@kvpx;min-width:@kvpx;padding:12px 16px 0 0;white-space:nowrap;word-break:keep-all;overflow-wrap:normal;word-wrap:normal;vertical-align:top;@mono;@label">{{nbsp .Label}}</td><td class="kv-value" style="padding:10px 0 0;vertical-align:top;@mono;font-size:13px;line-height:1.6;color:@ink;word-break:break-word;overflow-wrap:anywhere">{{.Value}}</td></tr>
{{end}}</table>
{{end}}{{if .Outro}}<table role="presentation" width="100%" cellpadding="0" cellspacing="0" border="0" style="margin:24px 0 0"><tr><td style="padding:16px 0 0;border-top:1px solid @line">
{{range .Outro}}<p style="margin:0 0 8px;@sans;font-size:13px;line-height:1.55;color:@muted">{{.}}</p>
{{end}}</td></tr></table>
{{end}}</td></tr>
<tr><td style="padding:20px 0 0;@mono;font-size:12px;line-height:1.6;color:@control">{{.Theme.Name}}{{if .Link}} &middot; <a href="{{.Theme.URL}}" style="color:@muted;text-decoration:none">{{.Link}}</a>{{end}}</td></tr>
</table>
</td></tr></table>
</body></html>
`)))
