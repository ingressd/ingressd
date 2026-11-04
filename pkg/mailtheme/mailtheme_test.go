// SPDX-License-Identifier: Apache-2.0

package mailtheme

import (
	"strings"
	"testing"
)

func TestRender(t *testing.T) {
	e := Email{
		Subject: "Your code", Preheader: "Code 123456", Eyebrow: "Sign in", Title: "Sign in to <web>",
		Intro: []string{"Use this code."}, CodeLabel: "Your sign-in code is", Code: "123456",
		Action:  &Action{Label: "Open", URL: "https://panel.example.com/"},
		Details: []Detail{{"Expires", "5 minutes"}}, Outro: []string{"Ignore otherwise."},
	}
	text, html, err := e.Render(Ingressd)
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{"Your sign-in code is: 123456", "Open: https://panel.example.com/", "Expires: 5 minutes", "\n-- \ningressd · https://ingressd.com"} {
		if !strings.Contains(text, want) {
			t.Errorf("text missing %q:\n%s", want, text)
		}
	}
	for _, want := range []string{"Sign in to &lt;web&gt;", "border-top:3px solid #ff6b2c", "color:#0a0e14;text-decoration:none", ">123456</td>", "ingressd.com</a>"} {
		if !strings.Contains(html, want) {
			t.Errorf("html missing %q", want)
		}
	}
	if strings.Contains(strings.ReplaceAll(html, "@media", ""), "@") {
		t.Error("unreplaced style token in html")
	}
}

// The details label column must keep a fixed width and unbreakable labels:
// a shrink-to-fit (width:1%) column collapsed to one letter wide in iOS Mail.
func TestDetailsLabelsDoNotCollapse(t *testing.T) {
	_, html, err := Email{Subject: "s", Title: "t", Details: []Detail{{"Requested from", "203.0.113.7"}, {"A <b>", "x"}}}.Render(Ingressd)
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{`width="112" style="width:112px;min-width:112px;`, "white-space:nowrap", ">Requested&nbsp;from</td>", ">A&nbsp;&lt;b&gt;</td>", "table-layout:fixed", "@media only screen and (max-width:480px)", "-webkit-text-size-adjust:100%"} {
		if !strings.Contains(html, want) {
			t.Errorf("html missing %q", want)
		}
	}
	if strings.Contains(html, "width:1%") {
		t.Error("shrink-to-fit label column is back")
	}
}

func TestThemeDefaults(t *testing.T) {
	_, html, err := Email{Subject: "s", Title: "t"}.Render(Theme{Name: "Acme", Accent: "nope"})
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(html, ">Acme</td>") || !strings.Contains(html, "solid #ff6b2c") {
		t.Fatal("name or fallback accent not applied")
	}
}

func TestOnAccent(t *testing.T) {
	for accent, want := range map[string]string{"#ff6b2c": ground, "#2563eb": ink, "#fff": ground, "#000": ink, "bad": ground} {
		if got := OnAccent(accent); got != want {
			t.Errorf("OnAccent(%s) = %s, want %s", accent, got, want)
		}
	}
}

func TestMark(t *testing.T) {
	h := 0
	for _, r := range markRows {
		w := 0
		for _, run := range r.Runs {
			w += run.W
		}
		if w != 16 {
			t.Errorf("mark row is %dpx wide, want 16", w)
		}
		h += r.H
	}
	if h != len(mark) {
		t.Errorf("mark is %dpx tall, want %d", h, len(mark))
	}
	_, html, err := Email{Subject: "s", Title: "t"}.Render(Theme{Accent: "#2563eb"})
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(html, `bgcolor="#2563eb" style="width:16px;height:2px`) {
		t.Error("mark not drawn in the accent")
	}
}
