// SPDX-License-Identifier: Apache-2.0

package config

import (
	"bytes"
	"errors"
	"fmt"
	"reflect"
	"regexp"
	"strings"

	"github.com/pmezard/go-difflib/difflib"

	"gopkg.in/yaml.v3"
)

// Comment-preserving edits of config.yaml. The API and CLI change config by
// editing the yaml.v3 node tree and re-encoding it, so comments, key order
// and untouched formatting choices (flow vs block style) survive.

// Document is a parsed config.yaml that can be edited and re-encoded.
type Document struct{ root *yaml.Node }

// ParseDocument parses YAML into an editable document. Empty input yields an
// empty mapping.
func ParseDocument(b []byte) (*Document, error) {
	var n yaml.Node
	if err := yaml.Unmarshal(b, &n); err != nil {
		return nil, fmt.Errorf("parse config: %w", err)
	}
	if n.Kind == 0 {
		n = yaml.Node{Kind: yaml.DocumentNode, Content: []*yaml.Node{{Kind: yaml.MappingNode, Tag: "!!map"}}}
	}
	if n.Kind != yaml.DocumentNode || len(n.Content) != 1 || n.Content[0].Kind != yaml.MappingNode {
		return nil, errors.New("parse config: top level must be a mapping")
	}
	return &Document{root: &n}, nil
}

// Bytes encodes the document with two-space indentation.
func (d *Document) Bytes() ([]byte, error) {
	var buf bytes.Buffer
	enc := yaml.NewEncoder(&buf)
	enc.SetIndent(2)
	if err := enc.Encode(d.root); err != nil {
		return nil, err
	}
	if err := enc.Close(); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}

func (d *Document) top() *yaml.Node { return d.root.Content[0] }

// Get returns the node at path (mapping keys), or nil.
func (d *Document) Get(path ...string) *yaml.Node {
	n := d.top()
	for _, k := range path {
		n = mapValue(n, k)
		if n == nil {
			return nil
		}
	}
	return n
}

// Keys returns the keys of the mapping at path, in file order.
func (d *Document) Keys(path ...string) []string {
	n := d.Get(path...)
	if n == nil || n.Kind != yaml.MappingNode {
		return nil
	}
	var keys []string
	for i := 0; i+1 < len(n.Content); i += 2 {
		keys = append(keys, n.Content[i].Value)
	}
	return keys
}

// Set stores value at path, creating intermediate mappings. If a value
// already exists it is merged in place so comments on unchanged parts stay.
func (d *Document) Set(value *yaml.Node, path ...string) error {
	if len(path) == 0 {
		return errors.New("empty path")
	}
	n := d.top()
	for i, k := range path {
		if n.Kind == yaml.ScalarNode && n.Tag == "!!null" {
			*n = yaml.Node{Kind: yaml.MappingNode, Tag: "!!map", HeadComment: n.HeadComment, LineComment: n.LineComment}
		}
		if n.Kind != yaml.MappingNode {
			return fmt.Errorf("%v is not a mapping", path[:i])
		}
		child := mapValue(n, k)
		last := i == len(path)-1
		if child == nil {
			if len(n.Content) == 0 {
				n.Style &^= yaml.FlowStyle // {} → block mapping once it has entries
			}
			child = value
			if !last {
				child = &yaml.Node{Kind: yaml.MappingNode, Tag: "!!map"}
			}
			n.Content = append(n.Content, &yaml.Node{Kind: yaml.ScalarNode, Tag: "!!str", Value: k}, child)
			if last {
				return nil
			}
		} else if last {
			Merge(child, value)
			return nil
		}
		n = child
	}
	return nil
}

// Delete removes the key at path. It reports whether the key existed.
func (d *Document) Delete(path ...string) bool {
	if len(path) == 0 {
		return false
	}
	parent := d.Get(path[:len(path)-1]...)
	if parent == nil || parent.Kind != yaml.MappingNode {
		return false
	}
	k := path[len(path)-1]
	for i := 0; i+1 < len(parent.Content); i += 2 {
		if parent.Content[i].Value == k {
			parent.Content = append(parent.Content[:i], parent.Content[i+2:]...)
			return true
		}
	}
	return false
}

// Merge makes dst equal to src while keeping dst's comments and styles
// wherever the structure is unchanged: mapping keys are updated in place,
// added or removed; scalars keep their comments; sequences of the same
// length are merged element by element.
func Merge(dst, src *yaml.Node) {
	switch {
	case dst.Kind == yaml.MappingNode && src.Kind == yaml.MappingNode:
		// Existing keys keep their file order; new keys follow in src order.
		var out []*yaml.Node
		for i := 0; i+1 < len(dst.Content); i += 2 {
			k, old := dst.Content[i], dst.Content[i+1]
			if v := mapValue(src, k.Value); v != nil {
				Merge(old, v)
				out = append(out, k, old)
			}
		}
		for i := 0; i+1 < len(src.Content); i += 2 {
			if k := src.Content[i]; mapValue(dst, k.Value) == nil {
				out = append(out, k, src.Content[i+1])
			}
		}
		if len(dst.Content) == 0 && len(out) > 0 {
			dst.Style &^= yaml.FlowStyle
		}
		dst.Content = out
	case dst.Kind == yaml.SequenceNode && src.Kind == yaml.SequenceNode && len(dst.Content) == len(src.Content):
		for i := range src.Content {
			Merge(dst.Content[i], src.Content[i])
		}
	case dst.Kind == yaml.SequenceNode && src.Kind == yaml.SequenceNode:
		style := dst.Style
		if len(dst.Content) == 0 {
			style = src.Style
		}
		dst.Content = src.Content
		dst.Style = style
	case dst.Kind == yaml.ScalarNode && src.Kind == yaml.ScalarNode:
		if dst.Value != src.Value || dst.Tag != src.Tag {
			dst.Value, dst.Tag = src.Value, src.Tag
			// Keep quoting style only if the value still needs no other.
			if src.Style != 0 {
				dst.Style = src.Style
			} else if dst.Style&(yaml.DoubleQuotedStyle|yaml.SingleQuotedStyle) == 0 {
				dst.Style = 0
			}
		}
	default:
		head, line, foot := dst.HeadComment, dst.LineComment, dst.FootComment
		*dst = *src
		if dst.HeadComment == "" {
			dst.HeadComment = head
		}
		if dst.LineComment == "" {
			dst.LineComment = line
		}
		if dst.FootComment == "" {
			dst.FootComment = foot
		}
	}
}

func mapValue(n *yaml.Node, key string) *yaml.Node {
	if n == nil || n.Kind != yaml.MappingNode {
		return nil
	}
	for i := 0; i+1 < len(n.Content); i += 2 {
		if n.Content[i].Value == key {
			return n.Content[i+1]
		}
	}
	return nil
}

// ToNode encodes a Go value (e.g. decoded JSON) as a YAML node.
func ToNode(v any) (*yaml.Node, error) {
	var n yaml.Node
	if err := n.Encode(v); err != nil {
		return nil, err
	}
	return &n, nil
}

// ParseNode parses a YAML snippet into a node.
func ParseNode(b []byte) (*yaml.Node, error) {
	var n yaml.Node
	if err := yaml.Unmarshal(b, &n); err != nil {
		return nil, err
	}
	if n.Kind == yaml.DocumentNode && len(n.Content) == 1 {
		return n.Content[0], nil
	}
	return &yaml.Node{Kind: yaml.ScalarNode, Tag: "!!null", Value: "null"}, nil
}

// ParseJSONNode parses a JSON value (JSON is YAML) into a node with plain
// block styles, keeping key order and integer types.
func ParseJSONNode(b []byte) (*yaml.Node, error) {
	n, err := ParseNode(b)
	if err != nil {
		return nil, err
	}
	plainStyle(n)
	return n, nil
}

func plainStyle(n *yaml.Node) {
	n.Style = 0
	for _, c := range n.Content {
		plainStyle(c)
	}
}

// NodeValue decodes a node into plain Go values (maps, slices, scalars),
// suitable for JSON encoding. Mapping keys become strings.
func NodeValue(n *yaml.Node) (any, error) {
	if n == nil {
		return nil, nil
	}
	var v any
	if err := n.Decode(&v); err != nil {
		return nil, err
	}
	return normalize(v), nil
}

func normalize(v any) any {
	switch t := v.(type) {
	case map[string]any:
		for k, x := range t {
			t[k] = normalize(x)
		}
		return t
	case map[any]any:
		m := make(map[string]any, len(t))
		for k, x := range t {
			m[fmt.Sprint(k)] = normalize(x)
		}
		return m
	case []any:
		for i, x := range t {
			t[i] = normalize(x)
		}
		return t
	default:
		return v
	}
}

// NodeYAML encodes a single node as a YAML snippet.
func NodeYAML(n *yaml.Node) (string, error) {
	var buf bytes.Buffer
	enc := yaml.NewEncoder(&buf)
	enc.SetIndent(2)
	if err := enc.Encode(n); err != nil {
		return "", err
	}
	_ = enc.Close()
	return buf.String(), nil
}

// Equal reports whether two nodes hold the same data, ignoring comments
// and formatting.
func Equal(a, b *yaml.Node) bool {
	va, erra := NodeValue(a)
	vb, errb := NodeValue(b)
	return erra == nil && errb == nil && reflect.DeepEqual(va, vb)
}

// TopLevel returns the document's top-level sections by key.
func (d *Document) TopLevel() map[string]*yaml.Node {
	m := map[string]*yaml.Node{}
	t := d.top()
	for i := 0; i+1 < len(t.Content); i += 2 {
		m[t.Content[i].Value] = t.Content[i+1]
	}
	return m
}

// Render re-encodes the document as a minimal edit of orig, the text it was
// parsed from: lines whose content did not change keep their original
// formatting (comment alignment, blank lines, indentation), and only edited
// lines take yaml.v3's canonical form. If the merged text would not parse to
// the same data, it falls back to the canonical encoding.
func (d *Document) Render(orig []byte) ([]byte, error) {
	canon, err := d.Bytes()
	if err != nil {
		return nil, err
	}
	od, err := ParseDocument(orig)
	if err != nil {
		return canon, nil
	}
	normOld, err := od.Bytes()
	if err != nil {
		return canon, nil
	}
	out := patchLines(splitLines(string(orig)), splitLines(string(normOld)), splitLines(string(canon)))
	merged := []byte(strings.Join(out, ""))
	md, err := ParseDocument(merged)
	if err != nil || !Equal(md.root, d.root) {
		return canon, nil
	}
	return merged, nil
}

func splitLines(s string) []string {
	lines := strings.SplitAfter(s, "\n")
	if n := len(lines); n > 0 && lines[n-1] == "" {
		lines = lines[:n-1]
	}
	return lines
}

var flowSpace = regexp.MustCompile(`\s*([{}\[\],])\s*`)

// lineKey normalizes a line for matching: whitespace runs collapse and
// spacing around flow punctuation is ignored.
func lineKey(s string) string {
	return flowSpace.ReplaceAllString(strings.Join(strings.Fields(s), " "), "$1")
}

// blanks returns the blank lines among ls (orig-only lines worth keeping).
func blanks(ls []string) []string {
	var out []string
	for _, l := range ls {
		if strings.TrimSpace(l) == "" {
			out = append(out, l)
		}
	}
	return out
}

func keys(lines []string) []string {
	k := make([]string, len(lines))
	for i, l := range lines {
		k[i] = lineKey(l)
	}
	return k
}

// patchLines applies the normOld→normNew edit to orig, where orig and
// normOld differ only in formatting.
func patchLines(orig, normOld, normNew []string) []string {
	// origFor[j] is the orig line matching normOld[j], or -1.
	origFor := make([]int, len(normOld))
	for j := range origFor {
		origFor[j] = -1
	}
	align := difflib.NewMatcherWithJunk(keys(orig), keys(normOld), false, nil)
	for _, m := range align.GetMatchingBlocks() {
		for k := 0; k < m.Size; k++ {
			origFor[m.B+k] = m.A + k
		}
	}
	var out []string
	next := 0 // next orig line not yet emitted or skipped
	emitOrig := func(j int) {
		i := origFor[j]
		if i < 0 {
			out = append(out, normOld[j])
			return
		}
		if i >= next {
			out = append(out, blanks(orig[next:i])...) // keep blank lines yaml.v3 drops
			out = append(out, orig[i])
			next = i + 1
		}
	}
	skipOrig := func(j int) {
		if i := origFor[j]; i >= next {
			out = append(out, blanks(orig[next:i])...)
			next = i + 1
		}
	}
	edit := difflib.NewMatcherWithJunk(keys(normOld), keys(normNew), false, nil)
	for _, op := range edit.GetOpCodes() {
		switch op.Tag {
		case 'e':
			for j := op.I1; j < op.I2; j++ {
				emitOrig(j)
			}
		case 'd':
			for j := op.I1; j < op.I2; j++ {
				skipOrig(j)
			}
		case 'r':
			for j := op.I1; j < op.I2; j++ {
				skipOrig(j)
			}
			out = append(out, normNew[op.J1:op.J2]...)
		case 'i':
			out = append(out, normNew[op.J1:op.J2]...)
		}
	}
	if next < len(orig) {
		out = append(out, blanks(orig[next:])...)
	}
	return out
}

// EditFunc adapts a document edit to a text transformation (as used by
// pipeline.Change.Edit), keeping unchanged lines byte-for-byte.
func EditFunc(fn func(d *Document) error) func(cur []byte) ([]byte, error) {
	return func(cur []byte) ([]byte, error) {
		d, err := ParseDocument(cur)
		if err != nil {
			return nil, err
		}
		if err := fn(d); err != nil {
			return nil, err
		}
		return d.Render(cur)
	}
}
