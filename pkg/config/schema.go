// SPDX-License-Identifier: Apache-2.0

package config

import (
	"reflect"
	"strings"

	"gopkg.in/yaml.v3"
)

// JSONSchema returns a JSON Schema (draft 2020-12) for config.yaml,
// generated from the Go types so it never drifts. Sections still held as
// raw yaml.Node accept anything. Semantic rules live in Validate.
func JSONSchema() map[string]any {
	s := schemaFor(reflect.TypeOf(Config{}))
	s["$schema"] = "https://json-schema.org/draft/2020-12/schema"
	s["title"] = "ingressd config.yaml"
	return s
}

var (
	nodeType     = reflect.TypeOf(yaml.Node{})
	durationType = reflect.TypeOf(Duration(0))
)

func schemaFor(t reflect.Type) map[string]any {
	if t.Kind() == reflect.Pointer {
		return schemaFor(t.Elem())
	}
	switch {
	case t == nodeType:
		return map[string]any{}
	case t == durationType:
		return map[string]any{"type": "string", "pattern": `^([0-9]+(\.[0-9]+)?(ns|us|µs|ms|s|m|h))+$`}
	}
	switch t.Kind() {
	case reflect.String:
		return map[string]any{"type": "string"}
	case reflect.Bool:
		return map[string]any{"type": "boolean"}
	case reflect.Int, reflect.Int64, reflect.Int32, reflect.Uint16, reflect.Uint32:
		return map[string]any{"type": "integer"}
	case reflect.Float64:
		return map[string]any{"type": "number"}
	case reflect.Slice:
		return map[string]any{"type": []string{"array", "null"}, "items": schemaFor(t.Elem())}
	case reflect.Map:
		return map[string]any{"type": []string{"object", "null"}, "additionalProperties": schemaFor(t.Elem())}
	case reflect.Struct:
		props := map[string]any{}
		for i := 0; i < t.NumField(); i++ {
			f := t.Field(i)
			if !f.IsExported() {
				continue
			}
			name, _, _ := strings.Cut(f.Tag.Get("yaml"), ",")
			if name == "" || name == "-" {
				continue
			}
			props[name] = schemaFor(f.Type)
		}
		return map[string]any{"type": []string{"object", "null"}, "properties": props, "additionalProperties": false}
	}
	return map[string]any{}
}
