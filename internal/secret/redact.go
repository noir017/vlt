package secret

import "strings"

// Redactor removes values vlt has already handled from any text it prints, so
// an error message coming from the network stack cannot echo a secret back.
type Redactor struct {
	values []string
}

// Add registers a sensitive value. Very short values are ignored so the
// redaction cannot mangle ordinary words.
func (r *Redactor) Add(v string) {
	if len(v) < 4 {
		return
	}
	r.values = append(r.values, v)
}

// Clean replaces every registered value with a marker.
func (r *Redactor) Clean(s string) string {
	for _, v := range r.values {
		if v != "" {
			s = strings.ReplaceAll(s, v, "[redacted]")
		}
	}
	return s
}
