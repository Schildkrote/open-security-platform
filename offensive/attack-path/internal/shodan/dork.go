// Package shodan provides a dork parser for Shodan-style search queries and
// a Source interface (mock + real API) that resolves dorks to exposure nodes
// in the attack graph.
//
// Dorks use key:value syntax with quotes, ranges and booleans:
//
//	product:nginx port:443
//	org:"Acme Corp" city:frankfurt
//	vuln:SSL_3_0 || port:25
package shodan

import (
	"fmt"
	"regexp"
	"strconv"
	"strings"
)

// Term is one parsed dork term.
type Term struct {
	Key   string `json:"key"`
	Value string `json:"value"`
}

// Query is a parsed dork: a set of OR-groups, each a set of AND-terms.
type Query struct {
	Groups [][]Term `json:"groups"` // OR across groups, AND within
	Raw    string   `json:"raw"`
}

// Parse parses a dork string into a Query. It supports quoted values,
// "||" as OR and implicit AND between space-separated terms. Unsupported
// syntax (e.g. parentheses, ranges) is an error rather than silently
// dropped.
func Parse(dork string) (*Query, error) {
	q := &Query{Raw: dork}
	for _, group := range strings.Split(dork, "||") {
		terms, err := parseGroup(strings.TrimSpace(group))
		if err != nil {
			return nil, fmt.Errorf("dork group %q: %w", group, err)
		}
		if len(terms) > 0 {
			q.Groups = append(q.Groups, terms)
		}
	}
	if len(q.Groups) == 0 {
		return nil, fmt.Errorf("empty dork")
	}
	return q, nil
}

var kvRe = regexp.MustCompile(`^([A-Za-z0-9_.-]+):(.*)$`)

func parseGroup(group string) ([]Term, error) {
	var terms []Term
	for _, tok := range tokenize(group) {
		m := kvRe.FindStringSubmatch(tok)
		if m == nil {
			return nil, fmt.Errorf("term %q is not key:value", tok)
		}
		terms = append(terms, Term{Key: m[1], Value: unquote(m[2])})
	}
	return terms, nil
}

// tokenize splits on whitespace, keeping quoted strings intact.
func tokenize(s string) []string {
	var out []string
	var cur strings.Builder
	inQuotes := false
	for _, r := range s {
		switch {
		case r == '"':
			inQuotes = !inQuotes
			cur.WriteRune(r)
		case (r == ' ' || r == '\t') && !inQuotes:
			if cur.Len() > 0 {
				out = append(out, cur.String())
				cur.Reset()
			}
		default:
			cur.WriteRune(r)
		}
	}
	if cur.Len() > 0 {
		out = append(out, cur.String())
	}
	return out
}

func unquote(s string) string {
	if len(s) >= 2 && strings.HasPrefix(s, `"`) && strings.HasSuffix(s, `"`) {
		return s[1 : len(s)-1]
	}
	return s
}

// Contains reports whether the query constrains a key to value.
func (q *Query) Contains(key, value string) bool {
	for _, group := range q.Groups {
		for _, t := range group {
			if strings.EqualFold(t.Key, key) && strings.EqualFold(t.Value, value) {
				return true
			}
		}
	}
	return false
}

// Ports returns all port values in the query (as ints), deduplicated.
func (q *Query) Ports() []int {
	seen := map[int]bool{}
	var out []int
	for _, group := range q.Groups {
		for _, t := range group {
			if strings.EqualFold(t.Key, "port") {
				if n, err := strconv.Atoi(t.Value); err == nil && !seen[n] {
					seen[n] = true
					out = append(out, n)
				}
			}
		}
	}
	return out
}
