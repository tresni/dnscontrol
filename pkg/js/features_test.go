package js

import (
	"encoding/json"
	"fmt"
	"testing"

	testifyrequire "github.com/stretchr/testify/require"
)

// runDSL executes a dnsconfig.js snippet and returns the resulting config
// marshaled to JSON, so tests can assert on computed record values.
func runDSL(t *testing.T, script string) string {
	t.Helper()
	conf, err := ExecuteJavascriptString([]byte(script), true, nil)
	testifyrequire.NoError(t, err)
	b, err := json.Marshal(conf)
	testifyrequire.NoError(t, err)
	return string(b)
}

// txtConfig wraps a JS expression in a TXT record so the computed value shows
// up in the config. The "SOBEK:" sentinel makes assertions unambiguous.
func txtConfig(setup, expr string) string {
	return fmt.Sprintf("%s\nD(\"example.com\", \"none\", TXT(\"t\", \"SOBEK:\" + (%s)));", setup, expr)
}

// TestSobekModernLanguageFeatures demonstrates that the Sobek engine supports
// ES2015+ syntax that otto (ES5-only) could not run. Each case computes a value
// using a modern feature and surfaces it through a TXT record.
func TestSobekModernLanguageFeatures(t *testing.T) {
	cases := []struct {
		desc  string
		setup string
		expr  string
		want  string
	}{
		{
			desc: "let and const",
			expr: "(() => { const a = 1; let b = 2; return a + b; })()",
			want: "SOBEK:3",
		},
		{
			desc: "arrow functions with map/join",
			expr: "['a', 'b', 'c'].map(s => s.toUpperCase()).join('-')",
			want: "SOBEK:A-B-C",
		},
		{
			desc: "template literals",
			expr: "((n) => `v-${n}-end`)(5)",
			want: "SOBEK:v-5-end",
		},
		{
			desc: "array destructuring with rest",
			expr: "(() => { const [head, ...tail] = [1, 2, 3]; return `${head}:${tail.join(',')}`; })()",
			want: "SOBEK:1:2,3",
		},
		{
			desc: "spread + Set dedup",
			expr: "[...new Set([1, 1, 2, 3, 3])].join(',')",
			want: "SOBEK:1,2,3",
		},
		{
			desc: "Map",
			expr: "(() => { const m = new Map([['k', 'v']]); return m.get('k'); })()",
			want: "SOBEK:v",
		},
		{
			desc: "object spread",
			expr: "(() => { const o = { a: 1 }; const o2 = { ...o, b: 2 }; return `${o2.a}${o2.b}`; })()",
			want: "SOBEK:12",
		},
		{
			desc: "default + rest parameters",
			expr: "((a, b = 10, ...more) => a + b + more.length)(5)",
			want: "SOBEK:15",
		},
		{
			desc:  "generators",
			setup: "function* gen() { yield 1; yield 2; yield 3; }",
			expr:  "[...gen()].join('+')",
			want:  "SOBEK:1+2+3",
		},
		{
			desc:  "classes",
			setup: "class Doubler { constructor(x) { this.x = x; } val() { return this.x * 2; } }",
			expr:  "new Doubler(21).val()",
			want:  "SOBEK:42",
		},
		{
			desc: "filter/reduce with arrows",
			expr: "[1, 2, 3, 4].filter(x => x % 2 === 0).reduce((a, b) => a + b, 0)",
			want: "SOBEK:6",
		},
		{
			desc: "Number.isInteger / Math additions",
			expr: "`${Number.isInteger(4)}-${Math.trunc(4.9)}`",
			want: "SOBEK:true-4",
		},
		{
			desc: "String.includes / startsWith",
			expr: "`${'hello'.includes('ell')}-${'hello'.startsWith('he')}`",
			want: "SOBEK:true-true",
		},
	}

	for _, tc := range cases {
		t.Run(tc.desc, func(t *testing.T) {
			out := runDSL(t, txtConfig(tc.setup, tc.expr))
			testifyrequire.Contains(t, out, tc.want, "config JSON should contain computed value")
		})
	}
}

// TestSobekNativePromise demonstrates that Sobek's native Promise support works
// end-to-end: a .then() callback (run when the script's job queue is drained
// after RunString) can build records. otto required the external ottoext
// promise/loop add-ons for this.
func TestSobekNativePromise(t *testing.T) {
	script := `Promise.resolve("PVAL").then(function (v) {
		D("example.com", "none", TXT("p", "SOBEK:" + v));
	});`
	out := runDSL(t, script)
	testifyrequire.Contains(t, out, "SOBEK:PVAL")
}

// TestSobekRegexSupport demonstrates JS regex features. Sobek uses the regexp2
// engine, which supports constructs (named groups, lookbehind, etc.) beyond
// what otto's Go-regexp-based implementation handled.
func TestSobekRegexSupport(t *testing.T) {
	cases := []struct {
		desc string
		expr string
		want string
	}{
		{
			desc: "capture group",
			expr: "'foo123bar'.match(/([0-9]+)/)[1]",
			want: "SOBEK:123",
		},
		{
			desc: "global replace with callback",
			expr: "'a1b2c3'.replace(/[0-9]/g, d => '#')",
			want: "SOBEK:a#b#c#",
		},
		{
			desc: "named capture groups",
			expr: "'2024-01-02'.match(/(?<year>\\d{4})-(?<month>\\d{2})/).groups.year",
			want: "SOBEK:2024",
		},
		{
			desc: "lookbehind assertion",
			expr: "'$100'.match(/(?<=\\$)\\d+/)[0]",
			want: "SOBEK:100",
		},
		{
			desc: "lookahead assertion",
			expr: "'100px'.match(/\\d+(?=px)/)[0]",
			want: "SOBEK:100",
		},
		{
			desc: "split on regex",
			expr: "'a,b;c d'.split(/[,; ]/).join('|')",
			want: "SOBEK:a|b|c|d",
		},
		{
			desc: "test predicate",
			expr: "String(/^[0-9]+$/.test('12345'))",
			want: "SOBEK:true",
		},
		{
			desc: "case-insensitive flag",
			expr: "String(/hello/i.test('HELLO WORLD'))",
			want: "SOBEK:true",
		},
		{
			desc: "matchAll with named groups",
			expr: "[...'a1b2'.matchAll(/(?<l>[a-z])(?<n>\\d)/g)].map(m => m.groups.l + m.groups.n).join(',')",
			want: "SOBEK:a1,b2",
		},
	}

	for _, tc := range cases {
		t.Run(tc.desc, func(t *testing.T) {
			out := runDSL(t, txtConfig("", tc.expr))
			testifyrequire.Contains(t, out, tc.want, "config JSON should contain regex result")
		})
	}
}
