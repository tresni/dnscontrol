package js

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
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
// up in the config. The "RESULT:" sentinel makes assertions unambiguous.
func txtConfig(setup, expr string) string {
	return fmt.Sprintf("%s\nD(\"example.com\", \"none\", TXT(\"t\", \"RESULT:\" + (%s)));", setup, expr)
}

// TestModernLanguageFeatures documents the ES2015+ language features supported
// in dnsconfig.js. Each case computes a value using a modern feature and
// surfaces it through a TXT record.
func TestModernLanguageFeatures(t *testing.T) {
	cases := []struct {
		desc  string
		setup string
		expr  string
		want  string
	}{
		{
			desc: "let and const",
			expr: "(() => { const a = 1; let b = 2; return a + b; })()",
			want: "RESULT:3",
		},
		{
			desc: "arrow functions with map/join",
			expr: "['a', 'b', 'c'].map(s => s.toUpperCase()).join('-')",
			want: "RESULT:A-B-C",
		},
		{
			desc: "template literals",
			expr: "((n) => `v-${n}-end`)(5)",
			want: "RESULT:v-5-end",
		},
		{
			desc: "array destructuring with rest",
			expr: "(() => { const [head, ...tail] = [1, 2, 3]; return `${head}:${tail.join(',')}`; })()",
			want: "RESULT:1:2,3",
		},
		{
			desc: "spread + Set dedup",
			expr: "[...new Set([1, 1, 2, 3, 3])].join(',')",
			want: "RESULT:1,2,3",
		},
		{
			desc: "Map",
			expr: "(() => { const m = new Map([['k', 'v']]); return m.get('k'); })()",
			want: "RESULT:v",
		},
		{
			desc: "object spread",
			expr: "(() => { const o = { a: 1 }; const o2 = { ...o, b: 2 }; return `${o2.a}${o2.b}`; })()",
			want: "RESULT:12",
		},
		{
			desc: "default + rest parameters",
			expr: "((a, b = 10, ...more) => a + b + more.length)(5)",
			want: "RESULT:15",
		},
		{
			desc:  "generators",
			setup: "function* gen() { yield 1; yield 2; yield 3; }",
			expr:  "[...gen()].join('+')",
			want:  "RESULT:1+2+3",
		},
		{
			desc:  "classes",
			setup: "class Doubler { constructor(x) { this.x = x; } val() { return this.x * 2; } }",
			expr:  "new Doubler(21).val()",
			want:  "RESULT:42",
		},
		{
			desc: "filter/reduce with arrows",
			expr: "[1, 2, 3, 4].filter(x => x % 2 === 0).reduce((a, b) => a + b, 0)",
			want: "RESULT:6",
		},
		{
			desc: "Number.isInteger / Math additions",
			expr: "`${Number.isInteger(4)}-${Math.trunc(4.9)}`",
			want: "RESULT:true-4",
		},
		{
			desc: "String.includes / startsWith",
			expr: "`${'hello'.includes('ell')}-${'hello'.startsWith('he')}`",
			want: "RESULT:true-true",
		},
	}

	for _, tc := range cases {
		t.Run(tc.desc, func(t *testing.T) {
			out := runDSL(t, txtConfig(tc.setup, tc.expr))
			testifyrequire.Contains(t, out, tc.want, "config JSON should contain computed value")
		})
	}
}

// TestNativePromise documents that native Promises are supported in
// dnsconfig.js: a .then() callback (run when the script's job queue is drained
// after evaluation) can build records.
func TestNativePromise(t *testing.T) {
	script := `Promise.resolve("PVAL").then(function (v) {
		D("example.com", "none", TXT("p", "RESULT:" + v));
	});`
	out := runDSL(t, script)
	testifyrequire.Contains(t, out, "RESULT:PVAL")
}

// TestErrorMessageIsClean verifies that a JS error surfaced from a required
// file is readable: it names the file and the JS error, and does not leak the
// "GoError:" prefix or internal Go "(native)" stack frames.
func TestErrorMessageIsClean(t *testing.T) {
	// A required file that throws a ReferenceError (undeclared variable in
	// strict mode), mirroring the real-world CAA_BUILDER-style failure.
	dir := t.TempDir()
	bad := filepath.Join(dir, "broken.js")
	if err := os.WriteFile(bad, []byte(`'use strict';
function boom() { undeclared = 1; }
boom();`), 0o600); err != nil {
		t.Fatal(err)
	}

	script := fmt.Sprintf("require(%q);", bad)
	_, err := ExecuteJavascriptString([]byte(script), true, nil)
	testifyrequire.Error(t, err)
	msg := err.Error()

	testifyrequire.Contains(t, msg, "broken.js", "should name the offending file")
	testifyrequire.Contains(t, msg, "ReferenceError", "should keep the JS error type")
	testifyrequire.NotContains(t, msg, "GoError", "should not leak the GoError prefix")
	testifyrequire.NotContains(t, msg, "(native)", "should not leak internal Go frames")
	// Match otto's concise style: no engine stack trace appended.
	testifyrequire.NotContains(t, msg, "<eval>", "should not append the engine stack trace")
}

// TestRecordBuilders exercises the helper "builder" macros that are not covered
// by the parse_tests fixtures, guarding against regressions in their internals
// (e.g. strict-mode violations that only surface when the builder runs).
func TestRecordBuilders(t *testing.T) {
	cases := []struct {
		desc   string
		script string
		want   []string
	}{
		{
			desc: "CAA_BUILDER",
			script: `D("example.com", "none", CAA_BUILDER({
				label: "@",
				iodef: "mailto:caa@example.com",
				iodef_critical: true,
				issue: ["letsencrypt.org", "comodoca.com"],
				issuewild: "none",
			}));`,
			want: []string{"letsencrypt.org", "comodoca.com", "mailto:caa@example.com", "CAA"},
		},
		{
			desc: "SPF_BUILDER",
			script: `D("example.com", "none", SPF_BUILDER({
				label: "@",
				parts: ["v=spf1", "include:_spf.google.com", "-all"],
			}));`,
			want: []string{"v=spf1", "include:_spf.google.com", "-all"},
		},
	}

	for _, tc := range cases {
		t.Run(tc.desc, func(t *testing.T) {
			out := runDSL(t, tc.script)
			for _, w := range tc.want {
				testifyrequire.Contains(t, out, w)
			}
		})
	}
}

// TestRegexSupport documents the JS regex features supported in dnsconfig.js,
// including named groups, lookbehind/lookahead, and matchAll.
func TestRegexSupport(t *testing.T) {
	cases := []struct {
		desc string
		expr string
		want string
	}{
		{
			desc: "capture group",
			expr: "'foo123bar'.match(/([0-9]+)/)[1]",
			want: "RESULT:123",
		},
		{
			desc: "global replace with callback",
			expr: "'a1b2c3'.replace(/[0-9]/g, d => '#')",
			want: "RESULT:a#b#c#",
		},
		{
			desc: "named capture groups",
			expr: "'2024-01-02'.match(/(?<year>\\d{4})-(?<month>\\d{2})/).groups.year",
			want: "RESULT:2024",
		},
		{
			desc: "lookbehind assertion",
			expr: "'$100'.match(/(?<=\\$)\\d+/)[0]",
			want: "RESULT:100",
		},
		{
			desc: "lookahead assertion",
			expr: "'100px'.match(/\\d+(?=px)/)[0]",
			want: "RESULT:100",
		},
		{
			desc: "split on regex",
			expr: "'a,b;c d'.split(/[,; ]/).join('|')",
			want: "RESULT:a|b|c|d",
		},
		{
			desc: "test predicate",
			expr: "String(/^[0-9]+$/.test('12345'))",
			want: "RESULT:true",
		},
		{
			desc: "case-insensitive flag",
			expr: "String(/hello/i.test('HELLO WORLD'))",
			want: "RESULT:true",
		},
		{
			desc: "matchAll with named groups",
			expr: "[...'a1b2'.matchAll(/(?<l>[a-z])(?<n>\\d)/g)].map(m => m.groups.l + m.groups.n).join(',')",
			want: "RESULT:a1,b2",
		},
	}

	for _, tc := range cases {
		t.Run(tc.desc, func(t *testing.T) {
			out := runDSL(t, txtConfig("", tc.expr))
			testifyrequire.Contains(t, out, tc.want, "config JSON should contain regex result")
		})
	}
}
