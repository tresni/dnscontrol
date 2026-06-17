package js

import (
	"fmt"
	"os"
	"path/filepath"
	"testing"

	testifyrequire "github.com/stretchr/testify/require"
)

// evalJS evaluates a JavaScript snippet in the same environment dnsconfig.js
// runs in and returns the string value of its final expression. This lets the
// capability probes assert computed values directly, without round-tripping
// through DNS records.
func evalJS(t *testing.T, js string) string {
	t.Helper()
	vm, err := newConfiguredVM(false, nil)
	testifyrequire.NoError(t, err)
	v, err := vm.RunString(js)
	testifyrequire.NoError(t, err)
	return v.String()
}

// TestModernLanguageFeatures documents the ES2015+ language features supported
// in dnsconfig.js. Each snippet's final expression is the computed value.
func TestModernLanguageFeatures(t *testing.T) {
	cases := []struct {
		desc string
		js   string
		want string
	}{
		{"let and const", "const a = 1; let b = 2; a + b", "3"},
		{"arrow functions with map/join", "['a', 'b', 'c'].map(s => s.toUpperCase()).join('-')", "A-B-C"},
		{"template literals", "((n) => `v-${n}-end`)(5)", "v-5-end"},
		{"array destructuring with rest", "const [head, ...tail] = [1, 2, 3]; `${head}:${tail.join(',')}`", "1:2,3"},
		{"spread + Set dedup", "[...new Set([1, 1, 2, 3, 3])].join(',')", "1,2,3"},
		{"Map", "new Map([['k', 'v']]).get('k')", "v"},
		{"object spread", "const o = { a: 1 }; const o2 = { ...o, b: 2 }; `${o2.a}${o2.b}`", "12"},
		{"default + rest parameters", "((a, b = 10, ...more) => a + b + more.length)(5)", "15"},
		{"generators", "function* gen() { yield 1; yield 2; yield 3; }\n[...gen()].join('+')", "1+2+3"},
		{"classes", "class Doubler { constructor(x) { this.x = x; } val() { return this.x * 2; } }\nnew Doubler(21).val()", "42"},
		{"filter/reduce with arrows", "[1, 2, 3, 4].filter(x => x % 2 === 0).reduce((a, b) => a + b, 0)", "6"},
		{"Number.isInteger / Math additions", "`${Number.isInteger(4)}-${Math.trunc(4.9)}`", "true-4"},
		{"String.includes / startsWith", "`${'hello'.includes('ell')}-${'hello'.startsWith('he')}`", "true-true"},
	}

	for _, tc := range cases {
		t.Run(tc.desc, func(t *testing.T) {
			testifyrequire.Equal(t, tc.want, evalJS(t, tc.js))
		})
	}
}

// TestRegexSupport documents the JS regex features supported in dnsconfig.js,
// including named groups, lookbehind/lookahead, and matchAll.
func TestRegexSupport(t *testing.T) {
	cases := []struct {
		desc string
		js   string
		want string
	}{
		{"capture group", "'foo123bar'.match(/([0-9]+)/)[1]", "123"},
		{"global replace with callback", "'a1b2c3'.replace(/[0-9]/g, d => '#')", "a#b#c#"},
		{"named capture groups", "'2024-01-02'.match(/(?<year>\\d{4})-(?<month>\\d{2})/).groups.year", "2024"},
		{"lookbehind assertion", "'$100'.match(/(?<=\\$)\\d+/)[0]", "100"},
		{"lookahead assertion", "'100px'.match(/\\d+(?=px)/)[0]", "100"},
		{"split on regex", "'a,b;c d'.split(/[,; ]/).join('|')", "a|b|c|d"},
		{"test predicate", "String(/^[0-9]+$/.test('12345'))", "true"},
		{"case-insensitive flag", "String(/hello/i.test('HELLO WORLD'))", "true"},
		{"matchAll with named groups", "[...'a1b2'.matchAll(/(?<l>[a-z])(?<n>\\d)/g)].map(m => m.groups.l + m.groups.n).join(',')", "a1,b2"},
	}

	for _, tc := range cases {
		t.Run(tc.desc, func(t *testing.T) {
			testifyrequire.Equal(t, tc.want, evalJS(t, tc.js))
		})
	}
}

// TestNativePromise documents that native Promises are supported in
// dnsconfig.js: a .then() callback runs when the script's job queue is drained
// after evaluation, without an event loop.
func TestNativePromise(t *testing.T) {
	vm, err := newConfiguredVM(false, nil)
	testifyrequire.NoError(t, err)
	_, err = vm.RunString(`var promiseResult;
Promise.resolve("PVAL").then(function (v) { promiseResult = v; });`)
	testifyrequire.NoError(t, err)
	testifyrequire.Equal(t, "PVAL", vm.Get("promiseResult").String())
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
