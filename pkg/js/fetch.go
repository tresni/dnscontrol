package js

import (
	"encoding/json"
	"io"
	"net/http"
	"strings"

	"github.com/grafana/sobek"
)

// defineFetch registers a synchronous fetch() implementation on the VM.
//
// otto used the ottoext fetch polyfill, which relied on an event loop. sobek
// has no event loop, but it does have native Promises whose reaction jobs are
// drained when control returns from RunString. So we perform the HTTP request
// synchronously (on the VM's goroutine, which is required since a sobek.Runtime
// is single-threaded) and resolve/reject an already-settled Promise. Any
// .then()/.catch() chains run when the surrounding script finishes.
//
// fetch is opt-in (--allow-fetch) and is not exercised by the test suite; this
// preserves the feature with a minimal, standards-shaped Response object.
func defineFetch(vm *sobek.Runtime) error {
	fetch := func(call sobek.FunctionCall) sobek.Value {
		promise, resolve, reject := vm.NewPromise()

		url := call.Argument(0).String()

		method := http.MethodGet
		var body io.Reader
		var reqHeaders map[string]string

		// Optional init object: { method, headers, body }.
		if opts, ok := call.Argument(1).Export().(map[string]interface{}); ok {
			if m, ok := opts["method"].(string); ok && m != "" {
				method = strings.ToUpper(m)
			}
			if b, ok := opts["body"].(string); ok {
				body = strings.NewReader(b)
			}
			if h, ok := opts["headers"].(map[string]interface{}); ok {
				reqHeaders = make(map[string]string, len(h))
				for k, v := range h {
					if s, ok := v.(string); ok {
						reqHeaders[k] = s
					}
				}
			}
		}

		req, err := http.NewRequest(method, url, body)
		if err != nil {
			_ = reject(vm.NewGoError(err))
			return vm.ToValue(promise)
		}
		for k, v := range reqHeaders {
			req.Header.Set(k, v)
		}

		res, err := http.DefaultClient.Do(req)
		if err != nil {
			_ = reject(vm.NewGoError(err))
			return vm.ToValue(promise)
		}
		defer res.Body.Close()

		data, err := io.ReadAll(res.Body)
		if err != nil {
			_ = reject(vm.NewGoError(err))
			return vm.ToValue(promise)
		}

		_ = resolve(newResponse(vm, res, data))
		return vm.ToValue(promise)
	}

	return vm.Set("fetch", fetch)
}

// newResponse builds a minimal, fetch-spec-shaped Response object.
func newResponse(vm *sobek.Runtime, res *http.Response, data []byte) *sobek.Object {
	obj := vm.NewObject()
	_ = obj.Set("ok", res.StatusCode >= 200 && res.StatusCode < 300)
	_ = obj.Set("status", res.StatusCode)
	_ = obj.Set("statusText", res.Status)
	_ = obj.Set("url", res.Request.URL.String())

	// headers.get(name) — case-insensitive, as in the fetch spec.
	headers := vm.NewObject()
	_ = headers.Set("get", func(call sobek.FunctionCall) sobek.Value {
		return vm.ToValue(res.Header.Get(call.Argument(0).String()))
	})
	_ = headers.Set("has", func(call sobek.FunctionCall) sobek.Value {
		return vm.ToValue(res.Header.Get(call.Argument(0).String()) != "")
	})
	_ = obj.Set("headers", headers)

	// text() resolves to the body as a string.
	_ = obj.Set("text", func(sobek.FunctionCall) sobek.Value {
		p, resolve, _ := vm.NewPromise()
		_ = resolve(vm.ToValue(string(data)))
		return vm.ToValue(p)
	})

	// json() resolves to the parsed body, or rejects on invalid JSON.
	_ = obj.Set("json", func(sobek.FunctionCall) sobek.Value {
		p, resolve, reject := vm.NewPromise()
		var parsed interface{}
		if err := json.Unmarshal(data, &parsed); err != nil {
			_ = reject(vm.NewGoError(err))
		} else {
			_ = resolve(vm.ToValue(parsed))
		}
		return vm.ToValue(p)
	})

	return obj
}
