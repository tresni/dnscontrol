package js

import (
	"crypto/sha1"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/hex"
	"fmt"

	"github.com/grafana/sobek"
)

// Exposes sha1, sha256, and sha512 hashing functions to Javascript.
func hashFunc(vm *sobek.Runtime) func(sobek.FunctionCall) sobek.Value {
	return func(call sobek.FunctionCall) sobek.Value {
		if len(call.Arguments) != 2 {
			throw(vm, "require takes exactly two arguments")
		}
		algorithm := call.Argument(0).String() // The algorithm to use for hashing
		value := call.Argument(1).String()     // The value to hash
		var result sobek.Value

		switch algorithm {
		case "SHA1", "sha1":
			tmp := sha1.New()
			tmp.Write([]byte(value))
			result = vm.ToValue(hex.EncodeToString(tmp.Sum(nil)))
		case "SHA256", "sha256":
			tmp := sha256.New()
			tmp.Write([]byte(value))
			result = vm.ToValue(hex.EncodeToString(tmp.Sum(nil)))
		case "SHA512", "sha512":
			tmp := sha512.New()
			tmp.Write([]byte(value))
			result = vm.ToValue(hex.EncodeToString(tmp.Sum(nil)))
		default:
			throw(vm, fmt.Sprintf("invalid algorithm %s given", algorithm))
		}
		return result
	}
}
