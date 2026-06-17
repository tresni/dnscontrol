package js

import (
	"crypto/sha1"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/hex"
	"fmt"
	"hash"

	"github.com/grafana/sobek"
)

// hashConstructors maps the algorithm names accepted by HASH() to the
// constructor for that hash.
var hashConstructors = map[string]func() hash.Hash{
	"SHA1": sha1.New, "sha1": sha1.New,
	"SHA256": sha256.New, "sha256": sha256.New,
	"SHA512": sha512.New, "sha512": sha512.New,
}

// Exposes sha1, sha256, and sha512 hashing functions to Javascript.
func hashFunc(vm *sobek.Runtime) func(sobek.FunctionCall) sobek.Value {
	return func(call sobek.FunctionCall) sobek.Value {
		if len(call.Arguments) != 2 {
			throw(vm, "require takes exactly two arguments")
		}
		algorithm := call.Argument(0).String() // The algorithm to use for hashing
		value := call.Argument(1).String()     // The value to hash

		newHash, ok := hashConstructors[algorithm]
		if !ok {
			throw(vm, fmt.Sprintf("invalid algorithm %s given", algorithm))
		}
		h := newHash()
		h.Write([]byte(value))
		return vm.ToValue(hex.EncodeToString(h.Sum(nil)))
	}
}
