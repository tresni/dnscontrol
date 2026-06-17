package js

import (
	_ "embed" // Used to embed helpers.js in the binary.
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"strings"

	"github.com/DNSControl/dnscontrol/v4/models"
	"github.com/DNSControl/dnscontrol/v4/pkg/printer"
	"github.com/DNSControl/dnscontrol/v4/pkg/rfc4183"
	"github.com/DNSControl/dnscontrol/v4/pkg/rtypecontrol"
	"github.com/DNSControl/dnscontrol/v4/pkg/transform"
	"github.com/grafana/sobek"
)

//go:embed helpers.js
var helpersJsStatic string
var helpersJsFileName = "pkg/js/helpers.js"

// underscoreJs is the underscore.js library, loaded into every VM. otto used
// to bundle this automatically; sobek does not, so we embed it ourselves.
//
//go:embed underscore.js
var underscoreJs string

// currentDirectory is the current directory as used by require().
// This is used to emulate nodejs-style require() directory handling.
// If require("a/b/c.js") is called, any require() statement in c.js
// needs to be accessed relative to "a/b".  Therefore we
// track the currentDirectory (which is the current directory as
// far as require() is concerned, not the actual os.Getwd().
var currentDirectory string

// EnableFetch sets whether to enable fetch() in JS execution environment.
var EnableFetch bool = false

// ExecuteJavaScript accepts a javascript file and runs it, returning the resulting dnsConfig.
func ExecuteJavaScript(file string, devMode bool, variables map[string]string) (*models.DNSConfig, error) {
	script, err := os.ReadFile(file)
	if err != nil {
		return nil, err
	}

	// Record the directory path leading up to this file.
	currentDirectory = filepath.Dir(file)

	return ExecuteJavascriptString(script, devMode, variables)
}

// ExecuteJavascriptString accepts a string containing javascript and runs it, returning the resulting dnsConfig.
func ExecuteJavascriptString(script []byte, devMode bool, variables map[string]string) (*models.DNSConfig, error) {
	vm := sobek.New()

	// load underscore.js (sobek, unlike otto, does not bundle it).
	if _, err := vm.RunString(underscoreJs); err != nil {
		return nil, err
	}

	// only define fetch() when explicitly enabled
	if EnableFetch {
		if err := defineFetch(vm); err != nil {
			return nil, err
		}
	}

	// add functions to the vm
	functions := map[string]any{
		"require":   requireFunc(vm),
		"REV":       reverse(vm),
		"REVCOMPAT": reverseCompat(vm),
		"glob":      listFiles(vm), // used for require_glob()
		"PANIC":     jsPanic(vm),
		"HASH":      hashFunc(vm),
	}
	for name, fn := range functions {
		if err := vm.Set(name, fn); err != nil {
			return nil, err
		}
	}

	// add cli variables to the vm
	for key, value := range variables {
		if err := vm.Set(key, value); err != nil {
			return nil, err
		}
	}

	helperJs := GetHelpers(devMode)
	// run helper script to prime vm and initialize variables
	if _, err := vm.RunString(helperJs); err != nil {
		return nil, cleanJSError(err)
	}

	// run user script
	if _, err := vm.RunString(string(script)); err != nil {
		return nil, cleanJSError(err)
	}

	// export conf as string and unmarshal
	value, err := vm.RunString(`JSON.stringify(conf)`)
	if err != nil {
		return nil, err
	}
	str := value.String()
	conf := &models.DNSConfig{}
	if err = json.Unmarshal([]byte(str), conf); err != nil {
		return nil, err
	}

	err = conf.PostProcess()
	if err != nil {
		return nil, err
	}
	// No need to call FixLegacyDC here. These records were created from dnsconfig.js, not from a provider.

	if err := rtypecontrol.ImportRawRecords(conf.Domains); err != nil {
		return nil, err
	}

	return conf, nil
}

// GetHelpers returns the contents of helpers.js, or the embedded version.
func GetHelpers(devMode bool) string {
	if devMode {
		// Load the file:
		b, err := os.ReadFile(helpersJsFileName)
		if err != nil {
			log.Fatal(err)
		}
		return string(b)
	}

	// Return the embedded bytes:
	return helpersJsStatic
}

func requireFunc(vm *sobek.Runtime) func(sobek.FunctionCall) sobek.Value {
	return func(call sobek.FunctionCall) sobek.Value {
		if len(call.Arguments) != 1 {
			throw(vm, "require takes exactly one argument")
		}
		file := call.Argument(0).String() // The filename as given by the user

		// relFile is the file we're actually going to pass to ReadFile().
		// It defaults to the user-provided name unless it is relative.
		relFile := file
		cleanFile := filepath.Clean(filepath.Join(currentDirectory, file))
		if strings.HasPrefix(file, ".") {
			relFile = cleanFile
		}

		// Record the old currentDirectory so that we can return there.
		currentDirectoryOld := currentDirectory
		// Record the directory path leading up to the file we're about to require.
		currentDirectory = filepath.Dir(cleanFile)

		printer.Debugf("requiring: %s (%s)\n", file, relFile)
		// quick fix, by replacing to linux slashes, to make it work with windows paths too.
		data, err := os.ReadFile(filepath.ToSlash(relFile))
		if err != nil {
			throw(vm, err.Error())
		}

		value := vm.ToValue(true)

		// If its a json file return the json value, else default to true
		ext := strings.ToLower(filepath.Ext(relFile))
		if strings.HasSuffix(ext, "json") || strings.HasSuffix(ext, "json5") {
			cmd := fmt.Sprintf(`JSON.parse(JSON.stringify(%s))`, string(data))
			value, err = vm.RunString(cmd)
		} else {
			_, err = vm.RunString(string(data))
		}

		if err != nil {
			throw(vm, fmt.Sprintf("File %s: %s", filepath.Base(relFile), jsErrorString(err)))
		}

		// Pop back to the old directory.
		currentDirectory = currentDirectoryOld

		return value
	}
}

func listFiles(vm *sobek.Runtime) func(sobek.FunctionCall) sobek.Value {
	return func(call sobek.FunctionCall) sobek.Value {
		// Check amount of arguments provided
		if len(call.Arguments) < 1 || len(call.Arguments) > 3 {
			throw(vm, "glob requires at least one argument: folder (string). "+
				"Optional: recursive (bool) [true], fileExtension (string) [.js]")
		}

		// Check if provided parameters are valid
		// First: Let's check dir.
		if dir, ok := call.Argument(0).Export().(string); !ok || len(dir) == 0 {
			throw(vm, "glob: first argument needs to be a path, provided as string.")
		}
		dir := call.Argument(0).String() // Path where to start listing
		printer.Debugf("listFiles: cd: %s, user: %s \n", currentDirectory, dir)
		// now we always prepend the current directory we're working in, which is being set within
		// the func ExecuteJavascript() above. So when require("domains/load_all.js") is being used,
		// where glob("customer1/") is being used, we basically search for files in domains/customer1/.
		dir = filepath.ToSlash(filepath.Join(currentDirectory, dir))

		if _, err := os.Stat(dir); os.IsNotExist(err) {
			throw(vm, "glob: provided path does not exist.")
		}

		// Second: Recursive?
		recursive := true
		if arg := call.Argument(1); !sobek.IsUndefined(arg) && !sobek.IsNull(arg) {
			if b, ok := arg.Export().(bool); ok {
				recursive = b // If it should be recursive
			} else {
				throw(vm, "glob: second argument, if recursive, needs to be bool.")
			}
		}

		// Third: File extension filter.
		fileExtension := ".js"
		if arg := call.Argument(2); !sobek.IsUndefined(arg) && !sobek.IsNull(arg) {
			if s, ok := arg.Export().(string); ok {
				fileExtension = s // Which file extension to filter for.
				if !strings.HasPrefix(fileExtension, ".") {
					// If it doesn't start with a dot, probably user forgot it and we do it instead.
					fileExtension = "." + fileExtension
				}
			} else {
				throw(vm, "glob: third argument, file extension, needs to be a string. * for no filter.")
			}
		}

		// Now we're doing the actual work: Listing files.
		// Folders are ending with a slash. Can be identified later on from the user with JavaScript.
		// Additionally, when more smart logic required, user can use regex in JS.
		files := make([]string, 0)      // init files list
		dirClean := filepath.Clean(dir) // let's clean it here once, instead of over-and-over again within loop
		err := filepath.Walk(dir, func(path string, fi os.FileInfo, err error) error {
			// quick fix to get it working on windows, as it returns paths with double-backslash, what usually
			// require() doesn't seem to handle well. For the sake of compatibility (and because slash looks nicer),
			// we simply replace "\\" to "/" using filepath.ToSlash()..
			path = filepath.ToSlash(filepath.Clean(path)) // convert to slashes for directories
			if !recursive && fi.IsDir() {
				// If recursive is disabled, it is a dir what we're processing, and the path is different
				// than specified, we're apparently in a different folder. Therefore: Skip it.
				// So: Why this way? Because Walk() is always recursive and otherwise would require a complete
				// different function to handle this scenario. This way it's easier to maintain.
				if path != dirClean {
					return filepath.SkipDir
				}
			}
			if fileExtension != "*" && fileExtension != filepath.Ext(path) {
				// ONLY skip, when the file extension is NOT matching, or when filter is NOT disabled.
				return nil
			}
			// dirPath := filepath.ToSlash(filepath.Dir(path)) + "/"
			files = append(files, path)
			return err
		})
		if err != nil {
			throw(vm, fmt.Sprintf("dirwalk failed: %v", err.Error()))
		}

		// let's pass the data back to the JS engine.
		return vm.ToValue(files)
	}
}

func jsPanic(vm *sobek.Runtime) func(sobek.FunctionCall) sobek.Value {
	return func(call sobek.FunctionCall) sobek.Value {
		if len(call.Arguments) != 1 {
			throw(vm, "PANIC takes exactly one argument")
		}

		message := call.Argument(0).String() // The filename as given by the user
		fmt.Fprintln(os.Stderr, message)
		os.Exit(1)

		// Won't be actually executed
		return sobek.Undefined()
	}
}

// throw raises a JavaScript Error with the given message. We construct a real
// JS Error (rather than vm.NewGoError) so the surfaced message reads
// "Error: ..." instead of the confusing "GoError: ..." prefix, which made
// config bugs look like internal dnscontrol failures.
func throw(vm *sobek.Runtime, str string) {
	errObj, err := vm.New(vm.Get("Error"), vm.ToValue(str))
	if err != nil {
		// Fall back to a Go error if the Error constructor is somehow unavailable.
		panic(vm.NewGoError(errors.New(str)))
	}
	panic(errObj)
}

// jsErrorString returns a JavaScript error's message without the engine stack
// trace. sobek's Exception.Error() appends a stack frame (including internal Go
// "(native)" frames); otto did not. This keeps our output concise and matching
// otto, e.g. "Error: File x.js: ReferenceError: foo is not defined".
func jsErrorString(err error) string {
	if ex, ok := err.(*sobek.Exception); ok {
		return ex.Value().String()
	}
	return err.Error()
}

// cleanJSError converts a thrown JavaScript exception into a concise Go error
// without the engine stack trace, matching otto's behavior.
func cleanJSError(err error) error {
	if ex, ok := err.(*sobek.Exception); ok {
		return errors.New(ex.Value().String())
	}
	return err
}

func reverse(vm *sobek.Runtime) func(sobek.FunctionCall) sobek.Value {
	return func(call sobek.FunctionCall) sobek.Value {
		if len(call.Arguments) != 1 {
			throw(vm, "REV takes exactly one argument")
		}
		dom := call.Argument(0).String()
		rev, err := transform.ReverseDomainName(dom)
		if err != nil {
			throw(vm, err.Error())
		}
		return vm.ToValue(rev)
	}
}

func reverseCompat(vm *sobek.Runtime) func(sobek.FunctionCall) sobek.Value {
	return func(call sobek.FunctionCall) sobek.Value {
		if len(call.Arguments) != 1 {
			throw(vm, "REVCOMPAT takes exactly one argument")
		}
		dom := call.Argument(0).String()
		err := rfc4183.SetCompatibilityMode(dom)
		if err != nil {
			throw(vm, err.Error())
		}
		return sobek.Undefined()
	}
}
