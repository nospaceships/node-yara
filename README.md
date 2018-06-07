
# yara

This module implements [YARA][yara] bindings for [Node.js][nodejs].

**This module is supported on Linux and MacOS (using homebrew) platforms only**

This module uses the installed version of libyara.  You should download,
compile and install your preferred version, or use one of the following
commands using your system package manager:

	# CentOS/Red Hat
	sudo yum install yara-devel
	
	# Debian/Ubuntu
	sudo apt-get install yara
	
	# MacOS (using homebrew)
	sudo brew install yara

This module is installed using [node package manager (npm)][npm]:

	# This module contains C++ source code which will be compiled
	# during installation using node-gyp.  A suitable build chain
	# must be configured before installation.

	npm install yara

It is loaded using the `require()` function:

	var yara = require("yara")

Following initialisation of this module `Scanner` objects can then
be created, and content scanned using YARA rules:

	yara.initialize(function(error) {
		if (error) {
			console.error(error.message)
		} else {
			var rule_string = [
					"rule is_good {",
					"	condition:",
					"		true",
					"}"
				].join("\n")

			var rules = [
				{filename: "rules.yara"},
				{string: rule_string}
			]

			var scanner = yara.createScanner()
			
			scanner.configure({rules: rules}, function(error, warnings) {
				if (error) {
					if (error instanceof CompileRulesError) {
						console.error(error.message + ": " + JSON.stringify(error.errors))
					} else {
						console.error(error.message)
					}
				} else {
					if (warnings.length) {
						console.error("Compile warnings: " + JSON.stringify(warnings))
					} else {
						var req = {buffer: Buffer.from("content")}
						
						scanner.scan(req, function(error, result) {
							if (error) {
								console.error(error.message)
							} else {
								console.error(JSON.stringify(result))
							}
						})
					}
				}
			})
		}
	})

[nodejs]: http://nodejs.org "Node.js"
[npm]: https://npmjs.org/ "npm"
[yara]: http://virustotal.github.io/yara/ "YARA"

# This Module vs the YARA C API

When working with the YARA C API one would typically perform the following:

 1. Initialize the YARA library
 2. Create a YARA compiler
 3. Compile one or more rules
 4. Define zero or more external variables
 5. Retrieve the compiled rules
 6. Scan one or more pieces of content (file or memory based) using the
   compiled rules

Node.js is asynchronous and this module takes advantage of this property by
performing steps 2 to 5 above as a single action.  This is done in a way that
YARA rules can be completely replaced at run-time while in the middle of
scanning files.

This can be useful for long-running processes which must reload rules on the
fly in the middle of scanning large numbers of files, for example.

When using this module in place of the YARA C API the following steps would
be used instead:

 1. Initialize the YARA library - call `yara.initialize()`
 2. Create a scanner instance - call `yara.createScanner()`
 3. Configure the scanner instance - call `Scanner.configure()`
 4. Scan one or more pieces of content (file or memory based) - call
    `Scanner.scan()`
 5. At any point, even while scanning files, re-configure the scanner instance
    with new rules and external variables - call `Scanner.configure()`

Nearly all features of the YARA C API are exposed by this module.  Features
that do not fit in with the Node.js environment are excluded, e.g. the
`yr_rules_scan_fd()` function and all the `yr_..._foreach()` functions.

Note also that the `yr_rules_save()` and `yr_rules_load()` functions are not
exposed in anyway, nor are the `yr_rules_save_stream()` and
`yr_rules_load_stream()` functions.

# Asynchronous Thread Pool Size

Content scanning is performed in background threads.  This is provided by the
[Native Abstractions for Node.js][nan] framework, specifically the
`AsyncWorker` class interface.

By default, Node.js employs 4 background threads by default.  When scanning
many hundreds of files at once, for example, this would reduce throughput.
Support for the `UV_THREADPOOL_SIZE` environment variable was introduced into
Node.js 0.10.0.  This can be used increase the number of background threads up
to a maximum of 128.  This should be set before starting Node.js, and cannot
be changed once Node.js has been started:

	export UV_THREADPOOL_SIZE=128; node

[nan]: https://github.com/nodejs/nan "Native Abstractions for Node.js"

# Constants

The following sections describe constants exported and used by this module.

## yara.MetaType

When a rule is matched during a scan the `result` object passed to the
`Scanner.scan()` callback will contain a `rules` attribute, which is an
array of objects each defining a matched rule.  Each rule object will have a
`metas` attribute, which is a further array of objects, each defining the
meta fields defined for the corresponding rule.  Each meta object contains
a `type` attribute which defines the YARA type for the meta field's value.
For example:

	var result = {
		"rules": [
			{
				"id": "is_stephen",
				...
				"metas": [
					{type: yara.MetaType.String, id: "m1", value: "something"},
					{type: yara.MetaType.Boolean, id: "m2", value: true}
				]
			}
		]
	}

This object contains constants which can be used for the `type` attribute.

The following constants are defined in this object (the corresponding YARA C
API constant is also given):

 * `Integer` - `META_TYPE_INTEGER`  
 * `Boolean` - `META_TYPE_BOOLEAN`
 * `String` - `META_TYPE_STRING`

## yara.ScanFlag

The `Scanner.scan()` method expects an object as its first argument.  This
object can contain a `flags` attribute which is used by the YARA scanning
engine.  Currently only the one flag below is defined by YARA, therefore
this attribute will be either `0` (the default) or the singular flag defined
below.

The following constants are defined in this object (the corresponding YARA C
API constant is also given):

 * `FastMode` - `SCAN_FLAGS_FAST_MODE`

## yara.VariableType

The `Scanner.scan()` method expects an object as its first argument.  This
object can contain a `variables` attribute, which is an array of objects,
each defining a YARA external variable.  Each variable object contains
a `type` attribute which defines the YARA type for the variables value.
For example:

	var options = {
		...
		variables: [
			{type: yara.VariableType.Integer, id: "age", value: 35}
			{type: yara.VariableType.String, id: "name", value: "Stephen Vickers"}
		]
	}

This object contains constants which can be used for the `type` attribute.

The following constants are defined in this object (the corresponding YARA C
API function used to define the variable an a YARA compiler instance is also
given):

 * `Integer` - `yr_compiler_define_integer_variable()`
 * `Float` - `yr_compiler_define_float_variable()`
 * `Boolean` - `yr_compiler_define_boolean_variable()`
 * `String` - `yr_compiler_define_string_variable()`

# Using This Module

This module exposes the `Scanner` class.  Instances of this class are used to
configure one or more YARA rules and zero or more external variables.  Once
configured with these items, `Scanner` instances are then used to scan content
using the `scan()` method.

This module exports the `createScanner()` function which is used to create
instances of the `Scanner` class.

Before any `Scanner` instances can be configured, or used for scanning, the
`yara.initialize()` function must be called.

## yara.libyaraVersion()

The `libyaraVersion()` function returns a string containing the version of
YARA which was statically compiled into the module during installation.

The following example will print `3.6.4` to standard output if the module was
installed using the `YARA=3.6.4 npm install yara` command:

	console.log(yara.libyaraVersion())

## yara.initialize(callback)

The `initialize()` function initializes the YARA library by calling the
YARA C API function `yr_initialize()`.

The `callback` function is called once `yr_initialize()` has been called.
The following arguments will be passed to the `callback` function:

 * `error` - Instance of the `Error` class, or `null` if no error occurred

The following example initializes the YARA library:

	yara.initialize(function(error) {
		if (error) {
			console.error(error.message)
		} else {
			// Create a scanner, configure it and scan some files...
		}
	})

## yara.createScanner()

The `createScanner()` function instantiates and returns an instance of the
`Scanner` class:

    var scanner = raw.createScanner()

This function takes no arguments.

## scanner.configure(options, callback)

The `configure()` method configures a `Scanner` instance with one or more YARA
rules and zero or more YARA external variables.

The required `options` parameter is an object, and can contain the following
items:

 * `rules` - An array of objects, each defining one YARA rule, each object
   must contain one of the following two attributes:
    * `filename` - A file containing YARA rules to configure the scanner with
    * `string` - A string containin YARA rules to configure the scanner with
 * `variables` - An array of objects, each defining one YARA external variable,
   each object must contain the following attributes:
    * `type` - One of the constants defined in the `yara.VariableType` object,
      e.g. `yara.VariableType.Integer`
    * `id` - The variables identifier as a string, e.g. `created_at`
    * `value` - The variables value, the type of this field will depend on the
      type specified in the `type` attribute, e.g. `true` for the type
      `yara.VariableType.Boolean`

The `callback` function is called once all rules have been compiled and all
external variables have been configured.  The following arguments will be
passed to the `callback` function:

 * `error` - Instance of the `Error` class, an instance of the
   `yara.CompileRulesError` class, or `null` if no error occurred, if `error`
   is an instance of the `yara.CompileRulesError` class then the attribute
   `errors` will be defined on the `error` object which is an array of one or
   more objects, each object defines an error generated when a rule was
   compiled, each object will contain the following attributes:
    * `index` - An integer index indicating which item in the `rules` array,
      specified in the `options` object passed to the `configure()` method,
      the error relates to, i.e. `0` for the first item
    * `line` - The line number within the rule the error relates to, e.g.
      `42` for line 42
    * `message` - A string describing the error, e.g.
      `syntax error, unexpected '}', expecting _CONDITION_`
 * `warnings` - An array of zero or more objects, each object defines a
   warning generated when a rule was compiled, if there were no warnings the
   array will be `0` in length, each object will contain the following
   attributes:
    * `index` - An integer index indicating which item in the `rules` array,
      specified in the `options` object passed to the `configure()` method,
      the warning relates to, i.e. `3` for the fourth item
    * `line` - The line number within the rule the warning relates to, e.g.
      `12` for line 12
    * `message` - A string describing the warning, e.g.
      `Using literal string "stephen" in a boolean operation.`

The following example configures a number of YARA rules from strings:

	var rules = [
		"rule always_true {\ncondition:\ntrue\n}",
		"rule always_false {\ncondition:\nfalse\n}"
	]

	var variables = [
		{type: yara.VariableType.Integer, id: "created_at", value: 1493332105},
		{type: yara.VariableType.String, id: "created_by", value: "Stephen Vickers"},
		{type: yara.VariableType.Boolean, id: "is_stable", value: true}
	]
	
	scanner.configure({rules: rules, variables: variables}, function(error, warnings) {
		if (error) {
			if (error instanceof CompileRulesError) {
				console.error(error.message + ": " + JSON.stringify(error.errors))
			} else {
				console.error(error.message)
			}
		} else {
			if (warnings.length)
				console.error("Compile warnings: " + JSON.stringify(warnings))
			} else {
				// Scan some files
			}
		}
	})

## scanner.scan(request, callback)

The `scan()` method scans the content contained within a Node.js `Buffer` object
or a file.

The required `request` parameter is an object, and can contain the following
items:

 * `filename` - A string specifying a file, either this attribute or the
   `buffer` attribute is required
 * `buffer` - A Node.js `Buffer` object, either this attribute or the
   `filename` attribute is required
 * `offset` - A number specifying how many bytes of the Node.js `Buffer`
   object specified by the `buffer` attribute to skip before scanning,
   defaults to `0`
 * `length` - A number specifying the number of bytes, starting at the offset
   specified by the `offset` attribute, to scan in the Node.js `Buffer` object
   specified by the `buffer` attribute, defaults to the result of
   `buffer.length - offset`
 * `flags` - Either the constant `yara.ScanFlag.FastMode` or the number `0`,
   defaults to `0`
 * `timeout` - A number specifying after how many seconds a scan should be
   aborted, defaults to `0` meaning no timeout
 * `matchedBytes` - A number specifying the number of bytes of actual matched
   data to include in the scan result, defaults to `0` meaning not to
	include any matched data, note that this number is also capped by the
	`MAX_MATCH_DATA` libyara configuration

The `callback` function is called once the scan has completed.  The following
arguments will be passed to the `callback` function:

 * `error` - Instance of the `Error` class or `null` if no error occurred
 * `result` - An object containing the following attributes:
    * `rules` - An array of objects, each defining a YARA rule found to match
      the content scanned, each object will contain the following attributes:
       * `id` - The rule identifier
       * `tags` - An array of strings, each is a tag defined in the YARA rule
       * `matches` - An array of objects, each identifying a string found in
         the content scanned, and at which offset, note since a YARA rule can
         match on other non-string items this array may have a length of `0`,
         each object will contain the following attributes:
          * `offset` - A number indicating at which offset in the content the
            string matched some data, e.g. `43`
          * `length` - A number indicating the length of the data matched
            in the content, e.g. `7`
          * `id` - The matching strings identifier, e.g. `$s1`
          * `bytes` - If the `matchedBytes` attribute was specified in the
            `request` parameter passed to the `scan()` method, this attribute
            will be present and will contain a Node.js `Buffer` instance with
				the bytes of data which matched, this may not contain all data that
				matched, and will contain a number of bytes up to the number
				specified by `matchedBytes`, or the `MAX_MATCH_DATA` libyara
				configuration if it is smaller, use the `length` attribute to
				determine if the `bytes` attribute contains all the matched data
       * `metas` - An array of objects, each identifying a meta field defined
         on the rule, since a rule may have no meta fields this array may have
         a length of `0`, each object will contain the following attributes:
          * `type` - One of the constants defined in the `yara.MetaType`
            object, e.g. `yara.MetaType.Integer`
          * `id` - The meta fields identifier, e.g. `created_by`
          * `value` - The meta fields value, e.g. `Stephen Vickers`

The following example scans a Node.js `Buffer` object:

	var buffer = Buffer.from("some bad content")
	
	scanner.scan({buffer: buffer}, function(error, result) {
		if (error) {
			console.error(error)
		} else {
			if (result.rules.length) {
				console.log("match: " + JSON.stringify(result))
			} else {
				console.log("no-match")
			}
		}
	})

# Example Programs

Example programs are included under the modules `example` directory.

# Changes

## Version 1.0.0 - 28/04/2017

 * Initial release

## Version 1.1.0 - 02/05/2017

 * Support Mac OS
 * Address indentation inconsistencies

## Version 1.2.0 - 29/05/2017

 * Introduce "official" support for Mac OS
 * Upgrade YARA to 3.6.0

## Version 1.3.0 - 14/07/2017

 * Extract specified number of bytes of matched data when a string from a rule
   matches (added the `matchedBytes` attribute to the `request` object to the
	`Scanner.scan()` method)
 * YARA dependancy is downloaded during build (defaults to `3.6.3`, override
   using `YARA=x.x.x npm install`)
 * Added the `libyaraVersion()` function to obtain the version of YARA which
   has been statically compiled into the module

## Version 1.3.1 - 24/07/2017

 * Matched data buffer in scan result is freed twice resulting a double free
   exception

## Version 1.4.0 - 09/01/2018

 * Update YARA version downloaded during install to the latest stable release
   (version 3.7.0)

## Version 2.0.0 - 29/01/2018

 * Use YARA library from local system instead of downloading during
   installation

## Version 2.0.1 - 29/01/2018

 * Receiving an assertion error when compiling a rule containing a syntax
   error

## Version 2.1.0 - 02/05/2018

 * Support Node.js 10
 * `Scanner.scan()` doesn't use a lock before checking rules are compiled on a
   scanner

## Version 2.1.2 - 06/06/2018

 * Set NoSpaceships Ltd to be the owner and maintainer

## Version 2.1.3 - 07/06/2018

 * Remove redundant sections from README.md

# License

Copyright (c) 2018 NoSpaceships Ltd <hello@nospaceships.com>

Copyright (c) 2017 Stephen Vickers <stephen.vickers.sv@gmail.com>

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in
all copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
THE SOFTWARE.
