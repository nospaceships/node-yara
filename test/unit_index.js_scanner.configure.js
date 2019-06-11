
var assert = require("assert")

var yara = require ("../")

before(function(done) {
	yara.initialize(function(error) {
		assert.ifError(error)
		done()
	})
})

describe("index.js", function() {
	describe("Scanner.configure()", function() {
		it("call scan() before configure()", function(done) {
			var scanner = yara.createScanner()

			assert.throws(function() {
				scanner.scan({}, function() {})
			}, /Please call configure\(\) before scan\(\)/)

			done()
		})

		it("rules.string - missing is ignored", function(done) {
			var scanner = yara.createScanner()
			scanner.configure({
					rules: [
						{}
					]
				}, done)
		})

		it("rules.string - empty is ignored", function(done) {
			var scanner = yara.createScanner()
			scanner.configure({
					rules: [
						{string: ""}
					]
				}, done)
		})

		it("rules.string - errors", function(done) {
			var scanner = yara.createScanner()

			scanner.configure({
					rules: [
						{string: "rule bad {}"}
					]
				}, function(error) {
					assert(error instanceof yara.CompileRulesError)
					assert(error.message == "Error compiling rules")

					var expErrors = [{
						index: 0,
						line: 1,
						message: "syntax error, unexpected '}', expecting <condition>"
					}]

					assert.deepEqual(error.errors, expErrors)

					done()
				})
		})

		it("rules.string - valid", function(done) {
			var scanner = yara.createScanner()

			scanner.configure({
					rules: [
						{string: "rule good {\ncondition:\ntrue\n}"}
					]
				}, function(error) {
					assert.ifError(error)
					done()
				})
		})

		it("rules.string - warnings", function(done) {
			var scanner = yara.createScanner()

			scanner.configure({
					rules: [
						{string: "rule good {\ncondition:\n\"stephen\"\n}"}
					]
				}, function(error, warnings) {
					assert.ifError(error)

					var expected = [
						{
							index: 0,
							line: 4,
							message: 'Using literal string "stephen" in a boolean operation.'
						}
					]

					assert.deepEqual(warnings, expected)

					done()
				})
		})

		it("rules.filename - empty is ignored", function(done) {
			var scanner = yara.createScanner()
			scanner.configure({
					rules: [
						{filename: ""}
					]
				}, done)
		})

		it("rules.file - invalid path", function(done) {
			var scanner = yara.createScanner()
			scanner.configure({
					rules: [
						{filename: "test/data/unit_index.js_scanner.configure/invalid.yara"}
					]
				}, function(error) {
					assert(error)
					assert.equal(error.message, "fopen(test/data/unit_index.js_scanner.configure/invalid.yara) failed: No such file or directory")
					done()
				})
		})

		it("rules.file - errors", function(done) {
			var scanner = yara.createScanner()

			scanner.configure({
					rules: [
						{filename: "test/data/unit_index.js_scanner.configure/bad.yara"}
					]
				}, function(error) {
					assert(error instanceof yara.CompileRulesError)
					assert(error.message == "Error compiling rules")

					var expErrors = [{
						index: 0,
						line: 4,
						message: "syntax error, unexpected hex string, expecting identifier"
					}]

					assert.deepEqual(error.errors, expErrors)

					done()
				})
		})

		it("rules.filename - valid", function(done) {
			var scanner = yara.createScanner()

			scanner.configure({
					rules: [
						{filename: "test/data/unit_index.js_scanner.configure/good.yara"}
					]
				}, function(error) {
					assert.ifError(error)
					done()
				})
		})

		it("variables.integer - valid", function(done) {
			var scanner = yara.createScanner()

			scanner.configure({
					rules: [
						{filename: "test/data/unit_index.js_scanner.configure/good.yara"}
					],
					variables: [
						{type: yara.VariableType.Integer, id: "skill_level", value: 34}
					]
				}, function(error) {
					assert.ifError(error)
					done()
				})
		})

		it("variables.float - valid", function(done) {
			var scanner = yara.createScanner()

			scanner.configure({
					rules: [
						{filename: "test/data/unit_index.js_scanner.configure/good.yara"}
					],
					variables: [
						{type: yara.VariableType.Float, id: "percent", value: 0.45}
					]
				}, function(error) {
					assert.ifError(error)
					done()
				})
		})

		it("variables.float - valid", function(done) {
			var scanner = yara.createScanner()

			scanner.configure({
					rules: [
						{filename: "test/data/unit_index.js_scanner.configure/good.yara"}
					],
					variables: [
						{type: yara.VariableType.Boolean, id: "isYara", value: true}
					]
				}, function(error) {
					assert.ifError(error)
					done()
				})
		})

		it("variables.string - valid", function(done) {
			var scanner = yara.createScanner()

			scanner.configure({
					rules: [
						{filename: "test/data/unit_index.js_scanner.configure/good.yara"}
					],
					variables: [
						{type: yara.VariableType.String, id: "name", value: "stephen"}
					]
				}, function(error) {
					assert.ifError(error)
					done()
				})
		})

		it("variables.notype - invalid", function(done) {
			var scanner = yara.createScanner()

			scanner.configure({
					rules: [
						{filename: "test/data/unit_index.js_scanner.configure/good.yara"}
					],
					variables: [
						{id: "skill_level", value: 34}
					]
				}, function(error) {
					assert(error instanceof Error)
					assert.equal(error.message, "Unknown variable type: 0")
					done()
				})
		})
	})
})
