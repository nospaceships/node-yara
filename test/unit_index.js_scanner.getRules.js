
var assert = require("assert")

var yara = require ("../")

var scanner;

before(function(done) {
	yara.initialize(function(error) {
		assert.ifError(error)

		scanner = yara.createScanner()

		scanner.configure({
				rules: [
					{string: "rule is_stephen : human man {\nmeta:\nm1 = \"m1\"\nm2 = true\nm3 = 123\n\nstrings:\n$s1 = \"stephen\"\ncondition:\nany of them\n}"},
					{string: "rule is_either : human man woman {\nstrings:\n$s1 = \"stephen\"\n$s2 = \"silvia\"\ncondition:\nany of them\n}"},
				]
			}, function(error) {
				assert.ifError(error)
				done()
			})
	})
})

describe("index.js", function() {
	describe("Scanner.getRules()", function() {
		it("returns rule metadata", function(done) {
			var result = scanner.getRules()

			var expected = {
				"rules": [
					{
						"id": "is_stephen",
						"tags": ["human", "man"],
						"metas": [
							{type: 2, id: "m1", value: "m1"},
							{type: 3, id: "m2", value: true},
							{type: 1, id: "m3", value: 123}
						]
					},
					{
						"id": "is_either",
						"tags": ["human", "man", "woman"],
						"metas": []
					}
				]
			}

			assert.deepEqual(result, expected)
			done()
		})

		it("returns empty array if no rules are configured", function(done) {
			var scanner = yara.createScanner()
			scanner.configure({
					rules: [
						{}
					]
				}, function() {
					var result = scanner.getRules();
					assert.deepEqual(result, { rules: []})
					done()
				})
		})
	})
})
