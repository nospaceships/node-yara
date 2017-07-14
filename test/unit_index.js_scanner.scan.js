
var assert = require("assert")

var yara = require ("../")

var scanner

before(function(done) {
	yara.initialize(function(error) {
		assert.ifError(error)

		scanner = yara.createScanner()

		scanner.configure({
				rules: [
					{string: "import \"pe\"\n"},
					{string: "import \"elf\"\n"},
					{string: "rule is_stephen : human man {\nmeta:\nm1 = \"m1\"\nm2 = true\nm3 = 123\n\nstrings:\n$s1 = \"stephen\"\ncondition:\n(age == 35) and (any of them)\n}"},
					{string: "rule is_silvia : human womman{\nstrings:\n$s1 = \"silvia\"\ncondition:\nany of them\n}"},
					{string: "rule is_either : human man woman {\nstrings:\n$s1 = \"stephen\"\n$s2 = \"silvia\"\ncondition:\nany of them\n}"},
				],
				variables: [
					{type: yara.VariableType.Integer, id: "age", value: 35}
				]
			}, function(error) {
				assert.ifError(error)
				done()
			})
	})
})

describe("index.js", function() {
	describe("Scanner.scan()", function() {
		it("buffer - valid", function(done) {
			var req = {
				buffer: Buffer.from("my name is stephen")
			}

			scanner.scan(req, function(error, result) {
				assert.ifError(error)

				var expected = {
					"rules": [
						{
							"id": "is_stephen",
							"tags": ["human", "man"],
							"matches": [
								{offset: 11, length: 7, id: "$s1"}
							],
							"metas": [
								{type: 2, id: "m1", value: "m1"},
								{type: 3, id: "m2", value: true},
								{type: 1, id: "m3", value: 123}
							]
						},
						{
							"id": "is_either",
							"tags": ["human", "man", "woman"],
							"matches": [
								{offset: 11, length: 7, id: "$s1"}
							],
							"metas": []
						}
					]
				}

				assert.deepEqual(result, expected)

				done()
			})
		})

		it("buffer - matched bytes (enough)", function(done) {
			var req = {
				matchedBytes: 100,
				buffer: Buffer.from("my name is stephen")
			}

			scanner.scan(req, function(error, result) {
				assert.ifError(error)

				var expected = {
					"rules": [
						{
							"id": "is_stephen",
							"tags": ["human", "man"],
							"matches": [
								{offset: 11, length: 7, id: "$s1", bytes: Buffer.from("stephen")}
							],
							"metas": [
								{type: 2, id: "m1", value: "m1"},
								{type: 3, id: "m2", value: true},
								{type: 1, id: "m3", value: 123}
							]
						},
						{
							"id": "is_either",
							"tags": ["human", "man", "woman"],
							"matches": [
								{offset: 11, length: 7, id: "$s1", bytes: Buffer.from("stephen")}
							],
							"metas": []
						}
					]
				}

				assert.deepEqual(result, expected)

				done()
			})
		})

		it("buffer - matched bytes (short)", function(done) {
			var req = {
				matchedBytes: 4,
				buffer: Buffer.from("my name is stephen")
			}

			scanner.scan(req, function(error, result) {
				assert.ifError(error)

				var expected = {
					"rules": [
						{
							"id": "is_stephen",
							"tags": ["human", "man"],
							"matches": [
								{offset: 11, length: 7, id: "$s1", bytes: Buffer.from("step")}
							],
							"metas": [
								{type: 2, id: "m1", value: "m1"},
								{type: 3, id: "m2", value: true},
								{type: 1, id: "m3", value: 123}
							]
						},
						{
							"id": "is_either",
							"tags": ["human", "man", "woman"],
							"matches": [
								{offset: 11, length: 7, id: "$s1", bytes: Buffer.from("step")}
							],
							"metas": []
						}
					]
				}

				assert.deepEqual(result, expected)

				done()
			})
		})

		it("buffer.length - out of range (negative)", function(done) {
			var req = {
				buffer: Buffer.from("1234"),
				length: -1
			}

			assert.throws(function() {
				scanner.scan(req, function(error, result) {})
			}, /Length is out of bounds/)

			done()
		})

		it("buffer.length - out of range (to high)", function(done) {
			var req = {
				buffer: Buffer.from("1234"),
				length: 5
			}

			assert.throws(function() {
				scanner.scan(req, function(error, result) {})
			}, /Length is out of bounds/)

			done()
		})

		it("buffer.length - out of range (plus offset)", function(done) {
			var req = {
				buffer: Buffer.from("1234"),
				length: 3,
				offset: 2
			}

			assert.throws(function() {
				scanner.scan(req, function(error, result) {})
			}, /Length is out of bounds/)

			done()
		})

		it("buffer.length - within range", function(done) {
			var req = {
				buffer: Buffer.from("silvia silvia"),
				length: 6
			}

			scanner.scan(req, function(error, result) {
				assert.ifError(error)
				assert.equal(result.rules.length, 2)

				done()
			})
		})

		it("buffer.length - exact", function(done) {
			var req = {
				buffer: Buffer.from("silvia silvia"),
				length: 12
			}

			scanner.scan(req, function(error, result) {
				assert.ifError(error)
				assert.equal(result.rules.length, 2)

				done()
			})
		})

		it("buffer.offset - out of range (negative)", function(done) {
			var req = {
				buffer: Buffer.from("1234"),
				offset: -1
			}

			assert.throws(function() {
				scanner.scan(req, function(error, result) {})
			}, /Offset is out of bounds/)

			done()
		})

		it("buffer.offset - out of range (to high)", function(done) {
			var req = {
				buffer: Buffer.from("1234"),
				offset: 4
			}

			assert.throws(function() {
				scanner.scan(req, function(error, result) {})
			}, /Offset is out of bounds/)

			done()
		})

		it("buffer.offset - within range (exact length)", function(done) {
			var req = {
				buffer: Buffer.from("silvia silvia"),
				length: 8,
				offset: 5
			}

			scanner.scan(req, function(error, result) {
				assert.ifError(error)
				assert.equal(result.rules.length, 2)

				done()
			})
		})

		it("buffer.offset - within range", function(done) {
			var req = {
				buffer: Buffer.from("silvia silvia"),
				offset: 2
			}

			scanner.scan(req, function(error, result) {
				assert.ifError(error)
				assert.equal(result.rules.length, 2)

				done()
			})
		})

		it("file - missing (and no buffer)", function(done) {
			var req = {}

			assert.throws(function() {
				scanner.scan(req, function(error, result) {})
			}, /Either filename of buffer is required/)

			done()
		})

		it("file - non-existant", function(done) {
			var req = {
				filename: "test/data/unit_index.js_scanner.scan/empty.txt"
			}

			scanner.scan(req, function(error, result) {
				assert.ifError(error)
				assert.equal(result.rules, 0)

				done()
			})
		})

		it("file - valid", function(done) {
			var req = {
				filename: "test/data/unit_index.js_scanner.scan/valid.txt"
			}

			scanner.scan(req, function(error, result) {
				assert.ifError(error)

				var expected = {
					"rules": [
						{
							"id": "is_stephen",
							"tags": ["human", "man"],
							"matches": [
								{offset: 20, length: 7, id: "$s1"}
							],
							"metas": [
								{type: 2, id: "m1", value: "m1"},
								{type: 3, id: "m2", value: true},
								{type: 1, id: "m3", value: 123}
							]
						},
						{
							"id": "is_either",
							"tags": ["human", "man", "woman"],
							"matches": [
								{offset: 20, length: 7, id: "$s1"}
							],
							"metas": []
						}
					]
				}

				assert.deepEqual(result, expected)

				done()
			})
		})

		it("flags - defaults to no FastMode", function(done) {
			scanner.configure({
					rules: [
						{filename: "test/data/unit_index.js_scanner.scan/flags.txt"}
					]
				}, function(error) {
					assert.ifError(error)

					var req = {
						buffer: Buffer.from("stephen stephen")
					}

					scanner.scan(req, function(error, result) {
						assert.ifError(error)

						var expected = {
							"rules": [
								{
									"id": "is_stephen",
									"tags": [],
									"matches": [
										{offset: 0, length: 7, id: "$s1"},
										{offset: 8, length: 7, id: "$s1"}
									],
									"metas": []
								}
							]
						}

						assert.deepEqual(result, expected)

						done()
					})
				})
		})

		it("flags - FastMode matches once", function(done) {
			scanner.configure({
					rules: [
						{filename: "test/data/unit_index.js_scanner.scan/flags.txt"}
					]
				}, function(error) {
					assert.ifError(error)

					var req = {
						buffer: Buffer.from("stephen stephen"),
						flags: yara.ScanFlag.FastMode
					}

					scanner.scan(req, function(error, result) {
						assert.ifError(error)

						var expected = {
							"rules": [
								{
									"id": "is_stephen",
									"tags": [],
									"matches": [
										{offset: 0, length: 7, id: "$s1"}
									],
									"metas": []
								}
							]
						}

						assert.deepEqual(result, expected)

						done()
					})
				})
		})
	})
})
