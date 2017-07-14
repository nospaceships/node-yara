
var fs = require("fs")

var yara = require ("../")

if (process.argv.length < 4) {
	console.log ("usage: node scan-dir <rules.yara> <dir>")
	process.exit (-1)
}

var rules = process.argv[2]
var dir   = process.argv[3]

var scanner = yara.createScanner()

var files = fs.readdirSync(dir);

function doOne(file) {
	fs.stat(dir + "/" + file, function(error, stats) {
		if (error) {
			console.error("stat(%s) failed: %s", dir + "/" + file, error.message)
		} else {
			if (! stats.isFile())
				return

			console.log("scanning: %s", dir + "/" + file)

			scanner.scan({filename: dir + "/" + file, matchedBytes: 10}, function(path, error, result) {
				if (error) {
					console.error("scan %s failed: %s", path, error.message)
				} else {
					if (result.rules.length) {
						console.log("matched %s: %s", path, JSON.stringify(result))
					}
				}
			}.bind(this, dir + "/" + file))
		}
	})
}

yara.initialize(function(error) {
	if (error) {
		console.error(error)
	} else {
		var options = {
			rules: [
				{filename: rules}
			]
		}

		scanner.configure(options, function(error) {
			if (error) {
				if (error instanceof yara.CompileRulesError) {
					console.error(error.message + ": " + JSON.stringify(error.errors))
				} else {
					console.error(error)
				}
			} else {
				files.forEach(function(file) {
					doOne(file)
				})
			}
		})
	}
})
