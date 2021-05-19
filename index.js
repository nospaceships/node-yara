
var util = require("util")
var yara = require ("./build/Release/yara");

function _parseMetadata(rule) {
	for (var i = 0; i < rule.metas.length; i++) {
		var fields = rule.metas[i].split(":")

		var type = parseInt(fields.shift())
		var id = fields.shift()

		var meta = {
			type: type,
			id: id,
			value: fields.join(":")
		}

		if (meta.type == yara.MetaType.Integer)
			meta.value = parseInt(meta.value)
		else if (meta.type == yara.MetaType.Boolean)
			meta.value = (meta.value == "true") ? true : false

		rule.metas[i] = meta
	}

	return rule;
}

function _expandConstantObject(object) {
	var keys = []
	for (var key in object)
		keys.push([key, object[key]])
	for (var i = 0; i < keys.length; i++)
		object[keys[i][1]] = keys[i][0]
}

_expandConstantObject(yara.ErrorCode)

function CompileRulesError(message) {
	this.name = "CompileRulesError"
	this.message = message
}

util.inherits(CompileRulesError, Error)

function Scanner(options) {
	this.yara = new yara.ScannerWrap()
}

Scanner.prototype.getRules = function() {
	var result = this.yara.getRules();
	result.rules.forEach(function(rule) {
		_parseMetadata(rule);
	});

	return result;
}

Scanner.prototype.configure = function(options, cb) {
	return this.yara.configure(options, function(error, warnings) {
		if (warnings) {
			for (var i = 0; i < warnings.length; i++) {
				var fields = warnings[i].split(":")
				warnings[i] = {
					index: parseInt(fields[0]),
					line: parseInt(fields[1]),
					message: fields[2]
				}
			}
		}

		if (error) {
			if (error.errors) {
				var errors = []

				error.errors.forEach(function(item) {
					var fields = item.split(":")
					errors.push({
						index: parseInt(fields[0]),
						line: parseInt(fields[1]),
						message: fields[2]
					})
				})

				error = new CompileRulesError(error.message)
				error.errors = errors
			}

			cb(error, warnings)
		} else {
			cb(null, warnings)
		}
	})
}

Scanner.prototype.scan = function(req, cb) {
	if (req.buffer) {
		if (! req.offset)
			req.offset = 0
		if (! req.length)
			req.length = req.buffer.length - req.offset
	}

	return this.yara.scan(req, function(error, result) {
		if (error) {
			cb(error)
		} else {
			result.rules.forEach(function(rule) {
				rule = _parseMetadata(rule);

				for (var i = 0; i < rule.matches.length; i++) {
					var fields = rule.matches[i].split(":")

					var match = {
						offset: parseInt(fields[0]),
						length: parseInt(fields[1]),
						id: fields[2]
					}

					if (i < rule.datas.length)
						match.bytes = rule.datas[i]

					rule.matches[i] = match
				}

				delete rule.datas
			})

			cb(null, result)
		}
	})
}

exports.CompileRulesError = CompileRulesError

exports.Scanner = Scanner

exports.MetaType = yara.MetaType

exports.ScanFlag = yara.ScanFlag

exports.VariableType = yara.VariableType

exports.createScanner = function(options) {
	return new Scanner(options || {})
}

exports.initialize = function(cb) {
	return yara.initialize(cb)
}

exports.libyaraVersion = function() {
	return yara.libyaraVersion()
}
