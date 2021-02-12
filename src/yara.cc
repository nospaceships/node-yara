#ifndef YARA_CC
#define YARA_CC

#include <list>
#include <map>
#include <stdexcept>
#include <string>
#include <sstream>

#include <errno.h>
#include <stdio.h>
#include <string.h>
#include "yara.h"

const char* yara_strerror(int code) {
	return strerror(code);
}

#define yara_throw(type, stream) \
		do { \
			std::ostringstream oss__; \
			oss__ << stream; \
			throw type(oss__.str().c_str()); \
		} while (1)

namespace yara {

static Nan::Persistent<FunctionTemplate> ScannerWrap_constructor;

std::map<int, const char*> error_codes;

enum VarType {
	IntegerVarType = 1,
	FloatVarType   = 2,
	BooleanVarType = 3,
	StringVarType  = 4
};

#define MAP_ERROR_CODE(name, code) error_codes[code] = name

#define ERROR_UNKNOWN_STRING "ERROR_UNKNOWN"

void compileCallback(int error_level, const char* file_name, int line_number,
		const char* message, void* user_data);

int scanCallback(int message, void* data, void* param);

const char* getErrorString(int code) {
	size_t count = error_codes.count(code);
	if (count > 0)
		return error_codes[code];
	else
		return ERROR_UNKNOWN_STRING;
}

class YaraError : public std::exception {
public:
	YaraError(const char* what) : _what(what) {};

	~YaraError() throw() {};

	virtual const char* what() const throw() {
		return _what.c_str();
	}

private:
	std::string _what;
};

void InitAll(Local<Object> exports) {
	MAP_ERROR_CODE("ERROR_SUCCESS", ERROR_SUCCESS);
	MAP_ERROR_CODE("ERROR_INSUFICIENT_MEMORY", ERROR_INSUFICIENT_MEMORY);
	MAP_ERROR_CODE("ERROR_COULD_NOT_ATTACH_TO_PROCESS", ERROR_COULD_NOT_ATTACH_TO_PROCESS);
	MAP_ERROR_CODE("ERROR_COULD_NOT_OPEN_FILE", ERROR_COULD_NOT_OPEN_FILE);
	MAP_ERROR_CODE("ERROR_COULD_NOT_MAP_FILE", ERROR_COULD_NOT_MAP_FILE);
	MAP_ERROR_CODE("ERROR_INVALID_FILE", ERROR_INVALID_FILE);
	MAP_ERROR_CODE("ERROR_CORRUPT_FILE", ERROR_CORRUPT_FILE);
	MAP_ERROR_CODE("ERROR_UNSUPPORTED_FILE_VERSION", ERROR_UNSUPPORTED_FILE_VERSION);
	MAP_ERROR_CODE("ERROR_INVALID_REGULAR_EXPRESSION", ERROR_INVALID_REGULAR_EXPRESSION);
	MAP_ERROR_CODE("ERROR_INVALID_HEX_STRING", ERROR_INVALID_HEX_STRING);
	MAP_ERROR_CODE("ERROR_SYNTAX_ERROR", ERROR_SYNTAX_ERROR);
	MAP_ERROR_CODE("ERROR_LOOP_NESTING_LIMIT_EXCEEDED", ERROR_LOOP_NESTING_LIMIT_EXCEEDED);
	MAP_ERROR_CODE("ERROR_DUPLICATED_LOOP_IDENTIFIER", ERROR_DUPLICATED_LOOP_IDENTIFIER);
	MAP_ERROR_CODE("ERROR_DUPLICATED_IDENTIFIER", ERROR_DUPLICATED_IDENTIFIER);
	MAP_ERROR_CODE("ERROR_DUPLICATED_TAG_IDENTIFIER", ERROR_DUPLICATED_TAG_IDENTIFIER);
	MAP_ERROR_CODE("ERROR_DUPLICATED_META_IDENTIFIER", ERROR_DUPLICATED_META_IDENTIFIER);
	MAP_ERROR_CODE("ERROR_DUPLICATED_STRING_IDENTIFIER", ERROR_DUPLICATED_STRING_IDENTIFIER);
	MAP_ERROR_CODE("ERROR_UNREFERENCED_STRING", ERROR_UNREFERENCED_STRING);
	MAP_ERROR_CODE("ERROR_UNDEFINED_STRING", ERROR_UNDEFINED_STRING);
	MAP_ERROR_CODE("ERROR_UNDEFINED_IDENTIFIER", ERROR_UNDEFINED_IDENTIFIER);
	MAP_ERROR_CODE("ERROR_MISPLACED_ANONYMOUS_STRING", ERROR_MISPLACED_ANONYMOUS_STRING);
	MAP_ERROR_CODE("ERROR_INCLUDES_CIRCULAR_REFERENCE", ERROR_INCLUDES_CIRCULAR_REFERENCE);
	MAP_ERROR_CODE("ERROR_INCLUDE_DEPTH_EXCEEDED", ERROR_INCLUDE_DEPTH_EXCEEDED);
	MAP_ERROR_CODE("ERROR_WRONG_TYPE", ERROR_WRONG_TYPE);
	MAP_ERROR_CODE("ERROR_EXEC_STACK_OVERFLOW", ERROR_EXEC_STACK_OVERFLOW);
	MAP_ERROR_CODE("ERROR_SCAN_TIMEOUT", ERROR_SCAN_TIMEOUT);
	MAP_ERROR_CODE("ERROR_TOO_MANY_SCAN_THREADS", ERROR_TOO_MANY_SCAN_THREADS);
	MAP_ERROR_CODE("ERROR_CALLBACK_ERROR", ERROR_CALLBACK_ERROR);
	MAP_ERROR_CODE("ERROR_INVALID_ARGUMENT", ERROR_INVALID_ARGUMENT);
	MAP_ERROR_CODE("ERROR_TOO_MANY_MATCHES", ERROR_TOO_MANY_MATCHES);
	MAP_ERROR_CODE("ERROR_INTERNAL_FATAL_ERROR", ERROR_INTERNAL_FATAL_ERROR);
	MAP_ERROR_CODE("ERROR_NESTED_FOR_OF_LOOP", ERROR_NESTED_FOR_OF_LOOP);
	MAP_ERROR_CODE("ERROR_INVALID_FIELD_NAME", ERROR_INVALID_FIELD_NAME);
	MAP_ERROR_CODE("ERROR_UNKNOWN_MODULE", ERROR_UNKNOWN_MODULE);
	MAP_ERROR_CODE("ERROR_NOT_A_STRUCTURE", ERROR_NOT_A_STRUCTURE);
	MAP_ERROR_CODE("ERROR_NOT_INDEXABLE", ERROR_NOT_INDEXABLE);
	MAP_ERROR_CODE("ERROR_NOT_A_FUNCTION", ERROR_NOT_A_FUNCTION);
	MAP_ERROR_CODE("ERROR_INVALID_FORMAT", ERROR_INVALID_FORMAT);
	MAP_ERROR_CODE("ERROR_TOO_MANY_ARGUMENTS", ERROR_TOO_MANY_ARGUMENTS);
	MAP_ERROR_CODE("ERROR_WRONG_ARGUMENTS", ERROR_WRONG_ARGUMENTS);
	MAP_ERROR_CODE("ERROR_WRONG_RETURN_TYPE", ERROR_WRONG_RETURN_TYPE);
	MAP_ERROR_CODE("ERROR_DUPLICATED_STRUCTURE_MEMBER", ERROR_DUPLICATED_STRUCTURE_MEMBER);
	MAP_ERROR_CODE("ERROR_EMPTY_STRING", ERROR_EMPTY_STRING);
	MAP_ERROR_CODE("ERROR_DIVISION_BY_ZERO", ERROR_DIVISION_BY_ZERO);
	MAP_ERROR_CODE("ERROR_REGULAR_EXPRESSION_TOO_LARGE", ERROR_REGULAR_EXPRESSION_TOO_LARGE);
	MAP_ERROR_CODE("ERROR_TOO_MANY_RE_FIBERS", ERROR_TOO_MANY_RE_FIBERS);
	MAP_ERROR_CODE("ERROR_COULD_NOT_READ_PROCESS_MEMORY", ERROR_COULD_NOT_READ_PROCESS_MEMORY);
	MAP_ERROR_CODE("ERROR_INVALID_EXTERNAL_VARIABLE_TYPE", ERROR_INVALID_EXTERNAL_VARIABLE_TYPE);

	ExportConstants(exports);
	ExportFunctions(exports);

	ScannerWrap::Init(exports);
}

NODE_MODULE(yara, InitAll)

void ExportConstants(Local<Object> target) {
	Local<Object> variable_type = Nan::New<Object>();

	Nan::Set(target, Nan::New("VariableType").ToLocalChecked(), variable_type);

	Nan::Set(variable_type, Nan::New("Integer").ToLocalChecked(), Nan::New<Number>(IntegerVarType));
	Nan::Set(variable_type, Nan::New("Float").ToLocalChecked(), Nan::New<Number>(FloatVarType));
	Nan::Set(variable_type, Nan::New("Boolean").ToLocalChecked(), Nan::New<Number>(BooleanVarType));
	Nan::Set(variable_type, Nan::New("String").ToLocalChecked(), Nan::New<Number>(StringVarType));

	Local<Object> scan_flag = Nan::New<Object>();

	Nan::Set(target, Nan::New("ScanFlag").ToLocalChecked(), scan_flag);

	Nan::Set(scan_flag, Nan::New("FastMode").ToLocalChecked(), Nan::New<Number>(SCAN_FLAGS_FAST_MODE));

	Local<Object> meta_type = Nan::New<Object>();

	Nan::Set(target, Nan::New("MetaType").ToLocalChecked(), meta_type);

	Nan::Set(meta_type, Nan::New("Integer").ToLocalChecked(), Nan::New<Number>(META_TYPE_INTEGER));
	Nan::Set(meta_type, Nan::New("Boolean").ToLocalChecked(), Nan::New<Number>(META_TYPE_BOOLEAN));
	Nan::Set(meta_type, Nan::New("String").ToLocalChecked(), Nan::New<Number>(META_TYPE_STRING));
}

void ExportFunctions(Local<Object> target) {
	Nan::Set(target, Nan::New("libyaraVersion").ToLocalChecked(), Nan::GetFunction(Nan::New<FunctionTemplate>(LibyaraVersion)).ToLocalChecked());
	Nan::Set(target, Nan::New("initialize").ToLocalChecked(), Nan::GetFunction(Nan::New<FunctionTemplate>(Initialize)).ToLocalChecked());
}

NAN_METHOD(LibyaraVersion) {
	Nan::HandleScope scope;

	Local<String> version = Nan::New(YR_VERSION).ToLocalChecked();

	info.GetReturnValue().Set(version);
}


class AsyncInitialize : public Nan::AsyncWorker {
public:
	AsyncInitialize(
			Nan::Callback *callback
		) : Nan::AsyncWorker(callback) {}

	~AsyncInitialize() {}

	void Execute() {
		int rc = yr_initialize();
		if (rc != ERROR_SUCCESS) {
			std::string errorstr = std::string("yr_initialize() failed: ") + getErrorString(rc);
			SetErrorMessage(errorstr.c_str());
		}
	}

protected:
	void HandleOKCallback() {
		Local<Value> argv[1];

		argv[0] = Nan::Null();

		callback->Call(1, argv, async_resource);
	}
};

NAN_METHOD(Initialize) {
	Nan::HandleScope scope;

	if (info.Length() < 1) {
		Nan::ThrowError("One argument is required");
		return;
	}

	if (! info[0]->IsFunction()) {
		Nan::ThrowError("Callback argument must be a function");
		return;
	}

	Nan::Callback* callback = new Nan::Callback(info[0].As<Function>());

	AsyncInitialize* async_initialize = new AsyncInitialize(callback);

	Nan::AsyncQueueWorker(async_initialize);

	info.GetReturnValue().Set(info.This());
}

void ScannerWrap::Init(Local<Object> exports) {
	Nan::HandleScope scope;

	Local<FunctionTemplate> tpl = Nan::New<FunctionTemplate>(ScannerWrap::New);
	tpl->SetClassName(Nan::New("ScannerWrap").ToLocalChecked());
	tpl->InstanceTemplate()->SetInternalFieldCount(1);

	Nan::SetPrototypeMethod(tpl, "configure", Configure);
	Nan::SetPrototypeMethod(tpl, "scan", Scan);
	Nan::SetPrototypeMethod(tpl, "getRules", GetRules);

	ScannerWrap_constructor.Reset(tpl);
	Nan::Set(exports, Nan::New("ScannerWrap").ToLocalChecked(), Nan::GetFunction(tpl).ToLocalChecked());
}

ScannerWrap::ScannerWrap() : compiler(NULL), rules(NULL) {
	pthread_rwlock_init(&lock, NULL);
}

ScannerWrap::~ScannerWrap() {
	if (compiler) {
		yr_compiler_destroy(compiler);
		compiler = NULL;
	}

	if (rules) {
		yr_rules_destroy(rules);
		rules = NULL;
	}

	pthread_rwlock_destroy(&lock);
}

void ScannerWrap::lock_read(void) {
	pthread_rwlock_rdlock(&lock);
}

void ScannerWrap::lock_write(void) {
	pthread_rwlock_wrlock(&lock);
}

void ScannerWrap::unlock(void) {
	pthread_rwlock_unlock(&lock);
}

NAN_METHOD(ScannerWrap::New) {
	Nan::HandleScope scope;

	ScannerWrap* scanner = new ScannerWrap();

	scanner->Wrap(info.This());

	info.GetReturnValue().Set(info.This());
}

struct RuleConfig {
	bool isFile;
	std::string source;
	std::string ns;
	uint32_t index;
};

struct VarConfig {
	VarType type;
	std::string id;
	int64_t value_integer;
	double value_float;
	bool value_boolean;
	std::string value_string;
};

class AsyncConfigure;

struct CompileArgs {
	RuleConfig* rule_config;
	AsyncConfigure* configure;
};

typedef std::list<RuleConfig*> RuleConfigList;
typedef std::list<VarConfig*> VarConfigList;

class AsyncConfigure : public Nan::AsyncWorker {
public:
	AsyncConfigure(
			ScannerWrap* scanner,
			RuleConfigList* rule_configs,
			VarConfigList* var_configs,
			Nan::Callback* callback
		) : Nan::AsyncWorker(callback),
				scanner_(scanner),
				rule_configs_(rule_configs),
				var_configs_(var_configs) {}

	~AsyncConfigure() {
		if (rule_configs_) {
			RuleConfig* rule_config;
			RuleConfigList::iterator rule_configs_it;

			for (rule_configs_it = rule_configs_->begin();
					rule_configs_it != rule_configs_->end();
					rule_configs_it++) {
				rule_config = *rule_configs_it;
				delete rule_config;
			}

			rule_configs_->clear();
			delete rule_configs_;
			rule_configs_ = NULL;
		}

		if (var_configs_) {
			VarConfig* var_config;
			VarConfigList::iterator var_configs_it;

			for (var_configs_it = var_configs_->begin();
					var_configs_it != var_configs_->end();
					var_configs_it++) {
				var_config = *var_configs_it;
				delete var_config;
			}

			var_configs_->clear();
			delete var_configs_;
			var_configs_ = NULL;
		}
	}

	void Execute() {
		scanner_->lock_write();

		try {
			if (scanner_->rules) {
				yr_rules_destroy(scanner_->rules);
				scanner_->rules = NULL;
			}

			if (scanner_->compiler) {
				yr_compiler_destroy(scanner_->compiler);
				scanner_->compiler = NULL;
			}

			CompileArgs compile_args;
			compile_args.configure = this;

			int rc = yr_compiler_create(&scanner_->compiler);
			if (rc != ERROR_SUCCESS)
				yara_throw(YaraError, "yr_compiler_create() failed: "
						<< getErrorString(rc));
			yr_compiler_set_callback(scanner_->compiler, compileCallback,
					(void*) &compile_args);

			VarConfig* var_config;
			VarConfigList::iterator var_configs_it;

			for (var_configs_it = var_configs_->begin();
					var_configs_it != var_configs_->end();
					var_configs_it++) {
				var_config = *var_configs_it;

				switch (var_config->type) {
					case IntegerVarType:
						rc = yr_compiler_define_integer_variable(
								scanner_->compiler,
								var_config->id.c_str(),
								var_config->value_integer
							);
						if (rc != ERROR_SUCCESS)
							yara_throw(YaraError, "yr_compiler_define_integer_variable() failed: "
									<< getErrorString(rc));
						break;
					case FloatVarType:
						rc = yr_compiler_define_float_variable(
								scanner_->compiler,
								var_config->id.c_str(),
								var_config->value_float
							);
						if (rc != ERROR_SUCCESS)
							yara_throw(YaraError, "yr_compiler_define_float_variable() failed: "
									<< getErrorString(rc));
						break;
					case BooleanVarType:
						rc = yr_compiler_define_boolean_variable(
								scanner_->compiler,
								var_config->id.c_str(),
								var_config->value_boolean ? 1 : 0
							);
						if (rc != ERROR_SUCCESS)
							yara_throw(YaraError, "yr_compiler_define_boolean_variable() failed: "
									<< getErrorString(rc));
						break;
					case StringVarType:
						rc = yr_compiler_define_string_variable(
								scanner_->compiler,
								var_config->id.c_str(),
								var_config->value_string.c_str()
							);
						if (rc != ERROR_SUCCESS)
							yara_throw(YaraError, "yr_compiler_define_string_variable() failed: "
									<< getErrorString(rc));
						break;
					default:
						yara_throw(YaraError, "Unknown variable type: "
								<< var_config->type);
						break;
				}
			}

			RuleConfig* rule_config;
			RuleConfigList::iterator rule_configs_it;

			error_count = 0;

			for (rule_configs_it = rule_configs_->begin();
					rule_configs_it != rule_configs_->end();
					rule_configs_it++) {
				rule_config = *rule_configs_it;

				compile_args.rule_config = rule_config;

				if (rule_config->isFile) {
					FILE *fp = fopen(rule_config->source.c_str(), "r");
					if (! fp)
						yara_throw(YaraError, "fopen(" << rule_config->source.c_str()
								<< ") failed: " << yara_strerror(errno));

					error_count += yr_compiler_add_file(
							scanner_->compiler,
							fp,
							rule_config->ns.length()
									? rule_config->ns.c_str()
									: NULL,
							rule_config->source.c_str()
						);

					fclose(fp);
				} else {
					error_count += yr_compiler_add_string(
							scanner_->compiler,
							rule_config->source.c_str(),
							rule_config->ns.length()
									? rule_config->ns.c_str()
									: NULL
						);
				}
			}

			if (error_count == 0) {
				rc = yr_compiler_get_rules(scanner_->compiler, &scanner_->rules);
				if (rc != ERROR_SUCCESS)
					yara_throw(YaraError, "yr_compiler_get_rules() failed: "
							<< getErrorString(rc));
			}
		} catch(std::exception& error) {
			SetErrorMessage(error.what());
		}

		scanner_->unlock();
	}

	uint32_t error_count;
	std::list<std::string> errors;
	std::list<std::string> warnings;

protected:

	void HandleOKCallback() {
		Local<Array> warnings_array = Nan::New<Array>();
		uint32_t warnings_index = 0;

		std::list<std::string>::iterator warnings_it = warnings.begin();

		while (warnings_it != warnings.end()) {
			Nan::MaybeLocal<String> str = Nan::New<String>((*warnings_it).c_str());
			Nan::Set(warnings_array, warnings_index++, str.ToLocalChecked());
			warnings_it++;
		}

		if (error_count > 0) {
			Local<Object> error = Nan::To<Object>(Nan::Error("Error compiling rules")).ToLocalChecked();

			Local<Array> errors_array = Nan::New<Array>();
			uint32_t index = 0;

			std::list<std::string>::iterator errors_it = errors.begin();

			while (errors_it != errors.end()) {
				Nan::MaybeLocal<String> str = Nan::New<String>((*errors_it).c_str());
				Nan::Set(errors_array, index++, str.ToLocalChecked());
				errors_it++;
			}

			Nan::Set(error, Nan::New<String>("errors").ToLocalChecked(), errors_array);

			Local<Value> argv[2];
			argv[0] = error;
			argv[1] = warnings_array;
			callback->Call(2, argv, async_resource);
		} else {
			Local<Value> argv[2];
			argv[0] = Nan::Null();
			argv[1] = warnings_array;
			callback->Call(2, argv, async_resource);
		}
	}

private:
	ScannerWrap* scanner_;
	RuleConfigList* rule_configs_;
	VarConfigList* var_configs_;
};

void compileCallback(int error_level, const char* file_name, int line_number,
		const char* message, void* user_data) {
	CompileArgs* args = (CompileArgs*) user_data;

	std::ostringstream oss;
	oss << args->rule_config->index << ":" << line_number << ":" << message;

	if (error_level == YARA_ERROR_LEVEL_WARNING)
		args->configure->warnings.push_back(oss.str());
	else
		args->configure->errors.push_back(oss.str());
}

NAN_METHOD(ScannerWrap::Configure) {
	Nan::HandleScope scope;

	if (info.Length() < 2) {
		Nan::ThrowError("Two arguments are required");
		return;
	}

	if (! info[0]->IsObject()) {
		Nan::ThrowError("Options argument must be an object");
		return;
	}

	if (! info[1]->IsFunction()) {
		Nan::ThrowError("Callback argument must be a function");
		return;
	}

	Local<Object> options = Nan::To<Object>(info[0]).ToLocalChecked();

	RuleConfigList* rule_configs = new RuleConfigList();

	Local<Array> rules = Local<Array>::Cast(
			Nan::Get(options, Nan::New("rules").ToLocalChecked()).ToLocalChecked()
		);

	for (uint32_t i = 0; i < rules->Length(); i++) {
		if (Nan::Get(rules, i).ToLocalChecked()->IsObject()) {
			Local<Object> rule = Nan::To<Object>(Nan::Get(rules, i).ToLocalChecked()).ToLocalChecked();

			std::string ns;
			std::string str;
			std::string filename;

			if (Nan::Get(rule, Nan::New("namespace").ToLocalChecked()).ToLocalChecked()->IsString()) {
				Local<String> s = Nan::To<String>(Nan::Get(rule, Nan::New("namespace").ToLocalChecked()).ToLocalChecked()).ToLocalChecked();
				ns = *Nan::Utf8String(s);
			}

			if (Nan::Get(rule, Nan::New("string").ToLocalChecked()).ToLocalChecked()->IsString()) {
				Local<String> s = Nan::To<String>(Nan::Get(rule, Nan::New("string").ToLocalChecked()).ToLocalChecked()).ToLocalChecked();
				str = *Nan::Utf8String(s);
			}

			if (Nan::Get(rule, Nan::New("filename").ToLocalChecked()).ToLocalChecked()->IsString()) {
				Local<String> s = Nan::To<String>(Nan::Get(rule, Nan::New("filename").ToLocalChecked()).ToLocalChecked()).ToLocalChecked();
				filename = *Nan::Utf8String(s);
			}

			RuleConfig* rule_config = new RuleConfig();

			rule_config->isFile = filename.length()
					? true
					: false;

			rule_config->source = filename.length()
					? filename
					: str;

			rule_config->ns = ns;

			rule_config->index = i;

			rule_configs->push_back(rule_config);
		}
	}

	VarConfigList* var_configs = new VarConfigList();

	Local<Array> variables = Local<Array>::Cast(
			Nan::Get(options, Nan::New("variables").ToLocalChecked()).ToLocalChecked()
		);

	for (uint32_t i = 0; i < variables->Length(); i++) {
		if (Nan::Get(variables, i).ToLocalChecked()->IsObject()) {
			Local<Object> variable = Nan::To<Object>(Nan::Get(variables, i).ToLocalChecked()).ToLocalChecked();

			VarType type;
			std::string id;

			Local<Uint32> t = Nan::To<Uint32>(Nan::Get(variable, Nan::New("type").ToLocalChecked()).ToLocalChecked()).ToLocalChecked();
			type = (VarType) t->Value();

			Local<String> i = Nan::To<String>(Nan::Get(variable, Nan::New("id").ToLocalChecked()).ToLocalChecked()).ToLocalChecked();
			id = *Nan::Utf8String(i);

			VarConfig* var_config = new VarConfig();

			var_config->type = type;
			var_config->id = id;

			switch (type) {
				case IntegerVarType:
					var_config->value_integer = Nan::To<Integer>(Nan::Get(variable, Nan::New("value").ToLocalChecked()).ToLocalChecked()).ToLocalChecked()->Value();
					break;
				case FloatVarType:
					var_config->value_float = Nan::To<Number>(Nan::Get(variable, Nan::New("value").ToLocalChecked()).ToLocalChecked()).ToLocalChecked()->Value();
					break;
				case BooleanVarType:
					var_config->value_boolean = Nan::To<Boolean>(Nan::Get(variable, Nan::New("value").ToLocalChecked()).ToLocalChecked()).ToLocalChecked()->Value();
					break;
				case StringVarType:
					var_config->value_string = *Nan::Utf8String(Nan::To<String>(Nan::Get(variable, Nan::New("value").ToLocalChecked()).ToLocalChecked()).ToLocalChecked());
					break;
			}

			var_configs->push_back(var_config);
		}
	}

	Nan::Callback* callback = new Nan::Callback(info[1].As<Function>());

	ScannerWrap* scanner = ScannerWrap::Unwrap<ScannerWrap>(info.This());

	AsyncConfigure* async_configure = new AsyncConfigure(
			scanner,
			rule_configs,
			var_configs,
			callback
		);

	Nan::AsyncQueueWorker(async_configure);

	info.GetReturnValue().Set(info.This());
}

struct ScanReq {
	std::string filename;
	const char* buffer;
	int64_t offset;
	int64_t length;
	int32_t flags;
	int32_t timeout;
};

struct MatchData {
	MatchData() {
		bytes = NULL;
		length = 0;
	};

	bool copy(const uint8_t* data_bytes, uint32_t data_length) {
		bytes = (uint8_t*) realloc((uint8_t*) bytes, data_length);
		if (! bytes)
			return false;
		memcpy((void*) bytes, (void*) data_bytes, data_length);
		length = data_length;
		return true;
	}

	// We don't free bytes since we assume it is managed by a Buffer instance
	~MatchData() {};

	uint8_t* bytes;
	uint32_t length;
};

struct CompiledRule {
	std::string id;
	std::list<std::string> tags;
	std::list<std::string> metas;
};

typedef std::list<CompiledRule*> CompiledRuleList;

struct ScanRuleMatch {
	std::string id;
	std::list<std::string> tags;
	std::list<std::string> metas;
	std::list<std::string> matches;
	std::list<MatchData*> datas;
};

typedef std::list<ScanRuleMatch*> ScanRuleMatchList;

class AsyncScan : public Nan::AsyncWorker {
public:
	AsyncScan(
			ScannerWrap* scanner,
			ScanReq* scan_req,
			Nan::Callback* callback
		) : Nan::AsyncWorker(callback),
				scanner_(scanner),
				scan_req_(scan_req) {
		matched_bytes = 0;
	}

	~AsyncScan() {
		ScanRuleMatch* rule_match;
		ScanRuleMatchList::iterator rule_matches_it;

		MatchData* match_data;
		std::list<MatchData*>::iterator match_data_it;

		for (rule_matches_it = rule_matches.begin();
				rule_matches_it != rule_matches.end();
				rule_matches_it++) {
			rule_match = *rule_matches_it;

			for (match_data_it = rule_match->datas.begin();
					match_data_it != rule_match->datas.end();
					match_data_it++) {
				match_data = *match_data_it;
				delete match_data;
			}

			rule_match->datas.clear();

			delete rule_match;
		}

		rule_matches.clear();
	}

	void Execute() {
		scanner_->lock_read();

		try {
			int rc;

			if (scan_req_->filename.length()) {
				rc = yr_rules_scan_file(
						scanner_->rules,
						scan_req_->filename.c_str(),
						scan_req_->flags,
						scanCallback,
						(void*) this,
						scan_req_->timeout
					);
			} else if (scan_req_->buffer) {
				rc = yr_rules_scan_mem(
						scanner_->rules,
						(uint8_t*) scan_req_->buffer + scan_req_->offset,
						scan_req_->length,
						scan_req_->flags,
						scanCallback,
						(void*) this,
						scan_req_->timeout
					);
			} else {
				yara_throw(YaraError, "Either filename of buffer is required");
			}

			if (rc != ERROR_SUCCESS)
				yara_throw(YaraError,
						(scan_req_->filename.length() ? "yr_rules_scan_file" : "yr_rules_scan_mem")
						<< "() failed: " << getErrorString(rc));
		} catch(std::exception& error) {
			SetErrorMessage(error.what());
		}

		scanner_->unlock();
	}

	ScanRuleMatchList rule_matches;
	int32_t matched_bytes;

protected:

	void HandleOKCallback() {

		Local<Object> res = Nan::New<Object>();

		Local<Array> rules = Nan::New<Array>();
		int rules_index = 0;

		for (ScanRuleMatchList::iterator rule_matches_it = rule_matches.begin();
				rule_matches_it != rule_matches.end();
				rule_matches_it++) {
			ScanRuleMatch* rule_match = *rule_matches_it;

			Local<Object> rule = Nan::New<Object>();

			Local<Array> tags = Nan::New<Array>();
			int tags_index = 0;

			for (std::list<std::string>::iterator tags_it = rule_match->tags.begin();
					tags_it != rule_match->tags.end();
					tags_it++) {
				Local<String> tag = Nan::New((*tags_it).c_str()).ToLocalChecked();
				Nan::Set(tags, tags_index++, tag);
			}

			Local<Array> metas = Nan::New<Array>();
			int metas_index = 0;

			for (std::list<std::string>::iterator metas_it = rule_match->metas.begin();
					metas_it != rule_match->metas.end();
					metas_it++) {
				Local<String> meta = Nan::New((*metas_it).c_str()).ToLocalChecked();
				Nan::Set(metas, metas_index++, meta);
			}

			Local<Array> matches = Nan::New<Array>();
			int matches_index = 0;

			for (std::list<std::string>::iterator matches_it = rule_match->matches.begin();
					matches_it != rule_match->matches.end();
					matches_it++) {
				Local<String> match = Nan::New((*matches_it).c_str()).ToLocalChecked();
				Nan::Set(matches, matches_index++, match);
			}

			Local<Array> datas = Nan::New<Array>();
			int datas_index = 0;

			for (std::list<MatchData*>::iterator datas_it = rule_match->datas.begin();
					datas_it != rule_match->datas.end();
					datas_it++) {
				Local<Object> data = Nan::NewBuffer((char*) (*datas_it)->bytes, (*datas_it)->length).ToLocalChecked();
				Nan::Set(datas, datas_index++, data);
			}

			Nan::Set(rule, Nan::New("id").ToLocalChecked(), Nan::New(rule_match->id.c_str()).ToLocalChecked());
			Nan::Set(rule, Nan::New("tags").ToLocalChecked(), tags);
			Nan::Set(rule, Nan::New("metas").ToLocalChecked(), metas);
			Nan::Set(rule, Nan::New("matches").ToLocalChecked(), matches);
			Nan::Set(rule, Nan::New("datas").ToLocalChecked(), datas);

			Nan::Set(rules, rules_index++, rule);
		}

		Nan::Set(res, Nan::New("rules").ToLocalChecked(), rules);

		Local<Value> argv[2];
		argv[0] = Nan::Null();
		argv[1] = res;
		callback->Call(2, argv, async_resource);
	}

private:
	ScannerWrap* scanner_;
	ScanReq* scan_req_;
};

int scanCallback(int message, void* data, void* param) {
	AsyncScan* async_scan = (AsyncScan*) param;

	YR_RULE* rule;
	YR_META* meta;
	YR_STRING* string;
	YR_MATCH* match;
	const char* tag;
	ScanRuleMatch* rule_match;

	switch (message) {
		case CALLBACK_MSG_RULE_MATCHING:
			rule = (YR_RULE*) data;
			rule_match = new ScanRuleMatch();

			rule_match->id = rule->identifier;

			yr_rule_tags_foreach(rule, tag) {
				rule_match->tags.push_back(std::string(tag));
			}

			yr_rule_metas_foreach(rule, meta) {
				std::ostringstream oss;
				oss << meta->type << ":" << meta->identifier << ":";

				if (meta->type == META_TYPE_INTEGER)
					oss << meta->integer;
				else if (meta->type == META_TYPE_BOOLEAN)
					oss << (meta->integer ? "true" : "false");
				else
					oss << meta->string;

				rule_match->metas.push_back(oss.str());
			}

			yr_rule_strings_foreach(rule, string) {
				yr_string_matches_foreach(string, match) {
					std::ostringstream oss;
					oss << match->offset << ":" << match->match_length << ":" << string->identifier;

					if (async_scan->matched_bytes > 0) {
						MatchData* match_data = new MatchData();

						// If memory allocation fails we can't really do much
						if (match_data->copy(match->data,
								(match->data_length < async_scan->matched_bytes)
										? match->data_length
										: async_scan->matched_bytes)) {
							rule_match->datas.push_back(match_data);
						} else {
							delete match_data;
						}
					}

					rule_match->matches.push_back(oss.str());
				}
			}

			async_scan->rule_matches.push_back(rule_match);

			break;

		case CALLBACK_MSG_RULE_NOT_MATCHING:
			break;

		case CALLBACK_MSG_SCAN_FINISHED:
			break;

		case CALLBACK_MSG_IMPORT_MODULE:
			break;

		case CALLBACK_MSG_MODULE_IMPORTED:
			break;

		default:
			break;
	};

	return CALLBACK_CONTINUE;
}

NAN_METHOD(ScannerWrap::GetRules) {
	Nan::HandleScope scope;

	CompiledRuleList compiled_rules;
	CompiledRuleList::iterator compiled_rules_it;
	YR_RULE* rule;

	ScannerWrap* scanner = ScannerWrap::Unwrap<ScannerWrap>(info.This());

	yr_rules_foreach(scanner->rules, rule) {
		CompiledRule* compiled_rule;
		YR_META* meta;
		YR_STRING* rule_string;
		const char* tag;

		compiled_rule = new CompiledRule();

		compiled_rule->id = rule->identifier;

		yr_rule_tags_foreach(rule, tag) {
			compiled_rule->tags.push_back(std::string(tag));
		}

		yr_rule_metas_foreach(rule, meta) {
			std::ostringstream oss;
			oss << meta->type << ":" << meta->identifier << ":";

			if (meta->type == META_TYPE_INTEGER)
				oss << meta->integer;
			else if (meta->type == META_TYPE_BOOLEAN)
				oss << (meta->integer ? "true" : "false");
			else
				oss << meta->string;

			compiled_rule->metas.push_back(oss.str());
		}

		compiled_rules.push_back(compiled_rule);
	}

	Local<Object> res = Nan::New<Object>();

	Local<Array> rules = Nan::New<Array>();
	int rules_index = 0;

	for (CompiledRuleList::iterator compiled_rules_it = compiled_rules.begin();
			compiled_rules_it != compiled_rules.end();
			compiled_rules_it++) {
		CompiledRule* compiled_rule = *compiled_rules_it;

		Local<Object> rule = Nan::New<Object>();

		Local<Array> tags = Nan::New<Array>();
		int tags_index = 0;

		for (std::list<std::string>::iterator tags_it = compiled_rule->tags.begin();
				tags_it != compiled_rule->tags.end();
				tags_it++) {
			Local<String> tag = Nan::New((*tags_it).c_str()).ToLocalChecked();
			Nan::Set(tags, tags_index++, tag);
		}

		Local<Array> metas = Nan::New<Array>();
		int metas_index = 0;

		for (std::list<std::string>::iterator metas_it = compiled_rule->metas.begin();
				metas_it != compiled_rule->metas.end();
				metas_it++) {
			Local<String> meta = Nan::New((*metas_it).c_str()).ToLocalChecked();
			Nan::Set(metas, metas_index++, meta);
		}

		Nan::Set(rule, Nan::New("id").ToLocalChecked(), Nan::New(compiled_rule->id.c_str()).ToLocalChecked());
		Nan::Set(rule, Nan::New("tags").ToLocalChecked(), tags);
		Nan::Set(rule, Nan::New("metas").ToLocalChecked(), metas);

		Nan::Set(rules, rules_index++, rule);
	}

	Nan::Set(res, Nan::New("rules").ToLocalChecked(), rules);

	info.GetReturnValue().Set(res);
}

NAN_METHOD(ScannerWrap::Scan) {
	Nan::HandleScope scope;

	if (info.Length() < 2) {
		Nan::ThrowError("Two arguments are required");
		return;
	}

	if (! info[0]->IsObject()) {
		Nan::ThrowError("Request argument must be an object");
		return;
	}

	if (! info[1]->IsFunction()) {
		Nan::ThrowError("Callback argument must be a function");
		return;
	}

	ScannerWrap* scanner = ScannerWrap::Unwrap<ScannerWrap>(info.This());

	scanner->lock_read();
	bool rules_compiled = scanner->rules ? true : false;
	scanner->unlock();

	if (! rules_compiled) {
		Nan::ThrowError("Please call configure() before scan()");
		return;
	}

	Local<Object> req = Nan::To<Object>(info[0]).ToLocalChecked();

	char* filename = NULL;
	char *buffer = NULL;
	int64_t offset = 0;
	int64_t length = 0;
	int32_t flags = 0;
	int32_t timeout = 0;
	int32_t matched_bytes = 0;

	if (Nan::Get(req, Nan::New("filename").ToLocalChecked()).ToLocalChecked()->IsString()) {
		Local<String> s = Nan::To<String>(Nan::Get(req, Nan::New("filename").ToLocalChecked()).ToLocalChecked()).ToLocalChecked();
		filename = *Nan::Utf8String(s);
	} else if (Nan::Get(req, Nan::New("buffer").ToLocalChecked()).ToLocalChecked()->IsObject()) {
		Local<Object> o = Nan::To<Object>(Nan::Get(req, Nan::New("buffer").ToLocalChecked()).ToLocalChecked()).ToLocalChecked();
		buffer = node::Buffer::Data(o);

		if (Nan::Get(req, Nan::New("offset").ToLocalChecked()).ToLocalChecked()->IsNumber()) {
			Local<Number> n = Nan::To<Number>(Nan::Get(req, Nan::New("offset").ToLocalChecked()).ToLocalChecked()).ToLocalChecked();

			if (n->Value() < 0) {
				Nan::ThrowError("Offset is out of bounds");
				return;
			} else if (n->Value() >= node::Buffer::Length(o)) {
				Nan::ThrowError("Offset is out of bounds");
				return;
			} else {
				offset = n->Value();
			}
		} else {
			offset = 0;
		}

		if (Nan::Get(req, Nan::New("length").ToLocalChecked()).ToLocalChecked()->IsNumber()) {
			Local<Number> n = Nan::To<Number>(Nan::Get(req, Nan::New("length").ToLocalChecked()).ToLocalChecked()).ToLocalChecked();

			if (n->Value() <= 0) {
				Nan::ThrowError("Length is out of bounds");
				return;
			} else if ((n->Value() + offset) > node::Buffer::Length(o)) {
				Nan::ThrowError("Length is out of bounds");
				return;
			} else {
				length = n->Value();
			}
		} else {
			length = node::Buffer::Length(o) - offset;
		}

		if (Nan::Get(req, Nan::New("flags").ToLocalChecked()).ToLocalChecked()->IsInt32()) {
			Local<Int32> n = Nan::To<Int32>(Nan::Get(req, Nan::New("flags").ToLocalChecked()).ToLocalChecked()).ToLocalChecked();

			if (n->Value() < 0) {
				Nan::ThrowError("Flags cannot be negative");
				return;
			} else {
				flags = n->Value();
			}
		} else {
			flags = 0;
		}

		if (Nan::Get(req, Nan::New("timeout").ToLocalChecked()).ToLocalChecked()->IsInt32()) {
			Local<Int32> n = Nan::To<Int32>(Nan::Get(req, Nan::New("timeout").ToLocalChecked()).ToLocalChecked()).ToLocalChecked();

			if (n->Value() < 0) {
				Nan::ThrowError("Timeout cannot be negative");
				return;
			} else {
				timeout = n->Value();
			}
		} else {
			timeout = 0;
		}
	}

	if ((! filename) && (! buffer)) {
		Nan::ThrowError("Either filename of buffer is required");
		return;
	}

	if (Nan::Get(req, Nan::New("matchedBytes").ToLocalChecked()).ToLocalChecked()->IsNumber()) {
		Local<Number> n = Nan::To<Number>(Nan::Get(req, Nan::New("matchedBytes").ToLocalChecked()).ToLocalChecked()).ToLocalChecked();

		if (n->Value() <= 0) {
			Nan::ThrowError("Matched bytes is out of bounds");
			return;
		} else {
			matched_bytes = n->Value();
		}
	} else {
		matched_bytes = 0;
	}

	ScanReq* scan_req = new ScanReq();

	if (filename)
		scan_req->filename = filename;

	scan_req->buffer = buffer;
	scan_req->offset = offset;
	scan_req->length = length;
	scan_req->flags = flags;
	scan_req->timeout = timeout;

	Nan::Callback* callback = new Nan::Callback(info[1].As<Function>());

	AsyncScan* async_scan = new AsyncScan(
			scanner,
			scan_req,
			callback
		);

	async_scan->matched_bytes = matched_bytes;

	Nan::AsyncQueueWorker(async_scan);

	info.GetReturnValue().Set(info.This());
}

}; /* namespace yara */

#endif /* YARA_CC */
