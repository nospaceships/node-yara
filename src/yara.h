#ifndef YARA_H
#define YARA_H

#include <pthread.h>

#include <nan.h>

#include <yara.h>

using namespace v8;

namespace yara {

void ExportConstants(Handle<Object> target);
void ExportFunctions(Handle<Object> target);

NAN_METHOD(ErrorCodeToString);
NAN_METHOD(LibyaraVersion);
NAN_METHOD(Initialize);

class ScannerWrap : public Nan::ObjectWrap {
public:
	static void Init(Handle<Object> exports);

	void lock_read(void);
	void lock_write(void);
	void unlock(void);

	YR_COMPILER* compiler;
	YR_RULES* rules;

private:
	ScannerWrap();
	~ScannerWrap();

	static NAN_METHOD(New);
	static NAN_METHOD(Configure);
	static NAN_METHOD(Scan);

	pthread_rwlock_t lock;
};

}; /* namespace yara */

#endif /* YARA_H */
