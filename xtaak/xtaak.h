#ifndef XTAAK_XTAAK_H_
#define XTAAK_XTAAK_H_

#include <stdlib.h>
#include <stdio.h>
#include <sys/mman.h>
#include <unistd.h>

namespace Xtaak {

enum {
	DEFAULT_MAX_CODE_SIZE = 4096,
	VERSION = 0x0010 /* 0xABCD = A.BC(D) */
};

#ifndef MIE_INTEGER_TYPE_DEFINED
#define MIE_INTEGER_TYPE_DEFINED
typedef unsigned char uint8;
#endif

enum Error {
	ERR_NONE = 0,
	ERR_CANT_PROTECT,
	ERR_CANT_ALLOC,
	ERR_INTERNAL
};

inline const char *ConvertErrorToString(Error err)
{
	static const char *errTbl[] = {
		"none",
		"can't protect",
		"can't alloc",
		"internal error",
	};
	if (err < 0 || err > ERR_INTERNAL) return 0;
	return errTbl[err];
}

inline void *AlignedMalloc(size_t size, size_t alignment)
{
#ifdef __ANDROID__
	return memalign(size, alignment);
#else
	void *p;
	int ret = posix_memalign(&p, alignment, size);
	return (ret == 0) ? p : 0;
#endif
}

inline void AlignedFree(void *p)
{
	free(p);
}

namespace inner {

enum { debug = 1 };
static const size_t ALIGN_PAGE_SIZE = 4096;

} // inner

/*
	custom allocator
*/
struct Allocator {
	virtual uint8 *alloc(size_t size) { return reinterpret_cast<uint8*>(AlignedMalloc(size, inner::ALIGN_PAGE_SIZE)); }
	virtual void free(uint8 *p) { AlignedFree(p); }
	virtual ~Allocator() {}
	/* override to return false if you call protect() manually */
	virtual bool useProtect() const { return true; }
};

class Operand {
public:
	enum Code {
		FP = 11, IP, SP, LR, PC,
		SPW = 13 + 32,
	};
};

class Reg : public Operand {
public:
	explicit Reg(int idx) {}
private:
	void operator=(const Reg&);
};

class CodeArray {
	enum {
		MAX_FIXED_BUF_SIZE = 8
	};
protected:
	size_t maxSize_;
	uint8 *top_;
	size_t size_;

public:
	CodeArray(size_t maxSize = MAX_FIXED_BUF_SIZE, void *userPtr = 0, Allocator *allocator = 0)
	{
	}
	const uint8 *getCurr() const { return &top_[size_]; }
};

class CodeGenerator : public CodeArray {
public:
	CodeGenerator(size_t maxSize = DEFAULT_MAX_CODE_SIZE, void *userPtr = 0, Allocator *allocator = 0)
		: CodeArray(maxSize, userPtr, allocator)
	{
	}
};

} // end of namespace

#endif // XTAAK_XTAAK_H_
