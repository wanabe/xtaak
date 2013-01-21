#ifndef XTAAK_XTAAK_H_
#define XTAAK_XTAAK_H_

#include <stdlib.h>
#include <stdio.h>

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

struct Allocator {
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
