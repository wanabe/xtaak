#ifndef XTAAK_XTAAK_H_
#define XTAAK_XTAAK_H_

#include <stdlib.h>
#include <stdio.h>
#include <sys/mman.h>
#include <unistd.h>
#include <stdint.h>

namespace Xtaak {

enum {
	DEFAULT_MAX_CODE_SIZE = 4096,
	VERSION = 0x0010 /* 0xABCD = A.BC(D) */
};

#ifndef MIE_INTEGER_TYPE_DEFINED
#define MIE_INTEGER_TYPE_DEFINED
typedef uint8_t uint8;
typedef uint32_t uint32;
#endif

enum Error {
	ERR_NONE = 0,
	ERR_BAD_COMBINATION,
	ERR_IMM_IS_TOO_BIG,
	ERR_CANT_PROTECT,
	ERR_CANT_ALLOC,
	ERR_NOT_IMPL,
	ERR_INTERNAL
};

inline const char *ConvertErrorToString(Error err)
{
	static const char *errTbl[] = {
		"none",
		"bad combination",
		"imm is too big",
		"can't protect",
		"can't alloc",
		"not implemented yet",
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
	virtual uint32 *alloc(size_t size) { return reinterpret_cast<uint32*>(AlignedMalloc(size * sizeof(uint32), inner::ALIGN_PAGE_SIZE)); }
	virtual void free(uint32 *p) { AlignedFree(p); }
	virtual ~Allocator() {}
	/* override to return false if you call protect() manually */
	virtual bool useProtect() const { return true; }
};

class Operand {
private:
	const uint8 idx_;
	const uint8 kind_;
public:
	enum Kind {
		NONE = 0,
		REG = 1 << 1,
	};
	enum Code {
		FP = 11, IP, SP, LR, PC,
		SPW = 13 + 32,
	};
	Operand() : idx_(0), kind_(0) { }
	Operand(int idx, Kind kind)
		: idx_(static_cast<uint8>(idx))
		, kind_(static_cast<uint8>(kind))
	{
	}
	int getIdx() const { return idx_; }
	bool isREG() const { return is(REG); }
	// any bit is accetable if bit == 0
	bool is(int kind) const
	{
		return (kind_ & kind);
	}
};

class Reg : public Operand {
public:
	explicit Reg(int idx) : Operand(idx, Operand::REG) {}
private:
	void operator=(const Reg&);
};

// 2nd parameter for constructor of CodeArray(maxSize, userPtr, alloc)
void *const AutoGrow = (void*)1;

class CodeArray {
	enum {
		MAX_FIXED_BUF_SIZE = 8
	};
	enum Type {
		FIXED_BUF, // use buf_(non alignment, non protect)
		USER_BUF, // use userPtr(non alignment, non protect)
		ALLOC_BUF, // use new(alignment, protect)
		AUTO_GROW // automatically move and grow memory if necessary
	};
	bool isAllocType() const { return type_ == ALLOC_BUF || type_ == AUTO_GROW; }
	Type getType(size_t maxSize, void *userPtr) const
	{
		if (userPtr == AutoGrow) return AUTO_GROW;
		if (userPtr) return USER_BUF;
		if (maxSize <= MAX_FIXED_BUF_SIZE) return FIXED_BUF;
		return ALLOC_BUF;
	}
	const Type type_;
	Allocator defaultAllocator_;
	Allocator *alloc_;
	uint32 buf_[MAX_FIXED_BUF_SIZE]; // for FIXED_BUF
protected:
	size_t maxSize_;
	uint32 *top_;
	size_t size_;

public:
	CodeArray(size_t maxSize = MAX_FIXED_BUF_SIZE, void *userPtr = 0, Allocator *allocator = 0)
	: type_(getType(maxSize, userPtr))
	, alloc_(allocator ? allocator : &defaultAllocator_)
	, maxSize_(maxSize)
	, top_(isAllocType() ? alloc_->alloc(maxSize) : type_ == USER_BUF ? reinterpret_cast<uint32*>(userPtr) : buf_)
	, size_(0)
	{
		if (maxSize_ > 0 && top_ == 0) throw ERR_CANT_ALLOC;
		if ((type_ == ALLOC_BUF && alloc_->useProtect()) && !protect(top_, maxSize, true)) {
			alloc_->free(top_);
			throw ERR_CANT_PROTECT;
		}
	}
	virtual ~CodeArray()
	{
		if (isAllocType()) {
			if (alloc_->useProtect()) protect(top_, maxSize_, false);
			alloc_->free(top_);
		}
	}
	const uint32 *getCurr() const { return &top_[size_]; }
	static inline bool protect(const void *addr, size_t size, bool canExec)
	{
		size_t pageSize = sysconf(_SC_PAGESIZE);
		size_t iaddr = reinterpret_cast<size_t>(addr);
		size_t roundAddr = iaddr & ~(pageSize - static_cast<size_t>(1));
		int mode = PROT_READ | PROT_WRITE | (canExec ? PROT_EXEC : 0);
		return mprotect(reinterpret_cast<void*>(roundAddr), size * sizeof(uint32) + (iaddr - roundAddr), mode) == 0;
	}
};

class CodeGenerator : public CodeArray {
public:
	const Reg fp, ip, sp, lr, pc, spW;
	void mov(const Operand& reg1, const Operand& reg2)
	{
		if (reg1.isREG() && reg1.getIdx() == Operand::PC &&
		    reg2.isREG() && reg2.getIdx() == Operand::LR) {
			top_[size_++] = 0xe1a0f00e;
		} else {
			throw ERR_NOT_IMPL;
		}
	}
public:
	CodeGenerator(size_t maxSize = DEFAULT_MAX_CODE_SIZE, void *userPtr = 0, Allocator *allocator = 0)
		: CodeArray(maxSize, userPtr, allocator)
		, fp(Operand::FP), ip(Operand::IP), sp(Operand::SP)
		, lr(Operand::LR), pc(Operand::PC), spW(Operand::SPW)
	{
	}
};

} // end of namespace

#endif // XTAAK_XTAAK_H_
