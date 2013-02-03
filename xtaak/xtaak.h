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
typedef int8_t int8;
typedef int32_t int32;
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
	return memalign(alignment, size);
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

inline bool IsInUint16(uint32 x) { return x <= 0xffff; }
inline bool IsInUint8(uint32 x) { return x <= 0xff; }
uint32 getShifterImm(uint32 x) {
	uint32 shift = 0;
	while(x > 0xff && shift < 0x1000) {
		x = (x >> 30) | (x << 2);
		shift += 0x100;
	}
	return shift | x;
}

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
	const int8 idx_;
	const uint8 kind_;
	const uint32 disp_;
public:
	enum Kind {
		NONE = 0,
		REG = 1 << 1,
		SFR = 1 << 2,
		DFR = 1 << 3,
	};
	enum Code {
		R0 = 0, R1, R2, R3, R4, R5, R6, R7, R8, R9, R10, R11, R12, R13, R14, R15,
		FP = 11, IP, SP, LR, PC,
		SPW = 13 + 32,
		D0 = 0, D1, D2,
		S0 = 0, S1, S2,
	};
	Operand() : idx_(0), kind_(0), disp_(0) { }
	Operand(int idx, Kind kind, uint32 disp)
		: idx_(static_cast<uint8>(idx))
		, kind_(static_cast<uint8>(kind)), disp_(disp)
	{
	}
	int getIdx() const { return idx_; }
	uint32 getDisp() const { return disp_; }
	bool isREG() const { return is(REG); }
	bool isSFR() const { return is(SFR); }
	bool isDFR() const { return is(DFR); }
	// any bit is accetable if bit == 0
	bool is(int kind) const
	{
		return (kind_ & kind);
	}
};

class Reg : public Operand {
private:
	void operator=(const Reg&);
	friend Reg operator+(const Reg& r, unsigned int disp)
	{
		return Reg(r, r.getDisp() + disp);
	}
public:
	explicit Reg(int idx) : Operand(idx, Operand::REG, 0)
	{
	}
	Reg(const Reg& base, unsigned int disp) : Operand(base.getIdx(), Operand::REG, disp)
	{
	}
};

class SFReg : public Operand {
private:
	void operator=(const SFReg&);
public:
	explicit SFReg(int idx) : Operand(idx, Operand::SFR, 0)
	{
	}
};

class DFReg : public Operand {
private:
	void operator=(const DFReg&);
public:
	explicit DFReg(int idx) : Operand(idx, Operand::DFR, 0)
	{
	}
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
	void dd(uint32 code)
	{
		top_[size_++] = code;
	}
};

class CodeGenerator : public CodeArray {
public:
	const Reg r0, r1, r2, r3, r4, r5, r6, r7, r8, r9, r10, r11, r12, r13, r14, r15;
	const Reg fp, ip, sp, lr, pc, spW;
	const SFReg s0, s1, s2;
	const DFReg d0, d1, d2;
	void mov(const Operand& reg1, const Operand& reg2)
	{
		if (reg1.isREG() && reg1.getIdx() == Operand::PC &&
		    reg2.isREG() && reg2.getIdx() == Operand::LR) {
			dd(0xe1a0f00e);
		} else {
			throw ERR_NOT_IMPL;
		}
	}
	void ldr(const Operand& reg1, const Operand& reg2)
	{
		if (reg1.isREG() && reg2.isREG()) {
			dd(0xe5900000 | reg2.getIdx() << 16
			   | reg1.getIdx() << 12| reg2.getDisp());
		} else {
			throw ERR_NOT_IMPL;
		}
	}
	void str(const Operand& reg1, const Operand& reg2)
	{
		if (reg1.isREG() && reg2.isREG()) {
			dd(0xe5800000 | reg2.getIdx() << 16
			   | reg1.getIdx() << 12| reg2.getDisp());
		} else {
			throw ERR_NOT_IMPL;
		}
	}
	void movw(const Operand& reg, const uint32 imm)
	{
		if (!reg.isREG()) { throw ERR_BAD_COMBINATION; }
		if (!inner::IsInUint16(imm)) { throw ERR_IMM_IS_TOO_BIG; }
		dd(0xe3000000 | (imm & 0xf000) << 4 | reg.getIdx() << 12
		   | (imm & 0xfff));
	}
	void movt(const Operand& reg, const uint32 imm)
	{
		if (!reg.isREG()) { throw ERR_BAD_COMBINATION; }
		if (!inner::IsInUint16(imm)) { throw ERR_IMM_IS_TOO_BIG; }
		dd(0xe3400000 | (imm & 0xf000) << 4 | reg.getIdx() << 12
		   | (imm & 0xfff));
	}
	void mov32(const Operand& reg, const uint32 imm)
	{
		movw(reg, imm & 0xffff);
		movt(reg, imm >> 16);
	}
	void add(const Operand& reg1, const Operand& reg2, const Operand& reg3)
	{
		if (!reg1.isREG() || !reg2.isREG()) { throw ERR_BAD_COMBINATION; }
		if (!reg3.isREG() || reg3.getDisp() != 0) { throw ERR_NOT_IMPL; }
		dd(0xe0800000 | reg2.getIdx() << 16 | reg1.getIdx() << 12
		   | reg3.getIdx());
	}
	void add(const Operand& reg1, const Operand& reg2, uint32 imm)
	{
		if (!reg1.isREG() || !reg2.isREG()) { throw ERR_BAD_COMBINATION; }
		imm = inner::getShifterImm(imm);
		if (!imm > 0x1000) { throw ERR_IMM_IS_TOO_BIG; }
		dd(0xe2800000 | reg2.getIdx() << 16 | reg1.getIdx() << 12
		   | imm);
	}
	void adds(const Operand& reg1, const Operand& reg2, const Operand& reg3)
	{
		if (!reg1.isREG() || !reg2.isREG()) { throw ERR_BAD_COMBINATION; }
		if (!reg3.isREG() || reg3.getDisp() != 0) { throw ERR_NOT_IMPL; }
		dd(0xe0900000 | reg2.getIdx() << 16 | reg1.getIdx() << 12
		   | reg3.getIdx());
	}
	void adds(const Operand& reg1, const Operand& reg2, uint32 imm)
	{
		if (!reg1.isREG() || !reg2.isREG()) { throw ERR_BAD_COMBINATION; }
		imm = inner::getShifterImm(imm);
		if (!imm > 0x1000) { throw ERR_IMM_IS_TOO_BIG; }
		dd(0xe2900000 | reg2.getIdx() << 16 | reg1.getIdx() << 12
		   | imm);
	}
	void cmp(const Operand& reg, uint32 imm)
	{
		if (!reg.isREG()) { throw ERR_BAD_COMBINATION; }
		imm = inner::getShifterImm(imm);
		if (!imm > 0x1000) { throw ERR_IMM_IS_TOO_BIG; }
		dd(0xe3500000 | reg.getIdx() << 16 | imm);
	}
	void ldm(const Operand& reg1, const Operand& reg2,
	         const Operand& reg3 = Reg(-1), const Operand& reg4 = Reg(-1),
	         const Operand& reg5 = Reg(-1))
	{
		uint32 bits = 0;
		bits |= 1 << reg2.getIdx();
		if (reg3.getIdx() != -1) { bits |= 1 << reg3.getIdx(); }
		if (reg4.getIdx() != -1) { bits |= 1 << reg4.getIdx(); }
		if (reg5.getIdx() != -1) { bits |= 1 << reg5.getIdx(); }
		dd(0xe8900000 | reg1.getIdx() << 16 | bits);
	}
	void stm(const Operand& reg1, const Operand& reg2,
	         const Operand& reg3 = Reg(-1), const Operand& reg4 = Reg(-1),
	         const Operand& reg5 = Reg(-1))
	{
		uint32 bits = 0;
		bits |= 1 << reg2.getIdx();
		if (reg3.getIdx() != -1) { bits |= 1 << reg3.getIdx(); }
		if (reg4.getIdx() != -1) { bits |= 1 << reg4.getIdx(); }
		if (reg5.getIdx() != -1) { bits |= 1 << reg5.getIdx(); }
		dd(0xe8800000 | reg1.getIdx() << 16 | bits);
	}
	void b(const int32 imm)
	{
		if (imm < -0x800000 || imm > 0x7fffff) { throw ERR_IMM_IS_TOO_BIG; }
		dd(0xea000000 | ((const uint32)imm & 0xffffff));
	}
	void b(const void *addr)
	{
		b(((int32)addr - (int32)getCurr() - 8) >> 2);
	}
	void bcc(const int imm)
	{
		if (imm < -0x800000 || imm > 0x7fffff) { throw ERR_IMM_IS_TOO_BIG; }
		dd(0x3a000000 | ((const uint32)imm & 0xffffff));
	}
	void bcc(const void *addr)
	{
		bcc(((int32)addr - (int32)getCurr() - 8) >> 2);
	}
	void beq(const int imm)
	{
		if (imm < -0x800000 || imm > 0x7fffff) { throw ERR_IMM_IS_TOO_BIG; }
		dd(0x0a000000 | ((const uint32)imm & 0xffffff));
	}
	void beq(const void *addr)
	{
		beq(((int32)addr - (int32)getCurr() - 8) >> 2);
	}
	void bvc(const int imm)
	{
		if (imm < -0x800000 || imm > 0x7fffff) { throw ERR_IMM_IS_TOO_BIG; }
		dd(0x7a000000 | ((const uint32)imm & 0xffffff));
	}
	void bvc(const void *addr)
	{
		bvc(((int32)addr - (int32)getCurr() - 8) >> 2);
	}
#ifndef DISABLE_VFP
	void fmsr(const Operand& sreg, const Operand& reg)
	{
		dd(0xee000a10 | (sreg.getIdx() >> 1) << 16 |
		   reg.getIdx() << 12 | (sreg.getIdx() & 1) << 7);
	}
	void fsitod(const Operand& dreg, const Operand& sreg)
	{
		dd(0xeeb80bc0 | dreg.getIdx() << 12 |
		   (sreg.getIdx() & 1) << 5 | (sreg.getIdx() >> 1));
	}
	void fstd(const Operand& dreg, const Operand& reg)
	{
		uint32 disp = reg.getDisp();
		uint32 offset = 0x800000 | disp;
		dd(0xed000b00 | reg.getIdx() << 16 |
		   dreg.getIdx() << 12 | offset);
	}
#endif
public:
	CodeGenerator(size_t maxSize = DEFAULT_MAX_CODE_SIZE, void *userPtr = 0, Allocator *allocator = 0)
		: CodeArray(maxSize, userPtr, allocator)
		, fp(Operand::FP), ip(Operand::IP), sp(Operand::SP)
		, lr(Operand::LR), pc(Operand::PC), spW(Operand::SPW)
		, r0(0), r1(1), r2(2), r3(3), r4(4), r5(5), r6(6), r7(7), r8(8), r9(9), r10(10), r11(11), r12(12), r13(13), r14(14), r15(15)
#ifndef DISABLE_VFP
		, s0(0), s1(1), s2(2)
		, d0(0), d1(1), d2(2)
#endif
	{
	}
};

} // end of namespace

#endif // XTAAK_XTAAK_H_
