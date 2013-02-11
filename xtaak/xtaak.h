#ifndef XTAAK_XTAAK_H_
#define XTAAK_XTAAK_H_

#include <stdlib.h>
#include <stdio.h>
#include <sys/mman.h>
#include <unistd.h>
#include <stdint.h>

#include <string>
#include <map>

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
	ERR_LABEL_IS_REDEFINED,
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
		"label is redefined",
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

class Reg {
private:
	const int8 idx_;
	const int disp_;
	const bool nilp_;
	void operator=(const Reg&);
	friend Reg operator+(const Reg& r, int disp)
	{
		return Reg(r, r.getDisp() + disp);
	}
	friend Reg operator-(const Reg& r, int disp)
	{
		return Reg(r, r.getDisp() - disp);
	}
public:
	enum Code {
		R0 = 0, R1, R2, R3, R4, R5, R6, R7, R8, R9, R10, R11, R12, R13, R14, R15,
		FP = 11, IP, SP, LR, PC,
		SPW = 13 + 32,
	};
	explicit Reg(int idx, bool nilp = false) : idx_(idx), disp_(0), nilp_(nilp)
	{
	}
	Reg(const Reg& base, int disp) : idx_(base.getIdx()), disp_(disp), nilp_(false)
	{
	}
	int getIdx() const { return idx_; }
	int getDisp() const { return disp_; }
	bool isNil() const { return nilp_; }
};

#ifndef DISABLE_VFP
class SFReg {
private:
	const int8 idx_;
	void operator=(const SFReg&);
public:
	enum Code {
		S0 = 0, S1, S2,
		FPSID = 0, FPSCR = 2, FPEXC = 4,
	};
	explicit SFReg(int idx) : idx_(idx)
	{
	}
	int getIdx() const { return idx_; }
};

class DFReg {
private:
	const int8 idx_;
	void operator=(const DFReg&);
public:
	enum Code {
		D0 = 0, D1, D2,
	};
	explicit DFReg(int idx) : idx_(idx)
	{
	}
	int getIdx() const { return idx_; }
};

#endif

class Nil : public Reg
#ifndef DISABLE_VFP
                   , SFReg, DFReg
#endif
{
public:
	Nil() : Reg(0, true)
#ifndef DISABLE_VFP
	        , SFReg(0), DFReg(0)
#endif
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
	void ddOr(uint32 code, const uint32 *addr)
	{
		size_t idx = addr - top_;
		if (idx >= size_) { throw ERR_INTERNAL; }
		top_[idx] |= code;
	}
};

class Offset {
	const int bitOffset_;
	const uint32 bitLen_;
	const uint32 sign_;
	const uint32 *base_;
public:
	Offset(int bitOffset, uint32 bitLen, uint32 sign, const uint32 *base)
		: bitOffset_(bitOffset)
		, bitLen_(bitLen)
		, sign_(sign)
		, base_(base)
	{
	}
	uint32 getImm(const uint32 *addr) const
	{
		int imm = (addr - base_) * 4 - 8;
		uint32 sign = sign_;
		if (sign) {
			if (imm < 0) {
				imm = -imm;
				sign = 0;
			}
			if (imm >= 1 << bitLen_) { throw ERR_IMM_IS_TOO_BIG; }
			return imm << bitOffset_ | sign;
		} else {
			sign = (1 << bitLen_) - 1;
			if (imm < -(int)(sign / 2) - 1 || imm > (int)(sign / 2)) {
				throw ERR_IMM_IS_TOO_BIG;
			}
			if (bitOffset_ < 0) {
				imm >>= -bitOffset_;
			} else {
				imm <<= bitOffset_;
			}
			return imm & sign;
		}
	}
	const uint32 *getBase() const
	{
		return base_;
	}
};

class Label {
	typedef std::map<std::string, const uint32 *> LabelTable;
	typedef std::multimap<std::string, const Offset> OffsetTable;
	LabelTable labelTable_;
	OffsetTable offsetTable_;
	uint32 anonymousCount_;
public:
	Label()
		: anonymousCount_(0)
	{
	}
	void define(const char *label, const uint32 *addr, CodeArray *code)
	{
		std::string labelStr(label);
		if (labelStr == "@@") {
			labelStr += toStr(++anonymousCount_);
		}
		std::pair<LabelTable::iterator, bool> ret = labelTable_.insert(LabelTable::value_type(labelStr, addr));
		OffsetTable::iterator itr;
		OffsetTable::iterator tail = offsetTable_.end();
		for(itr = offsetTable_.find(labelStr); itr != tail; itr++) {
			code->ddOr(itr->second.getImm(addr), itr->second.getBase());
		}
		offsetTable_.erase(labelStr);
	}
	uint32 getOffset(const char *label, int bitOffset, uint32 bitLen,
	                 uint32 sign, const uint32 *base)
	{
		std::string labelStr(label);
		Offset offset(bitOffset, bitLen, sign, base);
		if (labelStr == "@f" || labelStr == "@F") {
			labelStr = std::string("@@") + toStr(anonymousCount_ + 1);
		} else if (labelStr == "@b" || labelStr == "@B") {
			labelStr = std::string("@@") + toStr(anonymousCount_);
		}
		LabelTable::iterator itr = labelTable_.find(labelStr);
		LabelTable::iterator tail = labelTable_.end();
		if (itr != tail) { return offset.getImm(itr->second); }
		offsetTable_.insert(OffsetTable::value_type(labelStr, offset));
		return 0;
	}
	static inline std::string toStr(int num)
	{
		char buf[16];
		snprintf(buf, sizeof(buf), ".%08x", num);
		return buf;
	}
};

class CodeGenerator : public CodeArray {
public:
	enum Cond {
		NOCOND = -1, EQ = 0, NE, CS, CC, MI, PL, VS, VC, HI, LS, GE, LT, GT, LE, AL,
	};
private:
	Label label_;
	uint32 getOffset(const char *label, int bitOffset, uint32 bitLen,
	                 uint32 sign = 0, const uint32 *base = NULL)
	{
		return label_.getOffset(label, bitOffset, bitLen, sign,
		                        base ? base : getCurr());
	}
	void op(uint32 opcode, const Reg& regD, const Reg &regN,
	        const Reg &regM)
	{
		uint32 type = 0, imm = 0; // Todo
		if (imm > 31) { throw ERR_IMM_IS_TOO_BIG; }
		dd(cond_ << 28 | opcode << 20 | regN.getIdx() << 16 |
		   regD.getIdx() << 12 | imm << 7 | type << 5 | regM.getIdx());
	}
	void op(uint32 opcode, const Reg& regD, const Reg &regN,
	        uint32 imm)
	{
		imm = inner::getShifterImm(imm);
		if (!imm >= 0x1000) { throw ERR_IMM_IS_TOO_BIG; }
		dd(cond_ << 28 | opcode << 20 | regN.getIdx() << 16 |
		   regD.getIdx() << 12 | imm);
	}
	void op(uint32 opcode, const Reg& regD, uint32 imm)
	{
		if (!inner::IsInUint16(imm)) { throw ERR_IMM_IS_TOO_BIG; }
		dd(cond_ << 28 | opcode << 20 | (imm & 0xf000) << 4 |
		   regD.getIdx() << 12 | (imm & 0xfff));
	}
	void opMem(uint32 opcode, const Reg& regD, const Reg& regN)
	{
		uint32 u = 1 << 23;
		int imm = regN.getDisp();
		if (imm < 0)  {
			imm = -imm;
			u = 0;
		}
		if (imm >= 0x1000) { throw ERR_IMM_IS_TOO_BIG; }
		dd(cond_ << 28 | opcode << 20 | u | regN.getIdx() << 16 |
		   regD.getIdx() << 12 | imm);
	}
	void opMem(uint32 opcode, const Reg& regD, const char *label)
	{
		uint32 imm = getOffset(label, 0, 12, 1 << 23);
		dd(cond_ << 28 | opcode << 20 | pc.getIdx() << 16 |
		   regD.getIdx() << 12 | imm);
	}
	void opMem(uint32 opcode, const Reg& regN, const Reg *regs)
	{
		uint32 bits = 0;
		while (!regs->isNil()) { bits |= 1 << (regs++)->getIdx(); }
		dd(cond_ << 28 | opcode << 20 | regN.getIdx() << 16 | bits);
	}
	void opJmp(const int32 imm, Cond cond = NOCOND, bool l = false)
	{
		if (imm < -0x800000 || imm > 0x7fffff) { throw ERR_IMM_IS_TOO_BIG; }
		if (cond == NOCOND) { cond = cond_; }
		dd(cond << 28 | 0xa000000 | (l ? 1 << 24 : 0) |
		   ((const uint32)imm & 0xffffff));
	}
	void opJmp(const char *label, Cond cond = NOCOND, bool l = false)
	{
		if (cond == NOCOND) { cond = cond_; }
		uint32 imm = getOffset(label, -2, 24);
		dd(cond << 28 | 0xa000000 | (l ? 1 << 24 : 0) | imm);
	}
public:
	const static Nil nil;
	const Reg r0, r1, r2, r3, r4, r5, r6, r7, r8, r9, r10, r11, r12, r13, r14, r15;
	const Reg fp, ip, sp, lr, pc, spW;
	Cond cond_;
#ifndef DISABLE_VFP
	const SFReg s0, s1, s2;
	const DFReg d0, d1, d2;
	const SFReg fpscr;
#endif
	void L(const char *label)
	{
		label_.define(label, getCurr(), this);
	}
	void setCond(const Cond cond)
	{
		cond_ = cond;
	}
	void mov(const Reg& reg1, const Reg& reg2)
	{
		op(0x1a, reg1, nil, reg2);
	}
	void movw(const Reg& reg, const uint32 imm)
	{
		op(0x30, reg, imm);
	}
	void movt(const Reg& reg, const uint32 imm)
	{
		op(0x34, reg, imm);
	}
	void mov32(const Reg& reg, const uint32 imm)
	{
		movw(reg, imm & 0xffff);
		movt(reg, imm >> 16);
	}
	void add(const Reg& reg1, const Reg& reg2, const Reg& reg3)
	{
		op(0x08, reg1, reg2, reg3);
	}
	void add(const Reg& reg1, const Reg& reg2, uint32 imm)
	{
		op(0x28, reg1, reg2, imm);
	}
	void adds(const Reg& reg1, const Reg& reg2, const Reg& reg3)
	{
		op(0x09, reg1, reg2, reg3);
	}
	void adds(const Reg& reg1, const Reg& reg2, uint32 imm)
	{
		op(0x29, reg1, reg2, imm);
	}
	void sub(const Reg& reg1, const Reg& reg2, uint32 imm)
	{
		op(0x24, reg1, reg2, imm);
	}
	void subs(const Reg& reg1, const Reg& reg2, uint32 imm)
	{
		op(0x25, reg1, reg2, imm);
	}
	void cmp(const Reg& reg1, const Reg& reg2)
	{
		op(0x15, nil, reg1, reg2);
	}
	void cmp(const Reg& reg, uint32 imm)
	{
		op(0x35, nil, reg, imm);
	}
	void ldr(const Reg& reg1, const Reg& reg2)
	{
		opMem(0x51, reg1, reg2);
	}
	void ldr(const Reg& reg, const char *label)
	{
		opMem(0x51, reg, label);
	}
	void str(const Reg& reg1, const Reg& reg2)
	{
		opMem(0x50, reg1, reg2);
	}
	void ldm(const Reg& reg1, const Reg& reg2,
	         const Reg& reg3 = nil, const Reg& reg4 = nil,
	         const Reg& reg5 = nil)
	{
		const Reg regs[] = {reg2, reg3, reg4, reg5, nil};
		opMem(0x89, reg1, regs);
	}
	void ldmda(const Reg& reg1, const Reg& reg2,
	           const Reg& reg3 = nil, const Reg& reg4 = nil,
	           const Reg& reg5 = nil)
	{
		const Reg regs[] = {reg2, reg3, reg4, reg5, nil};
		opMem(0x81, reg1, regs);
	}
	void pop(const Reg& reg1, const Reg& reg2 = nil,
	         const Reg& reg3 = nil, const Reg& reg4 = nil,
	         const Reg& reg5 = nil, const Reg& reg6 = nil)
	{
		const Reg regs[] = {reg1, reg2, reg3, reg4, reg5, reg6, nil};
		opMem(0x8b, sp, regs);
	}
	void stm(const Reg& reg1, const Reg& reg2,
	         const Reg& reg3 = nil, const Reg& reg4 = nil,
	         const Reg& reg5 = nil)
	{
		const Reg regs[] = {reg2, reg3, reg4, reg5, nil};
		opMem(0x88, reg1, regs);
	}
	void push(const Reg& reg1, const Reg& reg2 = nil,
	          const Reg& reg3 = nil, const Reg& reg4 = nil,
	          const Reg& reg5 = nil, const Reg& reg6 = nil)
	{
		const Reg regs[] = {reg1, reg2, reg3, reg4, reg5, reg6, nil};
		opMem(0x92, sp, regs);
	}
	void b(const int32 imm)
	{
		opJmp(imm);
	}
	void b(const void *addr)
	{
		opJmp(((int32)addr - (int32)getCurr() - 8) >> 2);
	}
	void bl(const void *addr)
	{
		opJmp(((int32)addr - (int32)getCurr() - 8) >> 2, NOCOND, true);
	}
	void bcc(const int imm)
	{
		opJmp(imm, CC);
	}
	void bcc(const void *addr)
	{
		opJmp(((int32)addr - (int32)getCurr() - 8) >> 2, CC);
	}
	void bcc(const char *label)
	{
		opJmp(label, CC);
	}
	void beq(const int imm)
	{
		opJmp(imm, EQ);
	}
	void beq(const void *addr)
	{
		opJmp(((int32)addr - (int32)getCurr() - 8) >> 2, EQ);
	}
	void beq(const char *label)
	{
		opJmp(label, EQ);
	}
	void bne(const int imm)
	{
		opJmp(imm, NE);
	}
	void bne(const void *addr)
	{
		opJmp(((int32)addr - (int32)getCurr() - 8) >> 2, NE);
	}
	void bne(const char *label)
	{
		opJmp(label, NE);
	}
	void bvc(const int imm)
	{
		opJmp(imm, VC);
	}
	void bvc(const void *addr)
	{
		opJmp(((int32)addr - (int32)getCurr() - 8) >> 2, VC);
	}
	void bvc(const char *label)
	{
		opJmp(label, VC);
	}
#ifndef DISABLE_VFP
	void fop(uint32 opcode, const DFReg& dregD, const DFReg& dregN, const DFReg& dregM)
	{
		dd(cond_ << 28 | 0xe000b00 | (opcode >> 4) << 20 |
		   dregN.getIdx() << 16 | dregD.getIdx() << 12 |
		   (opcode & 0xf) << 4 | dregM.getIdx());
	}
	void fop(uint32 opcode, const SFReg& sregN, const Reg& regD)
	{
		dd(cond_ << 28 | 0xe000a10 | opcode << 20 |
		   (sregN.getIdx() >> 1) << 16 | regD.getIdx() << 12 |
		   (sregN.getIdx() & 1) << 7);
	}
	void fopExt(uint32 opcode, const DFReg& dregD, const DFReg& dregM)
	{
		dd(cond_ << 28 | 0xeb00b00 | (opcode >> 4) << 16 |
		   dregD.getIdx() << 12 | (opcode & 0xf) << 4 | dregM.getIdx());
	}
	void fopExt(uint32 opcode, const DFReg& dregD, const SFReg& sregM)
	{
		dd(cond_ << 28 | 0xeb00b00 | (opcode >> 4) << 16 |
		   dregD.getIdx() << 12 | (opcode & 0xf) << 4 |
		   (sregM.getIdx() & 1) << 5 | (sregM.getIdx() >> 1));
	}
	void fopMem(uint32 opcode, const SFReg& sregD, const Reg& regN)
	{
		int disp = regN.getDisp();
		uint32 offset = 0x800000 | disp;
		dd(cond_ << 28 | 0xc000a00 | opcode << 20 |
		   (sregD.getIdx() & 1) << 23 | regN.getIdx() << 16 |
		   (sregD.getIdx() >> 1) << 12 | offset);
	}
	void fopMem(uint32 opcode, const DFReg& dregD, const Reg& regN)
	{
		int disp = regN.getDisp();
		uint32 offset = 0x800000 | disp;
		dd(cond_ << 28 | 0xc000b00 | opcode << 20 |
		   regN.getIdx() << 16 | dregD.getIdx() << 12 | offset);
	}
	void faddd(const DFReg& dreg1, const DFReg& dreg2, const DFReg& dreg3)
	{
		fop(0x30, dreg1, dreg2, dreg3);
	}
	void fsubd(const DFReg& dreg1, const DFReg& dreg2, const DFReg& dreg3)
	{
		fop(0x34, dreg1, dreg2, dreg3);
	}
	void fcmpd(const DFReg& dreg1, const DFReg& dreg2)
	{
		fopExt(0x44, dreg1, dreg2);
	}
	void fmsr(const SFReg& sreg, const Reg& reg)
	{
		fop(0x0, sreg, reg);
	}
	void fmstat()
	{
		fop(0xf, fpscr, r15);
	}
	void fsitod(const DFReg& dreg, const SFReg& sreg)
	{
		fopExt(0x8c, dreg, sreg);
	}
	void flds(const SFReg& sreg, const Reg& reg)
	{
		fopMem(0x11, sreg, reg);
	}
	void fldd(const DFReg& dreg, const Reg& reg)
	{
		fopMem(0x11, dreg, reg);
	}
	void fstd(const DFReg& dreg, const Reg& reg)
	{
		fopMem(0x10, dreg, reg);
	}
#endif
public:
	CodeGenerator(size_t maxSize = DEFAULT_MAX_CODE_SIZE, void *userPtr = 0, Allocator *allocator = 0)
		: CodeArray(maxSize, userPtr, allocator), cond_(AL)
		, fp(Reg::FP), ip(Reg::IP), sp(Reg::SP)
		, lr(Reg::LR), pc(Reg::PC), spW(Reg::SPW)
		, r0(0), r1(1), r2(2), r3(3), r4(4), r5(5), r6(6), r7(7), r8(8), r9(9), r10(10), r11(11), r12(12), r13(13), r14(14), r15(15)
#ifndef DISABLE_VFP
		, s0(0), s1(1), s2(2)
		, d0(0), d1(1), d2(2)
		, fpscr(SFReg::FPSCR)
#endif
	{
	}
};
const Nil CodeGenerator::nil = Nil();

} // end of namespace

#endif // XTAAK_XTAAK_H_
