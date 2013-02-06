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
	const int disp_;
public:
	enum Kind {
		NIL = 0,
		REG = 1 << 1,
		SFR = 1 << 2,
		DFR = 1 << 3,
		SYSFR = 1 << 4,
	};
	enum Code {
		R0 = 0, R1, R2, R3, R4, R5, R6, R7, R8, R9, R10, R11, R12, R13, R14, R15,
		FP = 11, IP, SP, LR, PC,
		SPW = 13 + 32,
		D0 = 0, D1, D2,
		S0 = 0, S1, S2,
		FPSID = 0, FPSCR = 2, FPEXC = 4,
	};
	Operand() : idx_(0), kind_(0), disp_(0) { }
	Operand(int idx, Kind kind, uint32 disp)
		: idx_(static_cast<uint8>(idx))
		, kind_(static_cast<uint8>(kind)), disp_(disp)
	{
	}
	int getIdx() const { return idx_; }
	int getDisp() const { return disp_; }
	bool isREG() const { return is(REG); }
	bool isSFR() const { return is(SFR); }
	bool isDFR() const { return is(DFR); }
	bool isNIL() const { return !kind_; }
	// any bit is accetable if bit == 0
	bool is(int kind) const
	{
		return (kind_ & kind);
	}
};

class Reg : public Operand {
private:
	void operator=(const Reg&);
	friend Reg operator+(const Reg& r, int disp)
	{
		return Reg(r, r.getDisp() + disp);
	}
public:
	explicit Reg(int idx) : Operand(idx, Operand::REG, 0)
	{
	}
	Reg(const Reg& base, int disp) : Operand(base.getIdx(), Operand::REG, disp)
	{
	}
};

#ifndef DISABLE_VFP
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

class SysFReg : public Operand {
private:
	void operator=(const SysFReg&);
public:
	explicit SysFReg(int idx) : Operand(idx, Operand::SYSFR, 0)
	{
	}
};
#endif

class Nil : public Operand {
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
	enum Cond {
		NOCOND = -1, EQ = 0, NE, CS, CC, MI, PL, VS, VC, HI, LS, GE, LT, GT, LE, AL,
	};
	const static Nil nil;
	const Reg r0, r1, r2, r3, r4, r5, r6, r7, r8, r9, r10, r11, r12, r13, r14, r15;
	const Reg fp, ip, sp, lr, pc, spW;
	Cond cond_;
#ifndef DISABLE_VFP
	const SFReg s0, s1, s2;
	const DFReg d0, d1, d2;
	const SysFReg fpscr;
#endif
	void setCond(const Cond cond)
	{
		cond_ = cond;
	}
	void opReg(uint32 opcode, const Operand& regD, const Operand &regN,
	           const Operand &regM, uint32 type = 0, uint32 imm = 0)
	{
		if (!regD.isREG() && !regD.isNIL()) { throw ERR_BAD_COMBINATION; }
		if (!regN.isREG() && !regN.isNIL()) { throw ERR_BAD_COMBINATION; }
		if (!regM.isREG() && !regM.isNIL()) { throw ERR_BAD_COMBINATION; }
		if (imm > 31) { throw ERR_IMM_IS_TOO_BIG; }
		dd(cond_ << 28 | opcode << 20 | regN.getIdx() << 16 |
		   regD.getIdx() << 12 | imm << 7 | type << 5 | regM.getIdx());
	}
	void opImm(uint32 opcode, const Operand& regD, const Operand &regN,
	           uint32 imm)
	{
		if (!regD.isREG() && !regD.isNIL()) { throw ERR_BAD_COMBINATION; }
		if (!regN.isREG() && !regN.isNIL()) { throw ERR_BAD_COMBINATION; }
		imm = inner::getShifterImm(imm);
		if (!imm >= 0x1000) { throw ERR_IMM_IS_TOO_BIG; }
		dd(cond_ << 28 | opcode << 20 | regN.getIdx() << 16 |
		   regD.getIdx() << 12 | imm);
	}
	void opImm16(uint32 opcode, const Operand& regD, uint32 imm)
	{
		if (!regD.isREG()) { throw ERR_BAD_COMBINATION; }
		if (!inner::IsInUint16(imm)) { throw ERR_IMM_IS_TOO_BIG; }
		dd(cond_ << 28 | opcode << 20 | (imm & 0xf000) << 4 |
		   regD.getIdx() << 12 | (imm & 0xfff));
	}
	void opMem(uint32 opcode, const Operand& regD, const Operand& regN)
	{
		uint32 u = 0;
		if (!regD.isREG() || !regN.isREG()) { throw ERR_BAD_COMBINATION; }
		int imm = regN.getDisp();
		if (imm < 0)  {
			imm = -imm;
			u = 1 << 23;
		}
		if (imm >= 0x1000) { throw ERR_IMM_IS_TOO_BIG; }
		dd(cond_ << 28 | opcode << 20 | u | regN.getIdx() << 16 |
		   regD.getIdx() << 12 | imm);
	}
	void opMemRegs(uint32 opcode, const Operand& regN, const Operand *regs)
	{
		uint32 bits = 0;
		while (!regs->isNIL()) { bits |= 1 << (regs++)->getIdx(); }
		dd(cond_ << 28 | opcode << 20 | regN.getIdx() << 16 | bits);
	}
	void opJmp(const int32 imm, Cond cond = NOCOND, bool l = false)
	{
		if (imm < -0x800000 || imm > 0x7fffff) { throw ERR_IMM_IS_TOO_BIG; }
		if (cond == NOCOND) { cond = cond_; }
		dd(cond << 28 | 0xa000000 | (l ? 1 << 24 : 0) |
		   ((const uint32)imm & 0xffffff));
	}
	void mov(const Operand& reg1, const Operand& reg2)
	{
		opReg(0x1a, reg1, nil, reg2);
	}
	void movw(const Operand& reg, const uint32 imm)
	{
		opImm16(0x30, reg, imm);
	}
	void movt(const Operand& reg, const uint32 imm)
	{
		opImm16(0x34, reg, imm);
	}
	void mov32(const Operand& reg, const uint32 imm)
	{
		movw(reg, imm & 0xffff);
		movt(reg, imm >> 16);
	}
	void add(const Operand& reg1, const Operand& reg2, const Operand& reg3)
	{
		opReg(0x08, reg1, reg2, reg3);
	}
	void add(const Operand& reg1, const Operand& reg2, uint32 imm)
	{
		opImm(0x28, reg1, reg2, imm);
	}
	void adds(const Operand& reg1, const Operand& reg2, const Operand& reg3)
	{
		opReg(0x09, reg1, reg2, reg3);
	}
	void adds(const Operand& reg1, const Operand& reg2, uint32 imm)
	{
		opImm(0x29, reg1, reg2, imm);
	}
	void cmp(const Operand& reg1, const Operand& reg2)
	{
		opReg(0x15, Operand(), reg1, reg2);
	}
	void cmp(const Operand& reg, uint32 imm)
	{
		opImm(0x35, Operand(), reg, imm);
	}
	void ldr(const Operand& reg1, const Operand& reg2)
	{
		opMem(0x59, reg1, reg2);
	}
	void str(const Operand& reg1, const Operand& reg2)
	{
		opMem(0x58, reg1, reg2);
	}
	void ldm(const Operand& reg1, const Operand& reg2,
	         const Operand& reg3 = nil, const Operand& reg4 = nil,
	         const Operand& reg5 = nil)
	{
		const Operand regs[] = {reg2, reg3, reg4, reg5, nil};
		opMemRegs(0x89, reg1, regs);
	}
	void stm(const Operand& reg1, const Operand& reg2,
	         const Operand& reg3 = nil, const Operand& reg4 = nil,
	         const Operand& reg5 = nil)
	{
		const Operand regs[] = {reg2, reg3, reg4, reg5, nil};
		opMemRegs(0x88, reg1, regs);
	}
	void b(const int32 imm)
	{
		opJmp(imm);
	}
	void b(const void *addr)
	{
		opJmp(((int32)addr - (int32)getCurr() - 8) >> 2);
	}
	void bcc(const int imm)
	{
		opJmp(imm, CC);
	}
	void bcc(const void *addr)
	{
		opJmp(((int32)addr - (int32)getCurr() - 8) >> 2, CC);
	}
	void beq(const int imm)
	{
		opJmp(imm, EQ);
	}
	void beq(const void *addr)
	{
		opJmp(((int32)addr - (int32)getCurr() - 8) >> 2, EQ);
	}
	void bne(const int imm)
	{
		opJmp(imm, NE);
	}
	void bne(const void *addr)
	{
		opJmp(((int32)addr - (int32)getCurr() - 8) >> 2, NE);
	}
	void bvc(const int imm)
	{
		opJmp(imm, VC);
	}
	void bvc(const void *addr)
	{
		opJmp(((int32)addr - (int32)getCurr() - 8) >> 2, VC);
	}
#ifndef DISABLE_VFP
	void fopDD(uint32 opcode, const Operand& dregD, const Operand& dregN, const Operand& dregM)
	{
		dd(cond_ << 28 | 0xe000b00 | (opcode >> 4) << 20 |
		   dregN.getIdx() << 16 | dregD.getIdx() << 12 |
		   (opcode & 0xf) << 4 | dregM.getIdx());
	}
	void fopSR(uint32 opcode, const Operand& sregN, const Operand& regD)
	{
		dd(cond_ << 28 | 0xe000a10 | opcode << 20 |
		   (sregN.getIdx() >> 1) << 16 | regD.getIdx() << 12 |
		   (sregN.getIdx() & 1) << 7);
	}
	void fopExtD(uint32 opcode, const Operand& dregD, const Operand& dregM)
	{
		dd(cond_ << 28 | 0xeb00b00 | (opcode >> 4) << 16 |
		   dregD.getIdx() << 12 | (opcode & 0xf) << 4 | dregM.getIdx());
	}
	void fopExtDS(uint32 opcode, const Operand& dregD, const Operand& sregM)
	{
		dd(cond_ << 28 | 0xeb00b00 | (opcode >> 4) << 16 |
		   dregD.getIdx() << 12 | (opcode & 0xf) << 4 |
		   (sregM.getIdx() & 1) << 5 | (sregM.getIdx() >> 1));
	}
	void fopMemS(uint32 opcode, const Operand& sregD, const Operand& regN)
	{
		int disp = regN.getDisp();
		uint32 offset = 0x800000 | disp;
		dd(cond_ << 28 | 0xc000a00 | opcode << 20 |
		   (sregD.getIdx() & 1) << 23 | regN.getIdx() << 16 |
		   (sregD.getIdx() >> 1) << 12 | offset);
	}
	void fopMemD(uint32 opcode, const Operand& dregD, const Operand& regN)
	{
		int disp = regN.getDisp();
		uint32 offset = 0x800000 | disp;
		dd(cond_ << 28 | 0xc000b00 | opcode << 20 |
		   regN.getIdx() << 16 | dregD.getIdx() << 12 | offset);
	}
	void faddd(const Operand& dreg1, const Operand& dreg2, const Operand& dreg3)
	{
		fopDD(0x30, dreg1, dreg2, dreg3);
	}
	void fcmpd(const Operand& dreg1, const Operand& dreg2)
	{
		fopExtD(0x44, dreg1, dreg2);
	}
	void fmsr(const Operand& sreg, const Operand& reg)
	{
		fopSR(0x0, sreg, reg);
	}
	void fmstat()
	{
		fopSR(0xf, fpscr, r15);
	}
	void fsitod(const Operand& dreg, const Operand& sreg)
	{
		fopExtDS(0x8c, dreg, sreg);
	}
	void flds(const Operand& sreg, const Operand& reg)
	{
		fopMemS(0x11, sreg, reg);
	}
	void fldd(const Operand& dreg, const Operand& reg)
	{
		fopMemD(0x11, dreg, reg);
	}
	void fstd(const Operand& dreg, const Operand& reg)
	{
		fopMemD(0x10, dreg, reg);
	}
#endif
public:
	CodeGenerator(size_t maxSize = DEFAULT_MAX_CODE_SIZE, void *userPtr = 0, Allocator *allocator = 0)
		: CodeArray(maxSize, userPtr, allocator), cond_(AL)
		, fp(Operand::FP), ip(Operand::IP), sp(Operand::SP)
		, lr(Operand::LR), pc(Operand::PC), spW(Operand::SPW)
		, r0(0), r1(1), r2(2), r3(3), r4(4), r5(5), r6(6), r7(7), r8(8), r9(9), r10(10), r11(11), r12(12), r13(13), r14(14), r15(15)
#ifndef DISABLE_VFP
		, s0(0), s1(1), s2(2)
		, d0(0), d1(1), d2(2)
		, fpscr(Operand::FPSCR)
#endif
	{
	}
};
const Nil CodeGenerator::nil = Nil();

} // end of namespace

#endif // XTAAK_XTAAK_H_
