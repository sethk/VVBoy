#if INTERFACE
# include <sys/types.h>
# include <stdbool.h>
# include <stdio.h>
# include <sys/mman.h>
#endif // INTERFACE

#include "common.h"

#include <sys/stat.h>
#include <sys/fcntl.h>
#include <sys/errno.h>
#include <sys/param.h>
#include <libkern/OSByteOrder.h>
#include <unistd.h>
#include <math.h>
#include <stdlib.h>
#include <strings.h>
#include <signal.h>
#include <assert.h>
#include <err.h>
#include <histedit.h>
#include <float.h>
#include <OpenGL/gl3.h>
#define CIMGUI_DEFINE_ENUMS_AND_STRUCTS
#include <cimgui/cimgui.h>

/* MEM */
#if INTERFACE
	enum mem_segment
	{
		MEM_SEG_VIP = 0,
		MEM_SEG_VSU = 1,
		MEM_SEG_NVC = 2,
		MEM_SEG_CARTEX = 4,
		MEM_SEG_WRAM = 5,
		MEM_SEG_SRAM = 6,
		MEM_SEG_ROM = 7,
		MEM_NSEGS = 8
	};

	struct mem_seg_desc
	{
		size_t ms_size;
		u_int8_t *ms_ptr;
		u_int32_t ms_addrmask;
		bool ms_is_mmap;
		int ms_perms; // PROT_* from <sys/mman.h>
	};

# define MEM_ADDR2SEG(a) (((a) & 0x07000000) >> 24)
# define MEM_ADDR2OFF(a) ((a) & 0x00ffffff)
# define MEM_SEG2ADDR(s) ((s) << 24)

#endif // INTERFACE

#define INIT_DEAD_MEM 1
#define DEAD_MEM_PATTERN (0) // (0xdeadc0de)

struct mem_seg_desc mem_segs[(enum mem_segment)MEM_NSEGS];

static const char *mem_seg_names[MEM_NSEGS] =
{
	[MEM_SEG_VIP] = "VIP",
	[MEM_SEG_VSU] = "VSU",
	[MEM_SEG_NVC] = "NVC",
	[3] = "Not Used (0x03000000-0x03ffffff)",
	[MEM_SEG_CARTEX] = "CARTEX",
	[MEM_SEG_WRAM] = "WRAM",
	[MEM_SEG_SRAM] = "SRAM",
	[MEM_SEG_ROM] = "ROM"
};

#ifndef NDEBUG
static bool
validate_seg_size(size_t size)
{
	double log2size = log2(size);
	return (remainder(log2size, 1.0) == 0.0);
}
#endif // !NDEBUG

bool
mem_seg_alloc(enum mem_segment seg, size_t size, int perms)
{
	assert(validate_seg_size(size));
	mem_segs[seg].ms_ptr = malloc(size);
	if (!mem_segs[seg].ms_ptr)
	{
		warn("Could not allocate 0x%lx bytes for segment %s", size, mem_seg_names[seg]);
		return false;
	}
	mem_segs[seg].ms_size = size;
	mem_segs[seg].ms_addrmask = size - 1;
	mem_segs[seg].ms_perms = perms;

#ifndef NDEBUG
	bool init_dead_mem = INIT_DEAD_MEM;
	char *dead_mem_env = getenv("INIT_DEAD_MEM");
	if (dead_mem_env)
		init_dead_mem = atoi(dead_mem_env);
	if (init_dead_mem)
	{
		u_int32_t pattern = DEAD_MEM_PATTERN;
		memset_pattern4(mem_segs[MEM_SEG_WRAM].ms_ptr, &pattern, mem_segs[MEM_SEG_WRAM].ms_size);
	}
#endif // !NDEBUG

	return true;
}

bool
mem_seg_mmap(enum mem_segment seg, size_t size, int fd)
{
	mem_segs[seg].ms_size = size;
	mem_segs[seg].ms_ptr = mmap(NULL, size, PROT_READ, MAP_FILE | MAP_PRIVATE, fd, 0);
	if (!mem_segs[seg].ms_ptr)
	{
		warn("mmap() %s", mem_seg_names[seg]);
		return false;
	}
	mem_segs[seg].ms_addrmask = size - 1;
	mem_segs[seg].ms_is_mmap = true;
	return true;
}

static bool
mem_seg_realloc(enum mem_segment seg, size_t size)
{
	assert(!mem_segs[seg].ms_is_mmap);
	assert(validate_seg_size(size));
	mem_segs[seg].ms_ptr = realloc(mem_segs[seg].ms_ptr, size);
	if (!mem_segs[seg].ms_ptr)
	{
		warn("Could not reallocate 0x%lx bytes for segment %s", size, mem_seg_names[seg]);
		return false;
	}
	mem_segs[seg].ms_size = size;
	mem_segs[seg].ms_addrmask = size - 1;
	return true;
}

void
mem_seg_free(enum mem_segment seg)
{
	if (!mem_segs[seg].ms_is_mmap)
		free(mem_segs[seg].ms_ptr);
	else
	{
		if (munmap(mem_segs[seg].ms_ptr, mem_segs[seg].ms_size) == -1)
			warn("munmap(mem_segs[%s], ...) failed", mem_seg_names[seg]);
		mem_segs[seg].ms_is_mmap = false;
	}
	mem_segs[seg].ms_ptr = NULL;
}

u_int32_t
mem_size_ceil(u_int32_t size)
{
	// http://graphics.stanford.edu/~seander/bithacks.html#RoundUpPowerOf2Float
	--size;
	size|= size >> 1;
	size|= size >> 2;
	size|= size >> 4;
	size|= size >> 8;
	size|= size >> 16;
	return ++size;
}

static bool
mem_read(u_int32_t addr, void *dest, size_t size, bool is_exec, u_int *mem_waitp)
{
	assert(size > 0);
	enum mem_segment seg = MEM_ADDR2SEG(addr);
	const void *src;
	int mem_ops = PROT_READ;
	if (is_exec)
		mem_ops|= PROT_EXEC;
	u_int32_t mask = 0xffffffff;
	int perms;

	if (seg == MEM_SEG_VIP)
	{
		src = vip_mem_emu2host(addr, size, &perms);
		*mem_waitp = 8;
	}
	else
	{
		if (seg == MEM_SEG_VSU)
			src = vsu_mem_emu2host(addr, size, &perms);
		else if (seg == MEM_SEG_NVC)
			src = nvc_mem_emu2host(addr, &size, &mask, &perms);
		else if (mem_segs[seg].ms_size)
		{
			u_int32_t offset = addr & mem_segs[seg].ms_addrmask;

			if (seg == MEM_SEG_SRAM && MEM_ADDR2OFF(addr) + size > mem_segs[seg].ms_size)
			{
				if (!mem_seg_realloc(MEM_SEG_SRAM, mem_size_ceil(offset + size)))
					return false;
				offset = addr & mem_segs[MEM_SEG_SRAM].ms_addrmask;
			}

			src = mem_segs[seg].ms_ptr + offset;
			perms = mem_segs[seg].ms_perms;
		}
		else
		{
			src = NULL;
			perms = 0;
		}
		*mem_waitp = 2;
	}

	if (!src)
	{
		warnx("Bus error at 0x%08x", addr);
		debug_enter();
		return false;
	}

	if ((perms & mem_ops) != mem_ops)
	{
		debug_str_t addr_s, ops_s, perms_s;
		warnx("Invalid memory operation at %s, mem ops = %s, prot = %s\n",
		      debug_format_addr(addr, addr_s),
		      debug_format_perms(mem_ops, ops_s),
		      debug_format_perms(perms, perms_s));
		debug_enter();
		return false;
	}

	if (debug_trace_mem && !is_exec)
	{
		debug_str_t addr_s;
		debug_str_t hex_s;
		debug_tracef("mem", "[" DEBUG_ADDR_FMT "] -> %s\n",
		             debug_format_addr(addr, addr_s), debug_format_hex(src, size, hex_s));
	}

	switch (size)
	{
		case 1:
			*(u_int8_t *)dest = *(u_int8_t *)src;
			return true;
		case 2:
			*(u_int16_t *)dest = *(u_int16_t *)src;
			return true;
		case 4:
			*(u_int32_t *)dest = *(u_int32_t *)src;
			return true;
		default:
			bcopy(src, dest, size);
			return true;
	}
}

static bool
mem_write(u_int32_t addr, const void *src, size_t size, u_int *mem_waitp)
{
	assert(size > 0);
	enum mem_segment seg = MEM_ADDR2SEG(addr);
	void *dest = NULL;
	int perms;
	u_int32_t mask = 0xffffffff;

	if (seg == MEM_SEG_VIP)
	{
		dest = vip_mem_emu2host(addr, size, &perms);
		*mem_waitp = 4;
	}
	else
	{
		if (seg == MEM_SEG_VSU)
			dest = vsu_mem_emu2host(addr, size, &perms);
		else if (seg == MEM_SEG_NVC)
			dest = nvc_mem_emu2host(addr, &size, &mask, &perms);
		else if (mem_segs[seg].ms_size)
		{
			u_int32_t offset = addr & mem_segs[seg].ms_addrmask;

			if (seg == MEM_SEG_SRAM && MEM_ADDR2OFF(addr) + size > mem_segs[seg].ms_size)
			{
				if (!mem_seg_realloc(MEM_SEG_SRAM, mem_size_ceil(offset + size)))
					return false;
				offset = addr & mem_segs[MEM_SEG_SRAM].ms_addrmask;
			}

			dest = mem_segs[seg].ms_ptr + offset;
			perms = mem_segs[seg].ms_perms;
		}
		else
		{
			dest = NULL;
			perms = 0;
		}

		*mem_waitp = 2;
	}

	if (!dest)
	{
		// TODO: SEGV
		fprintf(stderr, "Bus error at 0x%08x\n", addr);
		debug_enter();
		return false;
	}

	if ((perms & PROT_WRITE) == 0)
	{
		debug_str_t addr_s, perms_s;
		static bool ignore_writes = false;
		if (debug_runtime_errorf(&ignore_writes, "Invalid memory operation at %s, mem ops = PROT_WRITE, prot = %s\n",
		                          debug_format_addr(addr, addr_s),
		                          debug_format_perms(perms, perms_s)))
			return true;
		debug_enter();
		return false;
	}

	if (debug_trace_mem)
	{
		debug_str_t addr_s;
		debug_str_t hex_s;
		debug_tracef("mem", "[" DEBUG_ADDR_FMT "] <- %s\n",
		             debug_format_addr(addr, addr_s), debug_format_hex(src, size, hex_s));
	}

	switch (size)
	{
		case 1:
			*(u_int8_t *)dest = (*(u_int8_t *)dest & ~mask) | (*(u_int8_t *)src & mask);
			return true;
		case 2:
			*(u_int16_t *)dest = (*(u_int16_t *)dest & ~mask) | (*(u_int16_t *)src & mask);
			return true;
		case 4:
			*(u_int32_t *)dest = (*(u_int32_t *)dest & ~mask) | (*(u_int32_t *)src & mask);
			return true;
		default:
			bcopy(src, dest, size);
			return true;
	}
}

void
mem_test_size(const char *name, size_t size, size_t expected)
{
	if (expected != size)
	{
		debug_runtime_errorf(NULL, "sizeof(%s) is %lu but should be %lu", name, size, expected);
		abort();
	}
}

void
mem_test_addr(const char *name, void *addr, void *expected)
{
	if (addr != expected)
	{
		debug_runtime_errorf(NULL, "emu2host(%s) is %p but should be %p (offset %ld)",
		                     name, addr, expected, (intptr_t)expected - (intptr_t)addr);
		abort();
	}
}

/* SRAM */
bool
sram_init(void)
{
	// TODO: load save file
	return mem_seg_alloc(MEM_SEG_SRAM, 8 << 10, PROT_READ | PROT_WRITE);
}

void
sram_fini(void)
{
	mem_seg_free(MEM_SEG_SRAM);
	// TODO: write save file
}

/* WRAM */
#define WRAM_SIZE 0x1000000

bool
wram_init(void)
{
	return mem_seg_alloc(MEM_SEG_WRAM, WRAM_SIZE, PROT_READ | PROT_WRITE);
}

void
wram_add_syms(void)
{
	debug_create_symbol("GLOBAL", 0x05000000);
	debug_create_symbol("STACK", 0x0500dfff);
}

void
wram_fini(void)
{
	mem_seg_free(MEM_SEG_WRAM);
}

/* CPU */
#if INTERFACE
#	define CPU_INST_PER_USEC (20)
#   define CPU_MAX_PC (0xfffffffe)

	union cpu_reg {u_int32_t u; int32_t s; float f; int16_t s16; u_int8_t u8s[4];};
	typedef union cpu_reg cpu_regs_t[32];

	union cpu_inst
	{
		u_int16_t ci_hwords[2];
		struct
		{
			u_int i_reg1 : 5;
			u_int i_reg2 : 5;
			u_int i_opcode : 6;
		} ci_i;
		struct
		{
			u_int ii_imm5 : 5;
			u_int ii_reg2 : 5;
			u_int ii_opcode : 6;
		} ci_ii;
		struct
		{
			u_int iii_disp9 : 9;
			u_int iii_cond : 4;
			u_int iii_opcode : 3;
		} ci_iii;
		struct
		{
			u_int iv_disp10 : 10;
			u_int iv_opcode : 6;
			u_int iv_disp16 : 16;
		} ci_iv;
		struct
		{
			u_int v_reg1 : 5;
			u_int v_reg2 : 5;
			u_int v_opcode : 6;
			u_int16_t v_imm16;
		} ci_v;
		struct
		{
			u_int vi_reg1 : 5;
			u_int vi_reg2 : 5;
			u_int vi_opcode : 6;
			int16_t vi_disp16;
		} ci_vi;
		struct
		{
			u_int vii_reg1 : 5;
			u_int vii_reg2 : 5;
			u_int vii_opcode : 6;
			u_int vii_rfu : 10;
			u_int vii_subop : 6;
		};
	};

	enum cpu_opcode
	{
		OP_MOV   = 0b000000,
		OP_ADD   = 0b000001,
		OP_SUB   = 0b000010,
		OP_CMP   = 0b000011,
		OP_SHL   = 0b000100,
		OP_SHR   = 0b000101,
		OP_JMP   = 0b000110,
		OP_SAR   = 0b000111,
		OP_MUL   = 0b001000,
		OP_DIV   = 0b001001,
		OP_MULU  = 0b001010,
		OP_DIVU  = 0b001011,
		OP_OR    = 0b001100,
		OP_AND   = 0b001101,
		OP_XOR   = 0b001110,
		OP_NOT   = 0b001111,
		OP_MOV2  = 0b010000,
		OP_ADD2  = 0b010001,
		OP_SETF  = 0b010010,
		OP_CMP2  = 0b010011,
		OP_SHL2  = 0b010100,
		OP_SHR2  = 0b010101,
		OP_CLI   = 0b010110,
		OP_SAR2  = 0b010111,
		OP_TRAP  = 0b011000,
		OP_RETI  = 0b011001,
		OP_HALT  = 0b011010,
		OP_LDSR  = 0b011100,
		OP_STSR  = 0b011101,
		OP_SEI   = 0b011110,
		OP_BSTR  = 0b011111,
		OP_BCOND = 0b100,
		OP_MOVEA = 0b101000,
		OP_ADDI  = 0b101001,
		OP_JR    = 0b101010,
		OP_JAL   = 0b101011,
		OP_ORI   = 0b101100,
		OP_ANDI  = 0b101101,
		OP_XORI  = 0b101110,
		OP_MOVHI = 0b101111,
		OP_LD_B  = 0b110000,
		OP_LD_H  = 0b110001,
		OP_LD_W  = 0b110011,
		OP_ST_B  = 0b110100,
		OP_ST_H  = 0b110101,
		OP_ST_W  = 0b110111,
		OP_IN_B  = 0b111000,
		OP_IN_H  = 0b111001,
		OP_CAXI  = 0b111010,
		OP_IN_W  = 0b111011,
		OP_OUT_B = 0b111100,
		OP_OUT_H = 0b111101,
		OP_FLOAT = 0b111110,
		OP_OUT_W = 0b111111
	};

	enum cpu_bcond
	{
		BCOND_BV  = 0b0000,
		BCOND_BL  = 0b0001,
		BCOND_BZ  = 0b0010,
		BCOND_BNH = 0b0011,
		BCOND_BN  = 0b0100,
		BCOND_BR  = 0b0101,
		BCOND_BLT = 0b0110,
		BCOND_BLE = 0b0111,
		BCOND_BNV = 0b1000,
		BCOND_BNC = 0b1001,
		BCOND_BNZ = 0b1010,
		BCOND_BH  = 0b1011,
		BCOND_BP  = 0b1100,
		BCOND_NOP = 0b1101,
		BCOND_BGE = 0b1110,
		BCOND_BGT = 0b1111,
	};

	enum cpu_bstr
	{
		BSTR_SCH0BSU = 0b00000,
		BSTR_SCH0BSD = 0b00001,
		BSTR_SCH1BSU = 0b00010,
		BSTR_SCH1BSD = 0b00011,
		BSTR_ORBSU   = 0b01000,
		BSTR_ANDBSU  = 0b01001,
		BSTR_XORBSU  = 0b01010,
		BSTR_MOVBSU  = 0b01011,
		BSTR_ORNBSU  = 0b01100,
		BSTR_ANDNBSU = 0b01101,
		BSTR_XORNBSU = 0b01110,
		BSTR_NOTBSU  = 0b01111,
	};

	enum cpu_regid
	{
		REGID_EIPC = 0,
		REGID_EIPSW = 1,
		REGID_FEPC = 2,
		REGID_FEPSW = 3,
		REGID_PSW = 5,
		REGID_CHCW = 24
	};

	enum cpu_chcw_flags
	{
		CPU_CHCW_ICC = (1 << 0),
		CPU_CHCW_ICE = (1 << 1)
	};

	enum float_subop
	{
		FLOAT_CMPF_S =  0b000000,
		FLOAT_CVT_WS =  0b000010,
		FLOAT_CVT_SW =  0b000011,
		FLOAT_ADDF_S =  0b000100,
		FLOAT_SUBF_S =  0b000101,
		FLOAT_MULF_S =  0b000110,
		FLOAT_DIVF_S =  0b000111,
		FLOAT_XB =      0b001000,
		FLOAT_XH =      0b001001,
		FLOAT_TRNC_SW = 0b001011,
		FLOAT_MPYHW =   0b001100,
	};
#endif // INTERFACE

union cpu_psw
{
	u_int32_t psw_word;
	struct
	{
		unsigned f_z : 1;
		unsigned f_s : 1;
		unsigned f_ov : 1;
		unsigned f_cy : 1;
		unsigned f_fpr : 1;
		unsigned f_fud : 1;
		unsigned f_fov : 1;
		unsigned f_fzd : 1;
		unsigned f_fiv : 1;
		unsigned f_fro : 1;
		unsigned reserved1 : 2;
		unsigned f_id : 1;
		unsigned f_ae : 1;
		unsigned f_ep : 1;
		unsigned f_np : 1;
		unsigned f_i : 4;
	} psw_flags;
};

struct cpu_state
{
	cpu_regs_t cs_r;
	u_int32_t cs_pc;
	union cpu_psw cs_psw;
	struct cpu_ecr
	{
		int16_t ecr_eicc;
		int16_t ecr_fecc;
	} cs_ecr;
	u_int32_t cs_eipc;
	union cpu_psw cs_eipsw;
	u_int32_t cs_fepc;
	union cpu_psw cs_fepsw;
	u_int32_t cs_chcw;
};

static struct cpu_state cpu_state;
static u_int cpu_wait;

bool
cpu_init(void)
{
	cpu_state.cs_r[0].u = 0; // Read-only
	cpu_wait = 1;

	return true;
}

void
cpu_add_syms(void)
{
	debug_create_symbol("vect.reset", 0xfffffff0);
	debug_create_symbol(".reset", 0x07000000 + (0xfffffff0 & mem_segs[MEM_SEG_ROM].ms_addrmask));
}

void
cpu_fini(void)
{
	// TODO
}

void
cpu_reset(void)
{
	cpu_state.cs_pc = 0xfffffff0;
	cpu_state.cs_psw.psw_word = 0;
	cpu_state.cs_psw.psw_flags.f_np = 1;
	cpu_state.cs_ecr.ecr_fecc = 0;
	cpu_state.cs_ecr.ecr_eicc = 0xfff0;
	cpu_state.cs_chcw = CPU_CHCW_ICE;
}

size_t
cpu_inst_size(const union cpu_inst *inst)
{
	return (inst->ci_i.i_opcode < 0x28) ? 2 : 4;
}

u_int32_t
cpu_inst_disp26(const union cpu_inst *inst)
{
	u_int32_t disp = (inst->ci_iv.iv_disp10 << 16) | inst->ci_iv.iv_disp16;
	if ((disp & 0x2000000) == 0x2000000)
		disp|= 0xfd000000;
	return disp;
}

bool
cpu_fetch(u_int32_t addr, union cpu_inst *inst)
{
	u_int mem_wait;
	if (!mem_read(addr, &(inst->ci_hwords[0]), 2, true, &mem_wait))
	{
		printf("Could not read instruction at 0x%08x\n", addr);
		return false;
	}
	inst->ci_hwords[0] = OSSwapLittleToHostInt16(inst->ci_hwords[0]);
	if (cpu_inst_size(inst) == 4)
	{
		if (!mem_read(addr + 2, &(inst->ci_hwords[1]), 2, true, &mem_wait))
		{
			printf("Could not read instruction at 0x%08x\n", addr + 2);
			return false;
		}
		inst->ci_hwords[1] = OSSwapLittleToHostInt16(inst->ci_hwords[1]);
	}
	return true;
}

static const u_int32_t sign_bit32 = 0x80000000;
static const u_int64_t sign_bit64 = 0x8000000000000000;
static const u_int64_t sign_bits32to64 = 0xffffffff80000000;

#if INTERFACE
inline static u_int32_t
cpu_extend9(u_int32_t s9)
{
	if ((s9 & 0x100) == 0x100)
		s9|= 0xfffffe00;
	return s9;
}

inline static u_int16_t
cpu_extend5to16(u_int16_t s5)
{
	if ((s5 & 0b10000) == 0b10000)
		s5|= 0xffe0;
	return s5;
}

inline static u_int32_t
cpu_extend16(u_int32_t s16)
{
	if ((s16 & 0x8000) == 0x8000)
		s16|= 0xffff0000;
	return s16;
}
#endif // INTERFACE

static bool
cpu_getfl(enum cpu_bcond cond)
{
	switch (cond)
	{
		/*
		BCOND_BV  = 0b0000,
		*/
		case BCOND_BL:
			return cpu_state.cs_psw.psw_flags.f_cy;
		case BCOND_BZ:
			return cpu_state.cs_psw.psw_flags.f_z;
		case BCOND_BNH:
			return (cpu_state.cs_psw.psw_flags.f_cy | cpu_state.cs_psw.psw_flags.f_z);
		case BCOND_BN:
			return cpu_state.cs_psw.psw_flags.f_s;
		case BCOND_BR:
			return true;
		case BCOND_BLT:
			return cpu_state.cs_psw.psw_flags.f_s ^ cpu_state.cs_psw.psw_flags.f_ov;
		case BCOND_BLE:
			return ((cpu_state.cs_psw.psw_flags.f_s ^ cpu_state.cs_psw.psw_flags.f_ov) |
			        cpu_state.cs_psw.psw_flags.f_z);
			/*
			BCOND_BNV = 0b1000,
			*/
		case BCOND_BNC:
			return !cpu_state.cs_psw.psw_flags.f_cy;
		case BCOND_BNZ:
			return !cpu_state.cs_psw.psw_flags.f_z;
		case BCOND_BH:
			return !(cpu_state.cs_psw.psw_flags.f_cy | cpu_state.cs_psw.psw_flags.f_z);
		case BCOND_BP:
			return !cpu_state.cs_psw.psw_flags.f_s;
		case BCOND_NOP:
			return false;
		case BCOND_BGE:
			return !(cpu_state.cs_psw.psw_flags.f_s ^ cpu_state.cs_psw.psw_flags.f_ov);
		case BCOND_BGT:
			return !((cpu_state.cs_psw.psw_flags.f_s ^ cpu_state.cs_psw.psw_flags.f_ov) |
			         cpu_state.cs_psw.psw_flags.f_z);
		default:
			fputs("Handle branch cond\n", stderr);
			debug_enter();
			return false;
	}
}

static void
cpu_setfl_zs0(u_int32_t result)
{
	cpu_state.cs_psw.psw_flags.f_z = (result == 0);
	cpu_state.cs_psw.psw_flags.f_s = ((result & sign_bit32) == sign_bit32);
	cpu_state.cs_psw.psw_flags.f_ov = 0;
}

static void
cpu_setfl(u_int64_t result, u_int32_t left, bool sign_agree)
{
	cpu_state.cs_psw.psw_flags.f_z = ((result & 0xffffffff) == 0);
	cpu_state.cs_psw.psw_flags.f_s = ((result & sign_bit32) == sign_bit32);
	cpu_state.cs_psw.psw_flags.f_cy = ((result & 0x100000000) == 0x100000000);
	if (sign_agree)
		cpu_state.cs_psw.psw_flags.f_ov = ((result & sign_bit32) != (left & sign_bit32));
	else
		cpu_state.cs_psw.psw_flags.f_ov = 0;
}

static void
cpu_setfl_float_zsoc(double result)
{
	cpu_state.cs_psw.psw_flags.f_cy = cpu_state.cs_psw.psw_flags.f_s = (result < 0);
	cpu_state.cs_psw.psw_flags.f_ov = 0;
	cpu_state.cs_psw.psw_flags.f_z = (result == 0);
}

static void
cpu_setfl_float(double double_result)
{
	if (double_result != 0.0)
	{
		if (double_result >= 0x1.ffffffp127 || double_result <= -0x1.ffffffp127)
			cpu_state.cs_psw.psw_flags.f_fov = 1;
		else
		{
			union
			{
				struct
				{
					unsigned double_mantissa : 29 __attribute__((packed));
					unsigned single_mantissa : 23 __attribute__((packed));
					unsigned raw_exp : 11 __attribute__((packed));
					unsigned sign : 1 __attribute__((packed));
				} __attribute__((packed));
				double d;
			} result = {.d = double_result};
			static_assert(sizeof(result) == 8, "double_result not packed correctly");
			if (result.raw_exp == 0)
			{
				if (result.single_mantissa == 0)
				{
					assert(result.double_mantissa != 0);
					cpu_state.cs_psw.psw_flags.f_fud = 1;
				}
			}
			else if (result.double_mantissa) // Precision beyond 24-bit float mantissa
				cpu_state.cs_psw.psw_flags.f_fpr = 1;
		}
	}
}

static u_int32_t
cpu_add(u_int32_t left, u_int32_t right)
{
	u_int64_t result = (u_int64_t)left + right;
	cpu_setfl(result, left, (left & sign_bit32) == (right & sign_bit32));
	return result;
}

static u_int32_t
cpu_sub(u_int32_t left, u_int32_t right)
{
	u_int64_t result = (u_int64_t)left - right;
	cpu_setfl(result, left, (left & sign_bit32) != (right & sign_bit32));
	return result;
}

static bool
cpu_float_reserved(float f)
{
	switch (fpclassify(f))
	{
		case FP_NORMAL:
		case FP_ZERO:
			return false;

		default:
		{
			cpu_state.cs_psw.psw_flags.f_fro = 1;
			fputs("TODO: Reserved operand exception\n", stderr);
			raise(SIGINT);
			return true;
		}
	}
}

static double
cpu_subf(float left, float right)
{
	assert(!cpu_float_reserved(left));
	assert(!cpu_float_reserved(right));
	double result = (double)left - right;
	cpu_setfl_float_zsoc(result);
	return result;
}

static u_int32_t
cpu_shift_left(u_int32_t start, u_int32_t shift)
{
	u_int32_t result;
	if (shift > 0)
	{
		result = start << shift;
		cpu_state.cs_psw.psw_flags.f_cy = ((start >> (31 - shift)) & 1);
	}
	else
	{
		result = start;
		cpu_state.cs_psw.psw_flags.f_cy = 0;
	}
	cpu_state.cs_psw.psw_flags.f_ov = 0;
	cpu_state.cs_psw.psw_flags.f_s = ((result & sign_bit32) == sign_bit32);
	cpu_state.cs_psw.psw_flags.f_z = (result == 0);
	return result;
}

static u_int32_t
cpu_shift_right(u_int32_t start, u_int32_t shift)
{
	u_int32_t result;
	if (shift)
	{
		result = start >> shift;
		cpu_state.cs_psw.psw_flags.f_cy = ((start << (31 - shift)) & 1);
	}
	else
	{
		result = start;
		cpu_state.cs_psw.psw_flags.f_cy = 0;
	}
	cpu_state.cs_psw.psw_flags.f_ov = 0;
	cpu_state.cs_psw.psw_flags.f_s = ((result & sign_bit32) == sign_bit32);
	cpu_state.cs_psw.psw_flags.f_z = (result == 0);
	return result;
}

static bool
cpu_movbsu(u_int32_t *src_word_addrp, u_int32_t *src_bit_offp,
           u_int32_t *bit_lengthp,
           u_int32_t *dest_word_addrp, u_int32_t *dest_bit_offp)
{
	if ((*bit_lengthp % 8) != 0)
	{
		debug_runtime_errorf(NULL, "MOVBSU only multiple of 8 bit lengths supported");
		return false;
	}

	cpu_wait = 48; // Just an average; actually dependent on size/alignment

	u_int read_byte_size = (*bit_lengthp > 32) ? 4 : *bit_lengthp >> 3;
	u_int32_t src_word;
	u_int mem_wait;
	if (!mem_read(*src_word_addrp, &src_word, read_byte_size, false, &mem_wait))
		return false;
	cpu_wait+= mem_wait;

	if (*src_bit_offp & 31)
	{
		debug_runtime_errorf(NULL, "MOVBSU with src bit offset not supported");
		return false;
	}
	if (*dest_bit_offp & 31)
	{
		debug_runtime_errorf(NULL, "MOVBSU with dest bit offset not supported");
		return false;
	}

	if (!mem_write(*dest_word_addrp, &src_word, read_byte_size, &mem_wait))
		return false;
	cpu_wait+= mem_wait;
	(*src_word_addrp)+= read_byte_size;
	(*dest_word_addrp)+= read_byte_size;
	(*bit_lengthp)-= read_byte_size << 3;

	/*
	u_int dest_bit_off = *dest_bit_offp & 31;
	if (dest_bit_off)
	{
		u_int32_t src_mask = 0xffffffff >> dest_bit_off;
		u_int32_t dest_read_bits = 31 - dest_bit_off;
		if (*bit_lengthp < dest_read_bits)
			src_mask&= ~(src_mask >> *bit_lengthp);
		u_int32_t dest_word;
		mem_read(*dest_word_addrp, &dest_word, 4, false);
		word&= read_mask;
	}
	 */
	/*
	u_int write_bits = 32 - dest_read_bits;
	u_int src_read_bits = (*bit_lengthp > write_bits) ? write_bits : *bit_lengthp;
	 */
	/*
	{
	u_int32_t src_word;
	if (!mem_read(*src_word_addr, &src_word, sizeof(src_word), false))
		return false;
	if (*dest_bit_off)
	{
	}
	if (!mem_write(*dest_word_addr, &word, sizeof(word)))
		return false;
	(*src_word_addr)+= 4;
	(*dest_word_addr)+= 4;
	(*length)-= 32;
	return true;
	}
	 */
	return true;
}

static bool
cpu_exec(const union cpu_inst inst)
{
#ifndef NDEBUG
	u_int32_t old_pc = cpu_state.cs_pc;
#endif // !NDEBUG

	switch (inst.ci_i.i_opcode)
	{
		case OP_MOV:
			cpu_state.cs_r[inst.ci_i.i_reg2] = cpu_state.cs_r[inst.ci_i.i_reg1];
			break;
		case OP_ADD:
			cpu_state.cs_r[inst.ci_i.i_reg2].u =
					cpu_add(cpu_state.cs_r[inst.ci_i.i_reg2].u, cpu_state.cs_r[inst.ci_i.i_reg1].u);
			break;
		case OP_SUB:
			cpu_state.cs_r[inst.ci_i.i_reg2].u =
					cpu_sub(cpu_state.cs_r[inst.ci_i.i_reg2].u, cpu_state.cs_r[inst.ci_i.i_reg1].u);
			break;
		case OP_CMP:
			cpu_sub(cpu_state.cs_r[inst.ci_i.i_reg2].u, cpu_state.cs_r[inst.ci_i.i_reg1].u);
			break;
		case OP_SHL:
			cpu_state.cs_r[inst.ci_i.i_reg2].u =
					cpu_shift_left(cpu_state.cs_r[inst.ci_i.i_reg2].u, cpu_state.cs_r[inst.ci_i.i_reg1].u & 0x1f);
			break;
		case OP_SHR:
			cpu_state.cs_r[inst.ci_i.i_reg2].u =
					cpu_shift_right(cpu_state.cs_r[inst.ci_i.i_reg2].u, cpu_state.cs_r[inst.ci_i.i_reg1].u & 0x1f);
			break;
		case OP_JMP:
			if (debug_trace_cpu_jmp)
			{
				debug_str_t addr_s, dest_addr_s;
				debug_tracef("cpu.jmp", DEBUG_ADDR_FMT ": %-4s %s\n",
				             debug_format_addr(cpu_state.cs_pc, addr_s),
				             (inst.ci_i.i_reg1 == 31) ? "RET" : "JMP",
				             debug_format_addr(cpu_state.cs_r[inst.ci_i.i_reg1].u, dest_addr_s));
			}
			cpu_state.cs_pc = cpu_state.cs_r[inst.ci_i.i_reg1].u;

			cpu_wait = 3;

			return true;
		case OP_SAR:
		{
			u_int32_t start = cpu_state.cs_r[inst.ci_i.i_reg2].u;
			u_int32_t shift = cpu_state.cs_r[inst.ci_i.i_reg1].u & 0x1f;
			u_int32_t result = start >> shift;
			cpu_state.cs_psw.psw_flags.f_cy = ((start >> (shift - 1)) & 1);
			cpu_state.cs_psw.psw_flags.f_ov = 0;
			if ((start & sign_bit32) == sign_bit32)
			{
				result|= (0xffffffff << (32 - shift));
				cpu_state.cs_psw.psw_flags.f_s = 1;
			}
			else
				cpu_state.cs_psw.psw_flags.f_s = 0;
			cpu_state.cs_psw.psw_flags.f_z = (result == 0);
			cpu_state.cs_r[inst.ci_i.i_reg2].u = result;
			break;
		}
		case OP_MUL:
		{
			int64_t result = (int64_t)cpu_state.cs_r[inst.ci_i.i_reg2].s * cpu_state.cs_r[inst.ci_i.i_reg1].s;
			cpu_state.cs_psw.psw_flags.f_z = (result == 0);
			cpu_state.cs_psw.psw_flags.f_s = ((result & sign_bit64) == sign_bit64);
			u_int64_t signbits = result & sign_bits32to64;
			cpu_state.cs_psw.psw_flags.f_ov = (signbits != 0 && signbits != sign_bits32to64);
			cpu_state.cs_r[30].u = (u_int64_t)result >> 32;
			cpu_state.cs_r[inst.ci_i.i_reg2].u = result & 0xffffffff;

			cpu_wait = 13;

			break;
		}
		case OP_DIV:
		{
			// TODO: Divide by zero exception
			int64_t left = cpu_state.cs_r[inst.ci_i.i_reg2].s,
					right = cpu_state.cs_r[inst.ci_i.i_reg1].s;
			int64_t result = left / right;
			cpu_state.cs_psw.psw_flags.f_z = (result == 0);
			cpu_state.cs_psw.psw_flags.f_s = ((result & sign_bit32) == sign_bit32);
			cpu_state.cs_psw.psw_flags.f_ov = (left < 0 && right < 0 && cpu_state.cs_psw.psw_flags.f_s);
			cpu_state.cs_r[30].u = left % right;
			cpu_state.cs_r[inst.ci_i.i_reg2].u = result;

			cpu_wait = 38;

			break;
		}
		case OP_MULU:
		{
			u_int64_t result = (u_int64_t)cpu_state.cs_r[inst.ci_i.i_reg2].u *
			                   (u_int32_t)cpu_state.cs_r[inst.ci_i.i_reg1].u;
			cpu_state.cs_psw.psw_flags.f_z = (result == 0);
			cpu_state.cs_psw.psw_flags.f_s = ((result & sign_bit64) == sign_bit64);
			u_int64_t signbits = result & sign_bits32to64;
			cpu_state.cs_psw.psw_flags.f_ov = (signbits != 0 && signbits != sign_bits32to64);
			cpu_state.cs_r[30].u = result >> 32;
			cpu_state.cs_r[inst.ci_i.i_reg2].u = result & 0xffffffff;

			cpu_wait = 13;

			break;
		}
		case OP_DIVU:
		{
			// TODO: Divide by zero exception
			u_int64_t left = cpu_state.cs_r[inst.ci_i.i_reg2].u,
					right = cpu_state.cs_r[inst.ci_i.i_reg1].u;
			u_int64_t result = left / right;
			cpu_state.cs_psw.psw_flags.f_z = (result == 0);
			cpu_state.cs_psw.psw_flags.f_s = ((result & sign_bit32) == sign_bit32);
			cpu_state.cs_psw.psw_flags.f_ov = 0;
			cpu_state.cs_r[30].u = left % right;
			cpu_state.cs_r[inst.ci_i.i_reg2].u = result;

			cpu_wait = 36;

			break;
		}
		case OP_OR:
		{
			u_int32_t result = cpu_state.cs_r[inst.ci_i.i_reg2].u | cpu_state.cs_r[inst.ci_i.i_reg1].u;
			cpu_setfl_zs0(result);
			cpu_state.cs_r[inst.ci_i.i_reg2].u = result;
			break;
		}
		case OP_AND:
		{
			u_int32_t result = cpu_state.cs_r[inst.ci_i.i_reg2].u & cpu_state.cs_r[inst.ci_i.i_reg1].u;
			cpu_setfl_zs0(result);
			cpu_state.cs_r[inst.ci_i.i_reg2].u = result;
			break;
		}
		case OP_XOR:
		{
			u_int32_t result = cpu_state.cs_r[inst.ci_i.i_reg2].u ^ cpu_state.cs_r[inst.ci_i.i_reg1].u;
			cpu_setfl_zs0(result);
			cpu_state.cs_r[inst.ci_i.i_reg2].u = result;
			break;
		}
		case OP_NOT:
		{
			u_int32_t result = ~cpu_state.cs_r[inst.ci_i.i_reg1].u;
			cpu_setfl_zs0(result);
			cpu_state.cs_r[inst.ci_i.i_reg2].u = result;
			break;
		}
		case OP_MOV2:
		{
			u_int32_t imm = inst.ci_ii.ii_imm5;
			if ((imm & 0b10000) == 0b10000)
				imm|= 0xffffffe0;
			cpu_state.cs_r[inst.ci_ii.ii_reg2].u = imm;
			break;
		}
		case OP_ADD2:
		{
			u_int32_t imm = inst.ci_ii.ii_imm5;
			if ((imm & 0b10000) == 0b10000)
				imm|= 0xffffffe0;
			cpu_state.cs_r[inst.ci_ii.ii_reg2].u = cpu_add(cpu_state.cs_r[inst.ci_ii.ii_reg2].u, imm);
			break;
		}
		case OP_SETF:
		{
			cpu_state.cs_r[inst.ci_ii.ii_reg2].u = cpu_getfl(inst.ci_ii.ii_imm5);
			break;
		}
		case OP_CMP2:
		{
			u_int32_t imm = inst.ci_ii.ii_imm5;
			if ((imm & 0b10000) == 0b10000)
				imm|= 0xffffffe0;
			cpu_sub(cpu_state.cs_r[inst.ci_ii.ii_reg2].u, imm);
			break;
		}
		case OP_SHL2:
			cpu_state.cs_r[inst.ci_ii.ii_reg2].u =
					cpu_shift_left(cpu_state.cs_r[inst.ci_ii.ii_reg2].u, inst.ci_ii.ii_imm5);
			break;
		case OP_SHR2:
			cpu_state.cs_r[inst.ci_ii.ii_reg2].u =
					cpu_shift_right(cpu_state.cs_r[inst.ci_ii.ii_reg2].u, inst.ci_ii.ii_imm5);
			break;
		case OP_CLI:
			cpu_state.cs_psw.psw_flags.f_id = 0;
			break;
		case OP_SAR2:
			if (inst.ci_ii.ii_imm5)
			{
				u_int32_t start = cpu_state.cs_r[inst.ci_ii.ii_reg2].u;
				u_int32_t shift = inst.ci_ii.ii_imm5;
				u_int32_t result = start >> shift;
				cpu_state.cs_psw.psw_flags.f_cy = ((start >> (shift - 1)) & 1);
				cpu_state.cs_psw.psw_flags.f_ov = 0;
				if ((start & sign_bit32) == sign_bit32)
				{
					result|= (0xffffffff << (32 - shift));
					cpu_state.cs_psw.psw_flags.f_s = 1;
				}
				else
					cpu_state.cs_psw.psw_flags.f_s = 0;
				cpu_state.cs_psw.psw_flags.f_z = (result == 0);
				cpu_state.cs_r[inst.ci_ii.ii_reg2].u = result;
			}
			break;
			/*
   OP_TRAP  = 0b011000,
			 cpu_wait = 15;
   */
		case OP_RETI:
			if (!cpu_state.cs_psw.psw_flags.f_ep)
			{
				debug_runtime_errorf(NULL, "Tried to return from interrupt/exception while EP=0\n");
				break;
			}

			if (debug_trace_cpu_jmp)
			{
				debug_str_t addr_s, dest_addr_s;
				u_int32_t dest_addr = (cpu_state.cs_psw.psw_flags.f_np) ? cpu_state.cs_fepc : cpu_state.cs_eipc;
				debug_tracef("cpu.jmp", DEBUG_ADDR_FMT ": RETI %s\n",
				             debug_format_addr(cpu_state.cs_pc, addr_s),
				             debug_format_addr(dest_addr, dest_addr_s));
			}

			if (cpu_state.cs_psw.psw_flags.f_np)
			{
				cpu_state.cs_pc = cpu_state.cs_fepc;
				cpu_state.cs_psw = cpu_state.cs_fepsw;
			}
			else
			{
				cpu_state.cs_pc = cpu_state.cs_eipc;
				cpu_state.cs_psw = cpu_state.cs_eipsw;
			}

			cpu_wait = 10;

			return true;
			/*
   OP_HALT  = 0b011010,
   */
		case OP_LDSR:
			switch (inst.ci_ii.ii_imm5)
			{
				case REGID_EIPC:
					cpu_state.cs_eipc = cpu_state.cs_r[inst.ci_ii.ii_reg2].u;
					break;
				case REGID_EIPSW:
					cpu_state.cs_eipsw.psw_word = cpu_state.cs_r[inst.ci_ii.ii_reg2].u;
					break;
				case REGID_FEPC:
					cpu_state.cs_fepc = cpu_state.cs_r[inst.ci_ii.ii_reg2].u;
					break;
				case REGID_FEPSW:
					cpu_state.cs_fepsw.psw_word = cpu_state.cs_r[inst.ci_ii.ii_reg2].u;
					break;
				case REGID_PSW:
					cpu_state.cs_psw.psw_word = cpu_state.cs_r[inst.ci_ii.ii_reg2].u;
					break;
				case REGID_CHCW:
				{
					u_int32_t chcw = cpu_state.cs_r[inst.ci_ii.ii_reg2].u;
					if (chcw & ~(CPU_CHCW_ICC | CPU_CHCW_ICE))
						debug_runtime_errorf(NULL, "Unsupported CHCW commands 0x%x",
						                     chcw & ~(CPU_CHCW_ICC | CPU_CHCW_ICE));
					cpu_state.cs_chcw = chcw & CPU_CHCW_ICE;
					break;
				}
				default:
					debug_runtime_errorf(NULL, "Unsupported regID %d", inst.ci_ii.ii_imm5);
					debug_enter();
					return false;
			}
			break;
		case OP_STSR:
			switch (inst.ci_ii.ii_imm5)
			{
				case REGID_EIPC:
					cpu_state.cs_r[inst.ci_ii.ii_reg2].u = cpu_state.cs_eipc;
					break;
				case REGID_EIPSW:
					cpu_state.cs_r[inst.ci_ii.ii_reg2].u = cpu_state.cs_eipsw.psw_word;
					break;
				case REGID_FEPC:
					cpu_state.cs_r[inst.ci_ii.ii_reg2].u = cpu_state.cs_fepc;
					break;
				case REGID_PSW:
					cpu_state.cs_r[inst.ci_ii.ii_reg2].u = cpu_state.cs_psw.psw_word;
					break;
				case REGID_CHCW:
					cpu_state.cs_r[inst.ci_ii.ii_reg2].u = cpu_state.cs_chcw;
					break;
				default:
					debug_runtime_errorf(NULL, "Unsupported regID %d", inst.ci_ii.ii_imm5);
					debug_enter();
					return false;
			}
		case OP_SEI:
			cpu_state.cs_psw.psw_flags.f_id = 1;
			break;
		case OP_BSTR:
		{
			u_int32_t *bit_lengthp = &(cpu_state.cs_r[28].u);
			if (!*bit_lengthp)
				break;

			u_int32_t *src_word_addrp = &(cpu_state.cs_r[30].u);
			u_int32_t *src_bit_offp = &(cpu_state.cs_r[27].u);
			u_int32_t *dest_word_addrp = &(cpu_state.cs_r[29].u);
			u_int32_t *dest_bit_offp = &(cpu_state.cs_r[26].u);

			switch (inst.ci_ii.ii_imm5)
			{
				case BSTR_MOVBSU:
					return cpu_movbsu(src_word_addrp, src_bit_offp, bit_lengthp, dest_word_addrp, dest_bit_offp);
				default:
				{
					debug_runtime_errorf(NULL, "Unsupported bitstring instruction");
					return false;
				}
			}
		}
		case OP_MOVEA:
		{
			u_int32_t imm = cpu_extend16(inst.ci_v.v_imm16);
			cpu_state.cs_r[inst.ci_v.v_reg2].s = cpu_state.cs_r[inst.ci_v.v_reg1].s + imm;
			break;
		}
		case OP_ADDI:
		{
			u_int32_t imm = cpu_extend16(inst.ci_v.v_imm16);
			cpu_state.cs_r[inst.ci_v.v_reg2].u = cpu_add(cpu_state.cs_r[inst.ci_v.v_reg1].u, imm);
			break;
		}
		case OP_JR:
		{
			u_int32_t disp = cpu_inst_disp26(&inst);

			if (debug_trace_cpu_jmp)
			{
				u_int32_t target_pc = cpu_state.cs_pc + disp;
				u_int32_t offset;
				struct debug_symbol *target_sym;
				if ((target_sym = debug_resolve_addr(target_pc, &offset)))
				{
					struct debug_symbol *current_sym;
					if ((current_sym = debug_resolve_addr(cpu_state.cs_pc, &offset)) != target_sym)
					{
						debug_str_t addr_s, target_pc_s;
						debug_tracef("cpu.jmp", DEBUG_ADDR_FMT ": Non-local JR to %s",
									 debug_format_addr(cpu_state.cs_pc, addr_s),
									 debug_format_addrsym(target_pc, target_sym, target_pc_s));
					}
				}
			}

			cpu_state.cs_pc+= disp;

			cpu_wait = 3;

			return true;
		}
		case OP_JAL:
		{
			u_int32_t disp = cpu_inst_disp26(&inst);
			if (debug_trace_cpu_jmp)
			{
				debug_str_t addr_s, dest_addr_s;
				debug_tracef("cpu.jmp", DEBUG_ADDR_FMT ": CALL %s(0x%08x, 0x%08x, 0x%08x, 0x%08x)\n",
				             debug_format_addr(cpu_state.cs_pc, addr_s),
				             debug_format_addr(cpu_state.cs_pc + disp, dest_addr_s),
				             cpu_state.cs_r[6].u,
				             cpu_state.cs_r[7].u,
				             cpu_state.cs_r[8].u,
				             cpu_state.cs_r[9].u);
			}
			cpu_state.cs_r[31].u = cpu_state.cs_pc + 4;
			cpu_state.cs_pc+= disp;

			cpu_wait = 3;

			return true;
		}
		case OP_ORI:
		{
			u_int32_t result = cpu_state.cs_r[inst.ci_v.v_reg1].u | inst.ci_v.v_imm16;
			cpu_setfl_zs0(result);
			cpu_state.cs_r[inst.ci_v.v_reg2].u = result;
			break;
		}
		case OP_ANDI:
		{
			u_int32_t result = cpu_state.cs_r[inst.ci_v.v_reg1].u & inst.ci_v.v_imm16;
			cpu_setfl_zs0(result);
			if (inst.ci_v.v_reg2)
				cpu_state.cs_r[inst.ci_v.v_reg2].u = result;
			break;
		}
		case OP_XORI:
		{
			u_int32_t result = cpu_state.cs_r[inst.ci_v.v_reg1].u ^ inst.ci_v.v_imm16;
			cpu_setfl_zs0(result);
			cpu_state.cs_r[inst.ci_v.v_reg2].u = result;
			break;
		}
		case OP_MOVHI:
			cpu_state.cs_r[inst.ci_v.v_reg2].u = cpu_state.cs_r[inst.ci_v.v_reg1].u | (inst.ci_v.v_imm16 << 16);
			break;
		case OP_LD_B:
		case OP_IN_B:
		{
			u_int32_t addr = cpu_state.cs_r[inst.ci_vi.vi_reg1].u + inst.ci_vi.vi_disp16;
			u_int8_t value;
			u_int mem_wait;
			if (!mem_read(addr, &value, sizeof(value), false, &mem_wait))
				return false;
			if ((value & 0x80) == 0x80)
				cpu_state.cs_r[inst.ci_vi.vi_reg2].u = 0xffffff00 | value;
			else
				cpu_state.cs_r[inst.ci_vi.vi_reg2].u = value;
			if (debug_watches)
				debug_watch_read(cpu_state.cs_pc, addr, value, 1);

			cpu_wait = 3 + mem_wait; // 1-2 for successive loads

			break;
		}
		case OP_LD_H:
		case OP_IN_H:
		{
			u_int32_t addr = cpu_state.cs_r[inst.ci_vi.vi_reg1].u + inst.ci_vi.vi_disp16;
			u_int16_t value;
			u_int mem_wait;
			if (!mem_read(addr, &value, sizeof(value), false, &mem_wait))
				return false;
			// TODO: Use (int16_t) here
			if ((value & 0x8000) == 0x8000)
				cpu_state.cs_r[inst.ci_vi.vi_reg2].u = 0xffff0000 | value;
			else
				cpu_state.cs_r[inst.ci_vi.vi_reg2].u = value;
			if (debug_watches)
				debug_watch_read(cpu_state.cs_pc, addr, value, 2);

			cpu_wait = 3 + mem_wait; // 1-2 for successive loads

			break;
		}
		case OP_LD_W:
		case OP_IN_W:
		{
			u_int32_t addr = cpu_state.cs_r[inst.ci_vi.vi_reg1].u + inst.ci_vi.vi_disp16;
			u_int mem_wait;
			if (!mem_read(addr, cpu_state.cs_r + inst.ci_vi.vi_reg2, sizeof(*cpu_state.cs_r), false, &mem_wait))
				return false;
			if (debug_watches)
				debug_watch_read(cpu_state.cs_pc, addr, cpu_state.cs_r[inst.ci_vi.vi_reg2].u, 4);

			cpu_wait = 3 + mem_wait; // 1-2 for successive loads

			break;
		}
		case OP_ST_B:
		case OP_OUT_B:
		{
			u_int32_t addr = cpu_state.cs_r[inst.ci_vi.vi_reg1].u + inst.ci_vi.vi_disp16;
			u_int8_t value = cpu_state.cs_r[inst.ci_vi.vi_reg2].u & 0xff;
			u_int mem_wait;
			if (!mem_write(addr, &value, sizeof(value), &mem_wait))
				return false;
			if (debug_watches)
				debug_watch_write(cpu_state.cs_pc, addr, value, 1);

			cpu_wait = 1 + mem_wait; // 2 for successive stores

			break;
		}
		case OP_ST_H:
		case OP_OUT_H:
		{
			u_int32_t addr = cpu_state.cs_r[inst.ci_vi.vi_reg1].u + inst.ci_vi.vi_disp16;
			u_int16_t value = cpu_state.cs_r[inst.ci_vi.vi_reg2].u & 0xffff;
			u_int mem_wait;
			if (!mem_write(addr, &value, sizeof(value), &mem_wait))
				return false;
			if (debug_watches)
				debug_watch_write(cpu_state.cs_pc, addr, value, 2);

			cpu_wait = 1 + mem_wait; // 2 for successive stores

			break;
		}
		case OP_ST_W:
		case OP_OUT_W:
		{
			u_int32_t addr = cpu_state.cs_r[inst.ci_vi.vi_reg1].u + inst.ci_vi.vi_disp16;
			u_int32_t value = cpu_state.cs_r[inst.ci_vi.vi_reg2].u;
			u_int mem_wait;
			if (!mem_write(addr, &value, sizeof(value), &mem_wait))
				return false;
			if (debug_watches)
				debug_watch_write(cpu_state.cs_pc, addr, value, 4);

			cpu_wait = 1 + mem_wait; // 2 for successive stores

			break;
		}
			/*
   OP_CAXI  = 0b111010,
			 cpu_wait = 22;
   */
		case OP_FLOAT:
			switch (inst.vii_subop)
			{
				case FLOAT_CMPF_S:
				{
					float left = cpu_state.cs_r[inst.vii_reg2].f, right = cpu_state.cs_r[inst.vii_reg1].f;
					if (cpu_float_reserved(left) || cpu_float_reserved(right))
						return false;
					cpu_subf(left, right);

					cpu_wait = 8; // 7-10

					break;
				}
				case FLOAT_CVT_WS:
					cpu_state.cs_r[inst.vii_reg2].f = (float)cpu_state.cs_r[inst.vii_reg1].s;
					if ((int32_t)cpu_state.cs_r[inst.vii_reg2].f != cpu_state.cs_r[inst.vii_reg1].s)
						cpu_state.cs_psw.psw_flags.f_fpr = 1;

					cpu_wait = 10; // 5-16

					break;
				case FLOAT_CVT_SW:
				{
					float source = cpu_state.cs_r[inst.vii_reg1].f;
					if (cpu_float_reserved(source))
						return false;
					if (source >= (double)INT32_MAX + 0.5 || source <= (double)INT32_MIN - 0.5)
					{
						cpu_state.cs_psw.psw_flags.f_fiv = 1;
						fputs("TODO: Floating-point invalid operation exception\n", stderr);
						raise(SIGINT);
						return false;
					}
					cpu_setfl_float_zsoc(source);
					cpu_state.cs_r[inst.vii_reg2].s = (int32_t)lroundf(source);
					if ((double)cpu_state.cs_r[inst.vii_reg2].s != source)
						cpu_state.cs_psw.psw_flags.f_fpr = 1;

					cpu_wait = 11; // 9-14

					break;
				}
				case FLOAT_ADDF_S:
				{
					float left = cpu_state.cs_r[inst.vii_reg2].f, right = cpu_state.cs_r[inst.vii_reg1].f;
					if (cpu_float_reserved(left) || cpu_float_reserved(right))
						return false;
					double result = (double)left + right;
					cpu_setfl_float_zsoc(result);
					cpu_setfl_float(result);
					cpu_state.cs_r[inst.vii_reg2].f = (float)result;

					cpu_wait = 18; // 9-28

					break;
				}
				case FLOAT_SUBF_S:
				{
					float left = cpu_state.cs_r[inst.vii_reg2].f, right = cpu_state.cs_r[inst.vii_reg1].f;
					if (cpu_float_reserved(left) || cpu_float_reserved(right))
						return false;
					double result = cpu_subf(left, right);
					cpu_setfl_float(result);
					cpu_state.cs_r[inst.vii_reg2].f = (float)result;

					cpu_wait = 20; // 12-28

					break;
				}
				case FLOAT_MULF_S:
				{
					float left = cpu_state.cs_r[inst.vii_reg2].f, right = cpu_state.cs_r[inst.vii_reg1].f;
					if (cpu_float_reserved(left) || cpu_float_reserved(right))
						return false;
					double result = (double)left * right;
					cpu_setfl_float_zsoc(result);
					cpu_setfl_float(result);
					cpu_state.cs_r[inst.vii_reg2].f = (float)result;

					cpu_wait = 19; // 8-30

					break;
				}
				case FLOAT_DIVF_S:
				{
					float left = cpu_state.cs_r[inst.vii_reg2].f, right = cpu_state.cs_r[inst.vii_reg1].f;
					if (right == 0)
					{
						if (left == 0)
						{
							cpu_state.cs_psw.psw_flags.f_fiv = 1;
							fputs("TODO: Invalid operation exception\n", stderr);
							raise(SIGINT);
							return false;
						}
						else if (cpu_float_reserved(left))
							return false;
						else
						{
							cpu_state.cs_psw.psw_flags.f_fzd = 1;
							fputs("TODO: Divide by zero exception\n", stderr);
							raise(SIGINT);
							return false;
						}
					}
					else if (cpu_float_reserved(left) || cpu_float_reserved(right))
						return false;
					double result = (double)left / right;
					cpu_setfl_float_zsoc(result);
					cpu_setfl_float(result);
					cpu_state.cs_r[inst.vii_reg2].f = (float)result;

					cpu_wait = 44;

					break;
				}
				case FLOAT_XB:
				{
					if (inst.vii_reg1 != 0)
						debug_runtime_errorf(NULL, "reg1 operand %s should be r0 for XB instruction",
						                     debug_rnames[inst.vii_reg1]);
					u_int8_t b0 = cpu_state.cs_r[inst.vii_reg2].u8s[0];
					cpu_state.cs_r[inst.vii_reg2].u8s[0] = cpu_state.cs_r[inst.vii_reg2].u8s[1];
					cpu_state.cs_r[inst.vii_reg2].u8s[1] = b0;
					break;
				}
				case FLOAT_XH:
				{
					if (inst.vii_reg1 != 0)
						debug_runtime_errorf(NULL, "reg1 operand %s should be r0 for XH instruction",
						                     debug_rnames[inst.vii_reg1]);
					u_int32_t u32 = cpu_state.cs_r[inst.vii_reg2].u << 16;
					u32|= cpu_state.cs_r[inst.vii_reg2].u >> 16;
					cpu_state.cs_r[inst.vii_reg2].u = u32;
					break;
				}
					/*
					case FLOAT_TRNC_SW:
					 cpu_wait = 11; // 8-14
						break;
					 */
				case FLOAT_MPYHW:
					// TODO: Are there really no flags set?
					cpu_state.cs_r[inst.vii_reg2].s =
							cpu_state.cs_r[inst.vii_reg1].s16 * cpu_state.cs_r[inst.vii_reg2].s16;
					break;
				default:
					debug_runtime_errorf(NULL, "TODO: execute instruction");
					debug_enter();
					return false;
			}
			break;
		default:
			if (inst.ci_iii.iii_opcode == OP_BCOND)
			{
				bool branch = cpu_getfl(inst.ci_iii.iii_cond);
				if (branch)
				{
					u_int32_t disp = cpu_extend9(inst.ci_iii.iii_disp9);
					cpu_state.cs_pc+= disp;

					cpu_wait = 3;

					return true;
				}

				break;
			}
			debug_runtime_errorf(NULL, "TODO: execute instruction");
			debug_enter();
			return false;
	}
	if (cpu_state.cs_r[0].s)
	{
		cpu_state.cs_r[0].s = 0;
		if (!debug_runtime_errorf(NULL, "r0 written to with non-zero value\n"))
			return false;
	}

	assert(cpu_state.cs_pc == old_pc);
	cpu_state.cs_pc+= cpu_inst_size(&inst);

	return true;
}

static void
cpu_assert_reg(const char *dis, unsigned reg, union cpu_reg value)
{
	if (cpu_state.cs_r[reg].u != value.u)
	{
		debug_runtime_errorf(NULL, "*** Test failure: %s\n\t%s (0x%08x) should be 0x%08x",
		        dis, debug_rnames[reg], cpu_state.cs_r[reg].u, value.u);
		abort();
	}
}

static void
cpu_assert_flag(const char *dis, const char *name, bool flag, bool value)
{
	if (flag != value)
	{
		debug_runtime_errorf(NULL, "*** Test failure: %s\n\t%s flag (%d) should be %s",
		        dis, name, flag, (value) ? "set" : "reset");
		abort();
	}
}

static void
cpu_assert_overflow(const char *dis, bool overflow)
{
	cpu_assert_flag(dis, "overflow", cpu_state.cs_psw.psw_flags.f_ov, overflow);
}

static void
cpu_assert_sign(const char *dis, bool sign)
{
	cpu_assert_flag(dis, "sign", cpu_state.cs_psw.psw_flags.f_s, sign);
}

static void
cpu_assert_carry(const char *dis, bool carry)
{
	cpu_assert_flag(dis, "carry", cpu_state.cs_psw.psw_flags.f_cy, carry);
}

static void
cpu_assert_zero(const char *dis, bool zero)
{
	cpu_assert_flag(dis, "zero", cpu_state.cs_psw.psw_flags.f_z, zero);
}

static void
cpu_assert_fov(const char *dis)
{
	cpu_assert_flag(dis, "floating-point overflow", cpu_state.cs_psw.psw_flags.f_fov, 1);
}

static void
cpu_assert_fud(const char *dis)
{
	cpu_assert_flag(dis, "floating-point underflow", cpu_state.cs_psw.psw_flags.f_fud, 1);
}

static void
cpu_assert_fpr(const char *dis)
{
	cpu_assert_flag(dis, "floating-point precision loss", cpu_state.cs_psw.psw_flags.f_fpr, 1);
}

static void
cpu_assert_mem(u_int32_t addr, u_int32_t expected, u_int byte_size)
{
	u_int32_t actual;
	assert(byte_size <= sizeof(actual));
	u_int mem_wait;
	if (!mem_read(addr, &(actual), sizeof(actual), false, &mem_wait))
		abort();
	if (bcmp(&actual, &expected, byte_size))
	{
		debug_str_t actual_bin_s, expected_bin_s;
		debug_runtime_errorf(NULL, "*** Test failure: memory at 0x%08x is\n\t%s, should be\n\t%s",
		                     addr,
		                     debug_format_binary(actual, byte_size * 8, actual_bin_s),
		                     debug_format_binary(expected, byte_size * 8, expected_bin_s));
	}
}

static void
cpu_test_add(int32_t left, int32_t right, int32_t result, bool overflow, bool carry, bool zero)
{
	union cpu_inst inst;
	inst.ci_v.v_opcode = OP_ADD;
	cpu_state.cs_r[7].s = left;
	inst.ci_v.v_reg2 = 7;
	cpu_state.cs_r[6].s = right;
	inst.ci_v.v_reg1 = 6;
	cpu_state.cs_psw.psw_flags.f_ov = (!overflow);
	cpu_state.cs_psw.psw_flags.f_cy = (!carry);
	cpu_state.cs_psw.psw_flags.f_z = (!zero);
	const char *dis = debug_disasm(&inst, 0, debug_current_context());
	cpu_exec(inst);
	union cpu_reg result_reg = {.s = result};
	cpu_assert_reg(dis, 7, result_reg);
	cpu_assert_overflow(dis, overflow);
	cpu_assert_carry(dis, carry);
	cpu_assert_zero(dis, zero);
}

static void
cpu_test_sub(int32_t left, int32_t right, int32_t result, bool overflow, bool carry)
{
	union cpu_inst inst;
	inst.ci_i.i_opcode = OP_SUB;
	cpu_state.cs_r[7].s = left;
	inst.ci_i.i_reg2 = 7;
	cpu_state.cs_r[6].s = right;
	inst.ci_i.i_reg1 = 6;
	cpu_state.cs_psw.psw_flags.f_ov = (!overflow);
	cpu_state.cs_psw.psw_flags.f_cy = (!carry);
	const char *dis = debug_disasm(&inst, 0, debug_current_context());
	cpu_exec(inst);
	union cpu_reg result_reg = {.s = result};
	cpu_assert_reg(dis, 7, result_reg);
	cpu_assert_overflow(dis, overflow);
	cpu_assert_carry(dis, carry);
}

static void
cpu_test_mul(int32_t left, int32_t right, u_int32_t result, bool overflow, bool sign, u_int32_t carry)
{
	union cpu_inst inst;
	inst.ci_i.i_opcode = OP_MUL;
	cpu_state.cs_r[7].s = left;
	inst.ci_i.i_reg2 = 7;
	cpu_state.cs_r[6].s = right;
	inst.ci_i.i_reg1 = 6;
	cpu_state.cs_r[30].u = 0xdeadc0de;
	cpu_state.cs_psw.psw_flags.f_ov = (!overflow);
	cpu_state.cs_psw.psw_flags.f_s = (!sign);
	const char *dis = debug_disasm(&inst, 0, debug_current_context());
	cpu_exec(inst);
	union cpu_reg result_reg = {.u = result};
	cpu_assert_reg(dis, 7, result_reg);
	cpu_assert_overflow(dis, overflow);
	cpu_assert_sign(dis, sign);
	cpu_assert_reg(dis, 30, (union cpu_reg){.u = carry});
}

static void
cpu_test_div(int32_t left, int32_t right, u_int32_t result, u_int32_t rem, bool overflow, bool sign)
{
	union cpu_inst inst;
	inst.ci_i.i_opcode = OP_DIV;
	cpu_state.cs_r[7].s = left;
	inst.ci_i.i_reg2 = 7;
	cpu_state.cs_r[6].s = right;
	inst.ci_i.i_reg1 = 6;
	cpu_state.cs_r[30].u = 0xdeadc0de;
	cpu_state.cs_psw.psw_flags.f_ov = (!overflow);
	cpu_state.cs_psw.psw_flags.f_s = (!sign);
	const char *dis = debug_disasm(&inst, 0, debug_current_context());
	cpu_exec(inst);
	cpu_assert_reg(dis, 7, (union cpu_reg){.u = result});
	cpu_assert_reg(dis, 30, (union cpu_reg){.u = rem});
	cpu_assert_overflow(dis, overflow);
	cpu_assert_sign(dis, sign);
}

static void
cpu_test_subf(float left, float right, float result, bool overflow, bool underflow, bool degraded)
{
	union cpu_inst inst;
	inst.vii_opcode = OP_FLOAT;
	inst.vii_subop = FLOAT_SUBF_S;
	cpu_state.cs_r[7].f = left;
	inst.vii_reg2 = 7;
	cpu_state.cs_r[6].f = right;
	inst.vii_reg1 = 6;
	cpu_state.cs_psw.psw_flags.f_fov = 0;
	cpu_state.cs_psw.psw_flags.f_fud = 0;
	cpu_state.cs_psw.psw_flags.f_fpr = 0;
	const char *dis = debug_disasm(&inst, 0, debug_current_context());
	cpu_exec(inst);
	cpu_assert_reg(dis, 7, (union cpu_reg){.f = result});
	if (overflow)
		cpu_assert_fov(dis);
	if (underflow)
		cpu_assert_fud(dis);
	if (degraded)
		cpu_assert_fpr(dis);
}

static void
cpu_test_movbsu(const u_int8_t src_bytes[],
                u_int32_t num_src_bytes,
                const u_int8_t dest_fill,
                u_int bit_length,
                u_int src_word_off,
                u_int src_bit_off,
                u_int dest_word_off,
                u_int dest_bit_off,
                const u_int8_t dest_bytes[],
                u_int32_t num_dest_bytes)
{
	u_int mem_wait;
	for (u_int i = 0; i < num_src_bytes; ++i)
		if (!mem_write(0x05000100 + i, &(src_bytes[i]), 1, &mem_wait))
			abort();

	for (u_int i = 0; i < num_dest_bytes; ++i)
		if (!mem_write(0x05000200 + i, &dest_fill, 1, &mem_wait))
			abort();

	cpu_state.cs_r[30].u = 0x05000100 + src_word_off;
	cpu_state.cs_r[29].u = 0x05000200 + dest_word_off;
	cpu_state.cs_r[28].u = bit_length;
	cpu_state.cs_r[27].u = src_bit_off;
	cpu_state.cs_r[26].u = dest_bit_off;
	union cpu_inst inst = {.ci_ii = {.ii_opcode = OP_BSTR, .ii_imm5 = BSTR_MOVBSU}};
	u_int32_t old_pc = cpu_state.cs_pc;
	do
		cpu_exec(inst);
	while (cpu_state.cs_pc == old_pc);

	for (u_int i = 0; i < num_dest_bytes; ++i)
		cpu_assert_mem(0x05000200 + i, dest_bytes[i], 1);
}

void
cpu_test(void)
{
	fputs("Running CPU self-test\n", stderr);

	cpu_test_add(1, 1, 2, false, false, false);
	cpu_test_add(2147483647, 1, -2147483648, true, false, false);
	cpu_test_add(1, 2147483647, -2147483648, true, false, false);
	cpu_test_add(2147483646, 1, 2147483647, false, false, false);
	cpu_test_add(1, 2147483646, 2147483647, false, false, false);
	cpu_test_add(2147450881, 32767, -2147483648, true, false, false);
	cpu_test_add(2147450880, 32767, 2147483647, false, false, false);
	cpu_test_add(-1, -1, -2, false, true, false);
	cpu_test_add(-2147483648, -1, 2147483647, true, true, false);
	cpu_test_add(1, -1, 0, false, true, true);

	cpu_test_sub(1, 0, 1, false, false);
	cpu_test_sub(1, 1, 0, false, false);
	cpu_test_sub(2, 1, 1, false, false);
	cpu_test_sub(0, 1, -1, false, true);
	cpu_test_sub(0, 2, -2, false, true);
	cpu_test_sub(-1, 0, -1, false, false);
	cpu_test_sub(-1, -2, 1, false, false);
	cpu_test_sub(-2147483648, 1, 2147483647, true, false);
	cpu_test_sub(2147483646, 2147483647, -1, false, true);
	cpu_test_sub(2147483647, -1, -2147483648, true, true);
	cpu_test_sub(2147483647, -2147483648, -1, true, true);
	cpu_test_sub(2147483647, -2147483647, -2, true, true);
	cpu_test_sub(0, 9, -9, false, true);

	cpu_test_mul(1, 1, 1, false, false, 0);
	cpu_test_mul(1, -1, -1, false, true, 0xffffffff);
	cpu_test_mul(-1, 1, -1, false, true, 0xffffffff);
	cpu_test_mul(0x7fffffff, 0x7fffffff, 1, true, false, 0x3fffffff);
	cpu_test_mul(0x40000000, 4, 0, true, false, 1);

	cpu_test_div(0x80000000, 0xffffffff, 0x80000000, 0, true, true);
	cpu_test_div(0x80000001, 0xffffffff, 0x7fffffff, 0, false, false);
	cpu_test_div(1, 1, 1, 0, false, false);
	cpu_test_div(2, 1, 2, 0, false, false);
	cpu_test_div(1, 2, 0, 1, false, false);
	cpu_test_div(1000, 500, 2, 0, false, false);
	cpu_test_div(1001, 500, 2, 1, false, false);
	cpu_test_div(-500, 2, -250, 0, false, true);

	cpu_test_subf(0x1p0f, 0x1p-24f, 0x1.fffffep-1, false, false, false);
	cpu_test_subf(0x1p0f, 0x1p-25f, 0x1p0f, false, false, true);
	cpu_test_subf(-0x1p0f, -0x1p-24f, -0x1.fffffep-1f, false, false, false);
	cpu_test_subf(-0x1p0f, -0x1p-25f, -0x1p0f, false, false, true);
	cpu_test_subf(0x1p0f, -0x1.1p-24f, 0x1.000002p0f, false, false, false);
	cpu_test_subf(0x1p0f, -0x1p-25f, 0x1p0f, false, false, true);
	cpu_test_subf(-FLT_MAX, 0x1p102f, -FLT_MAX, false, false, true);
	cpu_test_subf(-FLT_MAX, 0x1p103f, -INFINITY, true, false, false);

	u_int8_t src_bytes1[] = {0xde, 0xad, 0xc0, 0xde};
	cpu_test_movbsu(src_bytes1, sizeof(src_bytes1), 0xff, 32, 0, 0, 0, 0, src_bytes1, sizeof(src_bytes1));
	u_int8_t dest_bytes1[] = {0xff, 0xff, 0xff, 0xff, 0xde, 0xad, 0xc0, 0xde, 0xff, 0xff, 0xff, 0xff};
	cpu_test_movbsu(src_bytes1, sizeof(src_bytes1), 0xff, 32, 0, 0, 4, 0, dest_bytes1, sizeof(dest_bytes1));
	u_int8_t dest_bytes2[] = {0xde, 0xad, 0xc0, 0xff};
	cpu_test_movbsu(src_bytes1, sizeof(src_bytes1), 0xff, 24, 0, 0, 0, 0, dest_bytes2, sizeof(dest_bytes2));
	//const u_int8_t src_byte1 =  {0b01000000};
	//const u_int8_t dest_byte1 = {0b10000000};
	//const u_int8_t dest_byte2 = {0b10101110};
	//cpu_test_movbsu(&src_byte, sizeof(src_byte), 0b10101010, 1, 0, 1, 0, 5, &dest_byte, sizeof(dest_byte));
	/*
	const u_int8_t src_bytes2[] = {
			0b01000110, 0b11000001, 0b01001110, 0b01011101,
			0b10111010, 0b01110010, 0b10000011, 0b01100010,
			0b01001110, 0b01011101, 0b01000110, 0b11000001,
			0b10000011, 0b01100010, 0b10111010, 0b01110010,
	};
	cpu_test_movbsu(src_bytes2, sizeof(src_bytes2), 0b10101010, 128, 0, 0, 0, 0, src_bytes2, sizeof(src_bytes2));
	const u_int8_t dest_bytes1[] = {
			0b10101010,
			0b01000110, 0b11000001, 0b01001110, 0b01011101,
			0b10111010, 0b01110010, 0b10000011, 0b01100010,
			0b01001110, 0b01011101, 0b01000110, 0b11000001,
			0b10000011, 0b01100010, 0b10111010, 0b01110010,
			0b10101010,
	};
	cpu_test_movbsu(src_bytes, sizeof(src_bytes), 0b10101010, 128, 0, 0, 0, 8, dest_bytes1, sizeof(dest_bytes1));
	 */

	cpu_reset();
}

bool
cpu_step(void)
{
	if (cpu_wait > 1)
	{
		--cpu_wait;
		return true;
	}

	if (debug_break != DEBUG_ADDR_NONE && cpu_state.cs_pc == debug_break)
	{
		fprintf(stderr, "\nStopped at breakpoint\n");
		debugging = true;
	}

	if (debugging)
	{
		if (!debug_step())
			return false;
	}

	union cpu_inst inst;
	if (!cpu_fetch(cpu_state.cs_pc, &inst))
	{
		fprintf(stderr, "TODO: bus error fetching inst from PC 0x%08x\n", cpu_state.cs_pc);
		return false;
	}

	if (debug_trace_cpu)
	{
		debug_str_t addr_s;
		debug_tracef("cpu", DEBUG_ADDR_FMT ": %s\n",
		             debug_format_addr(cpu_state.cs_pc, addr_s),
		             debug_disasm(&inst, cpu_state.cs_pc, debug_current_context()));
	}

	if (!cpu_exec(inst))
		return false;

	++main_stats.ms_insts;
	return true;
}

void
cpu_intr(enum nvc_intlevel level)
{
	if (!cpu_state.cs_psw.psw_flags.f_np && !cpu_state.cs_psw.psw_flags.f_ep && !cpu_state.cs_psw.psw_flags.f_id)
	{
		if (level >= cpu_state.cs_psw.psw_flags.f_i)
		{
			if (debug_trace_cpu_int)
			{
				debug_str_t addr_s;
				debug_tracef("cpu", DEBUG_ADDR_FMT ": Interrupt level=%d\n",
				             debug_format_addr(cpu_state.cs_pc, addr_s), level);
			}

			cpu_state.cs_eipc = cpu_state.cs_pc;
			cpu_state.cs_eipsw = cpu_state.cs_eipsw;
			cpu_state.cs_ecr.ecr_eicc = 0xfe00 | (level << 4);
			cpu_state.cs_psw.psw_flags.f_ep = 1;
			cpu_state.cs_psw.psw_flags.f_id = 1;
			cpu_state.cs_psw.psw_flags.f_ae = 0;
			cpu_state.cs_psw.psw_flags.f_i = MIN(level + 1, 15);

			if (debug_trace_cpu_jmp)
			{
				debug_str_t addr_s, dest_addr_s;
				debug_tracef("cpu.jmp", DEBUG_ADDR_FMT ": INT%u %s\n",
				             debug_format_addr(cpu_state.cs_pc, addr_s),
				             level,
				             debug_format_addr(cpu_state.cs_ecr.ecr_eicc, dest_addr_s));
			}

			cpu_state.cs_pc = cpu_state.cs_ecr.ecr_eicc;

			++main_stats.ms_intrs;
		}
	}
}

/* VIP */
#if INTERFACE
	struct vip_chr
	{
		u_int16_t vc_rows[8];
	};

	struct vip_vrm
	{
		u_int8_t vv_left0[0x6000];
		struct vip_chr vv_chr0[512];
		u_int8_t vv_left1[0x6000];
		struct vip_chr vv_chr1[512];
		u_int8_t vv_right0[0x6000];
		struct vip_chr vv_chr2[512];
		u_int8_t vv_right1[0x6000];
		struct vip_chr vv_chr3[512];
	};

#   define VIP_CHR_FIND(chrno) &(vip_vrm.vv_chr0[(((chrno) & 0x600) << 2) | (chrno) & 0x1ff])

	struct vip_bgsc
	{
		unsigned vb_chrno : 11 __attribute__((packed));
		unsigned vb_rfu1 : 1 __attribute__((packed));
		unsigned vb_bvflp : 1 __attribute__((packed));
		unsigned vb_bhflp : 1 __attribute__((packed));
		unsigned vb_gplts : 2 __attribute__((packed));
	};

#   define vip_bgseg_width (64)
#   define vip_bgseg_height (64)

	typedef struct vip_bgsc vip_bgseg_t[vip_bgseg_width * vip_bgseg_height];

	struct vip_oam
	{
		int16_t vo_jx;
		unsigned vo_jp : 14 __attribute__((packed));
		unsigned vo_jron : 1 __attribute__((packed));
		unsigned vo_jlon : 1 __attribute__((packed));
		int16_t vo_jy;
		unsigned vo_jca : 11 __attribute__((packed));
		unsigned vo_rfu1 : 1 __attribute__((packed));
		unsigned vo_jvflp : 1 __attribute__((packed));
		unsigned vo_jhflp : 1 __attribute__((packed));
		unsigned vo_jplts : 2 __attribute__((packed));
	};

	struct vip_affine
	{
		int16_t va_mx;
		int16_t va_mp;
		int16_t va_my;
		int16_t va_dx;
		int16_t va_dy;
		u_int16_t va_rfu[3];
	};

	enum vip_world_bgm
	{
		WORLD_BGM_NORMAL = 0b00,
		WORLD_BGM_H_BIAS = 0b01,
		WORLD_BGM_AFFINE = 0b10,
		WORLD_BGM_OBJ = 0b11
	};

	struct vip_world_att
	{
		unsigned vwa_bgmap_base : 4 __attribute__((packed));
		unsigned vwa_rfu1 : 2 __attribute__((packed));
		unsigned vwa_end : 1 __attribute__((packed));
		unsigned vwa_over : 1 __attribute__((packed));
		unsigned vwa_scy : 2 __attribute__((packed));
		unsigned vwa_scx : 2 __attribute__((packed));
		unsigned vwa_bgm : 2 __attribute__((packed));
		unsigned vwa_ron : 1 __attribute__((packed));
		unsigned vwa_lon : 1 __attribute__((packed));
		int16_t vwa_gx;
		int16_t vwa_gp;
		int16_t vwa_gy;
		int16_t vwa_mx;
		int16_t vwa_mp;
		u_int16_t vwa_my;
		u_int16_t vwa_w;
		u_int16_t vwa_h;
		u_int16_t vwa_param_base;
		u_int16_t vwa_over_chrno;
		u_int16_t vwa_max_scr_y;
		u_int16_t vwa_first_obj;
		u_int16_t vwa_last_obj;
		u_int16_t vwa_reserved[2];
	};

	struct vip_hbias
	{
		int16_t vh_hofstl, vh_hofstr;
	};

	union vip_params
	{
		struct vip_hbias vp_hbias;
		struct vip_affine vp_affine;
	};

	struct vip_ctc
	{
		u_int8_t vc_length;
		u_int8_t vc_repeat;
	};

	struct vip_dram
	{
		union
		{
			vip_bgseg_t s_bgsegs[14];
			u_int16_t s_param_tbl[0xec00];
		} vd_shared;
		struct vip_world_att vd_world_atts[32];
		struct vip_ctc vd_left_clm_tbl[256];
		struct vip_ctc vd_right_clm_tbl[256];
		struct vip_oam vd_oam[1024];
	};
#endif // INTERFACE

struct vip_dram vip_dram;

#if INTERFACE
	enum vip_intflag
	{
		VIP_SCANERR = (1 << 0),
		VIP_LFBEND = (1 << 1),
		VIP_RFBEND = (1 << 2),
		VIP_GAMESTART = (1 << 3),
		VIP_FRAMESTART = (1 << 4),
		VIP_SBHIT = (1 << 13),
		VIP_XPEND = (1 << 14),
		VIP_TIMEERR = (1 << 15)
	};

	struct vip_dpctrl
	{
		unsigned vd_dprst: 1 __attribute__((packed));
		unsigned vd_disp : 1 __attribute__((packed));
		unsigned vd_dpbsy_l_fb0 : 1 __attribute__((packed));
		unsigned vd_dpbsy_r_fb0 : 1 __attribute__((packed));
		unsigned vd_dpbsy_l_fb1 : 1 __attribute__((packed));
		unsigned vd_dpbsy_r_fb1 : 1 __attribute__((packed));
		unsigned vd_scanrdy : 1 __attribute__((packed));
		unsigned vd_fclk : 1 __attribute__((packed));
		unsigned vd_re : 1 __attribute__((packed));
		unsigned vd_synce : 1 __attribute__((packed));
		unsigned vd_lock : 1 __attribute__((packed));
		unsigned vd_unused : 5 __attribute__((packed));
	};

	struct vip_xpctrl
	{
		unsigned vx_xprst : 1 __attribute__((packed));
		unsigned vx_xpen : 1 __attribute__((packed));
		unsigned vx_xpbsy_fb0 : 1 __attribute__((packed));
		unsigned vx_xpbsy_fb1 : 1 __attribute__((packed));
		unsigned vx_overtime : 1 __attribute__((packed));
		unsigned vx_unused : 3 __attribute__((packed));
		unsigned vx_sbcount : 5 __attribute__((packed)); // AKA sbcmp
		unsigned vx_unused2 : 2 __attribute__((packed));
		unsigned vx_sbout : 1 __attribute__((packed));
	};

	struct vip_regs
	{
		u_int16_t vr_intpnd;
		u_int16_t vr_intenb;
		u_int16_t vr_intclr;
		u_int16_t vr_rfu1[13];
		struct vip_dpctrl vr_dpstts;
		struct vip_dpctrl vr_dpctrl;
		u_int8_t vr_brta;
		u_int8_t vr_rfu2;
		u_int8_t vr_brtb;
		u_int8_t vr_rfu3;
		u_int8_t vr_brtc;
		u_int8_t vr_rfu4;
		u_int8_t vr_rest;
		u_int8_t vr_rfu5;
		u_int16_t vr_frmcyc;
		u_int16_t vr_undef2;
		u_int16_t vr_cta;
		u_int16_t vr_undef3[7];
		struct vip_xpctrl vr_xpstts;
		struct vip_xpctrl vr_xpctrl;
		u_int16_t vr_ver;
		u_int16_t vr_undef4;
		u_int16_t vr_spt[4];
		u_int16_t vr_undef5[8];
		u_int16_t vr_gplt[4];
		u_int16_t vr_jplt[4];
		u_int16_t vr_bkcol;
	};

#   define VIP_MAX_BRIGHT (212)

	struct vip_vspan
	{
		u_int vvs_scr_y;
		u_int vvs_win_y;
		u_int vvs_height;
	};

	struct vip_hspan
	{
		u_int vhs_scr_x;
		int vhs_win_x;
		u_int vhs_width;
	};
#endif // INTERFACE

static const enum vip_intflag vip_dpints =
		VIP_SCANERR | VIP_LFBEND | VIP_RFBEND | VIP_GAMESTART | VIP_FRAMESTART | VIP_TIMEERR;
static const enum vip_intflag vip_xpints = VIP_SBHIT | VIP_XPEND | VIP_TIMEERR;

struct vip_vrm vip_vrm;
struct vip_regs vip_regs;
u_int32_t vip_row_mask = (1 << 28) - 1;
u_int32_t vip_world_mask = ~0;

static u_int vip_disp_index = 0;
static u_int vip_frame_cycles = 0;
bool vip_use_bright = true;

bool
vip_init(void)
{
	mem_segs[MEM_SEG_VIP].ms_size = 0x80000;
	mem_segs[MEM_SEG_VIP].ms_addrmask = 0x7ffff;
	bzero(&vip_regs, sizeof(vip_regs));
	vip_regs.vr_dpstts.vd_scanrdy = 1;
	vip_disp_index = 0;

	return true;
}

void
vip_add_syms(void)
{
	debug_create_symbol("L:FB0", 0x00000);
	debug_create_symbol("L:FB1", 0x08000);
	debug_create_symbol("R:FB0", 0x10000);
	debug_create_symbol("R:FB1", 0x18000);
	debug_create_symbol("INTPND", 0x5f800);
	debug_create_symbol("INTENB", 0x5f802);
	debug_create_symbol("INTCLR", 0x5f804);
	debug_create_symbol("DPSTTS", 0x5f820);
	debug_create_symbol("DPCTRL", 0x5f822);
	debug_create_symbol("BRTA", 0x5f824);
	debug_create_symbol("BRTB", 0x5f826);
	debug_create_symbol("BRTC", 0x5f828);
	debug_create_symbol("REST", 0x5f82a);
	debug_create_symbol("FRMCYC", 0x5f82e);
	debug_create_symbol("CTA", 0x5f830);
	debug_create_symbol("XPSTTS", 0x5f840);
	debug_create_symbol("XPCTRL", 0x5f842);
	debug_create_symbol("VER", 0x5f844);
	debug_create_symbol("SPT0", 0x5f848);
	debug_create_symbol("SPT1", 0x5f84a);
	debug_create_symbol("SPT2", 0x5f84c);
	debug_create_symbol("SPT3", 0x5f84e);
	debug_create_symbol("GPLT0", 0x5f860);
	debug_create_symbol("GPLT1", 0x5f862);
	debug_create_symbol("GPLT2", 0x5f864);
	debug_create_symbol("GPLT3", 0x5f866);
	debug_create_symbol("JPLT0", 0x5f86a);
	debug_create_symbol("JPLT2", 0x5f86c);
	debug_create_symbol("JPLT3", 0x5f86e);
	debug_create_symbol("BKCOL", 0x5f870);
	debug_create_symbol_array("BGMAP", 0x20000, 13, 8192);
	debug_create_symbol_array("WORLD_ATT", 0x3d800, 32, 32);
	debug_create_symbol("CLM_TBL", 0x3dc00);
	debug_create_symbol("OAM", 0x3e000);
	debug_create_symbol("CHR", 0x78000);
}

void
vip_reset(void)
{
	// TODO: set initial reg states
}

void
vip_raise(enum vip_intflag intflag)
{
	vip_regs.vr_intpnd|= intflag;
	if (vip_regs.vr_intenb & intflag)
	{
		if (debug_vip_intflags & intflag)
		{
			fprintf(stderr, "Stopped on VIP interrupt %u\n", intflag);
			debugging = true;
		}

		cpu_intr(NVC_INTVIP);
	}
}

static void
vip_clear_start(u_int fb_index)
{
	if (debug_trace_vip)
		debug_tracef("vip", "Clear FB%u start\n", fb_index);

	if (fb_index == 0)
		vip_regs.vr_xpstts.vx_xpbsy_fb0 = 1;
	else
		vip_regs.vr_xpstts.vx_xpbsy_fb1 = 1;
}

static void
vip_clear_finish(u_int fb_index)
{
	if (debug_trace_vip)
		debug_tracef("vip", "Clear FB%u finish\n", fb_index);

	if (fb_index == 0)
	{
		bzero(vip_vrm.vv_left0, sizeof(vip_vrm.vv_left0));
		bzero(vip_vrm.vv_right0, sizeof(vip_vrm.vv_right0));
		vip_regs.vr_xpstts.vx_xpbsy_fb0 = 0;
	}
	else
	{
		bzero(vip_vrm.vv_left1, sizeof(vip_vrm.vv_left1));
		bzero(vip_vrm.vv_right1, sizeof(vip_vrm.vv_right1));
		vip_regs.vr_xpstts.vx_xpbsy_fb1 = 0;
	}
}

struct vip_chr *
vip_chr_find_slow(u_int chrno)
{
	if (chrno < 512)
		return &(vip_vrm.vv_chr0[chrno]);
	else if (chrno < 1024)
		return &(vip_vrm.vv_chr1[chrno - 512]);
	else if (chrno < 1536)
		return &(vip_vrm.vv_chr2[chrno - 1024]);
	else if (chrno < 2048)
		return &(vip_vrm.vv_chr3[chrno - 1536]);
	else
	{
		debug_runtime_errorf(NULL, "VIP: Invalid CHR No. %u", chrno);
		return NULL;
	}
}

u_int8_t
vip_chr_read_slow(const struct vip_chr *vc, u_int x, u_int y, bool hflip, bool vflip)
{
	assert(x < 8);
	assert(y < 8);
	if (hflip)
		x = 7 - x;
	if (vflip)
		y = 7 - y;
	return (vc->vc_rows[y] >> (x * 2)) & 0b11;
}

u_int8_t
vip_fb_read_slow(const u_int8_t *fb, u_int16_t x, u_int16_t y)
{
	u_int offset = x * 224 + y;
	u_int shift = (offset % 4) * 2;
	return (fb[offset / 4] >> shift) & 0b11;
}

u_int32_t
vip_fb_read_argb_slow(const u_int8_t *fb, u_int16_t x, u_int16_t y, u_int8_t repeat)
{
	assert(repeat == 0);
	u_int8_t pixel = vip_fb_read_slow(fb, x, y);
	u_int32_t intensity = 0;
	if (vip_use_bright)
	{
		switch (pixel)
		{
			case 3:
				assert(255 - intensity >= vip_regs.vr_brtc);
				intensity = vip_regs.vr_brtc + 1;
				/*FALLTHRU*/
			case 2:
				assert(255 - intensity >= vip_regs.vr_brtb);
				intensity += vip_regs.vr_brtb + 1;
				/*FALLTHRU*/
			case 1:
				assert(255 - intensity >= vip_regs.vr_brta);
				intensity += vip_regs.vr_brta + 1;
				/*FALLTHRU*/
			case 0:
				break;
		}
		intensity = (intensity * (repeat + 1) * 256) / VIP_MAX_BRIGHT;
		assert(intensity <= 0xff);
	}
	else // For debugging
		intensity = pixel | (pixel << 2) | (pixel << 4) | (pixel << 6);

	return 0xff000000 | (intensity << 16) | (intensity << 8) | intensity;
}

u_int8_t
vip_bgsc_read_slow(const struct vip_bgsc *vb, u_int chr_x, u_int chr_y, bool *opaquep)
{
	struct vip_chr *vc = VIP_CHR_FIND(vb->vb_chrno);
	u_int8_t pixel = vip_chr_read_slow(vc, chr_x, chr_y, vb->vb_bhflp, vb->vb_bvflp);
	if (pixel)
	{
		*opaquep = true;
		u_int8_t plt = vip_regs.vr_gplt[vb->vb_gplts];
		return (plt >> (pixel << 1)) & 0b11;
	}
	else
	{
		*opaquep = false;
		return 0;
	}
}

static void
vip_update_sbcount(u_int sbcount)
{
	vip_regs.vr_xpstts.vx_sbcount = sbcount;
	if (vip_regs.vr_xpctrl.vx_sbcount == vip_regs.vr_xpstts.vx_sbcount)
		vip_raise(VIP_SBHIT);
}

void
vip_frame_clock(void)
{
	enum vip_intflag intflags = VIP_FRAMESTART;

	if (debug_trace_vip)
		debug_tracef("vip", "FRAMESTART\n");

	if (vip_frame_cycles == 0)
	{
		intflags|= VIP_GAMESTART;
		if (debug_trace_vip)
			debug_tracef("vip", "GAMESTART\n");

		if (vip_regs.vr_xpctrl.vx_xprst)
		{
			if (debug_trace_vip)
				debug_tracef("vip", "XPRST\n");
			vip_regs.vr_intenb&= ~vip_xpints;
			vip_regs.vr_intpnd&= ~vip_xpints;
			vip_regs.vr_xpctrl.vx_xprst = 0;
			vip_regs.vr_xpstts.vx_xpen = 0;
			if (vip_disp_index == 0)
				vip_clear_start(1);
			else
				vip_clear_start(0);
		}
		else if (vip_regs.vr_xpctrl.vx_xpen != vip_regs.vr_xpstts.vx_xpen)
		{
			if (debug_trace_vip)
				debug_tracef("vip", "XPEN=%d\n", vip_regs.vr_xpctrl.vx_xpen);
			vip_regs.vr_xpstts.vx_xpen = vip_regs.vr_xpctrl.vx_xpen;
		}

		if (vip_regs.vr_xpstts.vx_xpen)
		{
			if (!vip_regs.vr_xpstts.vx_xpbsy_fb0 && !vip_regs.vr_xpstts.vx_xpbsy_fb1)
			{
				u_int fb_index = !vip_disp_index;

				if (debug_trace_vip)
					debug_tracef("vip", "Draw FB%u start\n", fb_index);

				if (fb_index == 0)
					vip_regs.vr_xpstts.vx_xpbsy_fb0 = 1;
				else
					vip_regs.vr_xpstts.vx_xpbsy_fb1 = 1;

				vip_draw_start(fb_index);
				vip_update_sbcount(0);
			}
			// else TODO: OVERTIME
		}
	}
	if (vip_frame_cycles == vip_regs.vr_frmcyc)
		vip_frame_cycles = 0;
	else
		vip_frame_cycles++;

	vip_raise(intflags);
}

static void
vip_scan_out(u_int fb_index, bool right)
{
	const u_int8_t *fb;
	if (fb_index == 0)
		fb = (right) ? vip_vrm.vv_right0 : vip_vrm.vv_left0;
	else
		fb = (right) ? vip_vrm.vv_right1 : vip_vrm.vv_left1;
	const struct vip_ctc *ctcs = (right) ? vip_dram.vd_right_clm_tbl : vip_dram.vd_left_clm_tbl;

	u_int32_t argb[224 * 384];
	vip_fb_convert(fb, ctcs, argb);
	gl_blit(argb, right);
}

void
vip_step(void)
{
	static u_int scanner_usec = 0;

	if (vip_regs.vr_dpctrl.vd_dprst)
	{
		if (debug_trace_vip)
			debug_tracef("vip", "DPRST\n");
		vip_regs.vr_dpctrl.vd_dprst = 0;
		vip_regs.vr_intenb&= ~vip_dpints;
		vip_regs.vr_intpnd&= ~vip_dpints;
		vip_frame_cycles = 0;
	}
	else
	{
		if (vip_regs.vr_intclr & vip_regs.vr_intpnd)
		{
			vip_regs.vr_intpnd&= ~vip_regs.vr_intclr;
			vip_regs.vr_intclr = 0;
		}
		if (vip_regs.vr_dpctrl.vd_lock != vip_regs.vr_dpctrl.vd_lock)
		{
			debug_runtime_errorf(NULL, "VIP: LOCK=%d\n", vip_regs.vr_dpctrl.vd_lock);
			vip_regs.vr_dpstts.vd_lock = vip_regs.vr_dpctrl.vd_lock;
		}
		if (vip_regs.vr_dpctrl.vd_synce != vip_regs.vr_dpstts.vd_synce)
		{
			if (debug_trace_vip)
				debug_tracef("vip", "SYNCE=%d\n", vip_regs.vr_dpctrl.vd_synce);
			vip_regs.vr_dpstts.vd_synce = vip_regs.vr_dpctrl.vd_synce;
		}
		if (vip_regs.vr_dpctrl.vd_disp != vip_regs.vr_dpstts.vd_disp)
		{
			if (debug_trace_vip)
				debug_tracef("vip", "DISP=%d\n", vip_regs.vr_dpctrl.vd_disp);
			vip_regs.vr_dpstts.vd_disp = vip_regs.vr_dpctrl.vd_disp;
		}
	}

	if (scanner_usec == 0)
		vip_frame_clock();
	else if (scanner_usec == 1000 && !vip_regs.vr_xpstts.vx_xpen)
	{
		if (vip_regs.vr_xpstts.vx_xpbsy_fb0)
			vip_clear_finish(0);
		else if (vip_regs.vr_xpstts.vx_xpbsy_fb1)
			vip_clear_finish(1);
	}
	else if (scanner_usec == 2500 && vip_regs.vr_dpstts.vd_synce)
	{
		if (vip_regs.vr_dpstts.vd_disp)
		{
			if (vip_disp_index == 0)
			{
				vip_regs.vr_dpstts.vd_dpbsy_l_fb0 = 1;
				if (debug_trace_vip)
					debug_tracef("vip", "Display L:FB0 start\n");
			}
			else
			{
				vip_regs.vr_dpstts.vd_dpbsy_l_fb1 = 1;
				if (debug_trace_vip)
					debug_tracef("vip", "Display L:FB1 start\n");
			}
			vip_scan_out(vip_disp_index, false);
		}
	}
	else if (scanner_usec == 7500 && vip_regs.vr_dpstts.vd_synce)
	{
		if (vip_regs.vr_dpstts.vd_disp)
		{
			if (vip_disp_index == 0)
			{
				vip_regs.vr_dpstts.vd_dpbsy_l_fb0 = 0;
				if (debug_trace_vip)
					debug_tracef("vip", "Display L:FB0 finish\n");
			}
			else
			{
				vip_regs.vr_dpstts.vd_dpbsy_l_fb1 = 0;
				if (debug_trace_vip)
					debug_tracef("vip", "Display L:FB1 finish\n");
			}
			vip_raise(VIP_LFBEND);
		}
	}
	else if (scanner_usec == 12500 && vip_regs.vr_dpstts.vd_synce)
	{
		if (vip_regs.vr_dpstts.vd_disp)
		{
			if (vip_disp_index == 0)
			{
				vip_regs.vr_dpstts.vd_dpbsy_r_fb0 = 1;
				if (debug_trace_vip)
					debug_tracef("vip", "Display R:FB0 start\n");
			}
			else
			{
				vip_regs.vr_dpstts.vd_dpbsy_r_fb1 = 1;
				if (debug_trace_vip)
					debug_tracef("vip", "Display R:FB1 start\n");
			}
			vip_scan_out(vip_disp_index, true);
		}
	}
	else if (scanner_usec == 17500 && vip_regs.vr_dpstts.vd_synce)
	{
		if (vip_regs.vr_dpstts.vd_disp)
		{
			if (vip_disp_index == 0)
			{
				vip_regs.vr_dpstts.vd_dpbsy_r_fb0 = 0;
				if (debug_trace_vip)
					debug_tracef("vip", "Display R:FB0 finish\n");
			}
			else
			{
				vip_regs.vr_dpstts.vd_dpbsy_r_fb1 = 0;
				if (debug_trace_vip)
					debug_tracef("vip", "Display R:FB1 finish\n");
			}

			vip_raise(VIP_RFBEND);
			vip_disp_index = (vip_disp_index + 1) % 2;
			++main_stats.ms_frames;
		}
	}

	if (vip_regs.vr_xpstts.vx_xpen && (scanner_usec % 250) == 0)
	{
		if (vip_regs.vr_xpstts.vx_xpbsy_fb0)
			vip_xp_step(0);
		else if (vip_regs.vr_xpstts.vx_xpbsy_fb1)
			vip_xp_step(1);
	}

	if (scanner_usec == 19999)
		scanner_usec = 0;
	else
		++scanner_usec;
}

void
vip_xp_step(u_int fb_index)
{
	if (vip_regs.vr_xpstts.vx_sbout)
	{
		vip_regs.vr_xpstts.vx_sbout = 0;

		if (vip_regs.vr_xpstts.vx_sbcount < 27)
			vip_update_sbcount(vip_regs.vr_xpstts.vx_sbcount + 1);
		else
		{
			vip_draw_finish(fb_index);

			if (debug_trace_vip)
				debug_tracef("vip", "Draw FB%u finish\n", fb_index);

			if (fb_index == 0)
				vip_regs.vr_xpstts.vx_xpbsy_fb0 = 0;
			else
				vip_regs.vr_xpstts.vx_xpbsy_fb1 = 0;

			vip_regs.vr_xpstts.vx_sbcount = 0;
			vip_raise(VIP_XPEND);
		}
	}
	else
	{
		if (debug_trace_vip)
			debug_tracef("vip", "Draw FB%u SBCOUNT=%u\n", fb_index, vip_regs.vr_xpstts.vx_sbcount);

		u_int8_t *left_fb, *right_fb;
		if (fb_index == 0)
		{
			left_fb = vip_vrm.vv_left0;
			right_fb = vip_vrm.vv_right0;
		}
		else
		{
			left_fb = vip_vrm.vv_left1;
			right_fb = vip_vrm.vv_right1;
		}

		if ((vip_row_mask & (1 << vip_regs.vr_xpstts.vx_sbcount)) != 0)
			vip_draw_8rows(left_fb, right_fb, vip_regs.vr_xpstts.vx_sbcount * 8);

		vip_regs.vr_xpstts.vx_sbout = 1;
	}
}

void
vip_fini(void)
{
	// TODO
}

void *
vip_mem_emu2host(u_int32_t addr, size_t size, int *permsp)
{
	// TODO: Set read/write permissions
	*permsp = PROT_READ | PROT_WRITE;

	static bool ignore_mirror = false;
	if (addr & 0x00f80000)
	{
		u_int32_t mirror = addr & 0x7ffff;
		if (!debug_runtime_errorf(&ignore_mirror, "Mirroring VIP address 0x%08x -> 0x%08x\n", addr, mirror))
			return NULL;
		addr = mirror;
	}
	else if (addr >= 0x40000 && addr < 0x60000 && (addr & 0x5ff00) != 0x5f800)
	{
		u_int32_t mirror = 0x5f800 | (addr & 0x7f);
		if (!debug_runtime_errorf(&ignore_mirror, "Mirroring VIP address 0x%08x -> 0x%08x\n", addr, mirror))
			return NULL;
		addr = mirror;
	}

	if (addr < 0x20000)
		return (u_int8_t *)&vip_vrm + addr;
	else if (addr < 0x40000)
		return (u_int8_t *)&vip_dram + (addr & 0x1ffff);
	else if ((addr & 0xfff00) == 0x5f800)
	{
		if (size & 1)
		{
			static bool always_ignore = false;
			if (!debug_runtime_errorf(&always_ignore, "Invalid VIP access size %lu", size))
				return NULL;
		}
		if (addr & 1)
		{
			static bool always_ignore = false;
			if (!debug_runtime_errorf(&always_ignore, "VIP address alignment error at 0x%08x", addr))
				return NULL;
		}
		u_int reg_num = (addr & 0x7f) >> 1;
		switch (reg_num)
		{
			case 0x00:
			case 0x10:
			case 0x18:
			case 0x20:
				*permsp = PROT_READ;
				break;
			case 0x02:
			case 0x11:
			case 0x12:
			case 0x13:
			case 0x14:
			case 0x15:
			case 0x17:
			case 0x21:
				*permsp = PROT_WRITE;
				break;
		}

#ifndef NDEBUG
		u_int16_t *regp = (u_int16_t *)&vip_regs + reg_num;
		assert(regp == (u_int16_t *)((u_int8_t *)&vip_regs + (addr & 0x7e)));
#endif // !NDEBUG

		return (u_int8_t *)&vip_regs + (addr & 0x7e);
	}
	else if (addr >= 0x78000 && addr < 0x7a000)
		return (u_int8_t *)&(vip_vrm.vv_chr0) + (addr - 0x78000);
	else if (addr >= 0x7a000 && addr < 0x7c000)
		return (u_int8_t *)&(vip_vrm.vv_chr1) + (addr - 0x7a000);
	else if (addr >= 0x7c000 && addr < 0x7e000)
		return (u_int8_t *)&(vip_vrm.vv_chr2) + (addr - 0x7c000);
	else if (addr >= 0x7e000 && addr < 0x80000)
		return (u_int8_t *)&(vip_vrm.vv_chr3) + (addr - 0x7e000);
	else
		return NULL;
}

bool
vip_clip_vspan(u_int scr_clip_y, u_int scr_clip_height, int scr_y, u_int win_height, struct vip_vspan *vspan)
{
	int max_scr_y = scr_y + win_height;
	if (max_scr_y <= (int)scr_clip_y)
		return false;

	u_int max_clip_y = scr_clip_y + scr_clip_height;
	if (scr_y >= (int)max_clip_y)
		return false;

	if (max_scr_y > (int)max_clip_y)
		win_height = max_clip_y - scr_y;

	if (scr_y < (int)scr_clip_y)
	{
		vspan->vvs_scr_y = scr_clip_y;
		vspan->vvs_win_y = scr_clip_y - scr_y;
		vspan->vvs_height = win_height - vspan->vvs_win_y;
	}
	else
	{
		vspan->vvs_scr_y = (u_int)scr_y;
		vspan->vvs_win_y = 0;
		vspan->vvs_height = win_height;
	}
	return true;
}

bool
vip_clip_hspan(int scr_x, int win_x, u_int win_width, struct vip_hspan *hspan)
{
	int max_scr_x = scr_x + win_width;
	if (max_scr_x <= 0)
		return false;

	if (scr_x >= 384)
		return false;

	if (max_scr_x > 384)
		win_width = 384 - scr_x;

	if (scr_x < 0)
	{
		hspan->vhs_scr_x = 0;
		hspan->vhs_win_x = win_x - scr_x;
		hspan->vhs_width = win_width + scr_x;
	}
	else
	{
		hspan->vhs_scr_x = (u_int)scr_x;
		hspan->vhs_win_x = win_x;
		hspan->vhs_width = win_width;
	}
	return true;
}

static void
vip_test_clip(int scr_clip_y,
              u_int scr_clip_height,
              int scr_y,
              u_int win_height,
              bool expect_overlap,
              u_int expect_scr_y,
              u_int expect_win_y,
              u_int expect_height)
{
	struct vip_vspan vspan;
	bool overlap = vip_clip_vspan(scr_clip_y, scr_clip_height, scr_y, win_height, &vspan);
	if (overlap != expect_overlap ||
			(overlap && (vspan.vvs_scr_y != expect_scr_y ||
					vspan.vvs_win_y != expect_win_y ||
					vspan.vvs_height != expect_height)))
	{
		debug_runtime_errorf(NULL, "vip_clip_vspan(scr_clip_y, scr_clip_height, scr_y, height) (%u, %u, %d, %u)"
		                           " -> overlap %d vspan{%u, %u, %u} should be overlap %d vspan{%u, %u, %u}",
		                     scr_clip_y, scr_clip_height, scr_y, win_height,
		                     overlap,
		                     vspan.vvs_scr_y, vspan.vvs_win_y, vspan.vvs_height,
		                     expect_overlap,
		                     expect_scr_y, expect_win_y, expect_height);
	}
}

void
vip_test(void)
{
	fputs("Running VIP self-test\n", stderr);

	static_assert(sizeof(vip_vrm) == 0x20000, "sizeof(vip_vrm) should be 0x20000");
	assert(sizeof(struct vip_oam) == 8);
	static_assert(sizeof(vip_dram) == 0x20000, "sizeof(vip_dram) should be 0x20000");
	assert(sizeof(vip_dram.vd_shared.s_bgsegs[0]) == 8192);
	assert(sizeof(vip_regs) == 0x72);
	mem_test_size("vip_world_att", sizeof(struct vip_world_att), 32);
#ifndef NDEBUG
	int perms;
	mem_test_addr("world_att[1]",
	              vip_mem_emu2host(debug_locate_symbol("WORLD_ATT:1"), 4, &perms),
	              &(vip_dram.vd_world_atts[1]));
	assert(vip_mem_emu2host(0x24000, 4, &perms) == &(vip_dram.vd_shared.s_bgsegs[2]));
	assert(vip_mem_emu2host(0x31000, 4, &perms) == &(vip_dram.vd_shared.s_param_tbl[0x8800]));
	assert(vip_mem_emu2host(0x3d800, 4, &perms) == &(vip_dram.vd_world_atts));
	assert(vip_mem_emu2host(0x3e000, 8, &perms) == &(vip_dram.vd_oam));
	assert(vip_mem_emu2host(0x5f800, 2, &perms) == &(vip_regs.vr_intpnd));
	assert(vip_mem_emu2host(0x5f820, 2, &perms) == &(vip_regs.vr_dpstts));
	assert(vip_mem_emu2host(0x5f866, 2, &perms) == &(vip_regs.vr_gplt[3]));
	assert(vip_mem_emu2host(0x5f870, 2, &perms) == &(vip_regs.vr_bkcol));
	assert(vip_mem_emu2host(0x78000, 2, &perms) == &(vip_vrm.vv_chr0));
	assert(vip_mem_emu2host(0x7e000, 2, &perms) == &(vip_vrm.vv_chr3));
#endif // !NDEBUG

	vip_test_clip(5, 5, 5, 5, true, 5, 0, 5);
	vip_test_clip(5, 5, 4, 6, true, 5, 1, 5);
	vip_test_clip(5, 5, 6, 4, true, 6, 0, 4);
	vip_test_clip(5, 5, 5, 4, true, 5, 0, 4);
	vip_test_clip(5, 5, 5, 6, true, 5, 0, 5);
	vip_test_clip(5, 5, 4, 5, true, 5, 1, 4);
	vip_test_clip(5, 5, 6, 3, true, 6, 0, 3);
	vip_test_clip(5, 5, 4, 6, true, 5, 1, 5);
	vip_test_clip(5, 5, 6, 5, true, 6, 0, 4);
	vip_test_clip(5, 5, 0, 5, false, 0, 0, 0);
	vip_test_clip(5, 5, 10, 5, false, 0, 0, 0);

	for (u_int chrno = 0; chrno < 2048; ++chrno)
	{
		struct vip_chr *slow_vc = vip_chr_find_slow(chrno);
		struct vip_chr *fast_vc = VIP_CHR_FIND(chrno);
		if (fast_vc != slow_vc)
			debug_runtime_errorf(NULL, "vip_chr_find_slow(%d) = %p, VIP_CHR_FIND() = %p", chrno, slow_vc, fast_vc);
	}
}

void
vip_toggle_rows(void)
{
	if (vip_row_mask == (1 << 28) - 1)
		vip_row_mask = 1;
	else
	{
		vip_row_mask <<= 1;
		if (!vip_row_mask)
			vip_row_mask = (1 << 28) - 1;
	}
	debug_tracef("vip", "Row mask 0x%08x\n", vip_row_mask);
}

void
vip_toggle_worlds(void)
{
	if (vip_world_mask == ~0U)
		vip_world_mask = 0x80000000;
	else
	{
		vip_world_mask >>= 1;
		if (!vip_world_mask)
			vip_world_mask = ~0;
	}
	debug_tracef("vip", "World mask 0x%08x\n", vip_world_mask);
}

/* VSU */
struct vsu_ram
{
	u_int8_t vr_ram[0x280];
	u_int32_t vr_sound5[32];
};

struct vsu_regs
{
	u_int8_t vr_regs[0x180];
	struct
	{
		unsigned vs_stop : 1 __attribute__((packed));
		unsigned vs_unused : 7 __attribute__((packed));
	} vr_sstop;
	u_int8_t vr_regs2[0x7f];
};

static struct vsu_ram vsu_ram;
static struct vsu_regs vsu_regs;

bool
vsu_init(void)
{
	// TODO
	return true;
}

void
vsu_add_syms(void)
{
	debug_create_symbol_array("SNDWAV", 0x01000000, 5, 0x80);
	debug_create_symbol("SND5.MOD", 0x01000280);
	debug_create_symbol("SOUND1", 0x01000400);
	debug_create_symbol("SOUND2", 0x01000440);
	debug_create_symbol("SOUND3", 0x01000480);
	debug_create_symbol("SOUND4", 0x010004c0);
	debug_create_symbol("SOUND5", 0x01000500);
	debug_create_symbol("SOUND6", 0x01000540);
	debug_create_symbol("SSTOP", 0x01000580);
}

void
vsu_test(void)
{
	fputs("Running VSU self-test\n", stderr);
	mem_test_size("vsu_ram", sizeof(vsu_ram), 0x300);
	mem_test_size("vsu_regs", sizeof(vsu_regs), 0x200);
#ifndef NDEBUG
	int perms;
	assert(vsu_mem_emu2host(0x01000580, 1, &perms) == &(vsu_regs.vr_sstop));
#endif // !NDEBUG
}

void
vsu_reset(void)
{
	// TODO
}

void
vsu_step(void)
{
	// TODO
}

void *
vsu_mem_emu2host(u_int32_t addr, size_t size, int *permsp)
{
	// TODO: More granularity on perms
	*permsp = PROT_READ | PROT_WRITE;

	if (addr + size <= 0x01000300)
		return (u_int8_t *)&vsu_ram + (addr & 0x3ff);
	else if (addr + size <= 0x01000400)
	{
		u_int32_t mirror = addr % 0x300;
		static bool always_ignore = false;
		if (!debug_runtime_errorf(&always_ignore, "Mirroring VSU RAM at 0x%08x -> 0x%x", addr, mirror))
			return NULL;
		return (u_int8_t *)&vsu_ram + mirror;
	}
	else if (addr >= 0x01000400 && addr + size <= 0x01000600)
		return (u_int8_t *)&vsu_regs + (addr - 0x01000400);
	else
	{
		if (debug_runtime_errorf(NULL, "VSU bus error at 0x%08x\n", addr))
		{
			static u_int32_t dummy;
			return &dummy;
		}
		return NULL;
	}
}

void
vsu_fini(void)
{
	// TODO
}

/* NVC */
struct nvc_regs
{
	u_int8_t nr_ccr;
	u_int8_t nr_ccsr;
	u_int8_t nr_cdtr;
	u_int8_t nr_cdrr;
	u_int8_t nr_sdlr;
	u_int8_t nr_sdhr;
	u_int8_t nr_tlr;
	u_int8_t nr_thr;
	struct
	{
		unsigned t_enb : 1,
		t_z_stat : 1,
		t_z_stat_clr : 1,
		t_z_int : 1,
		t_clk_sel : 1;
	} __attribute__((packed)) nr_tcr;
	u_int8_t nr_wcr;
	struct
	{
		unsigned s_abt_dis : 1,
				s_si_stat : 1,
				s_hw_si : 1,
				s_rfu1 : 1,
				s_soft_ck : 1,
				s_para_si : 1,
				s_rfu2 : 1,
				s_k_int_inh : 1;
	} __attribute__((packed)) nr_scr;
};

#if INTERFACE
	enum nvc_intlevel
	{
		NVC_INTKEY = 0,
		NVC_INTTIM = 1,
		NVC_INTCRO = 2,
		NVC_INTCOM = 3,
		NVC_INTVIP = 4
	};

	enum nvc_key
	{
		KEY_PWR = (1 << 0),
		KEY_SGN = (1 << 1),
		KEY_A = (1 << 2),
		KEY_B = (1 << 3),
		KEY_RT = (1 << 4),
		KEY_LT = (1 << 5),
		KEY_RU = (1 << 6),
		KEY_RR = (1 << 7),
		KEY_LR = (1 << 8),
		KEY_LL = (1 << 9),
		KEY_LD = (1 << 10),
		KEY_LU = (1 << 11),
		KEY_STA = (1 << 12),
		KEY_SEL = (1 << 13),
		KEY_RL = (1 << 14),
		KEY_RD = (1 << 15)
	};
#endif // INTERFACE

static struct nvc_regs nvc_regs;
static u_int nvc_next_tick;
static u_int nvc_timer_frac;
static u_int nvc_inst_per_usec = CPU_INST_PER_USEC;

bool
nvc_init(void)
{
	if (getenv("INST_PER_USEC"))
		nvc_inst_per_usec = atoi(getenv("INST_PER_USEC"));

	return cpu_init();
}

void
nvc_add_syms(void)
{
	debug_create_symbol("SCR", 0x02000028);
	debug_create_symbol("WCR", 0x02000024);
	debug_create_symbol("TCR", 0x02000020);
	debug_create_symbol("THR", 0x0200001c);
	debug_create_symbol("TLR", 0x02000018);
	debug_create_symbol("SDHR", 0x02000014);
	debug_create_symbol("SDLR", 0x02000010);
	debug_create_symbol("CDRR", 0x0200000c);
	debug_create_symbol("CDTR", 0x02000008);
	debug_create_symbol("CCSR", 0x02000004);
	debug_create_symbol("CCR", 0x02000000);

	u_int32_t rom_mask = mem_segs[MEM_SEG_ROM].ms_addrmask;
	debug_create_symbol("vect.key", 0xfffffe00);
	debug_create_symbol(".intkey", 0x07000000 + (0xfffffe00 & rom_mask));
	debug_create_symbol("vect.tim", 0xfffffe10);
	debug_create_symbol(".inttim", 0x07000000 + (0xfffffe10 & rom_mask));
	debug_create_symbol("vect.cro", 0xfffffe20);
	debug_create_symbol(".intcro", 0x07000000 + (0xfffffe20 & rom_mask));
	debug_create_symbol("vect.com", 0xfffffe30);
	debug_create_symbol(".intcom", 0x07000000 + (0xfffffe30 & rom_mask));
	debug_create_symbol("vect.vip", 0xfffffe40);
	debug_create_symbol(".intvip", 0x07000000 + (0xfffffe40 & rom_mask));
}

void
nvc_fini(void)
{
	cpu_fini();
}

void
nvc_reset(void)
{
	nvc_regs.nr_scr.s_hw_si = 1;
	nvc_regs.nr_scr.s_rfu1 = 1;
	nvc_regs.nr_scr.s_rfu2 = 1;
	nvc_keys = KEY_SGN;
	nvc_regs.nr_tlr = nvc_regs.nr_thr = 0xff;
	nvc_next_tick = 0;
	nvc_timer_frac = 0;
	// TODO: Initialize other NVC interval registers
	cpu_reset();
}

void
nvc_test(void)
{
	fputs("Running NVC self-test\n", stderr);

	mem_test_size("nvc_regs", sizeof(nvc_regs), 11);
	u_int32_t mask;
	size_t size = 1;
	int perms;
	mem_test_addr("nvc_sdlr", nvc_mem_emu2host(0x02000010, &size, &mask, &perms), &(nvc_regs.nr_sdlr));
	mem_test_addr("nvc_sdhr", nvc_mem_emu2host(0x02000014, &size, &mask, &perms), &(nvc_regs.nr_sdhr));
	mem_test_addr("nvc_tcr", nvc_mem_emu2host(0x02000020, &size, &mask, &perms), &(nvc_regs.nr_tcr));
}

bool
nvc_step(void)
{
	if (main_usec == nvc_next_tick)
	{
		if (nvc_regs.nr_tcr.t_enb)
		{
			if (debug_trace_nvc_tim)
			{
				debug_str_t tcr_s;
				debug_tracef("nvc", "TCR = %s, THR:TLR = %02hhx:%02hhx, nvc_next_tick = %u\n",
				             debug_format_flags(tcr_s,
				                                "T-Enb", nvc_regs.nr_tcr.t_enb,
				                                "Z-Stat", nvc_regs.nr_tcr.t_z_stat,
				                                "Z-Stat-Clr", nvc_regs.nr_tcr.t_z_stat_clr,
				                                "Tim-Z-Int", nvc_regs.nr_tcr.t_z_int,
				                                "T-Clk-Sel", nvc_regs.nr_tcr.t_clk_sel,
				                                NULL),
				             nvc_regs.nr_thr, nvc_regs.nr_tlr,
				             nvc_next_tick);
			}
			if (nvc_regs.nr_tlr > 0)
				--nvc_regs.nr_tlr;
			else if (nvc_regs.nr_thr > 0)
			{
				--nvc_regs.nr_thr;
				nvc_regs.nr_tlr = 0xff;
			}
			else if (!nvc_regs.nr_tcr.t_z_stat)
			{
				nvc_regs.nr_tcr.t_z_stat = 1;
				if (debug_trace_nvc)
					debug_tracef("nvc", "Timer expired\n");
				if (nvc_regs.nr_tcr.t_z_int)
					cpu_intr(NVC_INTTIM);
			}
		}
		else
		{
			if (nvc_regs.nr_tcr.t_z_stat && nvc_regs.nr_tcr.t_z_stat_clr)
			{
				debug_tracef("nvc", "Clearing timer interrupt\n");
				nvc_regs.nr_tcr.t_z_stat = 0;
			}
		}

		u_int tick_usec;
		if (nvc_regs.nr_tcr.t_clk_sel)
		{
			tick_usec = 305;
			nvc_timer_frac+= 175781250;
		}
		else
		{
			tick_usec = 1525;
			nvc_timer_frac += 878906250;
		}
		if (nvc_timer_frac > 1000000000)
		{
			++tick_usec;
			nvc_timer_frac -= 1000000000;
		}
		nvc_next_tick = (nvc_next_tick + tick_usec) % 1000000;
	}

	for (u_int x = 0; x < nvc_inst_per_usec; ++x)
		if (!cpu_step())
			return false;

	return true;
}

u_int16_t nvc_keys;

void
nvc_input(enum nvc_key key, bool state)
{
	// TODO: handle multi-key mask
	if (state)
		nvc_keys|= key;
	else
		nvc_keys&= ~key;

	//if ((main_usec % 512) == 0) // takes about 512 µs to read the controller data
	if (nvc_regs.nr_scr.s_hw_si)
	{
		nvc_regs.nr_scr.s_si_stat = 1;

		u_int32_t old_nvc_keys = (nvc_regs.nr_sdhr << 8) | nvc_regs.nr_sdlr;
		bool raise_intr = state && !nvc_regs.nr_scr.s_k_int_inh && !(old_nvc_keys & key);
		nvc_regs.nr_sdlr = nvc_keys & 0xff;
		nvc_regs.nr_sdhr = nvc_keys >> 8;
		if (debug_trace_nvc)
			debug_tracef("nvc", "Serial data 0x%08x -> 0x%08x, raise intr = %d\n", old_nvc_keys, nvc_keys, raise_intr);

		nvc_regs.nr_scr.s_si_stat = 0;

		if (raise_intr)
			cpu_intr(NVC_INTKEY);
	}
}

void *
nvc_mem_emu2host(u_int32_t addr, size_t *sizep, u_int32_t *maskp, int *permsp)
{
	if (*sizep != 1)
	{
		static bool ignore_size = false;
		if (!debug_runtime_errorf(&ignore_size, "Invalid NVC access size %lu @ 0x%08x\n", *sizep, addr))
			return NULL;
		*sizep = 1;
	}
	if (addr <= 0x02000028)
	{
		switch (addr)
		{
			case 0x02000024:
			case 0x02000028:
			case 0x0200001c:
			case 0x02000018:
			case 0x02000014:
			case 0x02000010:
			case 0x02000008:
			case 0x02000004:
			case 0x02000000:
				*permsp = PROT_READ | PROT_WRITE;
				break;
			case 0x02000020:
				*permsp = PROT_READ | PROT_WRITE;
				*maskp = 0x1d;
				break;
			default:
				*permsp = 0;
		}
		return (u_int8_t *) &nvc_regs + ((addr & 0x3f) >> 2);
	}
	else
	{
		debug_runtime_errorf(NULL, "NVC bus error at 0x%08x", addr);
		debug_enter();
		return NULL;
	}
}

/* DEBUG */
#if INTERFACE
	struct debug_symbol
	{
		char *ds_name;
		u_int32_t ds_addr;
		struct debug_symbol *ds_next;
		enum isx_symbol_type ds_type;
	};
# define DEBUG_ADDR_NONE (0xffffffff)

	struct debug_disasm_context
	{
		u_int32_t ddc_regmask;
#  define DEBUG_REGMASK_ALL (0xffffffff)
		cpu_regs_t ddc_regs;
	};

	extern bool debug_trace_cpu;
	extern bool debug_trace_vip;

# define DEBUG_ADDR_FMT "%-26s"

	enum debug_error_state
	{
		ERROR_IGNORE,
		ERROR_ALWAYS_IGNORE,
		ERROR_DEBUG,
		ERROR_ABORT
	};
#endif // INTERFACE

bool debugging = false;
bool debug_trace_cpu = false;
bool debug_trace_cpu_jmp = false;
bool debug_trace_cpu_int = false;
bool debug_trace_mem = false;
bool debug_trace_vip = false;
u_int16_t debug_vip_intflags = 0;
bool debug_trace_nvc = false;
bool debug_trace_nvc_tim = false;
FILE *debug_trace_file = NULL;
u_int32_t debug_break = DEBUG_ADDR_NONE;

struct debug_trace
{
	const char *dt_key;
	const char *dt_label;
	bool *dt_tracep;
};
static struct debug_trace debug_traces[] =
		{
				{"cpu", "CPU", &debug_trace_cpu},
				{"cpu.jmp", "CPU Jumps", &debug_trace_cpu_jmp},
				{"cpu.int", "CPU Interrupts", &debug_trace_cpu_int},
				{"mem", "Memory", &debug_trace_mem},
				{"vip", "VIP", &debug_trace_vip},
				{"nvc", "NVC", &debug_trace_nvc},
				{"nvc.tim", "NVC Timer", &debug_trace_nvc_tim}
		};

struct debug_watch
{
	u_int32_t dw_addr;
	int dw_ops;
	struct debug_watch *dw_next;
};
struct debug_watch *debug_watches = NULL;

static EditLine *s_editline;
static History *s_history;
static Tokenizer *s_token;

// TODO: Use hcreate()
static struct debug_symbol *debug_syms = NULL;

static char *
debug_prompt(EditLine *editline __unused)
{
	return "vvboy> ";
}

void
debug_add_syms(void)
{
	wram_add_syms();
	cpu_add_syms();
	vip_add_syms();
	vsu_add_syms();
	nvc_add_syms();
}

bool
debug_init(void)
{
	s_editline = el_init("vvboy", stdin, stdout, stderr);
	if (!s_editline)
	{
		warnx("Could not initialize editline");
		return false;
	}
	el_set(s_editline, EL_PROMPT, debug_prompt);
	el_source(s_editline, NULL);

	s_history = history_init();
	if (!s_history)
	{
		warnx("Could not initialize history editing");
		return false;
	}
	HistEvent event;
	history(s_history, &event, H_SETSIZE, INT_MAX);
	el_set(s_editline, EL_HIST, history, s_history);

	s_token = tok_init(NULL);
	if (!s_token)
	{
		warnx("Could not initialize tokenizer");
		return false;
	}

	return true;
}

void
debug_clear_syms(void)
{
	while (debug_syms)
	{
		struct debug_symbol *debug_sym = debug_syms;
		debug_syms = debug_sym->ds_next;
		debug_destroy_symbol(debug_sym);
	}
}

void
debug_fini(void)
{
	el_end(s_editline);
	history_end(s_history);
}

char *
debug_format_binary(u_int n, u_int nbits, debug_str_t bin_s)
{
	bin_s[0] = '0';
	bin_s[1] = 'b';
	assert(nbits <= debug_str_len - 3);
	char *end = bin_s + 2 + nbits;
	*end-- = '\0';
	while (nbits--)
	{
		*end-- = (n & 1) ? '1' : '0';
		n>>= 1;
	}
	return bin_s;
}

char *
debug_format_hex(const u_int8_t *bytes, u_int byte_size, debug_str_t s)
{
	u_int32_t value;
	switch (byte_size)
	{
		case 1:
			value = *bytes;
			break;
		case 2:
			value = *(u_int16_t *) bytes;
			break;
		case 4:
			value = *(u_int32_t *) bytes;
			break;
		default:
			assert(byte_size == 1 || byte_size == 2 || byte_size == 4);
			value = 0;
	}
	snprintf(s, debug_str_len, "0x%0*x", byte_size << 1, value);
	return s;
}

#if INTERFACE
typedef char debug_str_t[96];
# define debug_str_len sizeof(debug_str_t)
#endif // INTERFACE

struct debug_symbol *
debug_resolve_addr(u_int32_t addr, u_int32_t *match_offsetp)
{
	struct debug_symbol *sym = debug_syms;
	struct debug_symbol *match_sym = NULL;

	while (sym)
	{
		if (sym->ds_type == ISX_SYMBOL_POINTER && sym->ds_addr <= addr)
		{
			u_int32_t offset = addr - sym->ds_addr;
			if (offset <= 8192 && (!match_sym || *match_offsetp > offset))
			{
				match_sym = sym;
				*match_offsetp = offset;
			}
		}

		sym = sym->ds_next;
	}

	return match_sym;
}

const char *
debug_format_addrsym(u_int32_t addr, struct debug_symbol *sym, debug_str_t s)
{
	char human[32];

	if (sym)
	{
		u_int32_t offset = addr - sym->ds_addr;
		if (offset)
			snprintf(human, sizeof(human), " <%s+%u>", sym->ds_name, offset);
		else
			snprintf(human, sizeof(human), " <%s>", sym->ds_name);
	}
	else
		*human = '\0';

	snprintf(s, debug_str_len, "0x%08x%s", addr, human);

	return s;
}

const char *
debug_format_addr(u_int32_t addr, debug_str_t s)
{
	struct debug_symbol *match_sym;
	u_int32_t match_offset;

	match_sym = debug_resolve_addr(addr, &match_offset);
	return debug_format_addrsym(addr, match_sym, s);
}

const char *debug_rnames[32] =
{
	"r0", "r1", "hp", "sp", "gp", "tp", "r6", "r7",
	"r8", "r9", "r10", "r11", "r12", "r13", "r14", "r15",
	"r16", "r17", "r18", "r19", "r20", "r21", "r22", "r23",
	"r24", "r25", "r26", "r27", "r28", "r29", "r30", "lp"
};

void
debug_add_symbol(struct debug_symbol *debug_sym)
{
	debug_sym->ds_next = debug_syms;
	debug_syms = debug_sym;
}

struct debug_symbol *
debug_create_symbol(const char *name, u_int32_t addr)
{
	struct debug_symbol *debug_sym = calloc(1, sizeof(*debug_sym));
	if (!debug_sym)
		err(1, "Could not allocate debug symbol");
	debug_sym->ds_name = strdup(name);
	if (!debug_sym->ds_name)
		err(1, "Could not copy symbol name");
	debug_sym->ds_addr = addr;
	debug_sym->ds_type = ISX_SYMBOL_POINTER;
	debug_add_symbol(debug_sym);
	return debug_sym;
}

void
debug_create_symbol_array(const char *base_name, u_int32_t start, u_int count, u_int32_t size)
{
	for (u_int i = 0; i < count; ++i)
	{
		debug_str_t name;
		snprintf(name, sizeof(name), "%s:%u", base_name, i);
		debug_create_symbol(name, start + size * i);
	}
}

void
debug_destroy_symbol(struct debug_symbol *debug_sym)
{
	if (debug_sym->ds_name)
		free(debug_sym->ds_name);
	free(debug_sym);
}

struct debug_disasm_context *
debug_current_context(void)
{
	static struct debug_disasm_context context;
	bcopy(cpu_state.cs_r, context.ddc_regs, sizeof(cpu_state.cs_r));
	context.ddc_regmask = DEBUG_REGMASK_ALL;
	return &context;
}

const union cpu_reg *
debug_get_reg(struct debug_disasm_context *context, u_int rnum)
{
	static const union cpu_reg zero_reg = {.u = 0};
	static const union cpu_reg global_reg = {.u = 0x05008000};

	if (context && (context->ddc_regmask & (1 << rnum)))
		return &(context->ddc_regs[rnum]);
	else if (rnum == 0)
		return &zero_reg;
	else if (rnum == 4)
		return &global_reg;
	else
		return NULL;
}

static void
debug_put_reg(struct debug_disasm_context *context, u_int rnum, union cpu_reg reg)
{
	if (context)
	{
		context->ddc_regs[rnum] = reg;
		context->ddc_regmask |= (1 << rnum);
	}
}

static void
debug_clear_reg(struct debug_disasm_context *context, u_int rnum)
{
	if (context)
		context->ddc_regmask &= ~(1 << rnum);
}

// TODO: Combine with below
static void
debug_disasm_i(debug_str_t decode, debug_str_t decomp, const union cpu_inst *inst, const char *mnemonic, const char *op, struct debug_disasm_context *context)
{
	snprintf(decode, debug_str_len, "%s %s, %s",
	         mnemonic, debug_rnames[inst->ci_i.i_reg1], debug_rnames[inst->ci_i.i_reg2]);
	if (context && context->ddc_regmask == DEBUG_REGMASK_ALL)
		snprintf(decomp, debug_str_len, "%i %s %i",
		         context->ddc_regs[inst->ci_i.i_reg2].s, op, context->ddc_regs[inst->ci_i.i_reg1].s);
	if (inst->ci_i.i_opcode != OP_CMP)
		debug_clear_reg(context, inst->ci_i.i_reg2);
}

static void
debug_disasm_i_fmt(debug_str_t decode,
                   debug_str_t decomp,
                   const union cpu_inst *inst,
                   const char *mnemonic,
                   const char *decomp_fmt,
                   struct debug_disasm_context *context)
{
	snprintf(decode, debug_str_len, "%s %s, %s",
	         mnemonic, debug_rnames[inst->ci_i.i_reg1], debug_rnames[inst->ci_i.i_reg2]);
	if (context && context->ddc_regmask == DEBUG_REGMASK_ALL)
		snprintf(decomp, debug_str_len, decomp_fmt,
		         debug_rnames[inst->ci_i.i_reg1],
		         context->ddc_regs[inst->ci_i.i_reg1],
		         debug_rnames[inst->ci_i.i_reg2],
		         context->ddc_regs[inst->ci_i.i_reg2]);
	debug_clear_reg(context, inst->ci_i.i_reg2);
}

static void
debug_disasm_ii(debug_str_t decode,
                debug_str_t decomp,
                const union cpu_inst *inst,
                const char *mnemonic,
                const char *decomp_fmt,
                struct debug_disasm_context *context)
{
	snprintf(decode, debug_str_len, "%s %hi, %s",
	         mnemonic,
	         cpu_extend5to16(inst->ci_ii.ii_imm5),
	         debug_rnames[inst->ci_ii.ii_reg2]);
	if (context && context->ddc_regmask == DEBUG_REGMASK_ALL)
		snprintf(decomp, debug_str_len,
		         decomp_fmt,
		         inst->ci_ii.ii_imm5, context->ddc_regs[inst->ci_ii.ii_reg2], cpu_extend5to16(inst->ci_ii.ii_imm5));
	if (inst->ci_ii.ii_opcode != OP_SETF)
		debug_clear_reg(context, inst->ci_ii.ii_reg2);
}

static void
debug_disasm_v(debug_str_t decode,
               debug_str_t decomp,
               const union cpu_inst *inst,
               const char *mnemonic,
               const char *decomp_fmt,
               struct debug_disasm_context *context)
{
	snprintf(decode, debug_str_len, "%s %hd, %s, %s",
	         mnemonic, inst->ci_v.v_imm16, debug_rnames[inst->ci_v.v_reg1], debug_rnames[inst->ci_v.v_reg2]);
	const union cpu_reg *reg1;
	if ((reg1 = debug_get_reg(context, inst->ci_v.v_reg1)))
	{
		snprintf(decomp, debug_str_len, decomp_fmt,
		         inst->ci_v.v_imm16,
		         reg1->u,
		         debug_rnames[inst->ci_v.v_reg2]);
		switch (inst->ci_v.v_opcode)
		{
			union cpu_reg reg2;

			case OP_MOVHI:
			{
				reg2.u = reg1->u | (inst->ci_v.v_imm16 << 16);
				debug_put_reg(context, inst->ci_v.v_reg2, reg2);
				break;
			}
			case OP_MOVEA:
			{
				reg2.u = reg1->u + cpu_extend16(inst->ci_v.v_imm16);
				debug_put_reg(context, inst->ci_v.v_reg2, reg2);
				break;
			}
			default:
				debug_clear_reg(context, inst->ci_v.v_reg2);
		}
	}
}

static void
debug_disasm_vi(debug_str_t decode,
                debug_str_t decomp,
                const union cpu_inst *inst,
                const char *mnemonic,
                struct debug_disasm_context *context)
{
	snprintf(decode, debug_str_len, "%s %hd[%s], %s",
	         mnemonic, inst->ci_vi.vi_disp16, debug_rnames[inst->ci_vi.vi_reg1], debug_rnames[inst->ci_vi.vi_reg2]);
	const union cpu_reg *reg1;
	if ((reg1 = debug_get_reg(context, inst->ci_vi.vi_reg1)))
	{
		u_int32_t addr = reg1->u + inst->ci_vi.vi_disp16;
		debug_str_t addr_s;
		debug_format_addr(addr, addr_s);
		switch (inst->ci_vi.vi_opcode)
		{
			case OP_CAXI:
				snprintf(decomp, debug_str_len,
				         "[%s] <- r30 if oldval = %s", addr_s, debug_rnames[inst->ci_vi.vi_reg2]);
				break;
			case OP_LD_B:
			case OP_LD_H:
			case OP_LD_W:
				snprintf(decomp, debug_str_len, "[%s] -> %s", addr_s, debug_rnames[inst->ci_vi.vi_reg2]);
				debug_clear_reg(context, inst->ci_vi.vi_reg2);
				break;
			case OP_ST_B:
			{
				const union cpu_reg *reg2 = debug_get_reg(context, inst->ci_vi.vi_reg2);
				if (reg2)
					snprintf(decomp, debug_str_len, "[%s] <- 0x%02hhx", addr_s, reg2->u8s[0]);
				else
					snprintf(decomp, debug_str_len, "[%s] <- %s", addr_s, debug_rnames[inst->ci_vi.vi_reg2]);
				break;
			}
			case OP_ST_H:
			{
				const union cpu_reg *reg2 = debug_get_reg(context, inst->ci_vi.vi_reg2);
				if (reg2)
					snprintf(decomp, debug_str_len, "[%s] <- 0x%04hx", addr_s, reg2->s16);
				else
					snprintf(decomp, debug_str_len, "[%s] <- %s & 0xffff", addr_s, debug_rnames[inst->ci_vi.vi_reg2]);
				break;
			}
			case OP_ST_W:
			{
				const union cpu_reg *reg2 = debug_get_reg(context, inst->ci_vi.vi_reg2);
				if (reg2)
					snprintf(decomp, debug_str_len, "[%s] <- 0x%08x", addr_s, reg2->u);
				else
					snprintf(decomp, debug_str_len, "[%s] <- %s", addr_s, debug_rnames[inst->ci_vi.vi_reg2]);
				break;
			}
		}
	}
}

static void
debug_disasm_vi_fmt(debug_str_t decode,
                    debug_str_t decomp,
                    const union cpu_inst *inst,
                    const char *mnemonic,
                    const char *decomp_fmt,
                    struct debug_disasm_context *context)
{
	snprintf(decode, debug_str_len, "%s %hd[%s], %s",
	         mnemonic, inst->ci_vi.vi_disp16, debug_rnames[inst->ci_vi.vi_reg1], debug_rnames[inst->ci_vi.vi_reg2]);
	if (context && context->ddc_regmask == DEBUG_REGMASK_ALL)
	{
		u_int32_t addr = context->ddc_regs[inst->ci_vi.vi_reg1].u + inst->ci_vi.vi_disp16;
		debug_str_t addr_s;
		debug_format_addr(addr, addr_s);
		snprintf(decomp, debug_str_len, decomp_fmt,
		         addr_s,
		         debug_rnames[inst->ci_vi.vi_reg1],
		         context->ddc_regs[inst->ci_vi.vi_reg1].u,
		         debug_rnames[inst->ci_vi.vi_reg2],
		         context->ddc_regs[inst->ci_vi.vi_reg2].u);
	}
	// TODO: More specific clear
	debug_clear_reg(context, inst->ci_vi.vi_reg2);
}

static void
debug_disasm_vii(debug_str_t decode,
                 debug_str_t decomp,
                 const union cpu_inst *inst,
                 const char *mnemonic,
                 const char *decomp_fmt,
                 struct debug_disasm_context *context)
{
	const char *fmt;
	switch (inst->vii_subop)
	{
		default:
			fmt = "%s %s, %s";
			break;
		case FLOAT_XB:
		case FLOAT_XH:
			fmt = "%s %3$s";
			break;
	}

	snprintf(decode, debug_str_len, fmt, mnemonic, debug_rnames[inst->vii_reg1], debug_rnames[inst->vii_reg2]);
	if (context && context->ddc_regmask == DEBUG_REGMASK_ALL)
		snprintf(decomp, debug_str_len, decomp_fmt,
		         debug_rnames[inst->vii_reg1],
		         context->ddc_regs[inst->vii_reg1].f,
		         debug_rnames[inst->vii_reg2],
		         context->ddc_regs[inst->vii_reg2].f);
	debug_clear_reg(context, inst->vii_reg2);
}

static char *
debug_disasm_s(const union cpu_inst *inst, u_int32_t pc, struct debug_disasm_context *context, debug_str_t dis)
{
	debug_str_t decode, decomp = {0};
	const char *mnemonic = "???";
	switch (inst->ci_i.i_opcode)
	{
		case OP_MOV2:
			mnemonic = "MOV";
			break;
		case OP_SUB: mnemonic = "SUB"; break;
		case OP_CMP:
		case OP_CMP2:
			mnemonic = "CMP";
			break;
		case OP_JMP: mnemonic = "JMP"; break;
		case OP_SAR:
		case OP_SAR2:
			mnemonic = "SAR";
			break;
		case OP_MUL: mnemonic = "MUL"; break;
		case OP_OR: mnemonic = "OR"; break;
		case OP_AND: mnemonic = "AND"; break;
		case OP_XOR: mnemonic = "XOR"; break;
		case OP_CLI: mnemonic = "CLI"; break;
		case OP_LDSR: mnemonic = "LDSR"; break;
		case OP_STSR: mnemonic = "STSR"; break;
		case OP_SEI: mnemonic = "SEI"; break;
		case OP_JR: mnemonic = "JR"; break;
		case OP_JAL: mnemonic = "JAL"; break;
		case OP_ORI: mnemonic = "ORI"; break;
		case OP_ANDI: mnemonic = "ANDI"; break;
		case OP_XORI: mnemonic = "XORI"; break;
		default:
		{
			if (inst->ci_iii.iii_opcode == OP_BCOND)
			{
				switch (inst->ci_iii.iii_cond)
				{
					case BCOND_BV: mnemonic = "BV"; break;
					case BCOND_BL: mnemonic = "BL"; break;
					case BCOND_BZ: mnemonic = "BZ"; break;
					case BCOND_BNH: mnemonic = "BNH"; break;
					case BCOND_BN: mnemonic = "BN"; break;
					case BCOND_BR: mnemonic = "BR"; break;
					case BCOND_BLT: mnemonic = "BLT"; break;
					case BCOND_BLE: mnemonic = "BLE"; break;
					case BCOND_BNV: mnemonic = "BNV"; break;
					case BCOND_BNC: mnemonic = "BNC"; break;
					case BCOND_BNZ: mnemonic = "BNZ"; break;
					case BCOND_BH: mnemonic = "BH"; break;
					case BCOND_BP: mnemonic = "BP"; break;
					case BCOND_NOP: mnemonic = "NOP"; break;
					case BCOND_BGE: mnemonic = "BGE"; break;
					case BCOND_BGT: mnemonic = "BGT"; break;
				}
				break;
			}
			static char unknown[32];
			debug_str_t bin_s;
			snprintf(unknown, sizeof(unknown), "??? (%s)", debug_format_binary(inst->ci_i.i_opcode, 6, bin_s));
			mnemonic = unknown;
		}
	}
	switch (inst->ci_i.i_opcode)
	{
		case OP_MUL:
			snprintf(decode, debug_str_len, "%s %s, %s",
			         mnemonic, debug_rnames[inst->ci_i.i_reg1], debug_rnames[inst->ci_i.i_reg2]);
			if (context && context->ddc_regmask == DEBUG_REGMASK_ALL)
				snprintf(decomp, debug_str_len, "%i × %i",
				         context->ddc_regs[inst->ci_i.i_reg1].s, context->ddc_regs[inst->ci_i.i_reg2].s);
			debug_clear_reg(context, inst->ci_i.i_reg2);
			break;
		case OP_SUB:
			snprintf(decode, debug_str_len, "%s %s, %s",
			         mnemonic, debug_rnames[inst->ci_i.i_reg1], debug_rnames[inst->ci_i.i_reg2]);
			if (context && context->ddc_regmask == DEBUG_REGMASK_ALL)
				// TODO: use positional parameters
				snprintf(decomp, debug_str_len, "%i - %i | 0x%08x - 0x%08x",
				         context->ddc_regs[inst->ci_i.i_reg2].s, context->ddc_regs[inst->ci_i.i_reg1].s,
				         context->ddc_regs[inst->ci_i.i_reg2].u, context->ddc_regs[inst->ci_i.i_reg1].u);
			debug_clear_reg(context, inst->ci_i.i_reg2);
			break;
		case OP_ADD:
			debug_disasm_i_fmt(decode, decomp, inst, "ADD", "%3$s <- %4$d + %2$d (0x%4$08x + 0x%2$08x)", context);
			break;
		case OP_CMP:
			debug_disasm_i(decode, decomp, inst, "CMP", "<=>", context);
			break;
		case OP_DIV:
			debug_disasm_i(decode, decomp, inst, "DIV", "/", context);
			break;
		case OP_XOR:
			debug_disasm_i(decode, decomp, inst, "XOR", "^", context);
			break;
		case OP_SHL:
			debug_disasm_i(decode, decomp, inst, "SHL", "<<", context);
			break;
		case OP_SHR:
			debug_disasm_i(decode, decomp, inst, "SHR", ">>", context);
			break;
		case OP_SAR:
			debug_disasm_i(decode, decomp, inst, "SAR", ">>>", context);
			break;
		case OP_AND:
			debug_disasm_i(decode, decomp, inst, "AND", "&", context);
			break;
		case OP_OR:
			debug_disasm_i_fmt(decode, decomp, inst, "OR", "0x%4$08x | 0x%2$08x", context);
			break;
		case OP_MOV:
			debug_disasm_i_fmt(decode, decomp, inst, "MOV", "%3$s <- 0x%2$08x", context);
			break;
		case OP_MULU:
			debug_disasm_i_fmt(decode, decomp, inst, "MULU", "%4$u × %2$u", context);
			break;
		case OP_DIVU:
			debug_disasm_i_fmt(decode, decomp, inst, "DIVU", "%4$u ÷ %2$u", context);
			break;
		case OP_NOT:
			debug_disasm_i_fmt(decode, decomp, inst, "NOT", "%3$s <- ~%2$u", context);
			break;
		case OP_JMP:
			snprintf(decode, debug_str_len, "%s [%s]", mnemonic, debug_rnames[inst->ci_i.i_reg1]);
			const union cpu_reg *reg1 = debug_get_reg(context, inst->ci_i.i_reg1);
			if (reg1)
			{
				debug_str_t addr_s;
				snprintf(decomp, debug_str_len, "pc <- %s",
				         debug_format_addr(reg1->u, addr_s));
			}
			break;
		case OP_ADD2:
			debug_disasm_ii(decode, decomp, inst, "ADD", "%2$d + %3$hi (0x%2$08x + 0x%3$04x)", context);
			break;
		case OP_SETF:
		{
			switch (inst->ci_ii.ii_imm5)
			{
				case BCOND_BV: mnemonic = "V"; break;
				case BCOND_BL: mnemonic = "C/L"; break;
				case BCOND_BZ: mnemonic = "Z"; break;
				case BCOND_BNH: mnemonic = "NH"; break;
				case BCOND_BN: mnemonic = "S/N"; break;
				case BCOND_BR: mnemonic = "T"; break;
				case BCOND_BLT: mnemonic = "LT"; break;
				case BCOND_BLE: mnemonic = "LE"; break;
				case BCOND_BNV: mnemonic = "NV"; break;
				case BCOND_BNC: mnemonic = "NC/NL"; break;
				case BCOND_BNZ: mnemonic = "NZ"; break;
				case BCOND_BH: mnemonic = "H"; break;
				case BCOND_BP: mnemonic = "NS/P"; break;
				case BCOND_NOP: mnemonic = "F"; break;
				case BCOND_BGE: mnemonic = "GE"; break;
				case BCOND_BGT: mnemonic = "GT"; break;
			}
			debug_disasm_ii(decode, decomp, inst, "SETF", mnemonic, context);
			break;
		}
		case OP_MOV2:
		{
			u_int16_t imm = cpu_extend5to16(inst->ci_ii.ii_imm5);
			snprintf(decode, debug_str_len, "%s %hi, %s", mnemonic, imm, debug_rnames[inst->ci_ii.ii_reg2]);
			debug_clear_reg(context, inst->ci_ii.ii_reg2);
			break;
		}
		case OP_CMP2:
		{
			u_int16_t imm = cpu_extend5to16(inst->ci_ii.ii_imm5);
			snprintf(decode, debug_str_len, "%s %hi, %s", mnemonic, imm, debug_rnames[inst->ci_ii.ii_reg2]);
			if (context && context->ddc_regmask == DEBUG_REGMASK_ALL)
				snprintf(decomp, debug_str_len, "%d <=> %hi", context->ddc_regs[inst->ci_ii.ii_reg2].s, imm);
			break;
		}
		case OP_TRAP:
			snprintf(decode, debug_str_len, "%s", "TRAP");
			break;
		case OP_RETI:
			snprintf(decode, debug_str_len, "%s", "RETI");
			if (context && context->ddc_regmask == DEBUG_REGMASK_ALL)
				snprintf(decomp, debug_str_len, "pc <- 0x%08x, psw <- 0x%08x",
				         // TODO: Probably shouldn't decode these here
				         (cpu_state.cs_psw.psw_flags.f_np) ? cpu_state.cs_fepc : cpu_state.cs_eipc,
				         (cpu_state.cs_psw.psw_flags.f_np) ? cpu_state.cs_fepsw.psw_word : cpu_state.cs_eipsw.psw_word);
			break;
		case OP_HALT:
			snprintf(decode, debug_str_len, "%s", "HALT");
			break;
		case OP_CLI:
		case OP_SEI:
			snprintf(decode, debug_str_len, "%s", mnemonic);
			break;
		case OP_BSTR:
			switch (inst->ci_ii.ii_imm5)
			{
				case BSTR_SCH0BSU: mnemonic = "SCH0BSU"; break;
				case BSTR_SCH0BSD: mnemonic = "SCH0BSD"; break;
				case BSTR_SCH1BSU: mnemonic = "SCH1BSU"; break;
				case BSTR_SCH1BSD: mnemonic = "SCH1BSD"; break;
				case BSTR_ORBSU: mnemonic = "ORBSU"; break;
				case BSTR_ANDBSU: mnemonic = "ANDBSU"; break;
				case BSTR_XORBSU: mnemonic = "XORBSU"; break;
				case BSTR_MOVBSU: mnemonic = "MOVBSU"; break;
				case BSTR_ORNBSU: mnemonic = "ORNBSU"; break;
				case BSTR_ANDNBSU: mnemonic = "ANDNBSU"; break;
				case BSTR_XORNBSU: mnemonic = "XORNBSU"; break;
				case BSTR_NOTBSU: mnemonic = "NOTBSU"; break;
			}
			snprintf(decode, debug_str_len, "%s", mnemonic);
			if (context && context->ddc_regmask == DEBUG_REGMASK_ALL)
			{
				debug_str_t src_start_s, dest_start_s /*, src_end_s, dest_end_s*/;
				debug_format_addr(context->ddc_regs[30].u, src_start_s);
				debug_format_addr(context->ddc_regs[29].u, dest_start_s);
				u_int src_bit_off = context->ddc_regs[27].u & 31, dest_bit_off = context->ddc_regs[26].u & 31;
				snprintf(decomp, debug_str_len, "[%s.%u..] <- [%s.%u..] (%u bits)",
				         src_start_s, src_bit_off, dest_start_s, dest_bit_off, context->ddc_regs[28].u);
			}
			debug_clear_reg(context, 30);
			debug_clear_reg(context, 29);
			debug_clear_reg(context, 28);
			debug_clear_reg(context, 27);
			debug_clear_reg(context, 26);
			break;
		case OP_SHL2:
			debug_disasm_ii(decode, decomp, inst, "SHL", "0x%2$08x << %1$hu", context);
			break;
		case OP_SHR2:
			debug_disasm_ii(decode, decomp, inst, "SHR", "0x%2$08x >> %1$hu", context);
			break;
		case OP_SAR2:
			debug_disasm_ii(decode, decomp, inst, "SAR", "0x%2$08x >>> %1$hu", context);
			break;
		case OP_LDSR:
		case OP_STSR:
			snprintf(decode, debug_str_len, "%s %i, %s",
			         mnemonic, inst->ci_ii.ii_imm5, debug_rnames[inst->ci_ii.ii_reg2]);
			if (inst->ci_ii.ii_opcode == OP_STSR)
				debug_clear_reg(context, inst->ci_ii.ii_reg2);
			break;
		case OP_JR:
		case OP_JAL:
		{
			u_int32_t disp = cpu_inst_disp26(inst);
			snprintf(decode, debug_str_len, "%s %i", mnemonic, disp);
			if (pc)
			{
				debug_str_t addr_s;
				snprintf(decomp, debug_str_len, "%s", debug_format_addr(pc + disp, addr_s));
			}
			break;
		}
		case OP_ORI:
			debug_disasm_v(decode, decomp, inst, "ORI", "0x%2$08x | 0x%1$04hx", context);
			break;
		case OP_MOVEA:
			debug_disasm_v(decode, decomp, inst, "MOVEA", "%3$s <- 0x%2$08x + extend(0x%1$04hx)", context);
			break;
		case OP_ANDI:
			debug_disasm_v(decode, decomp, inst, "ANDI", "0x%2$08x & 0x%1$04hx", context);
			break;
		case OP_MOVHI:
			debug_disasm_v(decode, decomp, inst, "MOVHI", "%3$s <- 0x%2$08x | (0x%1$04hx << 16)", context);
			break;
		case OP_XORI:
			snprintf(decode, debug_str_len, "%s %hXh, %s, %s",
			         mnemonic, inst->ci_v.v_imm16, debug_rnames[inst->ci_v.v_reg1], debug_rnames[inst->ci_v.v_reg2]);
			debug_clear_reg(context, inst->ci_v.v_reg2);
			break;
		case OP_ADDI:
			debug_disasm_v(decode, decomp, inst, "ADDI", "%3$s <- 0x%2$08x + extend(0x%1$04hx)", context);
			break;
		case OP_CAXI:
			debug_disasm_vi(decode, decomp, inst, "CAXI", context);
			break;
		case OP_IN_B:
			debug_disasm_vi_fmt(decode, decomp, inst, "IN.B", "%4$s <- 0x%3$04hhx", context);
			break;
		case OP_IN_H:
			debug_disasm_vi_fmt(decode, decomp, inst, "IN.H", "%4$s <- [%1$s]", context);
			break;
		case OP_IN_W:
			debug_disasm_vi(decode, decomp, inst, "IN.W", context);
			break;
		case OP_LD_B:
			debug_disasm_vi(decode, decomp, inst, "LD.B", context);
			break;
		case OP_LD_H:
			debug_disasm_vi(decode, decomp, inst, "LD.H", context);
			break;
		case OP_LD_W:
			debug_disasm_vi(decode, decomp, inst, "LD.W", context);
			break;
		case OP_OUT_B:
			debug_disasm_vi(decode, decomp, inst, "OUT.B", context);
			break;
		case OP_OUT_H:
			debug_disasm_vi(decode, decomp, inst, "OUT.H", context);
			break;
		case OP_OUT_W:
			debug_disasm_vi_fmt(decode, decomp, inst, "OUT.W", "[%4$s] <- 0x%3$08x", context);
			break;
		case OP_ST_B:
			debug_disasm_vi(decode, decomp, inst, "ST.B", context);
			break;
		case OP_ST_H:
			debug_disasm_vi(decode, decomp, inst, "ST.H", context);
			break;
		case OP_ST_W:
			debug_disasm_vi(decode, decomp, inst, "ST.W", context);
			break;
		case OP_FLOAT:
		{
			switch (inst->vii_subop)
			{
				case FLOAT_CMPF_S:
					debug_disasm_vii(decode, decomp, inst, "CMPF.S", "%4$g <=> %2$g", context);
					break;
				case FLOAT_CVT_WS:
					debug_disasm_vii(decode, decomp, inst, "CVT.WS", "%3$s <- (float)%2$g", context);
					break;
				case FLOAT_CVT_SW:
					debug_disasm_vii(decode, decomp, inst, "CVT.SW", "%3$s <- lround(%2$g)", context);
					break;
				case FLOAT_ADDF_S:
					debug_disasm_vii(decode, decomp, inst, "ADDF.S", "%4$g + %2$g", context);
					break;
				case FLOAT_SUBF_S:
					debug_disasm_vii(decode, decomp, inst, "SUBF.S", "%4$g - %2$g", context);
					break;
				case FLOAT_MULF_S:
					debug_disasm_vii(decode, decomp, inst, "MULF.S", "%4$g × %2$g", context);
					break;
				case FLOAT_DIVF_S:
					debug_disasm_vii(decode, decomp, inst, "DIVF.S", "%4$g ÷ %2$g", context);
					break;
				case FLOAT_XB:
					debug_disasm_vii(decode, decomp, inst, "XB", "%3$s[4,3,2,1] = %3$s[4,3,1,2]", context);
					break;
				case FLOAT_XH:
					debug_disasm_vii(decode, decomp, inst, "XH", "%3$s[4,3,2,1] = %3$s[2,1,4,3]", context);
					break;
				case FLOAT_TRNC_SW:
					debug_disasm_vii(decode, decomp, inst, "TRNC.SW", "%3$s <- (int32_t)%4$g", context);
					break;
				case FLOAT_MPYHW:
					debug_disasm_vii(decode, decomp, inst, "MPYHW", "%4$hi x %2$hi", context);
					break;
				default:
				{
					debug_str_t bin_s;
					snprintf(decode, debug_str_len, "TODO: FLOAT %s", debug_format_binary(inst->vii_subop, 6, bin_s));
				}
			}
			break;
		}
		default:
			if (inst->ci_iii.iii_opcode == OP_BCOND)
			{
				u_int32_t disp = cpu_extend9(inst->ci_iii.iii_disp9);
				snprintf(decode, debug_str_len, "%s %i", mnemonic, disp);
				if (pc)
				{
					debug_str_t addr_s;
					snprintf(decomp, debug_str_len, "pc <- %s", debug_format_addr(pc + disp, addr_s));
				}
				break;
			}
			snprintf(decode, debug_str_len, "TODO: %s", mnemonic);
	}
	if (*decomp)
		snprintf(dis, debug_str_len, "%-20s; %s", decode, decomp);
	else
		snprintf(dis, debug_str_len, "%s", decode);
	return dis;
}

char *
debug_disasm(const union cpu_inst *inst, u_int32_t pc, struct debug_disasm_context *context)
{
	static debug_str_t dis;
	return debug_disasm_s(inst, pc, context, dis);
}

static const struct debug_help
{
	char dh_char;
	const char *dh_usage;
	const char *dh_desc;
} debug_help[] =
		{
				{'?', "", "Display this help (aliases: help)"},
				{'q', "", "Quit the emulator (aliases: quit, exit)"},
				{'c', "", "Continue execution (aliases: cont)"},
				{'s', "", "Step into the next instruction (aliases: step)"},
				{'b', "[<addr>]", "Set or remove breakpoint\n"
								  "\t\tOmit address to clear breakpoint"},
				{'i', "", "Show CPU info (aliases: info)"},
				{'x', "<addr> [<format>[<size>]] [<count>]", "Examine memory at <addr>\n"
						          "\t\tFormats: h (hex), i (instructions), b (binary), a (address), C (VIP CHR),"
				                                             " O (VIP OAM), B (VIP BGSC), T (Scanner Column Table)\n"
						          "\t\t\tW (VIP WORLD_ATT)\n"
						          "\t\tSizes: b (byte), h (half-word), w (word)\n"
						          "\t\tAddresses can be numeric or [<reg#>], <offset>[<reg#>], <sym>, <sym>+<offset>"},
				{'r', "", "Reset the CPU (aliases: reset)"},
				{'v', "", "Show VIP info (aliases: vip)"},
				{'d', "[<addr>]", "Disassemble from <addr> (defaults to [pc]) (aliases: dis)"},
				{'t', "[<subsystem>]", "Toggle tracing of a subsystem"},
				{'j', "<addr>", "Jump to <addr> (aliases: jump)"},
				{'N', "nvc", "Show NVC info (aliases: nvc)"},
				{'S', "[<name> [<addr>]]", "Add a debug symbol\n"
					"\t\tAddresses can be numeric or [<reg#>], <offset>[<reg#>], <sym>, <sym>+<offset>\n"
					"\t\tUse without address to show symbol address, use without name to show all symbols"},
				{'w', "( read | write | all | none ) <addr>",
					"Add or remove a debug watch\n\t\tUse without arguments to display watches"},
				{'W', "<mask>", "Set world drawing mask (aliases: world)"},
		};

static void
debug_print_help(const struct debug_help *help)
{
	printf("%c %s\t%s\n", help->dh_char, help->dh_usage, help->dh_desc);
}

static void
debug_usage(char ch)
{
	u_int help_index;
	for (help_index = 0; help_index < sizeof(debug_help) / sizeof(debug_help[0]); ++help_index)
	{
		if (debug_help[help_index].dh_char == ch)
		{
			debug_print_help(&(debug_help[help_index]));
			return;
		}
	}
	assert(!"No help found for character");
}

static bool
debug_mem_read(u_int32_t addr, void *dest, size_t size)
{
	u_int mem_wait;
	if (mem_read(addr, dest, size, false, &mem_wait))
		return true;
	else
	{
		warnx("Could not read %lu bytes from 0x%08x: Invalid address", size, addr);
		return false;
	}
}

u_int32_t
debug_locate_symbol(const char *s)
{
	for (struct debug_symbol *sym = debug_syms; sym; sym = sym->ds_next)
		if (!strcmp(sym->ds_name, s))
			return sym->ds_addr;
	return DEBUG_ADDR_NONE;
}

static bool
debug_parse_addr(const char *s, u_int32_t *addrp)
{
	size_t len = strlen(s);
	u_int32_t base, disp = 0;
	char reg_name[4];
	int nparsed;

	if ((sscanf(s, "%i[pc]%n", &disp, &nparsed) == 1 && (size_t)nparsed == len) ||
	    (sscanf(s, "[pc]%n", &nparsed) == 0 && (size_t)nparsed == len))
		base = cpu_state.cs_pc;
	else if ((sscanf(s, "%i[%2s]%n", &disp, reg_name, &nparsed) == 2 && (size_t)nparsed == len) ||
			(sscanf(s, "[%2s]%n", reg_name, &nparsed) == 1 && (size_t)nparsed == len) ||
			(sscanf(s, "%i[%3s]%n", &disp, reg_name, &nparsed) == 2 && (size_t)nparsed == len) ||
			(sscanf(s, "[%3s]%n", reg_name, &nparsed) == 1 && (size_t)nparsed == len))
	{
		u_int reg_num;
		for (reg_num = 0; reg_num < 32; ++reg_num)
			if (!strcmp(reg_name, debug_rnames[reg_num]))
				break;
		if (reg_num == 32)
		{
			warnx("Invalid register name %s", reg_name);
			return false;
		}
		base = cpu_state.cs_r[reg_num].u;
	}
	else if (sscanf(s, "%i%n", &base, &nparsed) == 1 && (size_t)nparsed == len)
		disp = 0;
	else
	{
		char sym_name[64 + 1], sign[2];
		int num_parsed;
		num_parsed = sscanf(s, "%64[^+-]%n%1[+-]%i%n", sym_name, &nparsed, sign, &disp, &nparsed);
		if (num_parsed >= 1 && (size_t)nparsed == len)
		{
#if 0
			fprintf(stderr, "Sym name: \"%s\"\n", sym_name);
#endif // 0
			if ((base = debug_locate_symbol(sym_name)) == DEBUG_ADDR_NONE)
			{
				warnx("Symbol not found: %s", s);
				return false;
			}
			if (num_parsed >= 2 && *sign == '-')
				disp = -disp;
		}
		else
		{
			warnx("Invalid address format “%s”", s);
			return false;
		}
	}
	*addrp = base + disp;
	return true;
}

bool
debug_disasm_at(u_int32_t *addrp)
{
	union cpu_inst inst;
	if (!cpu_fetch(*addrp, &inst))
		return false;
	printf(" %s\n", debug_disasm(&inst, *addrp, NULL));

	*addrp+= cpu_inst_size(&inst);
	return true;
}

void
debug_enter(void)
{
	debugging = true;
}

char *
debug_format_flags(debug_str_t s, ...)
{
	va_list ap;
	va_start(ap, s);
	const char *name;
	size_t len = 0;
	s[0] = '\0';
	while ((name = va_arg(ap, typeof(name))))
	{
		u_int flag = va_arg(ap, typeof(flag));
		if (flag)
			len+= snprintf(s + len, debug_str_len - len, "%s%s", (len > 0) ? "|" : "", name);
	}
	va_end(ap);
	return s;
}

const char *
debug_format_perms(int perms, debug_str_t s)
{
	return debug_format_flags(s,
	                          "NONE", (perms == 0),
	                          "READ", (perms & PROT_READ),
	                          "WRITE", (perms & PROT_WRITE),
	                          "EXEC", (perms & PROT_EXEC),
	                          NULL);
}

static void
debug_print_psw(union cpu_psw psw, const char *name)
{
	debug_str_t psw_s;
	printf("\t%s: 0x%08x (%s) (interrupt level %d)",
	       name,
	       psw.psw_word,
	       debug_format_flags(psw_s,
	                          "Z", psw.psw_flags.f_z,
	                          "S", psw.psw_flags.f_s,
	                          "OV", psw.psw_flags.f_ov,
	                          "CY", psw.psw_flags.f_cy,
	                          "FPR", psw.psw_flags.f_fpr,
	                          "FUD", psw.psw_flags.f_fud,
	                          "FOV", psw.psw_flags.f_fov,
	                          "FZD", psw.psw_flags.f_fzd,
	                          "FIV", psw.psw_flags.f_fiv,
	                          "FRO", psw.psw_flags.f_fro,
	                          "ID", psw.psw_flags.f_id,
	                          "AE", psw.psw_flags.f_ae,
	                          "EP", psw.psw_flags.f_ep,
	                          "NP", psw.psw_flags.f_np,
	                          NULL),
	       psw.psw_flags.f_i);
}

static void
debug_print_intreg(u_int16_t intreg, const char *name)
{
	debug_str_t flags_str;
	printf("%s: (%s)",
	       name,
	       debug_format_flags(flags_str,
	                          "SCANERR", intreg & VIP_SCANERR,
	                          "LFBEND", intreg & VIP_LFBEND,
	                          "RFBEND", intreg & VIP_RFBEND,
	                          "GAMESTART", intreg & VIP_GAMESTART,
	                          "FRAMESTART", intreg & VIP_FRAMESTART,
	                          "SBHIT", intreg & VIP_SBHIT,
	                          "XPEND", intreg & VIP_XPEND,
	                          "TIMEERR", intreg & VIP_TIMEERR,
	                          NULL));
}

static void
debug_print_dpctrl(struct vip_dpctrl vd, const char *name)
{
	debug_str_t flags_str;
	printf("%s: (%s)",
	       name,
	       debug_format_flags(flags_str,
	                          "DISP", vd.vd_disp,
	                          "DPBSY:L:FB0", vd.vd_dpbsy_l_fb0,
	                          "DPBSY:R:FB0", vd.vd_dpbsy_r_fb0,
	                          "DPBSY:L:FB1", vd.vd_dpbsy_l_fb1,
	                          "DPBSY:R:FB1", vd.vd_dpbsy_r_fb1,
	                          "SCANRDY", vd.vd_scanrdy,
	                          "FCLK", vd.vd_fclk,
	                          "RE", vd.vd_re,
	                          "SYNCE", vd.vd_synce,
	                          "LOCK", vd.vd_lock,
	                          NULL));
}

static void
debug_print_xpctrl(struct vip_xpctrl vx, const char *name)
{
	debug_str_t flags_str;
	printf("%s: (%s)",
	       name,
	       debug_format_flags(flags_str,
	                          "XPRST", vx.vx_xprst,
	                          "XPEN", vx.vx_xpen,
	                          "XPBSY:FB0", vx.vx_xpbsy_fb0,
	                          "XPBSY:FB1", vx.vx_xpbsy_fb1,
	                          "OVERTIME", vx.vx_overtime,
	                          "SBOUT", vx.vx_sbout,
	                          NULL));
}

void
debug_print_bgsc(struct vip_bgsc *vb)
{
	printf("CHR No: %u, BVFLP=%u, BHFLP=%u, GPLTS=%u\n",
	       vb->vb_chrno, vb->vb_bvflp, vb->vb_bhflp, vb->vb_gplts);
}

void
debug_format_world_att(char *buf, size_t buflen, const struct vip_world_att *vwa)
{
	debug_str_t flags_s;
	size_t bufoff = 0;
	const char *bgm_s;
	switch (vwa->vwa_bgm)
	{
		case WORLD_BGM_NORMAL: bgm_s = "NORMAL"; break;
		case WORLD_BGM_AFFINE: bgm_s = "AFFINE"; break;
		case WORLD_BGM_H_BIAS: bgm_s = "H_BIAS"; break;
		case WORLD_BGM_OBJ: bgm_s = "OBJ"; break;
	}
	bufoff+= snprintf(buf + bufoff, buflen - bufoff, "(%s) BGM=%s, SCX=%u, SCY=%u, BGMAP BASE=%u\n",
	                  debug_format_flags(flags_s,
	                                     "LON", vwa->vwa_lon,
	                                     "RON", vwa->vwa_ron,
	                                     "OVER", vwa->vwa_over,
	                                     "END", vwa->vwa_end,
	                                     NULL),
	                  bgm_s,
	                  vwa->vwa_scx,
	                  vwa->vwa_scy,
	                  vwa->vwa_bgmap_base);
	if (!vwa->vwa_end && (vwa->vwa_lon || vwa->vwa_ron))
	{
		bufoff+= snprintf(buf + bufoff, buflen - bufoff,
		                  "\tGX=%hd, GP=%hd, GY=%hd, MX=%hd, MP=%hd, MY=%hu, W=%hu, H=%hu\n",
		                  vwa->vwa_gx, vwa->vwa_gp, vwa->vwa_gy, vwa->vwa_mx, vwa->vwa_mp, vwa->vwa_my, vwa->vwa_w, vwa->vwa_h);
		bufoff+= snprintf(buf + bufoff, buflen - bufoff,
		                  "\tPARAM BASE=%hu, OVERPLANE CHARACTER=%hu\n", vwa->vwa_param_base, vwa->vwa_over_chrno);
	}
}

void
debug_format_oam(debug_str_t s, const struct vip_oam *vop)
{
	snprintf(s, debug_str_len, "JX=%hd, JP=%d, JRON=%u, JLON=%u, JY=%hd, JCA=%u"
			", JVFLP=%u, JHFLP=%u, JPLTS=%u\n",
	         vop->vo_jx, vop->vo_jp, vop->vo_jron, vop->vo_jlon, vop->vo_jy, vop->vo_jca,
	         vop->vo_jvflp, vop->vo_jhflp, vop->vo_jplts);
}

static void
debug_show_trace(const struct debug_trace trace)
{
	printf("%s tracing is %s\n", trace.dt_key, (*trace.dt_tracep) ? "on" : "off");
}

bool
debug_toggle_trace(const char *key)
{
	for (u_int i = 0; i < sizeof(debug_traces) / sizeof(debug_traces[0]); ++i)
		if (!strcmp(key, debug_traces[i].dt_key))
		{
			*debug_traces[i].dt_tracep = !*debug_traces[i].dt_tracep;
			debug_show_trace(debug_traces[i]);
			return true;
		}
	return false;
}

struct debug_watch *
debug_find_watch(u_int32_t addr, int mem_op)
{
	for (struct debug_watch *watch = debug_watches; watch; watch = watch->dw_next)
		if (watch->dw_addr == addr)
			return ((watch->dw_ops & mem_op) != 0) ? watch : NULL;
	return NULL;
}

void
debug_watch_read(u_int32_t pc, u_int32_t addr, u_int32_t value, u_int byte_size)
{
	if (debug_find_watch(addr, PROT_READ))
	{
		debug_str_t addr_s, mem_addr_s, hex_s;
		debug_tracef("watch", DEBUG_ADDR_FMT ": [" DEBUG_ADDR_FMT "] -> %s\n",
		             debug_format_addr(pc, addr_s),
		             debug_format_addr(addr, mem_addr_s),
		             debug_format_hex((u_int8_t *)&value, byte_size, hex_s));
	}
}

void
debug_watch_write(u_int32_t pc, u_int32_t addr, u_int32_t value, u_int byte_size)
{
	if (debug_find_watch(addr, PROT_WRITE))
	{
		debug_str_t addr_s, mem_addr_s, hex_s;
		debug_tracef("watch", DEBUG_ADDR_FMT ": [" DEBUG_ADDR_FMT "] <- %s\n",
		             debug_format_addr(pc, addr_s),
		             debug_format_addr(addr, mem_addr_s),
		             debug_format_hex((u_int8_t *)&value, byte_size, hex_s));
	}
}

bool
debug_step(void)
{
	bool running = true;

	main_unblock_sigint();

	assert(debugging);
	while (true)
	{
		union cpu_inst inst;
		if (cpu_fetch(cpu_state.cs_pc, &inst))
		{
			debug_str_t addr_s;
			printf("frame 0: " DEBUG_ADDR_FMT ": %s\n",
			       debug_format_addr(cpu_state.cs_pc, addr_s),
			       debug_disasm(&inst, cpu_state.cs_pc, debug_current_context()));
		}

		tok_reset(s_token);
		int length;
		const char *line = el_gets(s_editline, &length);
		if (line)
		{
			HistEvent hist_event;
			if (history(s_history, &hist_event, H_ENTER, line) == -1)
				warn("Could not save editline history");

			int argc;
			const char **argv;
			if (tok_str(s_token, line, &argc, &argv) == 0 && argc > 0)
			{
				if (!strcmp(argv[0], "?") || !strcmp(argv[0], "help"))
				{
					puts("Debugger commands:");
					for (u_int help_index = 0; help_index < sizeof(debug_help) / sizeof(debug_help[0]); ++help_index)
						debug_print_help(&(debug_help[help_index]));
				}
				else if (!strcmp(argv[0], "q") || !strcmp(argv[0], "quit") || !strcmp(argv[0], "exit"))
				{
					tk_quit();
					debugging = false;
					running = false;
					break;
				}
				else if (!strcmp(argv[0], "c") || !strcmp(argv[0], "cont"))
				{
					debugging = false;
					break;
				}
				else if (!strcmp(argv[0], "s") || !strcmp(argv[0], "step"))
					break;
				else if (!strcmp(argv[0], "b") || !strcmp(argv[0], "break"))
				{
					if (argc > 2)
					{
						debug_usage('b');
						continue;
					}

					if (argc == 2)
					{
						if (debug_parse_addr(argv[1], &debug_break))
						{
							debug_str_t addr_s;
							printf("Set breakpoint at %s\n", debug_format_addr(debug_break, addr_s));
						}
					}
					else
					{
						debug_break = DEBUG_ADDR_NONE;
						printf("Cleared breakpoint\n");
					}
				}
				else if (!strcmp(argv[0], "i") || !strcmp(argv[0], "info"))
				{
					static const char *fmt = "%5s: " DEBUG_ADDR_FMT;
					debug_str_t addr_s;
					for (u_int regIndex = 0; regIndex < 32; ++regIndex)
					{
						printf(fmt, debug_rnames[regIndex], debug_format_addr(cpu_state.cs_r[regIndex].u, addr_s));
						printf(" (%11i, %11g)", cpu_state.cs_r[regIndex].s, cpu_state.cs_r[regIndex].f);
						if (regIndex % 2 == 1)
							putchar('\n');
					}
					printf(fmt, "pc", debug_format_addr(cpu_state.cs_pc, addr_s));
					debug_print_psw(cpu_state.cs_psw, "  psw");
					putchar('\n');
					printf("  ecr: (eicc: 0x%04hx, fecc: 0x%04hx)\n",
					       cpu_state.cs_ecr.ecr_eicc, cpu_state.cs_ecr.ecr_fecc);
					printf(fmt, "eipc", debug_format_addr(cpu_state.cs_eipc, addr_s));
					debug_print_psw(cpu_state.cs_eipsw, "eipsw");
					putchar('\n');
					printf(fmt, "fepc", debug_format_addr(cpu_state.cs_fepc, addr_s));
					debug_print_psw(cpu_state.cs_fepsw, "fepsw");
					putchar('\n');
				}
				else if (!strcmp(argv[0], "x"))
				{
					if (argc >= 2)
					{
						u_int32_t addr;
						if (!debug_parse_addr(argv[1], &addr))
							continue;
						const char *format = "h";
						u_int count = 1;
						if (argc >= 3)
							format = argv[2];
						if (argc >= 4)
							count = strtoul(argv[3], NULL, 0);

						size_t int_size = 4;
						if ((format[0] == 'h' || format[0] == 'b') && strlen(format) == 2)
						{
							switch (format[1])
							{
								case 'b':
									int_size = 1;
									break;
								case 'h':
									int_size = 2;
									break;
								case 'w':
									int_size = 4;
									break;
							}
						}

						for (u_int objIndex = 0; objIndex < count; ++objIndex)
						{
							debug_str_t addr_s;
							printf("%s: ", debug_format_addr(addr, addr_s));
							if (format[0] == 'h' && strlen(format) <= 2)
							{
								u_int value;
								if (debug_mem_read(addr, &value, int_size))
									printf(" 0x%0.*x\n", (int)int_size << 1, value);
								addr+= int_size;
							}
							else if (!strcmp(format, "i"))
							{
								if (!debug_disasm_at(&addr))
									break;
							}
							else if (format[0] == 'b' && strlen(format) <= 2)
							{
								u_int value;
								if (debug_mem_read(addr, &value, int_size))
								{
									debug_str_t bin_s;
									printf(" %s\n", debug_format_binary(value, int_size << 3, bin_s));
								}
								addr+= int_size;
							}
							else if (!strcmp(format, "addr"))
							{
								u_int32_t addr_value;
								if (debug_mem_read(addr, &addr_value, sizeof(addr_value)))
									printf(" %s\n", debug_format_addr(addr_value, addr_s));
								addr+= sizeof(addr_value);
							}
							else if (!strcmp(format, "C"))
							{
								putchar('\n');
								for (u_int rindex = 0; rindex < 8; ++rindex)
								{
									u_int16_t chr_row;
									if (!debug_mem_read(addr, &(chr_row), sizeof(chr_row)))
										break;
									//static const char *shading = " ░▒▓";
									static const char *shading = " -=#";
									for (u_int cindex = 0; cindex < 8; ++cindex)
									{
										putchar(shading[chr_row & 0b11]);
										chr_row>>= 2;
									}
									putchar('\n');
									addr+= sizeof(chr_row);
								}
							}
							else if (!strcmp(format, "O"))
							{
								struct vip_oam oam;
								if (!debug_mem_read(addr, &oam, sizeof(oam)))
									break;
								debug_str_t oam_str;
								debug_format_oam(oam_str, &oam);
								puts(oam_str);
								addr+= sizeof(oam);
							}
							else if (!strcmp(format, "B"))
							{
								struct vip_bgsc bgsc;
								if (!debug_mem_read(addr, &bgsc, sizeof(bgsc)))
									break;
								debug_print_bgsc(&bgsc);
								addr+= sizeof(bgsc);
							}
							else if (!strcmp(format, "W"))
							{
								struct vip_world_att att;
								if (!debug_mem_read(addr, &att, sizeof(att)))
									break;
								char buf[1024];
								debug_format_world_att(buf, sizeof(buf), &att);
								fputs(buf, stdout);
								addr+= sizeof(att);
							}
							else if (!strcmp(format, "T"))
							{
								struct vip_ctc ctc;
								if (!debug_mem_read(addr, &ctc, sizeof(ctc)))
									break;
								printf("REPEAT: %hhu, LENGTH: %hhu\n", ctc.vc_repeat, ctc.vc_length);
								addr+= sizeof(ctc);
							}
							else if (!strcmp(format, "P"))
							{
								u_int16_t plt;
								if (!debug_mem_read(addr, &plt, sizeof(plt)))
									break;
								debug_str_t b01_s, b10_s, b11_s;
								printf("0b01 = %s, 0b10 = %s, 0b11 = %s\n",
								       debug_format_binary((plt >> 2) & 0b11, 2, b01_s),
								       debug_format_binary((plt >> 4) & 0b11, 2, b10_s),
								       debug_format_binary((plt >> 6) & 0b11, 2, b11_s));
								addr+= sizeof(plt);
							}
							else
							{
								debug_usage('x');
								break;
							}
						}
					}
					else
						debug_usage('x');
				}
				else if (!strcmp(argv[0], "r") || !strcmp(argv[0], "reset"))
					cpu_reset();
				else if (!strcmp(argv[0], "v") || !strcmp(argv[0], "vip"))
				{
					debug_print_intreg(vip_regs.vr_intpnd, "INTPND");
					fputs(", ", stdout);
					debug_print_intreg(vip_regs.vr_intenb, "INTENB");
					fputs(", ", stdout);
					debug_print_intreg(vip_regs.vr_intclr, "INTCLR");
					putchar('\n');
					debug_print_dpctrl(vip_regs.vr_dpstts, "DPSTTS");
					fputs(", ", stdout);
					debug_print_dpctrl(vip_regs.vr_dpctrl, "DPCTRL");
					putchar('\n');
					debug_print_xpctrl(vip_regs.vr_xpstts, "XPSTTS");
					printf(" SBCOUNT=%d", vip_regs.vr_xpstts.vx_sbcount);
					fputs(", ", stdout);
					debug_print_xpctrl(vip_regs.vr_xpctrl, "XPCTRL");
					printf(" SBCMP=%d", vip_regs.vr_xpctrl.vx_sbcount);
					putchar('\n');
					printf("BRTA: %hhu, BRTB: %hhu, BRTC: %hhu, REST: %hhu\n",
					       vip_regs.vr_brta, vip_regs.vr_brtb, vip_regs.vr_brtc, vip_regs.vr_rest);
					printf("FRMCYC: %d\n", vip_regs.vr_frmcyc);
					u_int world_index = 31;
					do
					{
						const struct vip_world_att *vwa = &(vip_dram.vd_world_atts[world_index]);
						if (vwa->vwa_end)
							break;
						char buf[1024];
						debug_format_world_att(buf, sizeof(buf), vwa);
						printf("WORLD_ATT[%u]: %s", world_index, buf);
					} while (world_index-- > 0);
				}
				else if (!strcmp(argv[0], "d") || !strcmp(argv[0], "dis"))
				{
					u_int inst_limit;
					u_int32_t pc;
					if (argc >= 2)
					{
						if (!debug_parse_addr(argv[1], &pc))
							continue;
					}
					else
						pc = cpu_state.cs_pc;

					struct debug_symbol *start_sym, *next_sym;
					u_int32_t offset;
					start_sym = debug_resolve_addr(pc, &offset);
					next_sym = start_sym;

					if (argc >= 3)
						inst_limit = strtoul(argv[2], NULL, 10);
					else if (start_sym)
						inst_limit = 8192;
					else
					{
						inst_limit = 25;
						printf("No symbol found at start address: only disassembling %u instructions\n", inst_limit);
					}

					while (next_sym == start_sym && inst_limit > 0)
					{
						debug_str_t addr_s;

						printf(DEBUG_ADDR_FMT ":", debug_format_addrsym(pc, next_sym, addr_s));
						if (!debug_disasm_at(&pc))
							break;
						next_sym = debug_resolve_addr(pc, &offset);
						--inst_limit;
					}
				}
				else if (!strcmp(argv[0], "N") || !strcmp(argv[0], "nvc"))
				{
					debug_str_t flags_s;
					printf("SCR: (%s)\n",
					       debug_format_flags(flags_s,
					                          "Abt-Dis", nvc_regs.nr_scr.s_abt_dis,
					                          "SI-Stat", nvc_regs.nr_scr.s_si_stat,
					                          "HW-SI", nvc_regs.nr_scr.s_hw_si,
					                          "Soft-Ck", nvc_regs.nr_scr.s_soft_ck,
					                          "Para-SI", nvc_regs.nr_scr.s_para_si,
					                          "K-Int-Inh", nvc_regs.nr_scr.s_k_int_inh,
					                          NULL));
				}
				else if (!strcmp(argv[0], "S"))
				{
					if (argc == 1)
					{
						for (struct debug_symbol *sym = debug_syms; sym; sym = sym->ds_next)
							printf("debug symbol: %s = 0x%08x, type = %u\n",
							       sym->ds_name, sym->ds_addr, sym->ds_type);
					}
					else if (argc == 2)
					{
						u_int32_t addr = debug_locate_symbol(argv[1]);
						if (addr != DEBUG_ADDR_NONE)
							printf("%s = 0x%08x\n", argv[1], addr);
						else
							printf("Symbol %s not found\n", argv[1]);
					}
					else if (argc == 3)
					{
						u_int32_t addr;
						if (!debug_parse_addr(argv[2], &addr))
							continue;

						if (debug_locate_symbol(argv[1]) == DEBUG_ADDR_NONE)
						{
							struct debug_symbol *sym = debug_create_symbol(argv[1], addr);
							rom_add_symbol(sym);
						}
						else
							printf("Symbol %s already exists\n", argv[1]);
					}
					else
					{
						debug_usage('S');
						continue;
					}
				}
				else if (!strcmp(argv[0], "w"))
				{
					if (argc == 1)
					{
						for (struct debug_watch *watch = debug_watches; watch; watch = watch->dw_next)
						{
							debug_str_t addr_s, ops_s;
							printf("Watch at %s, ops = %s\n",
							       debug_format_addr(watch->dw_addr, addr_s),
							       debug_format_perms(watch->dw_ops, ops_s));
						}
					}
					else if (argc == 3)
					{
						int ops;
						if (!strcmp(argv[1], "read"))
							ops = PROT_READ;
						else if (!strcmp(argv[1], "write"))
							ops = PROT_WRITE;
						else if (!strcmp(argv[1], "all"))
							ops = PROT_READ | PROT_WRITE;
						else if (!strcmp(argv[1], "none"))
							ops = 0;
						else
						{
							debug_usage('w');
							continue;
						}

						u_int32_t addr;
						if (!debug_parse_addr(argv[2], &addr))
						{
							debug_usage('w');
							continue;
						}

						struct debug_watch **prevp = &(debug_watches);
						struct debug_watch *watch;
						for (watch = debug_watches; watch; watch = watch->dw_next)
						{
							if (watch->dw_addr == addr)
								break;
							prevp = &(watch->dw_next);
						}
						if (watch)
						{
							if (ops)
							{
								if (watch->dw_ops == ops)
									printf("Watch at 0x%08x already exists\n", addr);
								else
									watch->dw_ops = ops;
							}
							else
							{
								*prevp = watch->dw_next;
								free(watch);
							}
						}
						else
						{
							if (!ops)
								printf("No watch found for 0x%08x\n", addr);
							else
							{
								watch = malloc(sizeof(*watch));
								if (!watch)
									err(1, "Allocate debug watch");
								watch->dw_addr = addr;
								watch->dw_ops = ops;
								watch->dw_next = debug_watches;
								debug_watches = watch;
							}
						}
					}
					else
						debug_usage('w');
				}
				else if (!strcmp(argv[0], "W") || !strcmp(argv[0], "world"))
				{
					if (argc == 1)
						printf("World mask 0x%08x\n", vip_world_mask);
					else if (argc == 2)
						vip_world_mask = strtoul(argv[1], NULL, 0);
					else
					{
						debug_usage('W');
						continue;
					}
				}
				else if (!strcmp(argv[0], "t"))
				{
					if (argc > 1)
					{
						if (!debug_toggle_trace(argv[1]))
						{
							debug_usage('t');
							continue;
						}
					}
					else
					{
						for (u_int i = 0; i < sizeof(debug_traces) / sizeof(debug_traces[0]); ++i)
							debug_show_trace(debug_traces[i]);
					}
				}
				else if (!strcmp(argv[0], "j") || !strcmp(argv[0], "jump"))
				{
					if (argc != 2)
					{
						debug_usage('j');
						continue;
					}

					u_int32_t addr;
					if (!debug_parse_addr(argv[1], &addr))
						printf("Could not parse address %s\n", argv[1]);

					cpu_state.cs_pc = addr;
				}
				else
					printf("Unknown command “%s” -- type ‘?’ for help\n", argv[0]);
			}
		}
		else
		{
			putchar('\n');
			tk_quit();
			break;
		}
	}

	main_block_sigint();

	return running;
}

void
debug_tracef(const char *tag, const char *fmt, ...)
{
	va_list ap;
	va_start(ap, fmt);
	char trace[2048];
	size_t offset;
	offset = snprintf(trace, sizeof(trace), "@%07d [%s] ", main_usec, tag);
	vsnprintf(trace + offset, sizeof(trace) - offset, fmt, ap);
	fputs(trace, stdout);
	if (debug_trace_file)
		fputs(trace, debug_trace_file);
	va_end(ap);
} __printflike(2, 3)

bool
debug_runtime_errorf(bool *ignore_flagp, const char *fmt, ...)
{
	va_list ap;
	va_start(ap, fmt);
	char msg[1024];
	vsnprintf(msg, sizeof(msg), fmt, ap);
	va_end(ap);
	fputs(msg, stderr);
	fputc('\n', stderr);

	if (debugging)
		return true;

	if (ignore_flagp && *ignore_flagp)
		return true;

	switch (tk_runtime_error(msg, (ignore_flagp != NULL)))
	{
		case ERROR_IGNORE:
			return true;

		case ERROR_ALWAYS_IGNORE:
			*ignore_flagp = true;
			return true;

		case ERROR_DEBUG:
			debugging = true;
			return false;

		case ERROR_ABORT:
			abort();
	}
	return false;
}

void
debug_imgui(void)
{
	if (igBeginMainMenuBar())
	{
		if (igBeginMenu("Debug", true))
		{
			igMenuItemPtr("Trace NVC", NULL, &debug_trace_nvc, true);

			igEndMenu();
		}

		igEndMainMenuBar();
	}
}

/* GL */
enum gl_texture
{
	TEXTURE_LEFT,
	TEXTURE_RIGHT,
	TEXTURE_DEBUG,
	NUM_TEXTURES
};
static GLuint gl_textures[NUM_TEXTURES];
static GLuint gl_vao, gl_vbo;
static GLuint gl_program;
static GLint gl_color_uniform;
static u_int32_t gl_debug_frame[512 * 512];

static bool
gl_check_errors(const char *desc)
{
	bool none = true;
	GLenum error;
	while ((error = glGetError()) != GL_NO_ERROR)
	{
		const char *err_desc;
		switch (error)
		{
			default:
			{
				static char unknown_err_desc[10];
				snprintf(unknown_err_desc, sizeof(unknown_err_desc), "%08x", error);
				err_desc = unknown_err_desc;
				break;
			}

			case GL_INVALID_ENUM: err_desc = "GL_INVALID_ENUM"; break;
			case GL_INVALID_VALUE: err_desc = "GL_INVALID_VALUE"; break;
			case GL_INVALID_OPERATION: err_desc = "GL_INVALID_OPERATION"; break;
			case GL_OUT_OF_MEMORY: err_desc = "GL_OUT_OF_MEMORY"; break;
		}

		debug_runtime_errorf(NULL, "GL error during %s: %s\n", desc, err_desc);
		none = false;
	}
	return none;
}

static bool
gl_check_program(GLuint program, GLenum pname,
                 const char *desc,
                 void (*get_func)(GLuint, GLenum, GLint *),
                 void (*log_func)(GLuint, GLsizei, GLsizei *, GLchar *))
{
	GLint status;
	get_func(program, pname, &status);
	if (status != GL_TRUE)
	{
		char log[256];
		log_func(program, sizeof(log), NULL, log);
		debug_runtime_errorf(NULL, "%s failed: %s", desc, log);
		return false;
	}
	return true;
}

bool
gl_init(void)
{
	enum
	{
		ATTRIB_POSITION,
		ATTRIB_TEX_COORD
	};

	static const GLchar * vertex_shader_src =
			"#version 150\n"
			"in vec2 i_position;\n"
            "in vec2 i_tex_coord;\n"
			"out vec2 v_tex_coord;\n"
			"void main() {\n"
            "    v_tex_coord = i_tex_coord;\n"
			"    gl_Position = vec4(i_position, 0.0, 1.0);\n"
			"}\n";

	static const GLchar * fragment_shader_src =
			"#version 150\n"
            "in vec2 v_tex_coord;\n"
			"out vec4 o_color;\n"
			"uniform sampler2D tex;\n"
			"uniform vec4 color;\n"
			"void main() {\n"
			"    o_color = texture(tex, v_tex_coord) * color;\n"
			"}\n";

	GLuint vertex_shader, fragment_shader;

	vertex_shader = glCreateShader(GL_VERTEX_SHADER);
	fragment_shader = glCreateShader(GL_FRAGMENT_SHADER);
	gl_check_errors("create shaders");

	glShaderSource(vertex_shader, 1, &vertex_shader_src, NULL);
	glCompileShader(vertex_shader);
	gl_check_program(vertex_shader, GL_COMPILE_STATUS, "compile vertex program", glGetShaderiv, glGetShaderInfoLog);

	glShaderSource(fragment_shader, 1, &fragment_shader_src, NULL);
	glCompileShader(fragment_shader);
	gl_check_program(fragment_shader, GL_COMPILE_STATUS, "compile fragment program", glGetShaderiv, glGetShaderInfoLog);

	gl_program = glCreateProgram();
	glAttachShader(gl_program, vertex_shader);
	glAttachShader(gl_program, fragment_shader);
	gl_check_errors("attach shaders");

	glBindAttribLocation(gl_program, ATTRIB_POSITION, "i_position");
	glBindAttribLocation(gl_program, ATTRIB_TEX_COORD, "i_tex_coord");
	glLinkProgram(gl_program);
	if (!gl_check_program(gl_program, GL_LINK_STATUS, "link program", glGetProgramiv, glGetProgramInfoLog))
		return false;

	gl_color_uniform = glGetUniformLocation(gl_program, "color");
	gl_check_errors("get color uniform");

	glUseProgram(gl_program);
	gl_check_errors("use program");

	glDisable(GL_DEPTH_TEST);
	glClearColor(0.0, 0.0, 0.0, 1.0);

	glGenVertexArrays(1, &gl_vao);
	glGenBuffers(1, &gl_vbo);
	glBindVertexArray(gl_vao);
	glBindBuffer(GL_ARRAY_BUFFER, gl_vao);
	if (!gl_check_errors("bind vertex buffers"))
		return false;

	glEnableVertexAttribArray(ATTRIB_POSITION);
	glEnableVertexAttribArray(ATTRIB_TEX_COORD);

	glVertexAttribPointer(ATTRIB_POSITION, 2, GL_FLOAT, GL_FALSE, sizeof(GLfloat) * 4, (void *)(0 * sizeof(GLfloat)));
	glVertexAttribPointer(ATTRIB_TEX_COORD, 2, GL_FLOAT, GL_FALSE, sizeof(GLfloat) * 4, (void *)(2 * sizeof(GLfloat)));
	if (!gl_check_errors("set attribute pointer"))
		return false;

	const GLfloat g_vertex_buffer_data[] = {
			// x, y, u, v
			-1, -1, 1.0, 0.0,
			1, -1, 1.0, 1.0,
			1, 1, 0.0, 1.0,

			-1, -1, 1.0, 0.0,
			1, 1, 0.0, 1.0,
			-1, 1, 0.0, 0.0
	};

	glBufferData(GL_ARRAY_BUFFER, sizeof(g_vertex_buffer_data), g_vertex_buffer_data, GL_STATIC_DRAW);
	if (!gl_check_errors("update buffer data"))
		return false;

	glGenTextures(NUM_TEXTURES, gl_textures);
	for (u_int i = 0; i < NUM_TEXTURES; ++i)
	{
		glBindTexture(GL_TEXTURE_2D, gl_textures[i]);
		glTexParameteri(GL_TEXTURE_2D, GL_TEXTURE_MIN_FILTER, GL_NEAREST);
		glTexParameteri(GL_TEXTURE_2D, GL_TEXTURE_MAG_FILTER, GL_NEAREST);
	}
	if (!gl_check_errors("set up textures"))
		return false;

	return true;
}

void
gl_fini(void)
{
	glDeleteTextures(2, gl_textures);
	gl_check_errors("delete textures");
}

void
gl_blit(const u_int32_t *fb_argb, bool right)
{
	glBindTexture(GL_TEXTURE_2D, gl_textures[(right) ? TEXTURE_RIGHT : TEXTURE_LEFT]);
	glTexImage2D(GL_TEXTURE_2D, 0, GL_RGBA, 224, 384, 0, GL_RGBA, GL_UNSIGNED_BYTE, fb_argb);
	gl_check_errors("update texture");
}

void
gl_clear(void)
{
	glClear(GL_COLOR_BUFFER_BIT);
}

void
gl_draw(void)
{
	glViewport(0, 0, tk_width, tk_height);
	gl_check_errors("set viewport");

	glUseProgram(gl_program);
	glBindVertexArray(gl_vao);
	glEnable(GL_BLEND);
	glBlendFunc(GL_ONE, GL_ONE);
	glBlendEquation(GL_FUNC_ADD);

	static bool draw_left = true;
	static bool draw_right = true;

	if (igBeginMainMenuBar())
	{
		if (igBeginMenu("GL", true))
		{
			if (igMenuItem("Draw left", NULL, draw_left, true))
				draw_left = !draw_left;
			if (igMenuItem("Draw right", NULL, draw_right, true))
				draw_right = !draw_right;

			igEndMenu();
		}

		igEndMainMenuBar();
	}

	if (draw_left)
	{
		glBindTexture(GL_TEXTURE_2D, gl_textures[TEXTURE_LEFT]);
		glUniform4f(gl_color_uniform, 1.0, 0, 0, 1.0);
		glDrawArrays(GL_TRIANGLES, 0, 6);
		gl_check_errors("draw left");
	}

	if (draw_right)
	{
		glBindTexture(GL_TEXTURE_2D, gl_textures[TEXTURE_RIGHT]);
		glUniform4f(gl_color_uniform, 0, 0, 1.0, 1.0);
		glDrawArrays(GL_TRIANGLES, 0, 6);
		gl_check_errors("draw right");
	}
}

void
gl_debug_clear(void)
{
	static const u_int32_t black = 0xff000000;
	memset_pattern4(gl_debug_frame, &black, sizeof(gl_debug_frame));
}
void
gl_debug_draw(u_int x, u_int y, u_int8_t pixel)
{
	assert(x < 512 && y < 512);
	u_int32_t argb = pixel;
	argb|= argb << 2;
	argb|= argb << 4;
	argb|= (argb << 8) | (argb << 16);
	gl_debug_frame[y * 512 + x] = argb;
}

u_int
gl_debug_blit(void)
{
	glBindTexture(GL_TEXTURE_2D, gl_textures[TEXTURE_DEBUG]);
	glTexImage2D(GL_TEXTURE_2D, 0, GL_RGB, 512, 512, 0, GL_RGBA, GL_UNSIGNED_INT_8_8_8_8_REV, gl_debug_frame);
	return gl_textures[TEXTURE_DEBUG];
}

/* IMGUI */
bool imgui_shown = false;

struct ImGuiContext *imgui_context;

static const struct ImVec2 IMVEC2_ZERO = {0, 0};

static bool
imgui_init(void)
{
	imgui_context = igCreateContext(NULL);

	struct ImGuiIO *io = igGetIO();
	ImFontAtlas_AddFontFromFileTTF(io->Fonts, "vendor/cimgui/imgui/misc/fonts/Roboto-Medium.ttf", 16.0f, NULL, NULL);

	return true;
}

static void
imgui_fini(void)
{
	igDestroyContext(imgui_context);
}

void
imgui_frame_begin(void)
{
	if (!imgui_shown)
		return;

	debug_imgui();

	static bool vip_worlds_open = false;
	static bool vip_rows_open = false;
	static bool vip_offscreen_open = false;
	static bool demo_open = false;
	if (igBeginMainMenuBar())
	{
		if (igBeginMenu("VIP", true))
		{
			if (igMenuItem("Worlds...", NULL, vip_worlds_open, true))
				vip_worlds_open = !vip_worlds_open;

			igMenuItemPtr("Use global palette", NULL, &vip_use_bright, true);

			if (igMenuItem("Rows...", NULL, vip_rows_open, true))
				vip_rows_open = !vip_rows_open;

			if (igMenuItem("View offscreen...", NULL, vip_offscreen_open, true))
				vip_offscreen_open = !vip_offscreen_open;

			igEndMenu();
		}

		if (igBeginMenu("UI", true))
		{
			if (igMenuItem("Show demo window", NULL, false, true))
				demo_open = true;

			igEndMenu();
		}

		igEndMainMenuBar();
	}

	if (vip_worlds_open)
	{
		if (igBegin("VIP Worlds", &vip_worlds_open, 0))
		{
			for (u_int i = 0; i < 32; ++i)
			{
				char label[32 + 1];
				snprintf(label, sizeof(label), "%d", i + 1);
				u_int32_t mask = 1 << i;
				bool shown = ((vip_world_mask & mask) != 0);
				if ((i % 8) != 0)
					igSameLine(0.0, -1.0f);
				if (igCheckbox(label, &shown))
				{
					if (shown)
						vip_world_mask |= mask;
					else
						vip_world_mask &= ~mask;
				}
			}
			if (igButton("All", IMVEC2_ZERO))
				vip_world_mask = ~0;
			igSameLine(0.0, -1.0f);
			if (igButton("None", IMVEC2_ZERO))
				vip_world_mask = 0;

			igEnd();
		}
	}

	if (vip_rows_open)
	{
		if (igBegin("VIP Rows", &vip_rows_open, 0))
		{
			for (u_int i = 0; i < 28; ++i)
			{
				char label[32 + 1];
				snprintf(label, sizeof(label), "%u-%u", i * 8 + 1, i * 8 + 8);
				u_int32_t mask = 1u << i;
				bool shown = ((vip_row_mask & mask) != 0);
				if ((i % 4) != 0)
					igSameLine(0.0, -1.0f);
				if (igCheckbox(label, &shown))
				{
					if (shown)
						vip_row_mask|= mask;
					else
						vip_row_mask&= ~mask;
				}
			}
			if (igButton("All", IMVEC2_ZERO))
				vip_row_mask = (1 << 28) - 1;
			igSameLine(0.0, -1.0f);
			if (igButton("None", IMVEC2_ZERO))
				vip_row_mask = 0;

			igEnd();
		}
	}

	if (vip_offscreen_open)
	{
		if (igBegin("VIP Offscreen", &vip_offscreen_open, 0))
		{
			enum
			{
				VIP_BGSEG,
				VIP_CHR,
				VIP_NUM_OFFSCREEN
			};
			static int offscreen;
			const char *labels[VIP_NUM_OFFSCREEN] =
					{
							[VIP_BGSEG] = "BGSEG",
							[VIP_CHR] = "CHR",
					};
			igCombo("What", &offscreen, labels, VIP_NUM_OFFSCREEN, -1);
			u_int texture;
			gl_debug_clear();
			float height;
			switch (offscreen)
			{
				case VIP_BGSEG:
				{
					static int off_index = 0;
					igInputInt("Which", &off_index, 1, 100, ImGuiInputTextFlags_AutoSelectAll);
					if (off_index < 0)
						off_index = 13;
					else if (off_index >= 14)
						off_index = 0;

					height = 512;
					struct vip_bgsc *vb = vip_dram.vd_shared.s_bgsegs[off_index];
					for (u_int bg_y = 0; bg_y < 64; ++bg_y)
						for (u_int bg_x = 0; bg_x < 64; ++bg_x)
						{
							for (u_int chr_x = 0; chr_x < 8; ++chr_x)
								for (u_int chr_y = 0; chr_y < 8; ++chr_y)
								{
									bool opaque;
									u_int8_t pixel = vip_bgsc_read_slow(vb, chr_x, chr_y, &opaque);
									//if (opaque)
										gl_debug_draw(bg_x * 8 + chr_x, bg_y * 8 + chr_y, pixel);
								}
							++vb;
						}
					break;
				}
				case VIP_CHR:
				{
					height = 256;
					for (u_int c = 0; c < 2048; ++c)
					{
						const struct vip_chr *vc = VIP_CHR_FIND(c);
						u_int x = c % 64;
						u_int y = c / 64;
						for (u_int chr_x = 0; chr_x < 8; ++chr_x)
							for (u_int chr_y = 0; chr_y < 8; ++chr_y)
								gl_debug_draw(x * 8 + chr_x, y * 8 + chr_y,
								              vip_chr_read_slow(vc, chr_x, chr_y, false, false));
					}
					break;
				}
			}
			static const struct ImVec4 color = {1, 1, 1, 1};
			static const struct ImVec4 border_color = {0.5, 0.5, 0.5, 1};
			texture = gl_debug_blit();
			igImage((ImTextureID)(uintptr_t)texture,
			        (struct ImVec2){512, height},
			        IMVEC2_ZERO, (struct ImVec2){1.0, (float)height / 512},
			        color, border_color);

			igEnd();
		}
	}

	if (demo_open)
		igShowDemoWindow(&demo_open);
}

void
imgui_frame_end(void)
{
	if (imgui_shown)
		igRender();
	else
		igEndFrame();
}

/* MAIN */
#if INTERFACE
	struct main_stats_t
	{
		u_int32_t ms_start_ticks;
		u_int ms_frames;
		u_int ms_insts;
		u_int ms_intrs;
	};
#endif // INTERFACE

u_int32_t main_usec;
static bool main_paused;
static int main_speed;
struct main_stats_t main_stats;

bool
main_init(void)
{
	return (sram_init() &&
			wram_init() &&
			vip_init() &&
			vsu_init() &&
			nvc_init() &&
			debug_init() &&
			imgui_init() &&
	        tk_init() &&
	        gl_init());
}

void
main_fini(void)
{
	gl_fini();
	tk_fini();
	imgui_fini();
	debug_fini();
	nvc_fini();
	vsu_fini();
	vip_fini();
	wram_fini();
	sram_fini();
}

void
main_update_caption(const char *stats)
{
	char caption[100];
	size_t offset = 0;
	offset+= snprintf(caption, sizeof(caption), (stats) ? "%s: %s [%s]" : "%s: %s", "VVBoy", rom_name, stats);
	if (main_paused)
		offset+= snprintf(caption + offset, sizeof(caption) - offset, " *Paused*");
	else if (main_speed != 0)
		offset += snprintf(caption + offset, sizeof(caption) - offset, " *Speed %gx*", pow(2.0, main_speed));
	tk_update_caption(caption);
}

static void
main_restart_clock(void)
{
	u_int32_t ticks = tk_get_ticks();
	if (main_stats.ms_insts > 0)
	{
		char stats_s[100];
		u_int32_t delta = ticks - main_stats.ms_start_ticks;
		float fps = (float)main_stats.ms_frames / ((float)delta / 1000);
		debug_tracef("main", "%u frames in %u ms (%g FPS), %u instructions, %u interrupts\n",
		             main_stats.ms_frames, delta, fps,
		             main_stats.ms_insts,
		             main_stats.ms_intrs);
		snprintf(stats_s, sizeof(stats_s), "%.3g EMU FPS", fps);
		main_update_caption(stats_s);
	}

	main_stats.ms_start_ticks = ticks;
	main_stats.ms_frames = 0;
	main_stats.ms_insts = 0;
	main_stats.ms_intrs = 0;

	main_usec = 0;
}

void
main_reset(void)
{
	main_restart_clock();

	main_paused = false;
	main_speed = 0;

	vip_reset();
	vsu_reset();
	nvc_reset();
}

bool
main_step(void)
{
	vip_step();
	vsu_step();
	if (!nvc_step())
		return false;

	if (++main_usec == 1000000)
		main_restart_clock();

	return true;
}

void
main_toggle_paused(void)
{
	main_paused = !main_paused;
	main_update_caption(NULL);
}

void
main_toggle_speed(void)
{
	if (main_speed == -3)
		main_speed = 0;
	else
		--main_speed;

	main_update_caption(NULL);
}

void
main_noop(int sig __unused)
{
}

void
main_block_sigint(void)
{
	sigset_t sigset;
	sigemptyset(&sigset);
	sigaddset(&sigset, SIGINT);
	signal(SIGINT, main_noop);

	sigprocmask(SIG_BLOCK, &sigset, NULL);
}

void
main_unblock_sigint(void)
{
	sigset_t sigset;
	sigemptyset(&sigset);
	sigaddset(&sigset, SIGINT);
	sigprocmask(SIG_UNBLOCK, &sigset, NULL);

	signal(SIGINT, SIG_DFL);
}

void
main_frame(void)
{
	gl_clear();

	imgui_frame_begin();

	u_int main_frame_usec = 20000;

	if (main_paused)
		return;
	if (main_speed != 0)
		main_frame_usec = lround(20000.0 * pow(2.0, main_speed));

	while (main_step() && (main_usec % main_frame_usec) != 0);

	// Check SIGINT -> Debugger
	sigset_t sigpend;
	sigpending(&sigpend);
	if (sigismember(&sigpend, SIGINT))
		debugging = true;

	gl_draw();

	imgui_frame_end();
}
