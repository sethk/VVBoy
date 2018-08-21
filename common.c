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
#define _SEARCH_PRIVATE
#include <search.h>
#include <OpenGL/gl3.h>
#define CIMGUI_DEFINE_ENUMS_AND_STRUCTS
#include <cimgui/cimgui.h>
#include <SDL_scancode.h>

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

	struct mem_request
	{
		u_int32_t mr_emu;
		size_t mr_size;
		int mr_ops;
		void *mr_host;
		int mr_perms;
		u_int32_t mr_mask;
		u_int mr_wait;
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
mem_prepare(struct mem_request *request)
{
	enum mem_segment seg = MEM_ADDR2SEG(request->mr_emu);
	if (seg == MEM_SEG_VIP)
		return vip_mem_prepare(request);
	else if (seg == MEM_SEG_VSU)
		return vsu_mem_prepare(request);
	else if (seg == MEM_SEG_NVC)
		return nvc_mem_prepare(request);
	else if (mem_segs[seg].ms_size)
	{
		u_int32_t offset = request->mr_emu & mem_segs[seg].ms_addrmask;

		if (seg == MEM_SEG_SRAM && MEM_ADDR2OFF(request->mr_emu) + request->mr_size > mem_segs[seg].ms_size)
		{
			if (!mem_seg_realloc(MEM_SEG_SRAM, mem_size_ceil(offset + request->mr_size)))
				return false;
			offset = request->mr_emu & mem_segs[MEM_SEG_SRAM].ms_addrmask;
		}

		request->mr_host = mem_segs[seg].ms_ptr + offset;
		request->mr_perms = mem_segs[seg].ms_perms;
		return true;
	}
	else
		return false;
}

void *
mem_emu2host(u_int32_t addr, size_t size)
{
	struct mem_request request = {.mr_emu = addr, .mr_size = size, .mr_ops = 0};
	if (!mem_prepare(&request))
		return NULL;
	return request.mr_host;
}

static bool
mem_read(u_int32_t addr, void *dest, size_t size, bool is_exec, u_int *mem_waitp)
{
	assert(size > 0);
	struct mem_request request =
			{
					.mr_emu = addr,
					.mr_size = size,
					.mr_perms = PROT_READ | PROT_WRITE,
					.mr_mask = 0xffffffff,
					.mr_wait = 2
			};
	request.mr_ops = PROT_READ;
	if (is_exec)
		request.mr_ops|= PROT_EXEC;

	if (!mem_prepare(&request))
	{
		debug_fatal_errorf("Bus error at 0x%08x", addr);
		return false;
	}

	if ((request.mr_perms & request.mr_ops) != request.mr_ops)
	{
		debug_str_t addr_s, ops_s, perms_s;
		debug_fatal_errorf("Invalid memory operation at %s, mem ops = %s, prot = %s",
		                   debug_format_addr(addr, addr_s),
		                   debug_format_perms(request.mr_ops, ops_s),
		                   debug_format_perms(request.mr_perms, perms_s));
		return false;
	}

	if (debug_trace_mem_read && !is_exec)
	{
		debug_str_t addr_s;
		debug_str_t hex_s;
		debug_tracef("mem.read", "[" DEBUG_ADDR_FMT "] -> %s",
		             debug_format_addr(addr, addr_s),
		             debug_format_hex(request.mr_host, size, hex_s));
	}

	switch (size)
	{
		case 1:
			*(u_int8_t *)dest = *(u_int8_t *)request.mr_host;
			break;
		case 2:
			*(u_int16_t *)dest = *(u_int16_t *)request.mr_host;
			break;
		case 4:
			*(u_int32_t *)dest = *(u_int32_t *)request.mr_host;
			break;
		default:
			bcopy(request.mr_host, dest, size);
	}

	*mem_waitp = request.mr_wait;
	return true;
}

static bool
mem_write(u_int32_t addr, const void *src, size_t size, u_int *mem_waitp)
{
	assert(size > 0);
	struct mem_request request =
	{
			.mr_emu = addr,
			.mr_size = size,
			.mr_perms = PROT_READ | PROT_WRITE | PROT_EXEC,
			.mr_ops = PROT_WRITE,
			.mr_mask = 0xffffffff,
			.mr_wait = 2
	};

	if (!mem_prepare(&request))
	{
		// TODO: SEGV
		debug_fatal_errorf("Bus error at 0x%08x", addr);
		return false;
	}

	if ((request.mr_perms & PROT_WRITE) == 0)
	{
		debug_str_t addr_s, perms_s;
		static bool ignore_writes = false;
		if (debug_runtime_errorf(&ignore_writes, "Invalid memory operation at %s, mem ops = PROT_WRITE, prot = %s\n",
		                          debug_format_addr(addr, addr_s),
		                          debug_format_perms(request.mr_perms, perms_s)))
			return true;
		debug_stop();
		return false;
	}

	if (debug_trace_mem_write)
	{
		debug_str_t addr_s;
		debug_str_t hex_s;
		debug_tracef("mem.write", "[" DEBUG_ADDR_FMT "] <- %s",
		             debug_format_addr(addr, addr_s), debug_format_hex(src, size, hex_s));
	}

	enum mem_segment seg = MEM_ADDR2SEG(addr);
	if (seg == MEM_SEG_VSU)
		vsu_mem_write(&request, src);
	else if (seg == MEM_SEG_NVC)
		nvc_mem_write(&request, src);
	else switch (size)
	{
		case 1:
			*(u_int8_t *)request.mr_host =
					(*(u_int8_t *)request.mr_host & ~request.mr_mask) | (*(u_int8_t *)src & request.mr_mask);
			break;
		case 2:
			*(u_int16_t *)request.mr_host =
					(*(u_int16_t *)request.mr_host & ~request.mr_mask) | (*(u_int16_t *)src & request.mr_mask);
			break;
		case 4:
			*(u_int32_t *)request.mr_host =
					(*(u_int32_t *)request.mr_host & ~request.mr_mask) | (*(u_int32_t *)src & request.mr_mask);
			break;
		default:
			bcopy(src, request.mr_host, size);
	}

	*mem_waitp = request.mr_wait;
	return true;
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
mem_test_addr(const char *name, u_int32_t emu_addr, size_t size, void *expected)
{
	void *addr = mem_emu2host(emu_addr, size);
	if (addr != expected)
	{
		debug_runtime_errorf(NULL, "mem_emu2host(%s) is %p but should be %p (offset %ld)",
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
	debug_create_symbol("vect.fpe", 0xffffff60);
	debug_create_symbol("vect.zdiv", 0xffffff80);
	debug_create_symbol("vect.ill", 0xffffff90);
	debug_create_symbol("vect.trapa", 0xffffffa0);
	debug_create_symbol("vect.trapb", 0xffffffb0);
	debug_create_symbol("vect.atrap", 0xffffffc0);
	debug_create_symbol("vect.nmi", 0xffffffd0);
	debug_create_symbol("vect.reset", 0xfffffff0);
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
		debug_fatal_errorf("Could not read instruction at 0x%08x", addr);
		return false;
	}
	inst->ci_hwords[0] = OSSwapLittleToHostInt16(inst->ci_hwords[0]);
	if (cpu_inst_size(inst) == 4)
	{
		if (!mem_read(addr + 2, &(inst->ci_hwords[1]), 2, true, &mem_wait))
		{
			debug_fatal_errorf("Could not read instruction at 0x%08x", addr + 2);
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

inline static u_int16_t
cpu_extend14to16(u_int16_t s14)
{
	if ((s14 & 0x2000) == 0x2000)
		s14|= 0xc000;
	return s14;
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
			debug_fatal_errorf("Handle branch cond");
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
			debug_fatal_errorf("TODO: Reserved operand exception");
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
		cpu_state.cs_psw.psw_flags.f_cy = ((start >> (32 - shift)) & 1);
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
		cpu_state.cs_psw.psw_flags.f_cy = ((start >> (shift - 1)) & 1);
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
cpu_shift_arith_right(u_int32_t start, u_int32_t shift)
{
	u_int32_t result;
	cpu_state.cs_psw.psw_flags.f_s = ((start & sign_bit32) == sign_bit32);
	if (shift)
	{
		result = start >> shift;
		cpu_state.cs_psw.psw_flags.f_cy = ((start >> (shift - 1)) & 1);
		if (cpu_state.cs_psw.psw_flags.f_s)
			result|= (0xffffffff << (32 - shift));
	}
	else
	{
		result = start;
		cpu_state.cs_psw.psw_flags.f_cy = 0;
	}
	cpu_state.cs_psw.psw_flags.f_ov = 0;
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
	static u_int32_t old_lp = 0x0;

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
				debug_tracef("cpu.jmp", DEBUG_ADDR_FMT ": %-4s %s",
				             debug_format_addr(cpu_state.cs_pc, addr_s),
				             (inst.ci_i.i_reg1 == 31) ? "RET" : "JMP",
				             debug_format_addr(cpu_state.cs_r[inst.ci_i.i_reg1].u, dest_addr_s));
			}
			cpu_state.cs_pc = cpu_state.cs_r[inst.ci_i.i_reg1].u;

			cpu_wait = 3;

			return true;
		case OP_SAR:
			cpu_state.cs_r[inst.ci_i.i_reg2].u = cpu_shift_arith_right(cpu_state.cs_r[inst.ci_i.i_reg2].u,
					cpu_state.cs_r[inst.ci_i.i_reg1].u & 0x1f);
			break;
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
			if (right == 0)
			{
				debug_fatal_errorf("TODO: Divide by zero exception");
				return false;
			}
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
			cpu_state.cs_r[inst.ci_ii.ii_reg2].u =
					cpu_shift_arith_right(cpu_state.cs_r[inst.ci_ii.ii_reg2].u, inst.ci_ii.ii_imm5 & 0x1f);
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
				debug_tracef("cpu.jmp", DEBUG_ADDR_FMT ": RETI %s",
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
					debug_stop();
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
					debug_stop();
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
				debug_tracef("cpu.jmp", DEBUG_ADDR_FMT ": CALL %s(0x%08x, 0x%08x, 0x%08x, 0x%08x)",
				             debug_format_addr(cpu_state.cs_pc, addr_s),
				             debug_format_addr(cpu_state.cs_pc + disp, dest_addr_s),
				             cpu_state.cs_r[6].u,
				             cpu_state.cs_r[7].u,
				             cpu_state.cs_r[8].u,
				             cpu_state.cs_r[9].u);
			}
			cpu_state.cs_r[31].u = cpu_state.cs_pc + 4;
			cpu_state.cs_pc+= disp;

			old_lp = cpu_state.cs_r[31].u;

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
						debug_fatal_errorf("TODO: Floating-point invalid operation exception");
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
							debug_fatal_errorf("TODO: Invalid operation exception");
							return false;
						}
						else if (cpu_float_reserved(left))
							return false;
						else
						{
							cpu_state.cs_psw.psw_flags.f_fzd = 1;
							debug_fatal_errorf("TODO: Divide by zero exception");
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
					debug_stop();
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
			debug_stop();
			return false;
	}
	if (cpu_state.cs_r[0].s)
	{
		cpu_state.cs_r[0].s = 0;
		if (!debug_runtime_errorf(NULL, "r0 written to with non-zero value\n"))
			return false;
	}

	if (debug_trace_cpu_lp)
	{
		if (old_lp != cpu_state.cs_r[31].u)
		{
			debug_str_t pc_s;
			debug_str_t old_lp_s;
			debug_str_t lp_s;
			debug_tracef("cpu.lp", "%s: Link pointer changed %s -> %s",
			             debug_format_addr(cpu_state.cs_pc, pc_s),
			             debug_format_addr(old_lp, old_lp_s),
			             debug_format_addr(cpu_state.cs_r[31].u, lp_s));
			old_lp = cpu_state.cs_r[31].u;
		}
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
cpu_test_shl(u_int32_t start, u_int shift, u_int32_t result, bool sign, bool carry, bool zero)
{
	union cpu_inst inst;
	inst.ci_ii.ii_opcode = OP_SHL2;
	inst.ci_ii.ii_imm5 = shift;
	cpu_state.cs_r[6].u = start;
	inst.ci_ii.ii_reg2 = 6;
	cpu_state.cs_psw.psw_flags.f_ov = true;
	cpu_state.cs_psw.psw_flags.f_s = !sign;
	cpu_state.cs_psw.psw_flags.f_cy = !carry;
	cpu_state.cs_psw.psw_flags.f_z = !zero;
	const char *dis = debug_disasm(&inst, 0, debug_current_context());
	cpu_exec(inst);
	cpu_assert_reg(dis, 6, (union cpu_reg){.u = result});
	cpu_assert_overflow(dis, false);
	cpu_assert_sign(dis, sign);
	cpu_assert_carry(dis, carry);
	cpu_assert_zero(dis, zero);
}

static void
cpu_test_shr(u_int32_t start, u_int shift, u_int32_t result, bool sign, bool carry, bool zero)
{
	union cpu_inst inst;
	inst.ci_ii.ii_opcode = OP_SHR2;
	inst.ci_ii.ii_imm5 = shift;
	cpu_state.cs_r[6].u = start;
	inst.ci_ii.ii_reg2 = 6;
	cpu_state.cs_psw.psw_flags.f_ov = true;
	cpu_state.cs_psw.psw_flags.f_s = !sign;
	cpu_state.cs_psw.psw_flags.f_cy = !carry;
	cpu_state.cs_psw.psw_flags.f_z = !zero;
	const char *dis = debug_disasm(&inst, 0, debug_current_context());
	cpu_exec(inst);
	cpu_assert_reg(dis, 6, (union cpu_reg){.u = result});
	cpu_assert_overflow(dis, false);
	cpu_assert_sign(dis, sign);
	cpu_assert_carry(dis, carry);
	cpu_assert_zero(dis, zero);
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
	debug_printf("Running CPU self-test\n");

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

	cpu_test_shl(0x00000080, 23, 0x40000000, false, false, false);
	cpu_test_shl(0x00000080, 24, 0x80000000, true, false, false);
	cpu_test_shl(0x00000080, 25, 0x00000000, false, true, true);
	cpu_test_shl(0x00000080, 26, 0x00000000, false, false, true);

	cpu_test_shr(0x01000000, 24, 0x00000001, false, false, false);
	cpu_test_shr(0x01000000, 25, 0x00000000, false, true, true);
	cpu_test_shr(0x01000000, 26, 0x00000000, false, false, true);
	cpu_test_shr(0x80000000, 0, 0x80000000, true, false, false);

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

	if (!debug_step())
		return false;

	union cpu_inst inst;
	if (!cpu_fetch(cpu_state.cs_pc, &inst))
	{
		debug_fatal_errorf("TODO: bus error fetching inst from PC 0x%08x", cpu_state.cs_pc);
		return false;
	}

	if (debug_trace_cpu)
	{
		debug_str_t addr_s;
		debug_tracef("cpu", DEBUG_ADDR_FMT ": %s",
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
				debug_tracef("cpu", DEBUG_ADDR_FMT ": Interrupt level=%d",
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
				debug_tracef("cpu.jmp", DEBUG_ADDR_FMT ": INT%u %s",
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
bool vip_worlds_open = false;
bool vip_bgseg_open = false;
bool vip_chr_open = false;
bool vip_oam_open = false;
bool vip_fb_open = false;
bool vip_rows_open = false;
u_int32_t vip_row_mask = (1 << 28) - 1;
u_int32_t vip_world_mask = ~0;
u_int8_t vip_bgm_types = 0xf;

const char *vip_bgm_strings[4] =
{
		[WORLD_BGM_NORMAL] = "NORMAL",
		[WORLD_BGM_AFFINE] = "AFFINE",
		[WORLD_BGM_H_BIAS] = "H_BIAS",
		[WORLD_BGM_OBJ] = "OBJ",
};
static u_int vip_disp_index = 0;
static u_int vip_frame_cycles = 0;
bool vip_use_bright = true;
static bool vip_scan_accurate = false;

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
			debug_printf("Stopped on VIP interrupt %u\n", intflag);
			debug_stop();
		}

		cpu_intr(NVC_INTVIP);
	}
}

static void
vip_clear_start(u_int fb_index)
{
	if (debug_trace_vip)
		debug_tracef("vip", "Clear FB%u start", fb_index);

	if (fb_index == 0)
		vip_regs.vr_xpstts.vx_xpbsy_fb0 = 1;
	else
		vip_regs.vr_xpstts.vx_xpbsy_fb1 = 1;
}

static void
vip_clear_finish(u_int fb_index)
{
	if (debug_trace_vip)
		debug_tracef("vip", "Clear FB%u finish", fb_index);

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
	u_int offset = x * 256 + y;
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
		debug_tracef("vip", "FRAMESTART");

	if (vip_frame_cycles == 0)
	{
		intflags|= VIP_GAMESTART;
		if (debug_trace_vip)
			debug_tracef("vip", "GAMESTART");

		if (vip_regs.vr_xpctrl.vx_xprst)
		{
			if (debug_trace_vip)
				debug_tracef("vip", "XPRST");
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
				debug_tracef("vip", "XPEN=%d", vip_regs.vr_xpctrl.vx_xpen);
			vip_regs.vr_xpstts.vx_xpen = vip_regs.vr_xpctrl.vx_xpen;
		}

		if (vip_regs.vr_xpstts.vx_xpen)
		{
			if (!vip_regs.vr_xpstts.vx_xpbsy_fb0 && !vip_regs.vr_xpstts.vx_xpbsy_fb1)
			{
				u_int fb_index = !vip_disp_index;

				if (debug_trace_vip)
					debug_tracef("vip", "Draw FB%u start", fb_index);

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
			debug_tracef("vip", "DPRST");
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
				debug_tracef("vip", "SYNCE=%d", vip_regs.vr_dpctrl.vd_synce);
			vip_regs.vr_dpstts.vd_synce = vip_regs.vr_dpctrl.vd_synce;
		}
		if (vip_regs.vr_dpctrl.vd_disp != vip_regs.vr_dpstts.vd_disp)
		{
			if (debug_trace_vip)
				debug_tracef("vip", "DISP=%d", vip_regs.vr_dpctrl.vd_disp);
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
					debug_tracef("vip", "Display L:FB0 start");
			}
			else
			{
				vip_regs.vr_dpstts.vd_dpbsy_l_fb1 = 1;
				if (debug_trace_vip)
					debug_tracef("vip", "Display L:FB1 start");
			}

			if (vip_scan_accurate)
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
					debug_tracef("vip", "Display L:FB0 finish");
			}
			else
			{
				vip_regs.vr_dpstts.vd_dpbsy_l_fb1 = 0;
				if (debug_trace_vip)
					debug_tracef("vip", "Display L:FB1 finish");
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
					debug_tracef("vip", "Display R:FB0 start");
			}
			else
			{
				vip_regs.vr_dpstts.vd_dpbsy_r_fb1 = 1;
				if (debug_trace_vip)
					debug_tracef("vip", "Display R:FB1 start");
			}

			if (vip_scan_accurate)
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
					debug_tracef("vip", "Display R:FB0 finish");
			}
			else
			{
				vip_regs.vr_dpstts.vd_dpbsy_r_fb1 = 0;
				if (debug_trace_vip)
					debug_tracef("vip", "Display R:FB1 finish");
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
				debug_tracef("vip", "Draw FB%u finish", fb_index);

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
			debug_tracef("vip", "Draw FB%u SBCOUNT=%u", fb_index, vip_regs.vr_xpstts.vx_sbcount);

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

bool
vip_mem_prepare(struct mem_request *request)
{
	if (request->mr_ops & PROT_READ)
		request->mr_wait = 8;
	else
		request->mr_wait = 4;

	static bool ignore_mirror = false;
	if (request->mr_emu & 0x00f80000)
	{
		u_int32_t mirror = request->mr_emu & 0x7ffff;
		if (!debug_runtime_errorf(&ignore_mirror, "Mirroring VIP address 0x%08x -> 0x%08x\n", request->mr_emu, mirror))
			return false;
		request->mr_emu = mirror;
	}
	else if (request->mr_emu >= 0x40000 && request->mr_emu < 0x60000 && (request->mr_emu & 0x5ff00) != 0x5f800)
	{
		u_int32_t mirror = 0x5f800 | (request->mr_emu & 0x7f);
		if (!debug_runtime_errorf(&ignore_mirror, "Mirroring VIP address 0x%08x -> 0x%08x\n", request->mr_emu, mirror))
			return false;
		request->mr_emu = mirror;
	}

	if (request->mr_emu < 0x20000)
		request->mr_host = (u_int8_t *)&vip_vrm + request->mr_emu;
	else if (request->mr_emu < 0x40000)
		request->mr_host = (u_int8_t *)&vip_dram + (request->mr_emu & 0x1ffff);
	else if ((request->mr_emu & 0xfff00) == 0x5f800)
	{
		if (request->mr_size & 1)
		{
			static bool always_ignore = false;
			if (!debug_runtime_errorf(&always_ignore, "Invalid VIP access size %lu", request->mr_size))
				return false;
		}
		if (request->mr_emu & 1)
		{
			static bool always_ignore = false;
			if (!debug_runtime_errorf(&always_ignore, "VIP address alignment error at 0x%08x", request->mr_emu))
				return false;
		}
		u_int reg_num = (request->mr_emu & 0x7f) >> 1;
		switch (reg_num)
		{
			case 0x00:
			case 0x10:
			case 0x18:
			case 0x20:
				request->mr_perms = PROT_READ;
				break;
			case 0x02:
			case 0x11:
			case 0x12:
			case 0x13:
			case 0x14:
			case 0x15:
			case 0x17:
			case 0x21:
			{
				request->mr_perms = PROT_WRITE;
				if (request->mr_ops & PROT_READ)
				{
					static bool ignore_read = false;
					debug_str_t addr_s;
					if (!debug_runtime_errorf(&ignore_read, "Trying to read write-only VIP register at %s",
					                          debug_format_addr(request->mr_emu, addr_s)))
						return false;
					request->mr_perms|= PROT_READ;
				}
				break;
			}
		}

#ifndef NDEBUG
		u_int16_t *regp = (u_int16_t *)&vip_regs + reg_num;
		assert(regp == (u_int16_t *)((u_int8_t *)&vip_regs + (request->mr_emu & 0x7e)));
#endif // !NDEBUG

		request->mr_host = (u_int8_t *)&vip_regs + (request->mr_emu & 0x7e);
	}
	else if (request->mr_emu >= 0x78000 && request->mr_emu < 0x7a000)
		request->mr_host = (u_int8_t *)&(vip_vrm.vv_chr0) + (request->mr_emu - 0x78000);
	else if (request->mr_emu >= 0x7a000 && request->mr_emu < 0x7c000)
		request->mr_host = (u_int8_t *)&(vip_vrm.vv_chr1) + (request->mr_emu - 0x7a000);
	else if (request->mr_emu >= 0x7c000 && request->mr_emu < 0x7e000)
		request->mr_host = (u_int8_t *)&(vip_vrm.vv_chr2) + (request->mr_emu - 0x7c000);
	else if (request->mr_emu >= 0x7e000 && request->mr_emu < 0x80000)
		request->mr_host = (u_int8_t *)&(vip_vrm.vv_chr3) + (request->mr_emu - 0x7e000);
	else
		return false;

	return true;
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
	debug_printf("Running VIP self-test\n");

	static_assert(sizeof(vip_vrm) == 0x20000, "sizeof(vip_vrm) should be 0x20000");
	assert(sizeof(struct vip_oam) == 8);
	static_assert(sizeof(vip_dram) == 0x20000, "sizeof(vip_dram) should be 0x20000");
	assert(sizeof(vip_dram.vd_shared.s_bgsegs[0]) == 8192);
	assert(sizeof(vip_regs) == 0x72);
	mem_test_size("vip_world_att", sizeof(struct vip_world_att), 32);
	mem_test_addr("world_att[1]", debug_locate_symbol("WORLD_ATT:1"), 4, &(vip_dram.vd_world_atts[1]));
	mem_test_addr("BGSEG:2", 0x24000, 4, &(vip_dram.vd_shared.s_bgsegs[2]));
	mem_test_addr("PARAM_TBL+0x8800", 0x31000, 4, &(vip_dram.vd_shared.s_param_tbl[0x8800]));
	assert(mem_emu2host(0x3d800, 4) == &(vip_dram.vd_world_atts));
	assert(mem_emu2host(0x3e000, 8) == &(vip_dram.vd_oam));
	assert(mem_emu2host(0x5f800, 2) == &(vip_regs.vr_intpnd));
	assert(mem_emu2host(0x5f820, 2) == &(vip_regs.vr_dpstts));
	assert(mem_emu2host(0x5f866, 2) == &(vip_regs.vr_gplt[3]));
	assert(mem_emu2host(0x5f870, 2) == &(vip_regs.vr_bkcol));
	assert(mem_emu2host(0x78000, 2) == &(vip_vrm.vv_chr0));
	assert(mem_emu2host(0x7e000, 2) == &(vip_vrm.vv_chr3));

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
	debug_tracef("vip", "Row mask 0x%08x", vip_row_mask);
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
	debug_tracef("vip", "World mask 0x%08x", vip_world_mask);
}

void
vip_frame_begin(void)
{
	if (vip_worlds_open)
	{
		igSetNextWindowSize((struct ImVec2){640, 500}, ImGuiCond_FirstUseEver);
		if (igBegin("VIP Worlds", &vip_worlds_open, 0))
		{
			igText("Draw types:");
			for (u_int i = 0; i < 4; ++i)
			{
				igSameLine(0, -1);

				u_int8_t mask = (1 << i);
				bool drawn = ((vip_bgm_types & mask) != 0);
				if (igCheckbox(vip_bgm_strings[i], &drawn))
				{
					if (drawn)
						vip_bgm_types |= mask;
					else
						vip_bgm_types &= ~mask;
				}
			}
			igSeparator();

			igColumns(5, "Worlds", true);
			igSeparator();
			igText("#");
			igSetColumnWidth(-1, 30);
			igNextColumn();
			bool show_all = (vip_world_mask == ~0u);
			if (igCheckbox("##Show worlds", &show_all))
			{
				if (show_all)
					vip_world_mask = ~0;
				else
					vip_world_mask = 0;
			}
			igSetColumnWidth(-1, 30);
			igNextColumn();
			igText("Flags");
			igSetColumnWidth(-1, 80);
			igNextColumn();
			igText("BGM");
			igSetColumnWidth(-1, 70);
			igNextColumn();
			igText("Description");
			igNextColumn();

			igSeparator();

			for (int i = 31; i >= 0; --i)
			{
				const struct vip_world_att *vwa = &(vip_dram.vd_world_atts[i]);
				igText("%u", i);
				igNextColumn();

				char label[32 + 1];
				snprintf(label, sizeof(label), "##World%d", i + 1);
				u_int32_t mask = 1 << i;
				bool shown = ((vip_world_mask & mask) != 0);
				if (igCheckbox(label, &shown))
				{
					if (shown)
						vip_world_mask |= mask;
					else
						vip_world_mask &= ~mask;
				}
				igNextColumn();

				debug_str_t flags_s;
				igTextDisabled("%s", debug_format_flags(flags_s,
				                                        "LON", vwa->vwa_lon,
				                                        "RON", vwa->vwa_ron,
				                                        "OVER", vwa->vwa_over,
				                                        "END", vwa->vwa_end,
				                                        NULL));
				igNextColumn();

				igTextDisabled("%s", vip_bgm_strings[vwa->vwa_bgm]);
				igNextColumn();

				char buf[1024];
				debug_format_world_att(buf, sizeof(buf), vwa);
				igTextDisabled("%s", buf);
				igNextColumn();
			}
			igColumns(1, NULL, false);
		}
		igEnd();
	}

	if (vip_rows_open)
	{
		igSetNextWindowSize((struct ImVec2){360, 0}, ImGuiCond_FirstUseEver);
		if (igBegin("VIP Rows", &vip_rows_open, ImGuiWindowFlags_NoResize))
		{
			igColumns(4, "Rows", false);
			for (u_int i = 0; i < 28; ++i)
			{
				char label[32 + 1];
				snprintf(label, sizeof(label), "%u-%u", i * 8 + 1, i * 8 + 8);
				u_int32_t mask = 1u << i;
				bool shown = ((vip_row_mask & mask) != 0);
				if (igCheckbox(label, &shown))
				{
					if (shown)
						vip_row_mask |= mask;
					else
						vip_row_mask &= ~mask;
				}
				igNextColumn();
			}
			igColumns(1, NULL, false);
			igSeparator();
			if (igButton("Draw All", IMVEC2_ZERO))
				vip_row_mask = (1 << 28) - 1;
			igSameLine(0.0, -1.0f);
			if (igButton("Draw None", IMVEC2_ZERO))
				vip_row_mask = 0;
		}
		igEnd();
	}

	if (vip_bgseg_open)
	{
		if (igBegin("VIP Backgrounds", &vip_bgseg_open, 0))
		{
			//gl_debug_clear(); // Opaque flag below
			static int segment = 0;
			igInputInt("Segment", &segment, 1, 100, ImGuiInputTextFlags_AutoSelectAll);
			if (segment < 0)
				segment = 13;
			else if (segment >= 14)
				segment = 0;

			struct vip_bgsc *vb = vip_dram.vd_shared.s_bgsegs[segment];
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
			imgui_debug_image(TEXTURE_DEBUG_BGSEG, 512, 512);
		}
		igEnd();
	}

	if (vip_chr_open)
	{
		if (igBegin("VIP Character Map", &vip_chr_open, 0))
		{
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
			imgui_debug_image(TEXTURE_DEBUG_CHR, 512, 256);
		}
		igEnd();
	}

	if (vip_oam_open)
	{
		igSetNextWindowSize((struct ImVec2){640, 500}, ImGuiCond_FirstUseEver);
		if (igBegin("VIP Object Attributes", &vip_oam_open, 0))
		{
			for (int obj_group = 3; obj_group >= 0; --obj_group)
			{
				char label[32];
				snprintf(label, sizeof(label), "Group %u", obj_group);

				bool open = igTreeNodeEx(label, ImGuiTreeNodeFlags_DefaultOpen);
				igSameLine(0, -1);
				igText("SPT%u=%u", obj_group, vip_regs.vr_spt[obj_group]);
				if (open)
				{
					int end_index = vip_regs.vr_spt[obj_group] & 0x3ff;
					if (end_index != 0x3ff)
					{
						int start_index;
						if (obj_group > 0)
							start_index = (vip_regs.vr_spt[obj_group - 1] + 1) & 0x3ff;
						else
							start_index = 0;

						for (int obj_index = end_index; obj_index >= start_index; --obj_index)
						{
							struct vip_oam *obj = &(vip_dram.vd_oam[obj_index]);
							debug_str_t oam_s;
							debug_format_oam(oam_s, obj);
							igText("OAM[%u]: %s", obj_group, oam_s);
						}
					}

					igTreePop();
				}
			}
		}
		igEnd();
	}

	if (vip_fb_open)
	{
		if (igBegin("VIP Frame Buffers", &vip_fb_open, 0))
		{
			static int fb_index = 0;
			igCombo2("Buffer", &fb_index, "Left 0\0Right 0\0Left 1\0Right 1", 0);
			const u_int8_t *fb;
			switch (fb_index)
			{
				case 0: fb = vip_vrm.vv_left0; break;
				case 1: fb = vip_vrm.vv_right0; break;
				case 2: fb = vip_vrm.vv_left1; break;
				case 3: fb = vip_vrm.vv_right1; break;
			}
			for (u_int y = 0; y < 224; ++y)
				for (u_int x = 0; x < 384; ++x)
					gl_debug_draw(x, y, vip_fb_read_slow(fb, x, y));

			imgui_debug_image(TEXTURE_DEBUG_FB, 384, 224);
		}
		igEnd();
	}
}

void
vip_frame_end(void)
{
	if (!debug_is_stopped() && !vip_scan_accurate)
	{
		vip_scan_out(vip_disp_index, false);
		vip_scan_out(vip_disp_index, true);
	}
}

/* VSU */
struct vsu_ram
{
	u_int8_t vr_waves[5][32];
	u_int8_t vr_snd5mod[32];
	u_int8_t vr_rfu[64];
};

struct vsu_regs
{
	struct vsu_sound_regs
	{
		struct
		{
			unsigned vi_data : 5 __attribute__((packed));
			unsigned vi_mode : 1 __attribute__((packed));
			unsigned vi_rfu1 : 1 __attribute__((packed));
			unsigned vi_start : 1 __attribute__((packed));
		} vsr_int;
		struct
		{
			unsigned vl_rlevel : 4 __attribute__((packed));
			unsigned vl_llevel : 4 __attribute__((packed));
		} vsr_lrv;
		u_int8_t vsr_fql;
		struct
		{
			unsigned vf_fqh : 3 __attribute__((packed));
			unsigned vf_rfu1 : 5 __attribute__((packed));
		} vsr_fqh;
		struct
		{
			unsigned ve_step : 3 __attribute__((packed));
			unsigned ve_ud : 1 __attribute__((packed));
			unsigned ve_init : 4 __attribute__((packed));
		} vsr_ev0;
		struct
		{
			unsigned ve_on : 1 __attribute__((packed));
			unsigned ve_rs : 1 __attribute__((packed));
			unsigned ve_rfu1 : 2 __attribute__((packed));
			unsigned ve_modswp : 1 __attribute__((packed));
			unsigned ve_short : 1 __attribute__((packed));
			unsigned ve_ed : 1 __attribute__((packed));
			unsigned ve_rfu2 : 1 __attribute__((packed));
		} vsr_ev1;
		struct
		{
			unsigned vr_addr : 3 __attribute__((packed));
			unsigned vr_rfu1 : 5 __attribute__((packed));
		} vsr_ram;
		struct
		{
			unsigned vs_shifts : 3 __attribute__((packed));
			unsigned vs_ud : 1 __attribute__((packed));
			unsigned vs_time : 3 __attribute__((packed));
			unsigned vs_clk : 1 __attribute__((packed));
		} vsr_swp;
		u_int32_t vsr_rfu[2];
	} vr_sounds[6];
	struct
	{
		unsigned vs_stop : 1 __attribute__((packed));
		unsigned vs_unused : 7 __attribute__((packed));
	} vr_stop;
	u_int32_t vs_rfu[7];
};

bool vsu_sounds_open = false;
bool vsu_buffers_open = false;
static struct vsu_ram vsu_ram;
static struct vsu_regs vsu_regs;
static int16_t vsu_buffers[2][834];
static u_int8_t vsu_sound_mask = 0b1;
static struct vsu_state
{
	bool vs_started;
	u_int vs_freq_count;
	u_int vs_wave_index;
	u_int vs_int_count;
	u_int16_t vs_env_value;
	u_int vs_env_count;
} vsu_states[6];

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
	debug_printf("Running VSU self-test\n", stderr);
	mem_test_size("vsu_ram", sizeof(vsu_ram), 0x100);
	mem_test_addr("S1INT", 0x01000400, 1, &(vsu_regs.vr_sounds[0].vsr_int));
	mem_test_addr("S2INT", 0x01000440, 1, &(vsu_regs.vr_sounds[1].vsr_int));
	mem_test_addr("S4FQH", 0x010004cc, 1, &(vsu_regs.vr_sounds[3].vsr_fqh));
	mem_test_addr("SSTOP", 0x01000580, 1, &(vsu_regs.vr_stop));
	mem_test_size("vsu_regs", sizeof(vsu_regs), 0x80);
}

void
vsu_reset(void)
{
	for (u_int sound = 0; sound < 6; ++sound)
		vsu_states[sound].vs_started = false;
	// TODO
}

void
vsu_step(void)
{
	if ((main_usec % 20000) == 0)
	{
		for (u_int sample_index = 0; sample_index < 834; ++sample_index)
		{
			for (u_int sound = 0; sound < 1; ++sound)
			{
				if (!(vsu_sound_mask & (1 << sound)))
					continue;

				struct vsu_state *state = &(vsu_states[sound]);
				if (state->vs_started)
				{
					const struct vsu_sound_regs *vsr = &(vsu_regs.vr_sounds[sound]);
					const u_int8_t *vsu_wave = vsu_ram.vr_waves[vsr->vsr_ram.vr_addr];
					int16_t sample = (vsu_wave[state->vs_wave_index] & 0b111111) - 32;
					sample*= state->vs_env_value;
					int16_t left_sample = sample * vsr->vsr_lrv.vl_llevel;
					int16_t right_sample = sample * vsr->vsr_lrv.vl_rlevel;
					assert(sample >= -1024 && sample <= 1023);
					assert((int32_t)sample * 0x40 <= INT16_MAX);
					assert((int32_t)sample * 0x40 >= INT16_MIN);
					vsu_buffers[0][sample_index] = left_sample * 0x20;
					vsu_buffers[1][sample_index] = right_sample * 0x20;

					state->vs_wave_index = (state->vs_wave_index + 1) % 32;
					if (state->vs_env_count == vsr->vsr_ev0.ve_step)
					{
						if (vsr->vsr_ev0.ve_ud)
						{
							if (state->vs_env_value == 0xf)
							{
								if (vsr->vsr_ev1.ve_rs)
									state->vs_env_value = 0;
							}
							else
								++state->vs_env_value;
						}
						else
						{
							if (state->vs_env_value == 0)
							{
								if (vsr->vsr_ev1.ve_rs)
									state->vs_env_value = 0xf;
							}
							else
								--state->vs_env_value;
						}
						state->vs_env_count = 0;
					}
					else
						++state->vs_env_count;
				}
			}
		}
	}
}

void
vsu_frame_end(void)
{
	if (vsu_sounds_open)
	{
		igSetNextWindowSize((struct ImVec2){600, 0}, ImGuiCond_Once);
		if (igBegin("Sounds", &vsu_sounds_open, 0))
		{
			for (u_int sound = 0; sound < 6; ++sound)
			{
				char id[32];
				struct vsu_sound_regs *vsr = &(vsu_regs.vr_sounds[sound]);
				snprintf(id, sizeof(id), "SOUND%u", sound);
				char interval_s[16];
				if (vsr->vsr_int.vi_mode)
				{
					u_int int_index = vsr->vsr_int.vi_data;
					float interval = 1000.0 / (260.4 * (int_index + 1));
					snprintf(interval_s, sizeof(interval_s), "Int.: %.2f ms (%u)", interval, int_index);
				}
				else
					snprintf(interval_s, sizeof(interval_s), "Continuous");

				u_int16_t freq_index = vsr->vsr_fql;
				freq_index|= vsr->vsr_fqh.vf_fqh << 8;
				float freq = 5000000.0 / ((2048 - freq_index) * 32);

				if (igTreeNodeExStr(id, ImGuiTreeNodeFlags_DefaultOpen, "%s%s %s, %.2f Hz (%u), R/L level %u/%u",
				                    id,
				                    (vsr->vsr_int.vi_start) ? " (STARTED)" : "",
				                    interval_s,
				                    freq, freq_index,
				                    vsr->vsr_lrv.vl_rlevel,
									vsr->vsr_lrv.vl_llevel))
				{
					float envs[120];
					u_int8_t env = vsr->vsr_ev0.ve_init;
					u_int step_time = vsr->vsr_ev0.ve_step + 1;
					for (u_int i = 0; i < 120; ++i)
					{
						envs[i] = env;
						if (!step_time)
						{
							if (vsr->vsr_ev0.ve_ud)
							{
								if (env == 0xf)
								{
									if (vsr->vsr_ev1.ve_rs)
										env = 0;
								}
								else
									++env;
							}
							else
							{
								if (env == 0)
								{
									if (vsr->vsr_ev1.ve_rs)
										env = 0xf;
								}
								else
									--env;
							}
							step_time = vsr->vsr_ev0.ve_step;
						}
						else
							--step_time;
					}
					char overlay[32];
					snprintf(overlay, sizeof(overlay), "Init %u, Step %u %s, %s",
					         vsr->vsr_ev0.ve_init,
					         vsr->vsr_ev0.ve_step + 1,
					         (vsr->vsr_ev0.ve_ud) ? "Up" : "Dn",
					         (vsr->vsr_ev1.ve_rs) ? "R/S" : "No R/S");
					igPlotLines("Env.", envs, 120, 0, overlay, 0, 0xf, (struct ImVec2){240, 64}, sizeof(float));
					igSameLine(0, -1);
					igText("(%s)", (vsr->vsr_ev1.ve_on) ? "ON" : "OFF");

					u_int wave_addr = vsr->vsr_ram.vr_addr % 5;
					float wave[32];
					for (u_int i = 0; i < 32; ++i)
					{
						int8_t sample = (vsu_ram.vr_waves[wave_addr][i] & 0b111111) - 32;
						wave[i] = sample;
					}
					igSameLine(0, -1);
					snprintf(overlay, sizeof(overlay), "Waveform RAM %u", wave_addr);
					igPlotLines("Wave.",
					            wave,
					            32, 0,
					            overlay,
					            -32, 31,
					            (struct ImVec2){256, 64},
					            sizeof(float));

					igTreePop();
				}
			}
		}
		igEnd();
	}

	if (vsu_buffers_open)
	{
		if (igBegin("Audio Buffers", &vsu_buffers_open, 0))
		{
			for (u_int channel = 0; channel < 2; ++channel)
			{
				float samples[834];
				for (u_int i = 0; i < 834; ++i)
					samples[i] = (double)vsu_buffers[channel][i];
				igPlotLines((channel == 0) ? "Left" : "Right",
				            samples, 834, 0,
				            NULL,
				            INT16_MIN, INT16_MAX,
				            (struct ImVec2){834, 128},
				            sizeof(float));
			}
		}
		igEnd();
	}
}

bool
vsu_mem_prepare(struct mem_request *request)
{
	if (request->mr_size != 1)
	{
		static bool ignore_size = false;
		if (!debug_runtime_errorf(&ignore_size, "Invalid VSU access size %ld @ 0x%08x\n",
		                          request->mr_size, request->mr_emu))
			return false;
		request->mr_size = 1;
	}

	// TODO: More granularity on perms
	if (request->mr_emu < 0x01000400)
	{
		if (request->mr_emu >= 0x01000300)
		{
			u_int32_t mirror = request->mr_emu & 0x010003ff;
			static bool always_ignore = false;
			if (!debug_runtime_errorf(&always_ignore, "Mirroring VSU RAM at 0x%08x -> 0x%x", request->mr_emu, mirror))
				return false;
			request->mr_emu = mirror;
		}

		request->mr_host = (u_int8_t *) &vsu_ram + ((request->mr_emu >> 2) & 0xff);
	}
	else if (request->mr_emu < 0x01000600)
		request->mr_host = (u_int8_t *)&vsu_regs + ((request->mr_emu >> 2) & 0x7f);
	else
	{
		if (!debug_runtime_errorf(NULL, "VSU bus error at 0x%08x\n", request->mr_emu))
			return false;

		static u_int32_t dummy;
		request->mr_host = &dummy;
	}

	return true;
}

static void
vsu_stop_sound(u_int sound)
{
	if (vsu_states[sound].vs_started)
		debug_tracef("vsu", "Stopping SOUND%u", sound);
}

void
vsu_mem_write(const struct mem_request *request, const void *src)
{
	u_int8_t value = *(u_int8_t *)src;
	*(u_int8_t *)request->mr_host = value;
	if ((request->mr_emu & 0b10000111111) == 0b10000000000)
	{
		u_int sound = (request->mr_emu >> 6) & 0b111;
		if (sound == 6)
		{
			// SSTOP
			if (value & 1)
			{
				for (u_int i = 0; i < 6; ++i)
					vsu_stop_sound(i);
			}
		}
		else
		{
			assert(sound < 6);
			// SxINT
			if (value & 0x80)
			{
				debug_tracef("vsu", "Starting SOUND%u", sound);
				const struct vsu_sound_regs *vsr = &(vsu_regs.vr_sounds[sound]);
				struct vsu_state *state = &(vsu_states[sound]);
				state->vs_started = true;
				state->vs_freq_count = 0;
				state->vs_wave_index = 0;
				state->vs_int_count = 0;
				state->vs_env_value = vsr->vsr_ev0.ve_init;
				state->vs_env_count = 0;
			}
			else
				vsu_stop_sound(sound);
		}
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
	struct nvc_tcr
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
static struct
{
	u_int16_t nt_preset;
	u_int16_t nt_next_count;
	u_int nt_next_tick;
	u_int nt_tick_frac;
} nvc_timer;
u_int nvc_cycles_per_usec = 20;
static u_int16_t nvc_keys;

bool
nvc_init(void)
{
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

	debug_create_symbol("vect.key", 0xfffffe00);
	debug_create_symbol("vect.tim", 0xfffffe10);
	debug_create_symbol("vect.cro", 0xfffffe20);
	debug_create_symbol("vect.com", 0xfffffe30);
	debug_create_symbol("vect.vip", 0xfffffe40);
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
	nvc_timer.nt_preset = 0xffff;
	// TODO: Initialize other NVC interval registers
	cpu_reset();
}

void
nvc_test(void)
{
	debug_printf("Running NVC self-test\n", stderr);

	mem_test_size("nvc_regs", sizeof(nvc_regs), 11);
	mem_test_addr("nvc_sdlr", 0x02000010, 1, &(nvc_regs.nr_sdlr));
	mem_test_addr("nvc_sdhr", 0x02000014, 1, &(nvc_regs.nr_sdhr));
	mem_test_addr("nvc_tcr", 0x02000020, 1, &(nvc_regs.nr_tcr));
}

static void
nvc_frame_begin(void)
{
#if 0
	if (igBeginMainMenuBar())
	{
		if (igBeginMenu("NVC", true))
		{
			igBeginChild("Clock", (struct ImVec2){300, 30}, false, 0);
			{
				igSliderInt("CPU cycles per µsec", (int *)&nvc_cycles_per_usec, 5, 30, NULL);
				igEndChild();
			}

			if (igBeginChild("Timer", (struct ImVec2){300, 30}, false, 0))
			{
				static int value = 0;
				igInputInt("Timer value", &value, 1, 100, 0);
				igSameLine(0, -1);
				if (igButton("Load", IMVEC2_ZERO))
				{
					nvc_regs.nr_tlr = value & 0xff;
					nvc_regs.nr_thr = value >> 8;
				}

			}
			igEndChild();

			igEndMenu();
		}

		igEndMainMenuBar();
	}
#endif // 0
}

static void
nvc_timer_set(u_int16_t next_count)
{
	u_int tick_usec;
	if (nvc_regs.nr_tcr.t_clk_sel)
	{
		tick_usec = 305;
		nvc_timer.nt_tick_frac+= 175781250;
	}
	else
	{
		tick_usec = 1525;
		nvc_timer.nt_tick_frac+= 878906250;
	}
	if (nvc_timer.nt_tick_frac > 1000000000)
	{
		++tick_usec;
		nvc_timer.nt_tick_frac -= 1000000000;
	}
	nvc_timer.nt_next_tick = (main_usec + tick_usec) % 1000000;
	nvc_timer.nt_next_count = next_count;
}

static char *
nvc_format_timer(debug_str_t s)
{
	debug_str_t tcr_s;
	snprintf(s, debug_str_len,
	         "TCR = %s, THR:TLR = %02hhx:%02hhx, preset = 0x%04x, next count = 0x%04x, next tick = %u",
	         debug_format_flags(tcr_s,
	                            "T-Enb", nvc_regs.nr_tcr.t_enb,
	                            "Z-Stat", nvc_regs.nr_tcr.t_z_stat,
	                            "Z-Stat-Clr", nvc_regs.nr_tcr.t_z_stat_clr,
	                            "Tim-Z-Int", nvc_regs.nr_tcr.t_z_int,
	                            "T-Clk-Sel", nvc_regs.nr_tcr.t_clk_sel,
	                            NULL),
	         nvc_regs.nr_thr, nvc_regs.nr_tlr,
	         nvc_timer.nt_preset,
	         nvc_timer.nt_next_count,
	         nvc_timer.nt_next_tick);
	return s;
}

static void
nvc_trace_timer(const char *desc)
{
	debug_str_t timer_s;
	debug_tracef("nvc.tim", "%s - %s", desc, nvc_format_timer(timer_s));
}

bool
nvc_step(void)
{
	if (nvc_regs.nr_tcr.t_enb && main_usec == nvc_timer.nt_next_tick)
	{
		nvc_regs.nr_tlr = nvc_timer.nt_next_count & 0xff;
		nvc_regs.nr_thr = nvc_timer.nt_next_count >> 8;

		if (nvc_timer.nt_next_count > 0)
			nvc_timer_set(nvc_timer.nt_next_count - 1);
		else
		{
			nvc_regs.nr_tcr.t_z_stat = 1;
			nvc_timer_set(nvc_timer.nt_preset);

			if (debug_trace_nvc_tim)
				nvc_trace_timer("Timer expired");
			if (nvc_regs.nr_tcr.t_z_int)
				cpu_intr(NVC_INTTIM);
		}
	}

	for (u_int x = 0; x < nvc_cycles_per_usec; ++x)
		if (!cpu_step())
			return false;

	return true;
}

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
			debug_tracef("nvc", "Serial data 0x%08x -> 0x%08x, raise intr = %d", old_nvc_keys, nvc_keys, raise_intr);

		nvc_regs.nr_scr.s_si_stat = 0;

		if (raise_intr)
			cpu_intr(NVC_INTKEY);
	}
}

bool
nvc_mem_prepare(struct mem_request *request)
{
	if (request->mr_size != 1)
	{
		static bool ignore_size = false;
		if (!debug_runtime_errorf(&ignore_size, "Invalid NVC access size %lu @ 0x%08x\n",
		                          request->mr_size, request->mr_emu))
			return false;
		request->mr_size = 1;
	}
	if (request->mr_emu <= 0x02000028)
	{
		switch (request->mr_emu)
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
				request->mr_perms = PROT_READ | PROT_WRITE;
				break;
			case 0x02000020:
				request->mr_perms = PROT_READ | PROT_WRITE;
				break;
			default:
				request->mr_perms = 0;
		}
		request->mr_host = (u_int8_t *) &nvc_regs + ((request->mr_emu & 0x3f) >> 2);
	}
	else
	{
		debug_runtime_errorf(NULL, "NVC bus error at 0x%08x", request->mr_emu);
		debug_stop();
		return false;
	}

	return true;
}

void
nvc_mem_write(const struct mem_request *request, const void *src)
{
	switch (request->mr_emu)
	{
		case 0x02000020:
		{
			const struct nvc_tcr *new_tcr = (struct nvc_tcr *)src;

			nvc_regs.nr_tcr.t_z_int = new_tcr->t_z_int;

			if (nvc_regs.nr_tcr.t_clk_sel != new_tcr->t_clk_sel)
			{
				if (nvc_regs.nr_tcr.t_enb)
				{
					static bool ignore_sel = false;
					debug_runtime_errorf(&ignore_sel, "T-Clk-Sel changed while timer enabled");
				}
				nvc_regs.nr_tcr.t_clk_sel = new_tcr->t_clk_sel;
			}

			if (!nvc_regs.nr_tcr.t_enb && new_tcr->t_enb)
			{
				nvc_regs.nr_tcr.t_enb = 1;
				nvc_timer_set(nvc_timer.nt_preset);

				if (debug_trace_nvc_tim)
					nvc_trace_timer("Timer enabled");
			}
			else if (nvc_regs.nr_tcr.t_enb && !new_tcr->t_enb)
			{
				nvc_regs.nr_tcr.t_enb = 0;

				if (debug_trace_nvc_tim)
					nvc_trace_timer("Timer disabled");
			}

			if (nvc_regs.nr_tcr.t_z_stat && new_tcr->t_z_stat_clr)
			{
				nvc_regs.nr_tcr.t_z_stat = 0;
				if (debug_trace_nvc_tim)
					nvc_trace_timer("Cleared timer zero status");
			}
			break;
		}
		case 0x0200001c:
			nvc_timer.nt_preset = (nvc_timer.nt_preset & 0xff) | *(u_int8_t *)src << 8;
			if (debug_trace_nvc_tim)
				nvc_trace_timer("Set timer high");
			break;
		case 0x02000018:
			nvc_timer.nt_preset = (nvc_timer.nt_preset & 0xff00) | *(u_int8_t *)src;
			if (debug_trace_nvc_tim)
				nvc_trace_timer("Set timer low");
			break;

		default:
			*(u_int8_t *)request->mr_host = *(u_int8_t *)src;
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

bool debug_trace_cpu = false;
bool debug_trace_cpu_jmp = false;
bool debug_trace_cpu_int = false;
bool debug_trace_cpu_lp = false;
bool debug_trace_mem_read = false;
bool debug_trace_mem_write = false;
bool debug_trace_vip = false;
u_int16_t debug_vip_intflags = 0;
bool debug_trace_nvc = false;
bool debug_trace_nvc_tim = false;
FILE *debug_trace_file = NULL;

static bool debug_stopped = false;
static bool debug_stepping = false;
static bool debug_stepping_frame = false;
static u_int32_t debug_break = DEBUG_ADDR_NONE;

struct debug_trace
{
	const char *dt_key;
	const char *dt_label;
	bool *dt_tracep;
};
static struct debug_trace debug_traces[] =
		{
				{"main", "Trace main loop", &main_trace},
				{"cpu", "Trace CPU", &debug_trace_cpu},
				{"cpu.jmp", "Trace CPU jumps", &debug_trace_cpu_jmp},
				{"cpu.int", "Trace CPU interrupts", &debug_trace_cpu_int},
				{"cpu.lp", "Trace CPU link pointer", &debug_trace_cpu_lp},
				{"mem.read", "Trace memory reads", &debug_trace_mem_read},
				{"mem.write", "Trace memory writes", &debug_trace_mem_write},
				{"vip", "Trace VIP", &debug_trace_vip},
				{"nvc", "Trace NVC", &debug_trace_nvc},
				{"nvc.tim", "Trace NVC timer", &debug_trace_nvc_tim}
		};

struct debug_watch
{
	u_int32_t dw_addr;
	int dw_ops;
	struct debug_watch *dw_next;
};
struct debug_watch *debug_watches = NULL;

#if DEBUG_TTY
	static EditLine *s_editline;
#endif // DEBUG_TTY
static History *s_history;
static Tokenizer *s_token;

// TODO: Use hcreate()
static struct debug_symbol *debug_syms = NULL;
static struct node *debug_addrs = NULL;

static bool debug_show_console = false;
static char debug_console_buffer[16 * 1024];
static bool debug_console_dirty = true;
static size_t debug_console_begin = 0, debug_console_end = 0;
static bool debug_clear_console = false;

#if DEBUG_TTY
static char *
debug_prompt(EditLine *editline __unused)
{
	return "vvboy> ";
}
#endif // DEBUG_TTY

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
	s_history = history_init();
	if (!s_history)
	{
		warnx("Could not initialize history editing");
		return false;
	}
	HistEvent event;
	history(s_history, &event, H_SETSIZE, INT_MAX);

	s_token = tok_init(NULL);
	if (!s_token)
	{
		warnx("Could not initialize tokenizer");
		return false;
	}

#if DEBUG_TTY
	s_editline = el_init("vvboy", stdin, stdout, stderr);
	if (!s_editline)
	{
		warnx("Could not initialize editline");
		return false;
	}
	el_set(s_editline, EL_PROMPT, debug_prompt);
	el_source(s_editline, NULL);
	el_set(s_editline, EL_HIST, history, s_history);
#endif // DEBUG_TTY

	return true;
}

static int
debug_symbol_cmpaddr(const struct debug_symbol *sym1, const struct debug_symbol *sym2)
{
	if (sym1->ds_addr < sym2->ds_addr)
		return -1;
	else if (sym1->ds_addr > sym2->ds_addr)
		return 1;
	else
		return 0;
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
	assert(!debug_syms);
	assert(!debug_addrs);
}

void
debug_fini(void)
{
	history_end(s_history);
#if DEBUG_TTY
	el_end(s_editline);
#endif // DEBUG_TTY
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
debug_resolve_addr_slow(u_int32_t addr, u_int32_t *match_offsetp)
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

static struct debug_symbol *
debug_search_addr(struct node *root, u_int32_t addr, u_int32_t *match_offsetp, bool inexact)
{
	if (!root)
		return NULL;
	struct debug_symbol *root_sym = (struct debug_symbol *)root->key;
	if (addr < root_sym->ds_addr)
		return debug_search_addr(root->llink, addr, match_offsetp, inexact);
	else if (addr > root_sym->ds_addr)
	{
		struct debug_symbol *next_sym = debug_search_addr(root->rlink, addr, match_offsetp, inexact);
		if (next_sym)
			return next_sym;
		else if (inexact)
		{
			u_int32_t offset = addr - root_sym->ds_addr;
			if (offset <= 8192)
			{
				*match_offsetp = offset;
				return root_sym;
			}
		}

		return NULL;
	}
	else
	{
		*match_offsetp = 0;
		return root_sym;
	}
}

struct debug_symbol *
debug_resolve_addr(u_int32_t addr, u_int32_t *match_offsetp)
{
	struct debug_symbol *sym = debug_search_addr(debug_addrs, addr, match_offsetp, true);

#if 0
	u_int32_t other_offset = *match_offsetp;
	struct debug_symbol *other_sym = debug_resolve_addr_slow(addr, &other_offset);
	assert(other_sym == sym && *match_offsetp == other_offset);
#endif // 1
	return sym;
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
	struct node *existing;
	existing = tfind(debug_sym, (void **)&debug_addrs, (int (*)(const void *, const void *))debug_symbol_cmpaddr);
	if (existing)
	{
		struct debug_symbol *existing_sym = (struct debug_symbol *)existing->key;
		debug_printf("Duplicate symbol %s has identical address to %s (0x%08x)\n",
				debug_sym->ds_name, existing_sym->ds_name, existing_sym->ds_addr);
		return;
	}

	u_int32_t existing_addr = debug_locate_symbol(debug_sym->ds_name);
	if (existing_addr != DEBUG_ADDR_NONE)
	{
		debug_printf("Duplicate symbol with name %s\n", debug_sym->ds_name);
		return;
	}

	debug_sym->ds_next = debug_syms;
	debug_syms = debug_sym;

	if (!existing && debug_sym->ds_type == ISX_SYMBOL_POINTER)
		tsearch(debug_sym, (void **)&debug_addrs, (int (*)(const void *, const void *))debug_symbol_cmpaddr);
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

struct debug_symbol *
debug_create_symbolf(u_int32_t addr, const char *fmt, ...)
{
	char name[64 + 1];
	va_list ap;
	va_start(ap, fmt);
	vsnprintf(name, sizeof(name), fmt, ap);
	va_end(ap);
	return debug_create_symbol(name, addr);
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
	if (debug_sym->ds_type == ISX_SYMBOL_POINTER)
		tdelete(debug_sym, (void **)&debug_addrs, (int (*)(const void *, const void *))debug_symbol_cmpaddr);

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
	const union cpu_reg *reg1 = debug_get_reg(context, inst->ci_i.i_reg1);
	const union cpu_reg *reg2 = debug_get_reg(context, inst->ci_i.i_reg2);
	if (reg1 && reg2)
		snprintf(decomp, debug_str_len, decomp_fmt,
		         debug_rnames[inst->ci_i.i_reg1],
		         reg1->u,
		         debug_rnames[inst->ci_i.i_reg2],
		         reg2->u);
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
	debug_printf("%c %s\t%s\n", help->dh_char, help->dh_usage, help->dh_desc);
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
		debug_printf("Could not read %lu bytes from 0x%08x: Invalid address", size, addr);
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
			debug_printf("Invalid register name %s", reg_name);
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
			debug_printf("Sym name: \"%s\"\n", sym_name);
#endif // 0
			if ((base = debug_locate_symbol(sym_name)) == DEBUG_ADDR_NONE)
			{
				debug_printf("Symbol not found: %s\n", sym_name);
				return false;
			}
			if (num_parsed >= 2 && *sign == '-')
				disp = -disp;
		}
		else
		{
			debug_printf("Invalid address format “%s”\n", s);
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
	debug_printf(" %s\n", debug_disasm(&inst, *addrp, NULL));

	*addrp+= cpu_inst_size(&inst);
	return true;
}

void
debug_stop(void)
{
	if (debug_stopped)
	{
		fprintf(stderr, "debug_stop() called while debug_stopped=true\n");
		return;
	}

	debug_stopped = true;
	debug_show_console = true;
	imgui_shown = true;

	main_update_caption(NULL);
}

bool
debug_is_stopped(void)
{
	return debug_stopped;
}

void
debug_toggle_stopped(void)
{
	if (!debug_stopped)
	{
		debug_printf("\nEmulation paused\n");
		debug_stop();
	}
	else
	{
		debug_printf("\nEmulation resumed\n");
		debug_stopped = false;
	}
}

void
debug_next_frame(void)
{
	assert(debug_stopped);
	assert(!debug_stepping);
	debug_stepping_frame = true;
	debug_stopped = false;
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
	debug_printf("\t%s: 0x%08x (%s) (interrupt level %d)",
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
	debug_printf("%s: (%s)",
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
	debug_printf("%s: (%s)",
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
	debug_printf("%s: (%s)",
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
	debug_printf("CHR No: %u, BVFLP=%u, BHFLP=%u, GPLTS=%u\n",
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
	bufoff+= snprintf(buf + bufoff, buflen - bufoff, "(%s) BGM=%s, SCX=%u, SCY=%u, BGMAP BASE=%u",
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
	if (!vwa->vwa_end && (vwa->vwa_lon || vwa->vwa_ron) && vwa->vwa_bgm != WORLD_BGM_OBJ)
	{
		bufoff+= snprintf(buf + bufoff, buflen - bufoff,
		                  "\n\tGX=%hd, GP=%hd, GY=%hd, MX=%hd, MP=%hd, MY=%hu, W=%hu, H=%hu\n",
		                  vwa->vwa_gx, vwa->vwa_gp, vwa->vwa_gy, vwa->vwa_mx, vwa->vwa_mp, vwa->vwa_my, vwa->vwa_w, vwa->vwa_h);
		bufoff+= snprintf(buf + bufoff, buflen - bufoff,
		                  "\tPARAM BASE=%hu, OVERPLANE CHARACTER=%hu", vwa->vwa_param_base, vwa->vwa_over_chrno);
	}
}

void
debug_format_oam(debug_str_t s, const struct vip_oam *vop)
{
	snprintf(s, debug_str_len, "JX=%hd, JP=%hd, JRON=%u, JLON=%u, JY=%hd, JCA=%u"
			", JVFLP=%u, JHFLP=%u, JPLTS=%u",
	         vop->vo_jx, cpu_extend14to16(vop->vo_jp), vop->vo_jron, vop->vo_jlon, vop->vo_jy, vop->vo_jca,
	         vop->vo_jvflp, vop->vo_jhflp, vop->vo_jplts);
}

static void
debug_show_trace(const struct debug_trace trace)
{
	debug_printf("%s tracing is %s\n", trace.dt_key, (*trace.dt_tracep) ? "on" : "off");
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
		debug_tracef("watch", DEBUG_ADDR_FMT ": [" DEBUG_ADDR_FMT "] -> %s",
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
		debug_tracef("watch", DEBUG_ADDR_FMT ": [" DEBUG_ADDR_FMT "] <- %s",
		             debug_format_addr(pc, addr_s),
		             debug_format_addr(addr, mem_addr_s),
		             debug_format_hex((u_int8_t *)&value, byte_size, hex_s));
	}
}

static void __unused
debug_exec(const char *cmd)
{
	bool running = true;

	HistEvent hist_event;
	if (history(s_history, &hist_event, H_ENTER, cmd) == -1)
		warn("Could not save editline history");

	int argc;
	const char **argv;
	tok_reset(s_token);
	if (tok_str(s_token, cmd, &argc, &argv) == 0 && argc > 0)
	{
		if (!strcmp(argv[0], "?") || !strcmp(argv[0], "help"))
		{
			debug_printf("Debugger commands:\n");
			for (u_int help_index = 0; help_index < sizeof(debug_help) / sizeof(debug_help[0]); ++help_index)
				debug_print_help(&(debug_help[help_index]));
		}
		else if (!strcmp(argv[0], "q") || !strcmp(argv[0], "quit") || !strcmp(argv[0], "exit"))
		{
			tk_quit();
			debug_stopped = false;
			running = false;
		}
		else if (!strcmp(argv[0], "c") || !strcmp(argv[0], "cont"))
		{
			if (debug_stopped)
				debug_stopped = false;
			else
				debug_printf("Not stopped in debugger\n");
		}
		else if (!strcmp(argv[0], "s") || !strcmp(argv[0], "step"))
		{
			if (debug_stopped)
			{
				debug_stepping = true;
				debug_stopped = false;
			}
			else
				debug_printf("Not stopped in debugger\n");
		}
		else if (!strcmp(argv[0], "b") || !strcmp(argv[0], "break"))
		{
			if (argc > 2)
			{
				debug_usage('b');
				return;
			}

			if (argc == 2)
			{
				if (debug_parse_addr(argv[1], &debug_break))
				{
					debug_str_t addr_s;
					debug_printf("Set breakpoint at %s\n", debug_format_addr(debug_break, addr_s));
				}
			}
			else
			{
				debug_break = DEBUG_ADDR_NONE;
				debug_printf("Cleared breakpoint\n");
			}
		}
		else if (!strcmp(argv[0], "i") || !strcmp(argv[0], "info"))
		{
			static const char *fmt = "%5s: " DEBUG_ADDR_FMT;
			debug_str_t addr_s;
			for (u_int regIndex = 0; regIndex < 32; ++regIndex)
			{
				debug_printf(fmt,
				             debug_rnames[regIndex],
				             debug_format_addr(cpu_state.cs_r[regIndex].u, addr_s));
				debug_printf(" (%11i, %11g)", cpu_state.cs_r[regIndex].s, cpu_state.cs_r[regIndex].f);
				if (regIndex % 2 == 1)
					debug_putchar('\n');
			}
			debug_printf(fmt, "pc", debug_format_addr(cpu_state.cs_pc, addr_s));
			debug_print_psw(cpu_state.cs_psw, "  psw");
			debug_putchar('\n');
			debug_printf("  ecr: (eicc: 0x%04hx, fecc: 0x%04hx)\n",
			             cpu_state.cs_ecr.ecr_eicc, cpu_state.cs_ecr.ecr_fecc);
			debug_printf(fmt, "eipc", debug_format_addr(cpu_state.cs_eipc, addr_s));
			debug_print_psw(cpu_state.cs_eipsw, "eipsw");
			debug_putchar('\n');
			debug_printf(fmt, "fepc", debug_format_addr(cpu_state.cs_fepc, addr_s));
			debug_print_psw(cpu_state.cs_fepsw, "fepsw");
			debug_putchar('\n');
		}
		else if (!strcmp(argv[0], "x"))
		{
			if (argc >= 2)
			{
				u_int32_t addr;
				if (!debug_parse_addr(argv[1], &addr))
					return;
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
					debug_printf("%s: ", debug_format_addr(addr, addr_s));
					if (format[0] == 'h' && strlen(format) <= 2)
					{
						u_int value;
						if (debug_mem_read(addr, &value, int_size))
							debug_printf(" 0x%0.*x\n", (int)int_size << 1, value);
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
							debug_printf(" %s\n", debug_format_binary(value, int_size << 3, bin_s));
						}
						addr+= int_size;
					}
					else if (!strcmp(format, "addr"))
					{
						u_int32_t addr_value;
						if (debug_mem_read(addr, &addr_value, sizeof(addr_value)))
							debug_printf(" %s\n", debug_format_addr(addr_value, addr_s));
						addr+= sizeof(addr_value);
					}
					else if (!strcmp(format, "C"))
					{
						debug_putchar('\n');
						for (u_int rindex = 0; rindex < 8; ++rindex)
						{
							u_int16_t chr_row;
							if (!debug_mem_read(addr, &(chr_row), sizeof(chr_row)))
								break;
							//static const char *shading = " ░▒▓";
							static const char *shading = " -=#";
							for (u_int cindex = 0; cindex < 8; ++cindex)
							{
								debug_putchar(shading[chr_row & 0b11]);
								chr_row>>= 2;
							}
							debug_putchar('\n');
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
						debug_printf("%s\n", oam_str);
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
						debug_printf("%s\n", buf);
						addr+= sizeof(att);
					}
					else if (!strcmp(format, "T"))
					{
						struct vip_ctc ctc;
						if (!debug_mem_read(addr, &ctc, sizeof(ctc)))
							break;
						debug_printf("REPEAT: %hhu, LENGTH: %hhu\n", ctc.vc_repeat, ctc.vc_length);
						addr+= sizeof(ctc);
					}
					else if (!strcmp(format, "P"))
					{
						u_int16_t plt;
						if (!debug_mem_read(addr, &plt, sizeof(plt)))
							break;
						debug_str_t b01_s, b10_s, b11_s;
						debug_printf("0b01 = %s, 0b10 = %s, 0b11 = %s\n",
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
			debug_printf(", ");
			debug_print_intreg(vip_regs.vr_intenb, "INTENB");
			debug_printf(", ");
			debug_print_intreg(vip_regs.vr_intclr, "INTCLR");
			debug_putchar('\n');
			debug_print_dpctrl(vip_regs.vr_dpstts, "DPSTTS");
			debug_printf(", ");
			debug_print_dpctrl(vip_regs.vr_dpctrl, "DPCTRL");
			debug_putchar('\n');
			debug_print_xpctrl(vip_regs.vr_xpstts, "XPSTTS");
			debug_printf(" SBCOUNT=%d", vip_regs.vr_xpstts.vx_sbcount);
			debug_printf(", ");
			debug_print_xpctrl(vip_regs.vr_xpctrl, "XPCTRL");
			debug_printf(" SBCMP=%d", vip_regs.vr_xpctrl.vx_sbcount);
			debug_putchar('\n');
			debug_printf("BRTA: %hhu, BRTB: %hhu, BRTC: %hhu, REST: %hhu\n",
			             vip_regs.vr_brta, vip_regs.vr_brtb, vip_regs.vr_brtc, vip_regs.vr_rest);
			debug_printf("FRMCYC: %d\n", vip_regs.vr_frmcyc);
			u_int world_index = 31;
			do
			{
				const struct vip_world_att *vwa = &(vip_dram.vd_world_atts[world_index]);
				if (vwa->vwa_end)
					break;
				char buf[1024];
				debug_format_world_att(buf, sizeof(buf), vwa);
				debug_printf("WORLD_ATT[%u]: %s", world_index, buf);
			} while (world_index-- > 0);
		}
		else if (!strcmp(argv[0], "d") || !strcmp(argv[0], "dis"))
		{
			u_int inst_limit;
			u_int32_t pc;
			if (argc >= 2)
			{
				if (!debug_parse_addr(argv[1], &pc))
					return;
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
				debug_printf("No symbol found at start address: only disassembling %u instructions\n",
				             inst_limit);
			}

			while (next_sym == start_sym && inst_limit > 0)
			{
				debug_str_t addr_s;

				debug_printf(DEBUG_ADDR_FMT ":", debug_format_addrsym(pc, next_sym, addr_s));
				if (!debug_disasm_at(&pc))
					break;
				next_sym = debug_resolve_addr(pc, &offset);
				--inst_limit;
			}
		}
		else if (!strcmp(argv[0], "N") || !strcmp(argv[0], "nvc"))
		{
			debug_str_t flags_s;
			debug_printf("SCR: (%s)\n",
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
					debug_printf("debug symbol: %s = 0x%08x, type = %u\n",
					             sym->ds_name, sym->ds_addr, sym->ds_type);
			}
			else if (argc == 2)
			{
				u_int32_t addr = debug_locate_symbol(argv[1]);
				if (addr != DEBUG_ADDR_NONE)
					debug_printf("%s = 0x%08x\n", argv[1], addr);
				else
					debug_printf("Symbol %s not found\n", argv[1]);
			}
			else if (argc == 3)
			{
				u_int32_t addr;
				if (!debug_parse_addr(argv[2], &addr))
					return;

				if (debug_locate_symbol(argv[1]) == DEBUG_ADDR_NONE)
				{
					struct debug_symbol *sym = debug_create_symbol(argv[1], addr);
					rom_add_symbol(sym);
				}
				else
					debug_printf("Symbol %s already exists\n", argv[1]);
			}
			else
			{
				debug_usage('S');
				return;
			}
		}
		else if (!strcmp(argv[0], "w"))
		{
			if (argc == 1)
			{
				for (struct debug_watch *watch = debug_watches; watch; watch = watch->dw_next)
				{
					debug_str_t addr_s, ops_s;
					debug_printf("Watch at %s, ops = %s\n",
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
					return;
				}

				u_int32_t addr;
				if (!debug_parse_addr(argv[2], &addr))
				{
					debug_usage('w');
					return;
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
							debug_printf("Watch at 0x%08x already exists\n", addr);
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
						debug_printf("No watch found for 0x%08x\n", addr);
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
				debug_printf("World mask 0x%08x\n", vip_world_mask);
			else if (argc == 2)
				vip_world_mask = strtoul(argv[1], NULL, 0);
			else
			{
				debug_usage('W');
				return;
			}
		}
		else if (!strcmp(argv[0], "t"))
		{
			if (argc > 1)
			{
				if (!debug_toggle_trace(argv[1]))
				{
					debug_usage('t');
					return;
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
				return;
			}

			u_int32_t addr;
			if (!debug_parse_addr(argv[1], &addr))
				debug_printf("Could not parse address %s\n", argv[1]);

			cpu_state.cs_pc = addr;
		}
		else
			debug_printf("Unknown command “%s” -- type ‘?’ for help\n", argv[0]);
	}
}

bool
debug_step(void)
{
	if (debug_stopped)
		return false;

	if (debug_break != DEBUG_ADDR_NONE && cpu_state.cs_pc == debug_break)
	{
		debug_printf("\nStopped at breakpoint\n");
		debug_stop();
	}

	if (debug_stepping)
	{
		debug_stop();
		debug_stepping = false;
		return true;
	}

#if DEBUG_TTY
	main_unblock_sigint();

	//bool running = true;
	while (true)
	{
		int length;
		const char *line = el_gets(s_editline, &length);
		if (line)
			debug_exec(line);
		else
		{
			debug_putchar('\n');
			tk_quit();
			break;
		}
	}

	main_block_sigint();

	//return running;
#endif // DEBUG_TTY

	return true;
}

void
debug_putchar(char ch)
{
	size_t next_end = debug_console_end + 1;
	if (next_end >= sizeof(debug_console_buffer))
		next_end = 0;

	if (next_end == debug_console_begin)
	{
		size_t next_begin = debug_console_begin + 1;
		if (next_begin >= sizeof(debug_console_buffer))
			next_begin = 0;

		if (next_begin == debug_console_end)
		{
			fprintf(stderr, "Console buffer overflow\n");
			return;
		}

		debug_console_begin = next_begin;
	}

	debug_console_buffer[debug_console_end] = ch;
	debug_console_end = next_end;
	debug_console_dirty = true;
}

void __printflike(1, 2)
debug_printf(const char *fmt, ...)
{
	va_list ap;
	va_start(ap, fmt);
	char msg[2048];
	size_t length = vsnprintf(msg, sizeof(msg), fmt, ap);
	va_end(ap);
#if DEBUG_TTY
	fputs(msg, stdout);
#endif // DEBUG_TTY
	for (size_t offset = 0; offset < length; ++offset)
		debug_putchar(msg[offset]);
}

void __printflike(2, 3)
debug_tracef(const char *tag, const char *fmt, ...)
{
	va_list ap;
	va_start(ap, fmt);
	char trace[2048];
	size_t length = snprintf(trace, sizeof(trace), "@%07d [%s] ", main_usec, tag);
	length+= vsnprintf(trace + length, sizeof(trace) - length, fmt, ap);
	va_end(ap);

	if (!debug_trace_file)
		debug_printf("%s\n", trace);
	else
	{
		fputs(trace, debug_trace_file);
		fputc('\n', debug_trace_file);
	}
}

bool __printflike(2, 3)
debug_runtime_errorf(bool *ignore_flagp, const char *fmt, ...)
{
	va_list ap;
	va_start(ap, fmt);
	char msg[1024];
	vsnprintf(msg, sizeof(msg), fmt, ap);
	va_end(ap);
	debug_printf("%s\n", msg);

	if (debug_stopped)
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
			debug_stop();
			return false;

		case ERROR_ABORT:
			abort();
	}
	return false;
}

void __printflike(1, 2)
debug_fatal_errorf(const char *fmt, ...)
{
	va_list ap;
	va_start(ap, fmt);
	char msg[1024];
	vsnprintf(msg, sizeof(msg), fmt, ap);
	debug_printf("%s\n", msg);
	va_end(ap);
	debug_stop();
}

void
debug_frame_begin(void)
{
	if (debug_clear_console)
	{
		debug_console_begin = debug_console_end;
		debug_clear_console = false;
	}
}

static void
debug_draw_console(bool show_buffers)
{
	if (debug_console_begin < debug_console_end)
		igTextUnformatted(debug_console_buffer + debug_console_begin,
		                  debug_console_buffer + debug_console_end);
	else if (debug_console_end < debug_console_begin)
	{
		size_t overlap_begin = debug_console_begin;
		size_t high_end;
		for (high_end = sizeof(debug_console_buffer) - 1; high_end > debug_console_begin; --high_end)
			if (debug_console_buffer[high_end] == '\n')
			{
				overlap_begin = high_end + 1;
				break;
			}

		size_t overlap_end;
		size_t low_begin = 0;
		for (overlap_end = 0; overlap_end < debug_console_begin; ++overlap_end)
			if (debug_console_buffer[overlap_end] == '\n')
			{
				low_begin = overlap_end + 1;
				break;
			}

		if (high_end > debug_console_begin)
		{
			if (show_buffers)
				igPushStyleColor(ImGuiCol_Text, (struct ImVec4) {1, 0.5, 0.5, 1});
			igTextUnformatted(debug_console_buffer + debug_console_begin,
			                  debug_console_buffer + high_end + 1);
			if (show_buffers)
				igPopStyleColor(1);
		}

		if (show_buffers)
			igPushStyleColor(ImGuiCol_Text, (struct ImVec4){1, 0, 1, 1});
		igTextWrapped((show_buffers) ? "[%.*s][%.*s]" : "%.*s%.*s",
		              sizeof(debug_console_buffer) - overlap_begin,
		              debug_console_buffer + overlap_begin,
		              overlap_end,
		              debug_console_buffer);
		if (show_buffers)
			igPopStyleColor(1);

		if (low_begin < debug_console_end)
		{
			size_t low_end = debug_console_end - 1;
			if (debug_console_buffer[low_end] == '\n')
				--low_end;

			if (low_begin < low_end)
			{
				if (show_buffers)
					igPushStyleColor(ImGuiCol_Text, (struct ImVec4) {0.5, 0.5, 1, 1});
				igTextUnformatted(debug_console_buffer + low_begin, debug_console_buffer + low_end + 1);
				if (show_buffers)
					igPopStyleColor(1);
			}
		}
	}
}

void
debug_frame_end(void)
{
	if (debug_stepping_frame)
	{
		debug_printf("\nStepped one frame\n");
		debug_stepping_frame = false;
		debug_stop();
	}

	static bool clear_each_frame = false;
	static bool scroll_to_end = true;

	if ((igIsKeyDown(SDL_SCANCODE_LGUI) || igIsKeyDown(SDL_SCANCODE_RGUI)) && igIsKeyPressed(SDL_SCANCODE_K, false))
		debug_clear_console = true;

	if (debug_show_console)
	{
		igSetNextWindowSize((struct ImVec2){500, 350}, ImGuiCond_FirstUseEver);
		if (igBegin("Console", &debug_show_console, ImGuiWindowFlags_MenuBar))
		{
			static bool wrap_lines = true;
			static bool show_buffers = false;
			static bool scroll_next_draw = false;

			if (igBeginMenuBar())
			{
				if (igBeginMenu("Trap", true))
				{
					igMenuItemPtr("VIP draw start", NULL, &vip_trap_draw_start, true);

					igEndMenu();
				}

				if (igBeginMenu("Log", true))
				{
					if (igMenuItem("Clear", NULL, false, true))
						debug_clear_console = true;
					igMenuItemPtr("Clear before each frame", NULL, &clear_each_frame, true);
					igSeparator();
					igMenuItemPtr("Scroll to end", NULL, &scroll_to_end, true);
					igSeparator();
					igMenuItemPtr("Wrap lines", NULL, &wrap_lines, true);
					igMenuItemPtr("Show buffers", NULL, &show_buffers, true);

					igEndMenu();
				}

				igEndMenuBar();
			}

			if (igBeginChild("Log", (struct ImVec2){0, -44}, true, 0))
			{
				if (wrap_lines)
					igPushTextWrapPos(0.0f);
				igPushFont(imgui_font_fixed);

				debug_draw_console(show_buffers);

				if (scroll_next_draw)
				{
					igSetScrollHere(1.0);
					scroll_next_draw = false;
				}

				igPopFont();
				if (wrap_lines)
					igPopTextWrapPos();
			}

			igEndChild();

			if (debug_stopped)
			{
				union cpu_inst inst;
				if (cpu_fetch(cpu_state.cs_pc, &inst))
				{
					debug_str_t addr_s;
					igText(DEBUG_ADDR_FMT ": %s\n",
					       debug_format_addr(cpu_state.cs_pc, addr_s),
					       debug_disasm(&inst, cpu_state.cs_pc, debug_current_context()));
				}
			}
			else
				igText("");

			if (debug_console_dirty)
			{
				scroll_next_draw = scroll_to_end; // Scrolling happens on next frame after window size change
				debug_console_dirty = false;
			}

			static bool reclaim_focus = true;
			static char cmd[256];
			igPushItemWidth(igGetContentRegionAvailWidth());
			if (igInputText("##Command", cmd, sizeof(cmd), ImGuiInputTextFlags_EnterReturnsTrue, NULL, NULL))
			{
				debug_printf("vvboy> %s\n", cmd);
				debug_exec(cmd);
				cmd[0] = '\0';
				reclaim_focus = true;
			}
			igPopItemWidth();
			igSetItemDefaultFocus();
			if (reclaim_focus)
			{
				igSetKeyboardFocusHere(-1);
				reclaim_focus = false;
			}
		}
		igEnd();
	}

	if (clear_each_frame && !debug_stopped)
		debug_clear_console = true;
}

/* GL */
#if INTERFACE
	enum gl_texture
	{
		TEXTURE_LEFT,
		TEXTURE_RIGHT,
		TEXTURE_DEBUG_BGSEG,
		TEXTURE_DEBUG_CHR,
		TEXTURE_DEBUG_FB,
		NUM_TEXTURES
	};
#endif // INTERFACE

bool gl_draw_left = true;
bool gl_draw_right = true;

static GLuint gl_textures[NUM_TEXTURES];
static GLuint gl_vao, gl_vbo;
static GLuint gl_program;
static GLint gl_color_uniform;
static u_int32_t gl_debug_frame[512 * 512];

// Saved GL state
static GLint last_viewport[4];
static GLint last_program;
static GLint last_vertex_array;
static GLboolean last_enable_blend;
static GLenum last_blend_src_rgb;
static GLenum last_blend_dst_rgb;
static GLenum last_blend_src_alpha;
static GLenum last_blend_dst_alpha;
static GLenum last_blend_equation_rgb;
static GLenum last_blend_equation_alpha;
static GLint last_texture;

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
gl_save_state(void)
{
	glGetIntegerv(GL_VIEWPORT, last_viewport);
	glGetIntegerv(GL_CURRENT_PROGRAM, &last_program);
	glGetIntegerv(GL_VERTEX_ARRAY_BINDING, &last_vertex_array);
	last_enable_blend = glIsEnabled(GL_BLEND);
	glGetIntegerv(GL_BLEND_SRC_RGB, (GLint*)&last_blend_src_rgb);
	glGetIntegerv(GL_BLEND_DST_RGB, (GLint*)&last_blend_dst_rgb);
	glGetIntegerv(GL_BLEND_SRC_ALPHA, (GLint*)&last_blend_src_alpha);
	glGetIntegerv(GL_BLEND_DST_ALPHA, (GLint*)&last_blend_dst_alpha);
	glGetIntegerv(GL_BLEND_EQUATION_RGB, (GLint*)&last_blend_equation_rgb);
	glGetIntegerv(GL_BLEND_EQUATION_ALPHA, (GLint*)&last_blend_equation_alpha);
	glGetIntegerv(GL_TEXTURE_BINDING_2D, &last_texture);
}

void
gl_restore_state(void)
{
	glBindTexture(GL_TEXTURE_2D, last_texture);
	glBlendEquationSeparate(last_blend_equation_rgb, last_blend_equation_alpha);
	glBlendFuncSeparate(last_blend_src_rgb, last_blend_dst_rgb, last_blend_src_alpha, last_blend_dst_alpha);
	if (last_enable_blend) glEnable(GL_BLEND); else glDisable(GL_BLEND);
	glBindVertexArray(last_vertex_array);
	glUseProgram(last_program);
	glViewport(last_viewport[0], last_viewport[1], (GLsizei)last_viewport[2], (GLsizei)last_viewport[3]);
}

void
gl_draw(u_int x, u_int y, u_int width, u_int height)
{
	glViewport(x, y, width, height);
	gl_check_errors("set viewport");

	glUseProgram(gl_program);
	glBindVertexArray(gl_vao);
	glEnable(GL_BLEND);
	glBlendFunc(GL_ONE, GL_ONE);
	glBlendEquation(GL_FUNC_ADD);

	if (gl_draw_left)
	{
		glBindTexture(GL_TEXTURE_2D, gl_textures[TEXTURE_LEFT]);
		glUniform4f(gl_color_uniform, 1.0, 0, 0, 1.0);
		glDrawArrays(GL_TRIANGLES, 0, 6);
		gl_check_errors("draw left");
	}

	if (gl_draw_right)
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
gl_debug_blit(enum gl_texture texture)
{
	glBindTexture(GL_TEXTURE_2D, gl_textures[texture]);
	glTexImage2D(GL_TEXTURE_2D, 0, GL_RGB, 512, 512, 0, GL_RGBA, GL_UNSIGNED_INT_8_8_8_8_REV, gl_debug_frame);
	return gl_textures[texture];
}

/* IMGUI */
bool imgui_shown = false;
static u_int imgui_emu_x, imgui_emu_y;
static u_int imgui_emu_scale = 2;

struct ImGuiContext *imgui_context;
struct ImFont *imgui_font_fixed;

const struct ImVec2 IMVEC2_ZERO = {0, 0};

static bool
imgui_init(void)
{
	imgui_context = igCreateContext(NULL);

	struct ImGuiIO *io = igGetIO();
	io->IniFilename = NULL;
	ImFontAtlas_AddFontFromFileTTF(io->Fonts, "vendor/cimgui/imgui/misc/fonts/Roboto-Medium.ttf", 16.0f, NULL, NULL);
	imgui_font_fixed = ImFontAtlas_AddFontDefault(io->Fonts, NULL);
	//io.Fonts->AddFontFromFileTTF("../../misc/fonts/Cousine-Regular.ttf", 15.0f);
	//io.Fonts->AddFontFromFileTTF("../../misc/fonts/DroidSans.ttf", 16.0f);
	//io.Fonts->AddFontFromFileTTF("../../misc/fonts/ProggyTiny.ttf", 10.0f);

	return true;
}

static void
imgui_fini(void)
{
	igDestroyContext(imgui_context);
}

static void
imgui_key_toggle(int key_index, bool *togglep, bool show_on_active)
{
	if (igIsKeyPressed(key_index, false))
	{
		*togglep = !*togglep;
		if (show_on_active && *togglep)
			imgui_shown = true;
	}
}

void
imgui_frame_begin(void)
{
	if (igIsKeyPressed(SDL_SCANCODE_ESCAPE, false) /*|| igIsKeyPressed(SDL_SCANCODE_SPACE, false)*/)
		imgui_shown = !imgui_shown;

	if (igIsKeyPressed(SDL_SCANCODE_F9, false))
		debug_toggle_stopped();
	if (debug_is_stopped() && igIsKeyPressed(SDL_SCANCODE_F8, true))
		debug_next_frame();

	imgui_key_toggle(SDL_SCANCODE_GRAVE, &debug_show_console, true);
	imgui_key_toggle(SDL_SCANCODE_F1, &vip_worlds_open, true);
	imgui_key_toggle(SDL_SCANCODE_F2, &vip_bgseg_open, true);
	imgui_key_toggle(SDL_SCANCODE_F3, &vip_chr_open, true);
	imgui_key_toggle(SDL_SCANCODE_F4, &vip_oam_open, true);
	imgui_key_toggle(SDL_SCANCODE_F5, &vip_fb_open, true);

	if (igIsKeyDown(SDL_SCANCODE_LGUI) || igIsKeyDown(SDL_SCANCODE_RGUI))
	{
		if (igIsKeyPressed(SDL_SCANCODE_1, false))
			imgui_emu_scale = 1;
		else if (igIsKeyPressed(SDL_SCANCODE_2, false))
			imgui_emu_scale = 2;
	}

	if (!imgui_shown)
	{
		// TODO: ignore mouse
		return;
	}

	static bool demo_open = false;
	static bool show_timing = false;
	if (igBeginMainMenuBar())
	{
		if (igBeginMenu("File", true))
		{
			if (igMenuItem("Quit", "Cmd+Q", NULL, true))
				tk_quit();

			igEndMenu();
		}

		if (igBeginMenu("Emulation", true))
		{
			if (igMenuItem("Reset", "Cmd+R", NULL, true))
				main_reset();

			igSeparator();

			if (igMenuItem("Pause", "F9", debug_is_stopped(), true))
				debug_toggle_stopped();

			if (igMenuItem("Advance frame", "F8", false, debug_is_stopped()))
				debug_next_frame();

			igSeparator();

			if (igBeginMenu("Debug", true))
			{
				for (u_int i = 0; i < sizeof(debug_traces) / sizeof(debug_traces[0]); ++i)
					igMenuItemPtr(debug_traces[i].dt_label, NULL, debug_traces[i].dt_tracep, true);

				igEndMenu();
			}

			igEndMenu();
		}

		if (igBeginMenu("View", true))
		{
			igMenuItemPtr("Debug console", "`", &debug_show_console, true);

			igSeparator();

			igMenuItemPtr("Worlds...", "F1", &vip_worlds_open, true);
			igMenuItemPtr("Backgrounds...", "F2", &vip_bgseg_open, true);
			igMenuItemPtr("Characters...", "F3", &vip_chr_open, true);
			igMenuItemPtr("Objects...", "F4", &vip_oam_open, true);
			igMenuItemPtr("Frame buffers...", "F5", &vip_fb_open, true);

			igSeparator();

			igMenuItemPtr("Sounds...", NULL, &vsu_sounds_open, true);
			igMenuItemPtr("Audio buffers...", NULL, &vsu_buffers_open, true);

			igEndMenu();
		}

		if (igBeginMenu("Settings", true))
		{
			if (igMenuItem("Window scale 100%", "Cmd+1", imgui_emu_scale == 1, true))
				imgui_emu_scale = 1;
			if (igMenuItem("Window scale 200%", "Cmd+2", imgui_emu_scale == 2, true))
				imgui_emu_scale = 2;

			igSeparator();

			igMenuItemPtr("Draw left eye", NULL, &gl_draw_left, true);
			igMenuItemPtr("Draw right eye", NULL, &gl_draw_right, true);

			igSeparator();

			igMenuItemPtr("Use global palette", NULL, &vip_use_bright, true);
			igMenuItemPtr("Accurate scanner timing", NULL, &vip_scan_accurate, true);
			igMenuItemPtr("Draw rows...", NULL, &vip_rows_open, true);
			igMenuItemPtr("Timing...", NULL, &show_timing, true);

			igSeparator();

			if (igMenuItem("Toggle GUI", "space/esc", false, true))
				imgui_shown = false;

			igEndMenu();
		}

		if (igBeginMenu("Help", true))
		{
			if (igMenuItem("Show UI demo", NULL, false, true))
				demo_open = true;

			igEndMenu();
		}

		igEndMainMenuBar();
	}

	if (show_timing)
	{
		if (igBegin("Timing", &show_timing, ImGuiWindowFlags_NoResize))
		{
			igSliderInt("CPU cycles per µsec", (int *)&nvc_cycles_per_usec, 5, 50, NULL);

			igEnd();
		}
	}

	if (demo_open)
		igShowDemoWindow(&demo_open);
}

static void
imgui_draw_emu(const struct ImDrawList *parent_list __unused, const struct ImDrawCmd *draw_cmd __unused)
{
	gl_save_state();
	gl_draw(imgui_emu_x, imgui_emu_y, 384 * imgui_emu_scale, 224 * imgui_emu_scale);
	gl_restore_state();
}

void
imgui_frame_end(void)
{
	if (imgui_shown)
		igRender();
	else
		igEndFrame();
}

void
imgui_debug_image(enum gl_texture texture, u_int width, u_int height)
{
	static const struct ImVec4 color = {1, 1, 1, 1};
	static const struct ImVec4 border_color = {0.5, 0.5, 0.5, 1};
	u_int texture_id = gl_debug_blit(texture);
	igImage((ImTextureID)(uintptr_t)texture_id,
	        (struct ImVec2) {width, height},
	        IMVEC2_ZERO, (struct ImVec2) {(float)width / 512, (float)height / 512},
	        color, border_color);
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
bool main_trace = false;
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
	if (debug_is_stopped())
		offset+= snprintf(caption + offset, sizeof(caption) - offset, " (Stopped)");
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
		if (main_trace)
			debug_tracef("main", "%u frames in %u ms (%g FPS), %u instructions, %u interrupts",
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

	main_speed = 0;

	vip_reset();
	vsu_reset();
	nvc_reset();
}

bool
main_step(void)
{
	if (!nvc_step())
		return false;

	vip_step();
	vsu_step();

	if (++main_usec == 1000000)
		main_restart_clock();

	return true;
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
main_draw(void)
{
	if (imgui_shown)
	{
		char id[64];
		snprintf(id, sizeof(id), "%s##VVBoy", rom_name);
		igPushStyleVar(ImGuiStyleVar_WindowRounding, 0);
		igPushStyleVarVec(ImGuiStyleVar_WindowPadding, IMVEC2_ZERO);
		struct ImGuiStyle *style = igGetStyle();
		u_int width = 384 * imgui_emu_scale, height = 224 * imgui_emu_scale;
		struct ImVec2 content_size =
				{
						width + style->WindowBorderSize * 2,
						height + style->WindowBorderSize
				};
		igSetNextWindowPos((struct ImVec2){tk_width / 2.0, tk_height / 2.0},
		                   ImGuiCond_FirstUseEver,
		                   (struct ImVec2){0.5, 0.5});
		igSetNextWindowContentSize(content_size);
		if (igBegin(id, NULL, ImGuiWindowFlags_NoResize |
		                      ImGuiWindowFlags_AlwaysAutoResize |
		                      ImGuiWindowFlags_NoFocusOnAppearing))
		{
			struct ImVec2 view_pos;
			struct ImVec2 content_min;
			igGetWindowPos(&view_pos);
			igGetWindowContentRegionMin(&content_min);
			imgui_emu_x = view_pos.x + content_min.x + style->WindowBorderSize;
			imgui_emu_y = tk_height - (view_pos.y + content_min.y + height);
			ImDrawList_AddCallback(igGetWindowDrawList(), imgui_draw_emu, NULL);
		}
		igEnd();
		igPopStyleVar(2);
	}
	else
		gl_draw(0, 0, tk_width, tk_height);
}

void
main_frame(void)
{
	gl_clear();

	imgui_frame_begin();

	u_int main_frame_usec = 20000;

	debug_frame_begin();
	nvc_frame_begin();
	vip_frame_begin();

#if 0
	if (igBeginMainMenuBar())
	{
		if (igBeginMenu("Run", true))
		{
			igBeginChild("Speed", (struct ImVec2){120, 30}, false, 0);
			{
				igSliderInt("Speed", &main_speed, -3, 3, "2^%.0f");
				igEndChild();
			}

			if (igMenuItem("Interrupt", NULL, false, true))
				debugging = true;

			igEndMenu();
		}

		igEndMainMenuBar();
	}
#endif // 0

	if (main_trace)
		debug_tracef("main", "Begin frame");

	if (main_speed != 0)
		main_frame_usec = lround(20000.0 * pow(2.0, main_speed));

	while (main_step() && (main_usec % main_frame_usec) != 0);

	// Check SIGINT -> Debugger
	sigset_t sigpend;
	sigpending(&sigpend);
	if (sigismember(&sigpend, SIGINT))
		debug_stop();

	if (main_trace)
		debug_tracef("main", "End frame");

	vip_frame_end();
	vsu_frame_end();

	main_draw();

	debug_frame_end();

	imgui_frame_end();
}
