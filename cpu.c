#include "types.h"
#include "cpu.h"

#if INTERFACE
#   define CPU_MAX_PC (0xfffffffe)

	union cpu_reg {u_int32_t u; int32_t s; float f; u_int16_t u16; int16_t s16; u_int8_t u8s[4];};
	typedef union cpu_reg cpu_regs_t[32];

	union cpu_inst
	{
		u_int16_t ci_hwords[2];
		struct
		{
			u_int16_t i_reg1 : 5;
			u_int16_t i_reg2 : 5;
			u_int16_t i_opcode : 6;
		} ci_i;
		struct
		{
			u_int16_t ii_imm5 : 5;
			u_int16_t ii_reg2 : 5;
			u_int16_t ii_opcode : 6;
		} ci_ii;
		struct
		{
			u_int16_t iii_disp9 : 9;
			u_int16_t iii_cond : 4;
			u_int16_t iii_opcode : 3;
		} ci_iii;
		struct
		{
			u_int16_t iv_disp10 : 10;
			u_int16_t iv_opcode : 6;
			u_int16_t iv_disp16 : 16;
		} ci_iv;
		struct
		{
			u_int16_t v_reg1 : 5;
			u_int16_t v_reg2 : 5;
			u_int16_t v_opcode : 6;
			u_int16_t v_imm16;
		} ci_v;
		struct
		{
			u_int16_t vi_reg1 : 5;
			u_int16_t vi_reg2 : 5;
			u_int16_t vi_opcode : 6;
			int16_t vi_disp16;
		} ci_vi;
		struct
		{
			u_int16_t vii_reg1 : 5;
			u_int16_t vii_reg2 : 5;
			u_int16_t vii_opcode : 6;
			u_int16_t vii_rfu : 10;
			u_int16_t vii_subop : 6;
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
		// TODO: BIT()
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

	union cpu_psw
	{
		u_int32_t psw_word;
		struct
		{
			u_int f_z : 1;
			u_int f_s : 1;
			u_int f_ov : 1;
			u_int f_cy : 1;
			u_int f_fpr : 1;
			u_int f_fud : 1;
			u_int f_fov : 1;
			u_int f_fzd : 1;
			u_int f_fiv : 1;
			u_int f_fro : 1;
			u_int reserved1 : 2;
			u_int f_id : 1;
			u_int f_ae : 1;
			u_int f_ep : 1;
			u_int f_np : 1;
			u_int f_i : 4;
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
#endif // INTERFACE

#include <assert.h>
#include <float.h>
#include <math.h>

struct cpu_state cpu_state;
bool cpu_accurate_timing = true;
static u_int cpu_wait;

enum cpu_event
{
	CPU_EVENT_INTR_ENTER = EVENT_SUBSYS_BITS(EVENT_SUBSYS_CPU) | EVENT_WHICH_BITS(0),
	CPU_EVENT_INTR_RETURN = EVENT_SUBSYS_BITS(EVENT_SUBSYS_CPU) | EVENT_WHICH_BITS(1),
	CPU_EVENT_INTR_ENABLE = EVENT_SUBSYS_BITS(EVENT_SUBSYS_CPU) | EVENT_WHICH_BITS(2),
	CPU_EVENT_INTR_DISABLE = EVENT_SUBSYS_BITS(EVENT_SUBSYS_CPU) | EVENT_WHICH_BITS(3),
};

bool
cpu_init(void)
{
	enum event_subsys dummy_subsys;
	(void)dummy_subsys; // Hint for makeheaders

	debug_create_symbol("vect.fpe", 0xffffff60, true);
	debug_create_symbol("vect.div0", 0xffffff80, true);
	debug_create_symbol("vect.ill", 0xffffff90, true);
	debug_create_symbol("vect.trapa", 0xffffffa0, true);
	debug_create_symbol("vect.trapb", 0xffffffb0, true);
	debug_create_symbol("vect.atrap", 0xffffffc0, true);
	debug_create_symbol("vect.nmi", 0xffffffd0, true);
	debug_create_symbol("vect.reset", 0xfffffff0, true);

	events_set_desc(CPU_EVENT_INTR_ENTER, "Interrupt %u (%s)");
	events_set_desc(CPU_EVENT_INTR_RETURN, "Return from interrupt");
	events_set_desc(CPU_EVENT_INTR_ENABLE, "Enable interrupts");
	events_set_desc(CPU_EVENT_INTR_DISABLE, "Disable interrupts");

	cpu_state.cs_r[0].u = 0; // Read-only
	cpu_wait = 1;

	return true;
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

u_int
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

// TODO: Just return instruction pointer
// TODO: Return next pc
bool
cpu_fetch(u_int32_t pc, union cpu_inst *inst)
{
	enum mem_segment dummy_segment;
	(void)dummy_segment; // Hint for makeheaders

	const union cpu_inst *rom_inst = (const union cpu_inst *)rom_get_read_ptr(pc);

	if (mem_checks && MEM_ADDR2SEG(pc) != MEM_SEG_ROM)
	{
		debug_str_t addr_s;
		if (!debug_runtime_errorf(NULL, "Reading instruction from non-ROM addr " DEBUG_ADDR_FMT,
					debug_format_addr(pc, addr_s)))
			return false;
	}

	*inst = *rom_inst;
	return true;
}

static const u_int32_t sign_bit32 = 0x80000000;
static const u_int64_t sign_bit64 = 0x8000000000000000;
static const u_int64_t sign_bits32to64 = 0xffffffff80000000;

#if INTERFACE
inline static u_int32_t
cpu_extend8(u_int32_t s8)
{
	if ((s8 & 0x80) == 0x80)
		s8|= 0xffffff00;
	return s8;
}

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
cpu_extend5to32(u_int32_t s5)
{
	if ((s5 & 0b10000) == 0b10000)
		s5|= 0xffffffe0;
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
					u_int64_t double_mantissa : 29;
					u_int64_t single_mantissa : 23;
					u_int64_t raw_exp : 11;
					u_int64_t sign : 1;
				};
				double d;
			} result = {.d = double_result};
			ASSERT_SIZEOF(result, 8);
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
cpu_orbsu(u_int32_t *src_word_addrp, u_int32_t *src_bit_offp,
		  u_int32_t *bit_lengthp,
		  u_int32_t *dest_word_addrp, u_int32_t *dest_bit_offp)
{
	if ((*bit_lengthp % 8) != 0)
	{
		debug_runtime_errorf(NULL, "ORBSU only multiple of 8 bit lengths supported");
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
		debug_runtime_errorf(NULL, "ORBSU with src bit offset not supported");
		return false;
	}
	if (*dest_bit_offp & 31)
	{
		debug_runtime_errorf(NULL, "ORBSU with dest bit offset not supported");
		return false;
	}

	u_int32_t dest_word;
	if (!mem_read(*dest_word_addrp, &dest_word, read_byte_size, false, &mem_wait))
		return false;

	dest_word|= src_word;

	if (!mem_write(*dest_word_addrp, &dest_word, read_byte_size, &mem_wait))
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

u_int32_t
cpu_next_pc(const union cpu_inst inst)
{
	if (inst.ci_i.i_opcode == OP_JMP)
		return cpu_state.cs_r[inst.ci_i.i_reg1].u;
	else if (inst.ci_i.i_opcode == OP_RETI)
		return cpu_state.cs_r[31].u;
	else if (inst.ci_iii.iii_opcode == OP_BCOND)
	{
		bool branch = cpu_getfl(inst.ci_iii.iii_cond);
		if (branch)
		{
			u_int32_t disp = cpu_extend9(inst.ci_iii.iii_disp9);
			return cpu_state.cs_pc + disp;
		}
	}

	return cpu_state.cs_pc + cpu_inst_size(&inst);
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

			if (mem_checks && MEM_ADDR2SEG(cpu_state.cs_r[inst.ci_i.i_reg1].u) != MEM_SEG_ROM)
			{
				debug_str_t addr_s;
				if (!debug_runtime_errorf(NULL, "JMP to non-ROM addr " DEBUG_ADDR_FMT,
							debug_format_addr(cpu_state.cs_r[inst.ci_i.i_reg1].u, addr_s)))
					return false;
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
			cpu_state.cs_r[inst.ci_ii.ii_reg2].u = cpu_extend5to32(inst.ci_ii.ii_imm5);
			break;
		}
		case OP_ADD2:
		{
			u_int32_t imm = cpu_extend5to32(inst.ci_ii.ii_imm5);
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
			u_int32_t imm = cpu_extend5to32(inst.ci_ii.ii_imm5);
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

			events_fire(CPU_EVENT_INTR_ENABLE, 0, NULL);

			break;
		case OP_SAR2:
			cpu_state.cs_r[inst.ci_ii.ii_reg2].u =
					cpu_shift_arith_right(cpu_state.cs_r[inst.ci_ii.ii_reg2].u, inst.ci_ii.ii_imm5);
			break;
			/*
   OP_TRAP  = 0b011000,
			 cpu_wait = 15;
   */
		case OP_RETI:
			if (!cpu_state.cs_psw.psw_flags.f_ep)
			{
				static bool ignore_reti = false;
				debug_runtime_errorf(&ignore_reti, "Tried to return from interrupt/exception while EP=0\n");
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

			events_fire(CPU_EVENT_INTR_RETURN, 0, 0);

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
				{
					bool old_id = cpu_state.cs_psw.psw_flags.f_id;

					cpu_state.cs_psw.psw_word = cpu_state.cs_r[inst.ci_ii.ii_reg2].u;

					if (old_id != cpu_state.cs_psw.psw_flags.f_id)
						events_fire((cpu_state.cs_psw.psw_flags.f_id) ? CPU_EVENT_INTR_DISABLE : CPU_EVENT_INTR_ENABLE,
								0, NULL);

					break;
				}
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

			events_fire(CPU_EVENT_INTR_DISABLE, 0, NULL);

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
				case BSTR_ORBSU:
					return cpu_orbsu(src_word_addrp, src_bit_offp, bit_lengthp, dest_word_addrp, dest_bit_offp);
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
			cpu_state.cs_r[inst.ci_vi.vi_reg2].u = cpu_extend8(value);
			if (debug_watches)
				debug_watch_read(cpu_state.cs_pc, addr, value, 1);

			cpu_wait = 3 + mem_wait; // 1-2 for successive loads

			break;
		}
		case OP_LD_H:
		case OP_IN_H:
		{
			u_int32_t addr = cpu_state.cs_r[inst.ci_vi.vi_reg1].u + inst.ci_vi.vi_disp16;
			u_int mem_wait;
			const u_int16_t *mem_ptr = mem_get_read_ptr(addr, 2, &mem_wait);
			if (!mem_ptr)
				return false;
			cpu_state.cs_r[inst.ci_vi.vi_reg2].u = cpu_extend16(*mem_ptr);
			if (debug_watches)
				debug_watch_read(cpu_state.cs_pc, addr, *mem_ptr, 2);

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
			u_int8_t *src = cpu_state.cs_r[inst.ci_vi.vi_reg2].u8s + 0;
			u_int mem_wait;
			if (!mem_write(addr, src, sizeof(*src), &mem_wait))
				return false;
			if (debug_watches)
				debug_watch_write(cpu_state.cs_pc, addr, *src, sizeof(*src));

			cpu_wait = 1 + mem_wait; // 2 for successive stores

			break;
		}
		case OP_ST_H:
		case OP_OUT_H:
		{
			u_int32_t addr = cpu_state.cs_r[inst.ci_vi.vi_reg1].u + inst.ci_vi.vi_disp16;
			u_int16_t *src = &(cpu_state.cs_r[inst.ci_vi.vi_reg2].u16);
			u_int mem_wait;
			if (!mem_write(addr, src, sizeof(*src), &mem_wait))
				return false;
			if (debug_watches)
				debug_watch_write(cpu_state.cs_pc, addr, *src, sizeof(*src));

			cpu_wait = 1 + mem_wait; // 2 for successive stores

			break;
		}
		case OP_ST_W:
		case OP_OUT_W:
		{
			u_int32_t addr = cpu_state.cs_r[inst.ci_vi.vi_reg1].u + inst.ci_vi.vi_disp16;
			u_int32_t *src = &(cpu_state.cs_r[inst.ci_vi.vi_reg2].u);
			u_int mem_wait;
			if (!mem_write(addr, src, sizeof(*src), &mem_wait))
				return false;
			if (debug_watches)
				debug_watch_write(cpu_state.cs_pc, addr, *src, sizeof(*src));

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
cpu_assert_reg(const char *dis, u_int reg, union cpu_reg value)
{
	if (cpu_state.cs_r[reg].u != value.u)
		main_fatal_error(OS_RUNERR_TYPE_EMULATION, "*** Test failure: %s\n\t%s (0x%08x) should be 0x%08x",
				dis, debug_rnames[reg], cpu_state.cs_r[reg].u, value.u);
}

static void
cpu_assert_flag(const char *dis, const char *name, bool flag, bool value)
{
	if (flag != value)
		main_fatal_error(OS_RUNERR_TYPE_EMULATION, "*** Test failure: %s\n\t%s flag (%d) should be %s",
		        dis, name, flag, (value) ? "set" : "reset");
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
		main_fatal_error(OS_RUNERR_TYPE_EMULATION, "*** Test failure: cannot read memory at 0x%08x, size %u\n",
				addr, actual);
	if (os_bcmp(&actual, &expected, byte_size))
	{
		debug_str_t actual_bin_s, expected_bin_s;
		main_fatal_error(OS_RUNERR_TYPE_EMULATION, "*** Test failure: memory at 0x%08x is\n\t%s, should be\n\t%s",
		                     addr,
		                     debug_format_binary(actual, byte_size * 8, actual_bin_s),
		                     debug_format_binary(expected, byte_size * 8, expected_bin_s));
	}
}

static void
cpu_test_add(int32_t left, int32_t right, int32_t result, bool overflow, bool carry, bool zero)
{
	ASSERT_SIZEOF(union cpu_inst, 4);

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
			main_fatal_error(OS_RUNERR_TYPE_EMULATION, "*** Memory write failed during test");

	for (u_int i = 0; i < num_dest_bytes; ++i)
		if (!mem_write(0x05000200 + i, &dest_fill, 1, &mem_wait))
			main_fatal_error(OS_RUNERR_TYPE_EMULATION, "*** Memory write failed during test");

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
		if (cpu_accurate_timing)
		{
			--cpu_wait;
			return true;
		}
		else
			cpu_wait = 0;
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
			cpu_state.cs_eipsw = cpu_state.cs_psw;
			cpu_state.cs_ecr.ecr_eicc = 0xfe00 | (level << 4);
			cpu_state.cs_psw.psw_flags.f_ep = 1;
			cpu_state.cs_psw.psw_flags.f_id = 1;
			cpu_state.cs_psw.psw_flags.f_ae = 0;
			cpu_state.cs_psw.psw_flags.f_i = min_int(level + 1, 15);

			if (debug_trace_cpu_jmp)
			{
				debug_str_t addr_s, dest_addr_s;
				debug_tracef("cpu.jmp", DEBUG_ADDR_FMT ": INT%u %s",
				             debug_format_addr(cpu_state.cs_pc, addr_s),
				             level,
				             debug_format_addr(cpu_state.cs_ecr.ecr_eicc, dest_addr_s));
			}

			cpu_state.cs_pc = cpu_state.cs_ecr.ecr_eicc;

			events_fire(CPU_EVENT_INTR_ENTER, level, nvc_intnames[level]);

			++main_stats.ms_intrs;
		}
	}
}

