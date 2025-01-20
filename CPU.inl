#include "Emu.hh"
#include "CPU.hh"
#include "Memory.hh"
#include "ROM.hh"

#include <cassert>
#include <cfloat>
#include <cmath>

typedef char debug_str_t[96];
#define DEBUG_ADDR_FMT "%-26s"
extern bool __printflike(1, 2) debug_fatal_errorf(const char *fmt, ...);
extern bool __printflike(2, 3) debug_runtime_errorf(bool *always_ignore_flagp, const char *fmt, ...);
extern void __printflike(2, 3) debug_tracef(const char *tag, const char *fmt, ...);
extern bool debug_trace_cpu_jmp;
extern bool debug_trace_cpu_lp;
extern void debug_stop(void);
extern const char *debug_format_addrsym(u_int32_t addr, struct debug_symbol *sym, debug_str_t s);
extern struct debug_watch *debug_watches;
extern void debug_watch_read(u_int32_t pc, u_int32_t addr, u_int32_t value, u_int byte_size);
extern void debug_watch_write(u_int32_t pc, u_int32_t addr, u_int32_t value, u_int byte_size);
extern const char *debug_format_addr(u_int32_t addr, debug_str_t s);
extern struct debug_disasm_context *debug_current_context(void);
struct debug_symbol *debug_resolve_addr(u_int32_t addr, u_int32_t *match_offsetp);
extern const char *debug_rnames[32];
char *debug_disasm(const union cpu_inst *inst, u_int32_t pc, struct debug_disasm_context *context);
extern class Memory mem;

static inline bool
cpu_getfl(cpu_bcond cond)
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
			return debug_fatal_errorf("Handle branch cond");
	}
}

static inline void
cpu_setfl_zs0(u_int32_t result)
{
	cpu_state.cs_psw.psw_flags.f_z = (result == 0);
	cpu_state.cs_psw.psw_flags.f_s = ((result & sign_bit32) == sign_bit32);
	cpu_state.cs_psw.psw_flags.f_ov = 0;
}

static inline void
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

static inline void
cpu_setfl_float_zsoc(double result)
{
	cpu_state.cs_psw.psw_flags.f_cy = cpu_state.cs_psw.psw_flags.f_s = (result < 0);
	cpu_state.cs_psw.psw_flags.f_ov = 0;
	cpu_state.cs_psw.psw_flags.f_z = (result == 0);
}

static inline void
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

static inline bool
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

static inline double
cpu_subf(float left, float right)
{
	assert(!cpu_float_reserved(left));
	assert(!cpu_float_reserved(right));
	double result = (double)left - right;
	cpu_setfl_float_zsoc(result);
	return result;
}

static inline u_int32_t
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

static inline u_int32_t
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

static inline u_int32_t
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

template<bool CheckedMem>
static inline bool
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
	if (!mem.ReadString<CheckedMem>(*src_word_addrp, &src_word, read_byte_size, &mem_wait))
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
	if (!mem.ReadString<CheckedMem>(*dest_word_addrp, &dest_word, read_byte_size, &mem_wait))
		return false;

	dest_word|= src_word;

	if (!mem.WriteString<CheckedMem>(*dest_word_addrp, &dest_word, read_byte_size, &mem_wait))
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

template<bool CheckedMem>
static inline bool
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
	if (!mem.ReadString<CheckedMem>(*src_word_addrp, &src_word, read_byte_size, &mem_wait))
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

	if (!mem.WriteString<CheckedMem>(*dest_word_addrp, &src_word, read_byte_size, &mem_wait))
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

static inline u_int32_t
cpu_add(u_int32_t left, u_int32_t right)
{
	u_int64_t result = (u_int64_t)left + right;
	cpu_setfl(result, left, (left & sign_bit32) == (right & sign_bit32));
	return result;
}

static inline u_int32_t
cpu_sub(u_int32_t left, u_int32_t right)
{
	u_int64_t result = (u_int64_t)left - right;
	cpu_setfl(result, left, (left & sign_bit32) != (right & sign_bit32));
	return result;
}

// TODO: Just return instruction pointer
// TODO: Return next pc
template<bool CheckedMem>
bool
cpu_fetch(u_int32_t pc, union cpu_inst *inst)
{
	const union cpu_inst *rom_inst = rom_get_inst_ptr<CheckedMem>(pc);

	if (!rom_inst)
		return false;

	*inst = *rom_inst;
	return true;
}

static inline u_int
cpu_inst_size(const union cpu_inst *inst)
{
	return (inst->ci_i.i_opcode < 0x28) ? 2 : 4;
}

static inline u_int32_t
cpu_inst_disp26(const union cpu_inst *inst)
{
	u_int32_t disp = (inst->ci_iv.iv_disp10 << 16) | inst->ci_iv.iv_disp16;
	if ((disp & 0x2000000) == 0x2000000)
		disp|= 0xfd000000;
	return disp;
}

template<bool CheckedMem>
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

			if constexpr (CheckedMem)
			{
				if (MEM_ADDR2SEG(cpu_state.cs_r[inst.ci_i.i_reg1].u) != Memory::SEG_ROM)
				{
					debug_str_t addr_s;
					if (!debug_runtime_errorf(NULL, "JMP to non-ROM addr " DEBUG_ADDR_FMT,
								debug_format_addr(cpu_state.cs_r[inst.ci_i.i_reg1].u, addr_s)))
						return false;
				}
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
				return debug_fatal_errorf("TODO: Divide by zero exception");

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
			cpu_state.cs_r[inst.ci_ii.ii_reg2].u = cpu_getfl(static_cast<cpu_bcond>(inst.ci_ii.ii_imm5));
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
					return cpu_orbsu<CheckedMem>(src_word_addrp, src_bit_offp, bit_lengthp, dest_word_addrp, dest_bit_offp);
				case BSTR_MOVBSU:
					return cpu_movbsu<CheckedMem>(src_word_addrp, src_bit_offp, bit_lengthp, dest_word_addrp, dest_bit_offp);
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
			if (!mem.Read<CheckedMem>(addr, value, &mem_wait))
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
			uint16_t half_word;
			u_int mem_wait;
			if (!mem.Read<CheckedMem>(addr, half_word, &mem_wait))
				return false;
			cpu_state.cs_r[inst.ci_vi.vi_reg2].u = cpu_extend16(half_word);
			if (debug_watches)
				debug_watch_read(cpu_state.cs_pc, addr, half_word, 2);

			cpu_wait = 3 + mem_wait; // 1-2 for successive loads

			break;
		}
		case OP_LD_W:
		case OP_IN_W:
		{
			u_int32_t addr = cpu_state.cs_r[inst.ci_vi.vi_reg1].u + inst.ci_vi.vi_disp16;
			u_int mem_wait;
			if (!mem.Read<CheckedMem>(addr, cpu_state.cs_r[inst.ci_vi.vi_reg2], &mem_wait))
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
			const u_int8_t &src = cpu_state.cs_r[inst.ci_vi.vi_reg2].u8s[0];
			u_int mem_wait;
			if (!mem.Write<CheckedMem>(addr, src, &mem_wait))
				return false;
			if (debug_watches)
				debug_watch_write(cpu_state.cs_pc, addr, src, sizeof(src));

			cpu_wait = 1 + mem_wait; // 2 for successive stores

			break;
		}
		case OP_ST_H:
		case OP_OUT_H:
		{
			u_int32_t addr = cpu_state.cs_r[inst.ci_vi.vi_reg1].u + inst.ci_vi.vi_disp16;
			const u_int16_t src = cpu_state.cs_r[inst.ci_vi.vi_reg2].u16;
			u_int mem_wait;
			if (!mem.Write<CheckedMem>(addr, src, &mem_wait))
				return false;
			if (debug_watches)
				debug_watch_write(cpu_state.cs_pc, addr, src, sizeof(src));

			cpu_wait = 1 + mem_wait; // 2 for successive stores

			break;
		}
		case OP_ST_W:
		case OP_OUT_W:
		{
			u_int32_t addr = cpu_state.cs_r[inst.ci_vi.vi_reg1].u + inst.ci_vi.vi_disp16;
			const u_int32_t src = cpu_state.cs_r[inst.ci_vi.vi_reg2].u;
			u_int mem_wait;
			if (!mem.Write<CheckedMem>(addr, src, &mem_wait))
				return false;
			if (debug_watches)
				debug_watch_write(cpu_state.cs_pc, addr, src, sizeof(src));

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
						return debug_fatal_errorf("TODO: Floating-point invalid operation exception");
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
							return debug_fatal_errorf("TODO: Invalid operation exception");
						}
						else if (cpu_float_reserved(left))
							return false;
						else
						{
							cpu_state.cs_psw.psw_flags.f_fzd = 1;
							return debug_fatal_errorf("TODO: Divide by zero exception");
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
				bool branch = cpu_getfl(inst.ci_iii.GetCondition());
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

template<bool CheckedMem>
inline bool
cpu_step(void)
{
	extern bool debug_step(void);
	extern bool debug_trace_cpu;
	extern bool __printflike(1, 2) debug_fatal_errorf(const char *fmt, ...);

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
	if (!cpu_fetch<CheckedMem>(cpu_state.cs_pc, &inst))
		return debug_fatal_errorf("TODO: bus error fetching inst from PC 0x%08x", cpu_state.cs_pc);

	if (debug_trace_cpu)
	{
		debug_str_t addr_s;
		debug_tracef("cpu", DEBUG_ADDR_FMT ": %s",
		             debug_format_addr(cpu_state.cs_pc, addr_s),
		             debug_disasm(&inst, cpu_state.cs_pc, debug_current_context()));
	}

	if (!cpu_exec<CheckedMem>(inst))
		return false;

	++emu_stats.ms_insts;
	return true;
}
