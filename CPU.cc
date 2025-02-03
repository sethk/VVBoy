#include "CPU.hh"
#include "CPU.Gen.hh"
#include "CPU.inl"

struct cpu_state cpu_state;
bool cpu_accurate_timing = true;
u_int cpu_wait;

bool
cpu_init(void)
{
	event_subsys dummy_subsys;
	(void)dummy_subsys; // Hint for makeheaders

	events_set_desc(CPU_EVENT_INTR_ENTER, "Interrupt %u (%s)");
	events_set_desc(CPU_EVENT_INTR_RETURN, "Return from interrupt");
	events_set_desc(CPU_EVENT_INTR_ENABLE, "Enable interrupts");
	events_set_desc(CPU_EVENT_INTR_DISABLE, "Disable interrupts");

	cpu_state.cs_r[0].u = 0; // Read-only
	cpu_wait = 1;

	return true;
}

void
cpu_init_debug()
{
	debug_create_symbol("vect.fpe", 0xffffff60, true);
	debug_create_symbol("vect.div0", 0xffffff80, true);
	debug_create_symbol("vect.ill", 0xffffff90, true);
	debug_create_symbol("vect.trapa", 0xffffffa0, true);
	debug_create_symbol("vect.trapb", 0xffffffb0, true);
	debug_create_symbol("vect.atrap", 0xffffffc0, true);
	debug_create_symbol("vect.nmi", 0xffffffd0, true);
	debug_create_symbol("vect.reset", 0xfffffff0, true);
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

u_int32_t
cpu_next_pc(const union cpu_inst inst)
{
	if (inst.ci_i.i_opcode == OP_JMP)
		return cpu_state.cs_r[inst.ci_i.i_reg1].u;
	else if (inst.ci_i.i_opcode == OP_RETI)
		return cpu_state.cs_r[31].u;
	else if (inst.ci_iii.iii_opcode == OP_BCOND)
	{
		bool branch = cpu_getfl(inst.ci_iii.GetCondition());
		if (branch)
		{
			u_int32_t disp = cpu_extend9(inst.ci_iii.iii_disp9);
			return cpu_state.cs_pc + disp;
		}
	}

	return cpu_state.cs_pc + cpu_inst_size(&inst);
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
	if (!mem.Read<true>(addr, actual, &mem_wait))
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
	cpu_exec<true>(inst);
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
	cpu_exec<true>(inst);
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
	cpu_exec<true>(inst);
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
	cpu_exec<true>(inst);
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
	cpu_exec<true>(inst);
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
	cpu_exec<true>(inst);
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
	cpu_exec<true>(inst);
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
                u_int src_byte_off,
                u_int src_bit_off,
                u_int dest_byte_off,
                u_int dest_bit_off,
                const u_int8_t dest_bytes[],
                u_int32_t num_dest_bytes)
{
	u_int mem_wait;
	for (u_int i = 0; i < num_src_bytes; ++i)
		if (!mem.Write<true>(0x05000100 + i, src_bytes[i], &mem_wait))
			main_fatal_error(OS_RUNERR_TYPE_EMULATION, "*** Memory write failed during test");

	for (u_int i = 0; i < num_dest_bytes; ++i)
		if (!mem.Write<true>(0x05000200 + i, dest_fill, &mem_wait))
			main_fatal_error(OS_RUNERR_TYPE_EMULATION, "*** Memory write failed during test");

	cpu_state.cs_r[30].u = 0x05000100 + src_byte_off;
	cpu_state.cs_r[29].u = 0x05000200 + dest_byte_off;
	cpu_state.cs_r[28].u = bit_length;
	cpu_state.cs_r[27].u = src_bit_off;
	cpu_state.cs_r[26].u = dest_bit_off;
	union cpu_inst inst = {.ci_ii = {.ii_opcode = OP_BSTR, .ii_imm5 = BSTR_MOVBSU}};
	u_int32_t old_pc = cpu_state.cs_pc;
	do
		cpu_exec<true>(inst);
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
}

void
cpu_intr(nvc_intlevel level)
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

			++emu_stats.ms_intrs;
		}
	}
}

