#include "types.h"
#include "debug.h"

#if INTERFACE
	struct debug_symbol
	{
		char *ds_name;
		u_int32_t ds_addr;
		struct debug_symbol *ds_next;
		enum isx_symbol_type ds_type;
		bool ds_is_system;
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

#endif // INTERFACE

#include <stdlib.h>
#if HAVE_LIBEDIT
# include <histedit.h>
#endif // HAVE_LIBEDIT
#include <limits.h>
#include <assert.h>

bool debug_show_console = false;
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
bool debug_trace_vsu = false;
bool debug_trace_vsu_buf = true;
os_file_handle_t debug_trace_file = NULL;

enum debug_mode
{
	DEBUG_RUN,
	DEBUG_STOP,
	DEBUG_CONTINUE,
	DEBUG_STEP,
	DEBUG_NEXT
};

static enum debug_mode debug_mode = DEBUG_RUN;
static bool debug_stepping_frame = false;
static u_int32_t debug_break = DEBUG_ADDR_NONE;
static u_int32_t debug_next_pc = DEBUG_ADDR_NONE;

struct debug_trace
{
	const char *dt_key;
	const char *dt_label;
	bool *dt_tracep;
};
static struct debug_trace debug_traces[] =
		{
				{"emu", "Trace main emulation loop", &emu_trace},
				{"cpu", "Trace CPU", &debug_trace_cpu},
				{"cpu.jmp", "Trace CPU jumps", &debug_trace_cpu_jmp},
				{"cpu.int", "Trace CPU interrupts", &debug_trace_cpu_int},
				{"cpu.lp", "Trace CPU link pointer", &debug_trace_cpu_lp},
				{"mem.read", "Trace memory reads", &debug_trace_mem_read},
				{"mem.write", "Trace memory writes", &debug_trace_mem_write},
				{"vip", "Trace VIP", &debug_trace_vip},
				{"nvc", "Trace NVC", &debug_trace_nvc},
				{"nvc.tim", "Trace NVC timer", &debug_trace_nvc_tim},
				{"vsu", "Trace VSU", &debug_trace_vsu}
		};

struct debug_watch
{
	u_int32_t dw_addr;
	int dw_ops;
	struct debug_watch *dw_next;
};
struct debug_watch *debug_watches = NULL;

enum debug_event
{
	DEBUG_EVENT_WATCH_READ = EVENT_SUBSYS_BITS(EVENT_SUBSYS_DEBUG) | EVENT_WHICH_BITS(0),
	DEBUG_EVENT_WATCH_WRITE = EVENT_SUBSYS_BITS(EVENT_SUBSYS_DEBUG) | EVENT_WHICH_BITS(1)
};

#if HAVE_LIBEDIT
	#if DEBUG_TTY
		static EditLine *s_editline;
	#endif // DEBUG_TTY
	static History *s_history;
	static Tokenizer *s_token;
#endif // HAVE_LIBEDIT

// TODO: Use hcreate()
static struct debug_symbol *debug_syms = NULL;
static os_tnode_t *debug_addrs = NULL;

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

bool
debug_init(void)
{
	enum event_subsys dummy_subsys;
	(void)dummy_subsys; // Hint for makeheaders

	events_set_desc(DEBUG_EVENT_WATCH_READ, "%1$08x <- [0x%2$08x]");
	events_set_desc(DEBUG_EVENT_WATCH_WRITE, "[0x%08x] <- %08x");

#if HAVE_LIBEDIT
	s_history = history_init();
	if (!s_history)
	{
		os_runtime_error(OS_RUNERR_TYPE_WARNING, BIT(OS_RUNERR_RESP_OKAY), "Could not initialize history editing");
		return false;
	}
	HistEvent event;
	history(s_history, &event, H_SETSIZE, INT_MAX);

	s_token = tok_init(NULL);
	if (!s_token)
	{
		os_runtime_error(OS_RUNERR_TYPE_WARNING, BIT(OS_RUNERR_RESP_OKAY), "Could not initialize tokenizer");
		return false;
	}

	#if DEBUG_TTY
		s_editline = el_init("vvboy", stdin, stdout, stderr);
		if (!s_editline)
		{
			os_runtime_error(OS_RUNERR_TYPE_WARNING, BIT(OS_RUNERR_RESP_OKAY), "Could not initialize editline");
			return false;
		}
		el_set(s_editline, EL_PROMPT, debug_prompt);
		el_source(s_editline, NULL);
		el_set(s_editline, EL_HIST, history, s_history);
	#endif // DEBUG_TTY
#endif // HAVE_LIBEDIT

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
debug_clear_rom_syms(void)
{
	struct debug_symbol **prev_nextp = &debug_syms;
	while (*prev_nextp)
	{
		struct debug_symbol *debug_sym = *prev_nextp;
		if (!(*prev_nextp)->ds_is_system)
		{
			*prev_nextp = debug_sym->ds_next;
			debug_destroy_symbol(debug_sym);
		}
		else
			prev_nextp = &debug_sym->ds_next;
	}
}

void
debug_fini(void)
{
#if HAVE_LIBEDIT
		history_end(s_history);
	#if DEBUG_TTY
		el_end(s_editline);
	#endif // DEBUG_TTY
#endif // HAVE_LIBEDIT
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
	os_snprintf(s, debug_str_len, "0x%0*x", byte_size << 1, value);
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
debug_search_addr(os_tnode_t *root, u_int32_t addr, u_int32_t *match_offsetp, bool inexact)
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
			os_snprintf(human, sizeof(human), " <%s+%u>", sym->ds_name, offset);
		else
			os_snprintf(human, sizeof(human), " <%s>", sym->ds_name);
	}
	else
		*human = '\0';

	os_snprintf(s, debug_str_len, "0x%08x%s", addr, human);

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
	os_tnode_t *existing;
	existing = tfind(debug_sym, &debug_addrs, (int (*)(const void *, const void *))debug_symbol_cmpaddr);
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
		tsearch(debug_sym, &debug_addrs, (int (*)(const void *, const void *))debug_symbol_cmpaddr);
}

struct debug_symbol *
debug_create_symbol(const char *name, u_int32_t addr, bool is_system)
{
	struct debug_symbol *debug_sym = calloc(1, sizeof(*debug_sym));
	if (!debug_sym)
		main_fatal_error(OS_RUNERR_TYPE_OSERR, "Could not allocate debug symbol");
	debug_sym->ds_name = strdup(name);
	if (!debug_sym->ds_name)
		main_fatal_error(OS_RUNERR_TYPE_OSERR, "Could not copy symbol name");
	debug_sym->ds_addr = addr;
	debug_sym->ds_type = ISX_SYMBOL_POINTER;
	debug_sym->ds_is_system = is_system;
	debug_add_symbol(debug_sym);
	return debug_sym;
}

struct debug_symbol *
debug_create_symbolf(u_int32_t addr, bool is_system, const char *fmt, ...)
{
	char name[64 + 1];
	va_list ap;
	va_start(ap, fmt);
	os_vsnprintf(name, sizeof(name), fmt, ap);
	va_end(ap);
	return debug_create_symbol(name, addr, is_system);
}

void
debug_create_symbol_array(const char *base_name, u_int32_t start, u_int count, u_int32_t size, bool is_system)
{
	for (u_int i = 0; i < count; ++i)
	{
		debug_str_t name;
		os_snprintf(name, sizeof(name), "%s:%u", base_name, i);
		debug_create_symbol(name, start + size * i, is_system);
	}
}

void
debug_destroy_symbol(struct debug_symbol *debug_sym)
{
	if (debug_sym->ds_type == ISX_SYMBOL_POINTER)
		tdelete(debug_sym, &debug_addrs, (int (*)(const void *, const void *))debug_symbol_cmpaddr);

	if (debug_sym->ds_name)
		free(debug_sym->ds_name);
	free(debug_sym);
}

struct debug_disasm_context *
debug_current_context(void)
{
	static struct debug_disasm_context context;
	os_bcopy(cpu_state.cs_r, context.ddc_regs, sizeof(cpu_state.cs_r));
	context.ddc_regmask = DEBUG_REGMASK_ALL;
	return &context;
}

const union cpu_reg *
debug_get_reg(const struct debug_disasm_context *context, u_int rnum)
{
	static const union cpu_reg zero_reg = {.u = 0};
	static const union cpu_reg global_reg = {.u = 0x05008000};

	if (context && (context->ddc_regmask & (1 << rnum))) // TODO: BIT()
		return &(context->ddc_regs[rnum]);
	else if (rnum == 0)
		return &zero_reg;
	else if (rnum == 4)
		return &global_reg;
	else
		return NULL;
}

static char *
debug_disasm_fmtreg(debug_str_t reg_s, const char *fmt, struct debug_disasm_context *context, u_int rnum)
{
	const union cpu_reg *reg = debug_get_reg(context, rnum);
	if (reg)
		os_snprintf(reg_s, debug_str_len, fmt, reg->u);
	else
		os_snprintf(reg_s, debug_str_len, "%s", debug_rnames[rnum]);
	return reg_s;
}

static void
debug_put_reg(struct debug_disasm_context *context, u_int rnum, union cpu_reg reg)
{
	if (context && rnum != 0)
	{
		context->ddc_regs[rnum] = reg;
		context->ddc_regmask |= (1 << rnum); // TODO: BIT()
	}
}

static void
debug_clear_reg(struct debug_disasm_context *context, u_int rnum)
{
	if (context)
		context->ddc_regmask &= ~(1 << rnum); // TODO: BIT()
}

static void
debug_disasm_i(debug_str_t decode,
               debug_str_t decomp,
               const union cpu_inst *inst,
               const char *mnemonic,
			   const char *reg1_fmt,
			   const char *reg2_fmt,
               const char *decomp_fmt,
               struct debug_disasm_context *context)
{
	os_snprintf(decode, debug_str_len, "%s %s, %s",
				mnemonic, debug_rnames[inst->ci_i.i_reg1], debug_rnames[inst->ci_i.i_reg2]);

	debug_str_t reg1_s, reg2_s;
	debug_disasm_fmtreg(reg1_s, reg1_fmt, context, inst->ci_i.i_reg1);
	debug_disasm_fmtreg(reg2_s, reg2_fmt, context, inst->ci_i.i_reg2);
	os_snprintf(decomp, debug_str_len, decomp_fmt,
				debug_rnames[inst->ci_i.i_reg1],
				reg1_s,
				debug_rnames[inst->ci_i.i_reg2],
				reg2_s);
	debug_clear_reg(context, inst->ci_i.i_reg2);
}

static void
debug_disasm_ii(debug_str_t decode,
                debug_str_t decomp,
                const union cpu_inst *inst,
                const char *mnemonic,
                const char *imm5_fmt,
                const char *reg2_fmt,
                const char *decomp_fmt,
                struct debug_disasm_context *context)
{
	debug_str_t imm5_s;
	os_snprintf(imm5_s, debug_str_len, imm5_fmt, inst->ci_ii.ii_imm5, cpu_extend5to32(inst->ci_ii.ii_imm5));

	os_snprintf(decode, debug_str_len, "%s %s, %s", mnemonic, imm5_s, debug_rnames[inst->ci_ii.ii_reg2]);

	debug_str_t reg2_s;
	debug_disasm_fmtreg(reg2_s, reg2_fmt, context, inst->ci_ii.ii_reg2);
	os_snprintf(decomp, debug_str_len, decomp_fmt, debug_rnames[inst->ci_ii.ii_reg2], reg2_s, imm5_s);
}

static void
debug_disasm_v(debug_str_t decode,
               debug_str_t decomp,
               const union cpu_inst *inst,
               const char *mnemonic,
               const char *imm16_fmt,
               const char *reg1_fmt,
               const char *decomp_fmt,
               struct debug_disasm_context *context)
{
	debug_str_t imm16_s;
	u_int32_t imm32 = cpu_extend16(inst->ci_v.v_imm16);
	os_snprintf(imm16_s, debug_str_len, imm16_fmt, inst->ci_v.v_imm16, imm32);

	os_snprintf(decode, debug_str_len, "%s %s, %s, %s",
				mnemonic, imm16_s, debug_rnames[inst->ci_v.v_reg1], debug_rnames[inst->ci_v.v_reg2]);

	debug_str_t reg1_s;
	debug_disasm_fmtreg(reg1_s, reg1_fmt, context, inst->ci_v.v_reg1);

	os_snprintf(decomp, debug_str_len, decomp_fmt,
				debug_rnames[inst->ci_v.v_reg2],
				reg1_s,
				imm16_s,
				imm32);

	const union cpu_reg *reg1 = debug_get_reg(context, inst->ci_v.v_reg1);
	if (reg1)
	{
		switch (inst->ci_v.v_opcode)
		{
			enum cpu_opcode dummy_opcode;
			(void)dummy_opcode; // Hint for makeheaders

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
	else
		debug_clear_reg(context, inst->ci_v.v_reg2);
}

static void
debug_disasm_vi(debug_str_t decode,
                debug_str_t decomp,
                const union cpu_inst *inst,
                const char *mnemonic,
                struct debug_disasm_context *context)
{
	os_snprintf(decode, debug_str_len, "%s %hd[%s], %s",
				mnemonic, inst->ci_vi.vi_disp16, debug_rnames[inst->ci_vi.vi_reg1], debug_rnames[inst->ci_vi.vi_reg2]);

	debug_str_t addr_s;
	{
		const union cpu_reg *reg1;
		if ((reg1 = debug_get_reg(context, inst->ci_vi.vi_reg1)))
		{
			u_int32_t addr = reg1->u + inst->ci_vi.vi_disp16;
			debug_format_addr(addr, addr_s);
		}
		else
			os_snprintf(addr_s, debug_str_len, "%s%+hd", debug_rnames[inst->ci_vi.vi_reg1], inst->ci_vi.vi_disp16);
	}

	switch (inst->ci_vi.vi_opcode)
	{
		case OP_CAXI:
			os_snprintf(decomp, debug_str_len,
						"[%s] <- r30 if oldval = %s", addr_s, debug_rnames[inst->ci_vi.vi_reg2]);
			break;
		case OP_LD_B:
		case OP_LD_H:
		case OP_LD_W:
			os_snprintf(decomp, debug_str_len, "%s <- [%s]", debug_rnames[inst->ci_vi.vi_reg2], addr_s);
			debug_clear_reg(context, inst->ci_vi.vi_reg2);
			break;
		case OP_ST_B:
		{
			const union cpu_reg *reg2 = debug_get_reg(context, inst->ci_vi.vi_reg2);
			if (reg2)
				os_snprintf(decomp, debug_str_len, "[%s] <- 0x%02hhx", addr_s, reg2->u8s[0]);
			else
				os_snprintf(decomp, debug_str_len, "[%s] <- %s", addr_s, debug_rnames[inst->ci_vi.vi_reg2]);
			break;
		}
		case OP_ST_H:
		{
			const union cpu_reg *reg2 = debug_get_reg(context, inst->ci_vi.vi_reg2);
			if (reg2)
				os_snprintf(decomp, debug_str_len, "[%s] <- 0x%04hx", addr_s, reg2->s16);
			else
				os_snprintf(decomp, debug_str_len, "[%s] <- %s & 0xffff", addr_s, debug_rnames[inst->ci_vi.vi_reg2]);
			break;
		}
		case OP_ST_W:
		{
			const union cpu_reg *reg2 = debug_get_reg(context, inst->ci_vi.vi_reg2);
			if (reg2)
				os_snprintf(decomp, debug_str_len, "[%s] <- 0x%08x", addr_s, reg2->u);
			else
				os_snprintf(decomp, debug_str_len, "[%s] <- %s", addr_s, debug_rnames[inst->ci_vi.vi_reg2]);
			break;
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
	os_snprintf(decode, debug_str_len, "%s %hd[%s], %s",
				mnemonic, inst->ci_vi.vi_disp16, debug_rnames[inst->ci_vi.vi_reg1], debug_rnames[inst->ci_vi.vi_reg2]);
	if (context && context->ddc_regmask == DEBUG_REGMASK_ALL)
	{
		u_int32_t addr = context->ddc_regs[inst->ci_vi.vi_reg1].u + inst->ci_vi.vi_disp16;
		debug_str_t addr_s;
		debug_format_addr(addr, addr_s);
		os_snprintf(decomp, debug_str_len, decomp_fmt,
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
	enum float_subop dummy_subop;
	(void)dummy_subop; // Hint for makeheaders

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

	os_snprintf(decode, debug_str_len, fmt, mnemonic, debug_rnames[inst->vii_reg1], debug_rnames[inst->vii_reg2]);
	if (context && context->ddc_regmask == DEBUG_REGMASK_ALL)
		os_snprintf(decomp, debug_str_len, decomp_fmt,
					debug_rnames[inst->vii_reg1],
					context->ddc_regs[inst->vii_reg1].f,
					debug_rnames[inst->vii_reg2],
					context->ddc_regs[inst->vii_reg2].f);
	debug_clear_reg(context, inst->vii_reg2);
}

static const char *
debug_regid_str(enum cpu_regid regid)
{
	switch (regid)
	{
		case REGID_EIPC: return "EIPC";
		case REGID_EIPSW: return "EIPSW";
		case REGID_FEPC: return "FEPC";
		case REGID_FEPSW: return "FEPSW";
		case REGID_PSW: return "PSW";
		case REGID_CHCW: return "CHCW";
		default: return "???";
	}
}

static char *
debug_disasm_s(const union cpu_inst *inst, u_int32_t pc, struct debug_disasm_context *context, debug_str_t dis)
{
	enum cpu_bcond dummy_bcond;
	(void)dummy_bcond; // Hint for makeheaders

	debug_str_t decode, decomp = {0};
	const char *mnemonic = "???";
	switch (inst->ci_i.i_opcode)
	{
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
			os_snprintf(unknown, sizeof(unknown), "??? (%s)", debug_format_binary(inst->ci_i.i_opcode, 6, bin_s));
			mnemonic = unknown;
		}
	}
	switch (inst->ci_i.i_opcode)
	{
		case OP_MUL:
			os_snprintf(decode, debug_str_len, "%s %s, %s",
						mnemonic, debug_rnames[inst->ci_i.i_reg1], debug_rnames[inst->ci_i.i_reg2]);
			if (context && context->ddc_regmask == DEBUG_REGMASK_ALL)
				os_snprintf(decomp, debug_str_len, "%i × %i",
							context->ddc_regs[inst->ci_i.i_reg1].s, context->ddc_regs[inst->ci_i.i_reg2].s);
			debug_clear_reg(context, inst->ci_i.i_reg2);
			break;
		case OP_SUB:
			os_snprintf(decode, debug_str_len, "%s %s, %s",
						mnemonic, debug_rnames[inst->ci_i.i_reg1], debug_rnames[inst->ci_i.i_reg2]);
			if (context && context->ddc_regmask == DEBUG_REGMASK_ALL)
				// TODO: use positional parameters
				os_snprintf(decomp, debug_str_len, "%i - %i | 0x%08x - 0x%08x",
							context->ddc_regs[inst->ci_i.i_reg2].s, context->ddc_regs[inst->ci_i.i_reg1].s,
							context->ddc_regs[inst->ci_i.i_reg2].u, context->ddc_regs[inst->ci_i.i_reg1].u);
			debug_clear_reg(context, inst->ci_i.i_reg2);
			break;
		case OP_ADD:
			debug_disasm_i(decode, decomp, inst, "ADD", "%d (0x%1$08x)", "%d (0x%1$08x)", "%3$s <- %4$s + %2$s", context);
			break;
		case OP_CMP:
			debug_disasm_i(decode, decomp, inst, "CMP", "%d", "%d", "%4$s <=> %2$s", context);
			break;
		case OP_DIV:
			debug_disasm_i(decode, decomp, inst, "DIV", "%d", "%d", "%3$s <- %4$s / %2$s", context);
			break;
		case OP_XOR:
			debug_disasm_i(decode, decomp, inst, "XOR", "0x%08x", "0x%08x", "%3$s <- %4$s ^ %2$s", context);
			break;
		case OP_SHL:
			debug_disasm_i(decode, decomp, inst, "SHL", "0x%08x", "%u", "%3$s <- %4s << %2$s", context);
			break;
		case OP_SHR:
			debug_disasm_i(decode, decomp, inst, "SHR", "0x%08x", "%u", "%3$s <- %4$s >> %2$s", context);
			break;
		case OP_SAR:
			debug_disasm_i(decode, decomp, inst, "SAR", "0x%08x", "%u", "%3$s <- %4$s >>> %2$s", context);
			break;
		case OP_AND:
			debug_disasm_i(decode, decomp, inst, "AND", "0x%08x", "0x%08x", "%3$s <- %4$s & %2$s", context);
			break;
		case OP_OR:
			debug_disasm_i(decode, decomp, inst, "OR", "0x%08x", "0x%08x", "%3$s <- %4$s | %2$s", context);
			break;
		case OP_MOV:
		{
			debug_disasm_i(decode, decomp, inst, "MOV", "%d(%1$xh)", "", "%3$s <- %2$s", context);
			const union cpu_reg *reg1 = debug_get_reg(context, inst->ci_i.i_reg1);
			if (reg1)
				debug_put_reg(context, inst->ci_i.i_reg2, *reg1);
			break;
		}
		case OP_MULU:
			debug_disasm_i(decode, decomp, inst, "MULU", "%u", "%u", "%3$s <- %4$s × %2$s", context);
			break;
		case OP_DIVU:
			debug_disasm_i(decode, decomp, inst, "DIVU", "%u", "%u", "%3$s <- %4$s ÷ %2$s", context);
			break;
		case OP_NOT:
			debug_disasm_i(decode, decomp, inst, "NOT", "%u<0x%08x>", "", "%3$s <- ~%2$s", context);
			break;
		case OP_JMP:
			os_snprintf(decode, debug_str_len, "%s [%s]", mnemonic, debug_rnames[inst->ci_i.i_reg1]);
			const union cpu_reg *reg1 = debug_get_reg(context, inst->ci_i.i_reg1);
			if (reg1)
			{
				debug_str_t addr_s;
				os_snprintf(decomp, debug_str_len, "pc <- %s",
							debug_format_addr(reg1->u, addr_s));
			}
			break;
		case OP_ADD2:
			debug_disasm_ii(decode, decomp, inst, "ADD", "%2$i", "%i", "%1$s <- %2$s + %3$s", context);
			debug_clear_reg(context, inst->ci_ii.ii_reg2);
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
			debug_disasm_ii(decode, decomp, inst, "SETF", mnemonic, "?", "%1$s <- PSW:%2$s", context);
			debug_clear_reg(context, inst->ci_ii.ii_reg2);
			break;
		}
		case OP_MOV2:
		{
			debug_disasm_ii(decode, decomp, inst, "MOV", "%2$i(%2$xh)", "?", "%1$s <- %3$s", context);
			union cpu_reg imm;
			imm.u = cpu_extend5to32(inst->ci_ii.ii_imm5);
			debug_put_reg(context, inst->ci_ii.ii_reg2, imm);
			break;
		}
		case OP_CMP2:
		{
			u_int16_t imm = cpu_extend5to16(inst->ci_ii.ii_imm5);
			os_snprintf(decode, debug_str_len, "%s %hi, %s", mnemonic, imm, debug_rnames[inst->ci_ii.ii_reg2]);
			if (context && context->ddc_regmask == DEBUG_REGMASK_ALL)
				os_snprintf(decomp, debug_str_len, "%d <=> %hi", context->ddc_regs[inst->ci_ii.ii_reg2].s, imm);
			break;
		}
		case OP_TRAP:
			os_snprintf(decode, debug_str_len, "%s", "TRAP");
			break;
		case OP_RETI:
		{
			struct cpu_state dummy_state;
			(void)dummy_state; // Hint for makeheaders

			os_snprintf(decode, debug_str_len, "%s", "RETI");
			if (context && context->ddc_regmask == DEBUG_REGMASK_ALL)
				os_snprintf(decomp, debug_str_len, "pc <- 0x%08x, psw <- 0x%08x",
							// TODO: Probably shouldn't decode these here
							(cpu_state.cs_psw.psw_flags.f_np) ? cpu_state.cs_fepc : cpu_state.cs_eipc,
							(cpu_state.cs_psw.psw_flags.f_np) ? cpu_state.cs_fepsw.psw_word : cpu_state.cs_eipsw.psw_word);
			break;
		}
		case OP_HALT:
			os_snprintf(decode, debug_str_len, "%s", "HALT");
			break;
		case OP_CLI:
		case OP_SEI:
			os_snprintf(decode, debug_str_len, "%s", mnemonic);
			break;
		case OP_BSTR:
		{
			enum cpu_bstr dummy_bstr;
			(void)dummy_bstr; // Hint for makeheaders

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
			os_snprintf(decode, debug_str_len, "%s", mnemonic);
			if (context && context->ddc_regmask == DEBUG_REGMASK_ALL)
			{
				debug_str_t src_start_s, dest_start_s /*, src_end_s, dest_end_s*/;
				debug_format_addr(context->ddc_regs[30].u, src_start_s);
				debug_format_addr(context->ddc_regs[29].u, dest_start_s);
				u_int src_bit_off = context->ddc_regs[27].u & 31, dest_bit_off = context->ddc_regs[26].u & 31;
				os_snprintf(decomp, debug_str_len, "[%s.%u..] <- [%s.%u..] (%u bits)",
							src_start_s, src_bit_off, dest_start_s, dest_bit_off, context->ddc_regs[28].u);
			}
			debug_clear_reg(context, 30);
			debug_clear_reg(context, 29);
			debug_clear_reg(context, 28);
			debug_clear_reg(context, 27);
			debug_clear_reg(context, 26);
			break;
		}
		case OP_SHL2:
			debug_disasm_ii(decode, decomp, inst, "SHL", "%hu", "%08x", "%1$s <- %2$s << %3$s", context);
			debug_clear_reg(context, inst->ci_ii.ii_reg2);
			break;
		case OP_SHR2:
			debug_disasm_ii(decode, decomp, inst, "SHR", "%hu", "%08x", "%1$s <- %2$s >> %3$s", context);
			debug_clear_reg(context, inst->ci_ii.ii_reg2);
			break;
		case OP_SAR2:
			debug_disasm_ii(decode, decomp, inst, "SAR", "%hu", "%08x", "%1$s <- %2$s >>> %3$s", context);
			debug_clear_reg(context, inst->ci_ii.ii_reg2);
			break;
		case OP_LDSR:
		{
			char decomp_fmt[32];
			os_snprintf(decomp_fmt, sizeof(decomp_fmt), "%s <- %%2$s", debug_regid_str(inst->ci_ii.ii_imm5));
			debug_disasm_ii(decode, decomp, inst, "LDSR", "%hu", "0x%08x", decomp_fmt, context);
			break;
		}
		case OP_STSR:
			os_snprintf(decode, debug_str_len, "%s %i, %s",
						mnemonic, inst->ci_ii.ii_imm5, debug_rnames[inst->ci_ii.ii_reg2]);
			debug_clear_reg(context, inst->ci_ii.ii_reg2);
			break;
		case OP_JR:
		case OP_JAL:
		{
			u_int32_t disp = cpu_inst_disp26(inst);
			os_snprintf(decode, debug_str_len, "%s %i", mnemonic, disp);
			if (pc)
			{
				debug_str_t addr_s;
				os_snprintf(decomp, debug_str_len, "%s", debug_format_addr(pc + disp, addr_s));
			}
			break;
		}
		case OP_ORI:
			debug_disasm_v(decode, decomp, inst, "ORI", "0x%04hx", "0x%08x", "%s <- %s | %s", context);
			break;
		case OP_MOVEA:
			debug_disasm_v(decode, decomp, inst, "MOVEA", "%2$d", "0x%08x", "%s <- %s + 0x%4$08x", context);
			break;
		case OP_ANDI:
			debug_disasm_v(decode, decomp, inst, "ANDI", "0x%04hx", "0x%08x", "%s <- %s & %s", context);
			break;
		case OP_MOVHI:
			debug_disasm_v(decode, decomp, inst, "MOVHI", "0x%04hx", "0x%08x", "%s <- %s | %s0000", context);
			break;
		case OP_XORI:
			debug_disasm_v(decode, decomp, inst, "XORI", "0x%04hx", "0x%08x", "%s <- %s ^ %s", context);
			break;
		case OP_ADDI:
			debug_disasm_v(decode, decomp, inst, "ADDI", "%2$d", "0x%08x", "%s <- %s + %s", context);
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
					os_snprintf(decode, debug_str_len, "TODO: FLOAT %s", debug_format_binary(inst->vii_subop, 6, bin_s));
				}
			}
			break;
		}
		default:
			if (inst->ci_iii.iii_opcode == OP_BCOND)
			{
				u_int32_t disp = cpu_extend9(inst->ci_iii.iii_disp9);
				os_snprintf(decode, debug_str_len, "%s %i", mnemonic, disp);
				if (pc)
				{
					debug_str_t addr_s;
					os_snprintf(decomp, debug_str_len, "pc <- %s", debug_format_addr(pc + disp, addr_s));
				}
				break;
			}
			os_snprintf(decode, debug_str_len, "TODO: %s", mnemonic);
	}
	if (*decomp)
		os_snprintf(dis, debug_str_len, "%-20s; %s", decode, decomp);
	else
		os_snprintf(dis, debug_str_len, "%s", decode);
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
				{'h', "", "Stop execution (aliases: halt, stop)"},
				{'c', "", "Continue execution (aliases: cont)"},
				{'s', "", "Step into the next instruction (aliases: step)"},
				{'n', "", "Step over the next instruction, ignoring calls (aliases: next)"},
				{'b', "[<addr>]", "Set or remove breakpoint\n"
								  "\t\tOmit address to clear breakpoint"},
				{'f', "", "Finish executing the current function (aliases: finish)"},
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
	for (help_index = 0; help_index < COUNT_OF(debug_help); ++help_index)
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
debug_mem_read(u_int32_t addr, void *dest, u_int size)
{
	u_int mem_wait;
	if (mem_read(addr, dest, size, false, &mem_wait))
		return true;
	else
	{
		debug_printf("Could not read %u bytes from 0x%08x: Invalid address", size, addr);
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
	if (debug_mode == DEBUG_STOP)
	{
		debug_printf("debug_stop() called while debug_mode=STOPPED\n");
		return;
	}

	debug_mode = DEBUG_STOP;
	debug_show_console = true;
	imgui_shown = true;

	main_update_caption(NULL);
}

void
debug_continue(void)
{
	if (debug_mode != DEBUG_STOP)
	{
		debug_printf("debug_run() called while debug_mode=%u\n", debug_mode);
		return;
	}

	debug_mode = DEBUG_CONTINUE;

	main_update_caption(NULL);
}

bool
debug_is_stopped(void)
{
	return (debug_mode == DEBUG_STOP);
}

void
debug_toggle_stopped(void)
{
	if (debug_mode != DEBUG_STOP)
	{
		debug_printf("\nEmulation paused\n");
		debug_stop();
	}
	else
	{
		debug_printf("\nEmulation resumed\n");
		debug_continue();
	}
}

void
debug_step_into(void)
{
	assert(debug_mode == DEBUG_STOP);
	debug_mode = DEBUG_STEP;
}

void
debug_step_over(void)
{
	assert(debug_mode == DEBUG_STOP);
	union cpu_inst inst;
	if (cpu_fetch(cpu_state.cs_pc, &inst))
	{
		debug_next_pc = cpu_next_pc(inst);
		debug_continue();
	}
}

void
debug_next_frame(void)
{
	assert(debug_mode == DEBUG_STOP);
	debug_stepping_frame = true;
	debug_continue();
}

char *
debug_format_flags(debug_str_t s, ...)
{
	va_list ap;
	va_start(ap, s);
	const char *name;
	size_t len = 0;
	s[0] = '\0';
	while ((name = va_arg(ap, char *)))
	{
		u_int flag = va_arg(ap, u_int);
		if (flag)
			len+= os_snprintf(s + len, debug_str_len - len, "%s%s", (len > 0) ? "|" : "", name);
	}
	va_end(ap);
	return s;
}

const char *
debug_format_perms(int perms, debug_str_t s)
{
	enum os_perm dummy_perm;
	(void)dummy_perm; // Hint for makeheaders

	return debug_format_flags(s,
							  "NONE", (perms == 0),
							  "READ", (perms & OS_PERM_READ),
							  "WRITE", (perms & OS_PERM_WRITE),
							  "EXEC", (perms & OS_PERM_EXEC),
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
debug_show_trace(const struct debug_trace trace)
{
	debug_printf("%s tracing is %s\n", trace.dt_key, (*trace.dt_tracep) ? "on" : "off");
}

bool
debug_toggle_trace(const char *key)
{
	for (u_int i = 0; i < COUNT_OF(debug_traces); ++i)
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
	if (debug_find_watch(addr, OS_PERM_READ))
	{
		debug_str_t addr_s, mem_addr_s, hex_s;
		debug_tracef("watch", DEBUG_ADDR_FMT ": %s <- [" DEBUG_ADDR_FMT "]",
		             debug_format_addr(pc, addr_s),
		             debug_format_hex((u_int8_t *)&value, byte_size, hex_s),
		             debug_format_addr(addr, mem_addr_s));

		events_fire(DEBUG_EVENT_WATCH_READ, addr, (void *)(uintptr_t)value);
	}
}

void
debug_watch_write(u_int32_t pc, u_int32_t addr, u_int32_t value, u_int byte_size)
{
	if (debug_find_watch(addr, OS_PERM_WRITE))
	{
		debug_str_t addr_s, mem_addr_s, hex_s;
		debug_tracef("watch", DEBUG_ADDR_FMT ": [" DEBUG_ADDR_FMT "] <- %s",
		             debug_format_addr(pc, addr_s),
		             debug_format_addr(addr, mem_addr_s),
		             debug_format_hex((u_int8_t *)&value, byte_size, hex_s));

		events_fire(DEBUG_EVENT_WATCH_WRITE, addr, (void *)(uintptr_t)value);
	}
}

#if HAVE_LIBEDIT
static void __unused
debug_exec(const char *cmd)
{
	bool running = true;

	HistEvent hist_event;
	if (history(s_history, &hist_event, H_ENTER, cmd) == -1)
		os_runtime_error(OS_RUNERR_TYPE_WARNING, BIT(OS_RUNERR_RESP_OKAY), "Could not save editline history");

	int argc;
	const char **argv;
	tok_reset(s_token);
	if (tok_str(s_token, cmd, &argc, &argv) == 0 && argc > 0)
	{
		if (!strcmp(argv[0], "?") || !strcmp(argv[0], "help"))
		{
			debug_printf("Debugger commands:\n");
			for (u_int help_index = 0; help_index < COUNT_OF(debug_help); ++help_index)
				debug_print_help(&(debug_help[help_index]));
		}
		else if (!strcmp(argv[0], "q") || !strcmp(argv[0], "quit") || !strcmp(argv[0], "exit"))
		{
			main_quit();
			debug_mode = DEBUG_RUN;
			running = false;
		}
		else if (!strcmp(argv[0], "h") || !strcmp(argv[0], "halt") || !strcmp(argv[0], "stop"))
		{
			if (debug_mode == DEBUG_RUN)
				debug_mode = DEBUG_STOP;
			else
				debug_printf("Not running\n");
		}
		else if (!strcmp(argv[0], "c") || !strcmp(argv[0], "cont"))
		{
			if (debug_mode == DEBUG_STOP)
				debug_mode = DEBUG_CONTINUE;
			else
				debug_printf("Not stopped in debugger\n");
		}
		else if (!strcmp(argv[0], "s") || !strcmp(argv[0], "step"))
		{
			if (debug_mode == DEBUG_STOP)
				debug_step_into();
			else
				debug_printf("Not stopped in debugger\n");
		}
		else if (!strcmp(argv[0], "n") || !strcmp(argv[0], "next"))
		{
			if (debug_mode == DEBUG_STOP)
				debug_step_over();
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
		else if (!strcmp(argv[0], "f") || !strcmp(argv[0], "finish"))
		{
			if (debug_mode == DEBUG_STOP)
			{
				debug_next_pc = cpu_state.cs_r[31].u;
				debug_continue();
			}
			else
				debug_printf("Not stopped in debugger\n");
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

				u_int int_size = 4;
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
					else if (!strcmp(format, "a") || !strcmp(format, "addr"))
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
						vip_format_oam(oam_str, &oam);
						debug_printf("%s\n", oam_str);
						addr+= sizeof(oam);
					}
					else if (!strcmp(format, "B"))
					{
						struct vip_bgsc bgsc;
						if (!debug_mem_read(addr, &bgsc, sizeof(bgsc)))
							break;
						vip_print_bgsc(&bgsc);
						addr+= sizeof(bgsc);
					}
					else if (!strcmp(format, "W"))
					{
						struct vip_world_att att;
						if (!debug_mem_read(addr, &att, sizeof(att)))
							break;
						char buf[1024];
						vip_format_world_att(buf, sizeof(buf), &att);
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
			vip_print_regs();
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
					struct debug_symbol *sym = debug_create_symbol(argv[1], addr, false);
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
				if (!debug_watches)
					debug_printf("No watches set\n");
				else
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
					ops = OS_PERM_READ;
				else if (!strcmp(argv[1], "write"))
					ops = OS_PERM_WRITE;
				else if (!strcmp(argv[1], "all"))
					ops = OS_PERM_RDWR;
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
							main_fatal_error(OS_RUNERR_TYPE_OSERR, "Allocate debug watch");
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
				for (u_int i = 0; i < COUNT_OF(debug_traces); ++i)
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
#endif // HAVE_LIBEDIT

static void
debug_print_inst(void)
{
	union cpu_inst inst;
	if (cpu_fetch(cpu_state.cs_pc, &inst))
	{
		debug_str_t addr_s;
		debug_printf(DEBUG_ADDR_FMT ": %s\n",
					 debug_format_addr(cpu_state.cs_pc, addr_s),
					 debug_disasm(&inst, cpu_state.cs_pc, debug_current_context()));
	}
}

bool
debug_step(void)
{
	if (debug_mode == DEBUG_RUN)
	{
		if (debug_break != DEBUG_ADDR_NONE && cpu_state.cs_pc == debug_break)
		{
			debug_printf("\nStopped at breakpoint\n");
			debug_stop();
			return false;
		}
		else if (debug_next_pc != DEBUG_ADDR_NONE && cpu_state.cs_pc == debug_next_pc)
		{
			debug_print_inst();
			debug_stop();
			debug_next_pc = DEBUG_ADDR_NONE;
			return false;
		}
	}
	else if (debug_mode == DEBUG_CONTINUE)
	{
		debug_mode = DEBUG_RUN;
		return true;
	}
	else if (debug_mode == DEBUG_STEP)
	{
		debug_print_inst();
		debug_stop();
		return true;
	}
	else if (debug_mode == DEBUG_STOP)
		return false;

#if DEBUG_TTY
	main_unblock_sigint();

	while (debug_mode != DEBUG_RUN)
	{
		int length;
		const char *line = el_gets(s_editline, &length);
		if (line)
			debug_exec(line);
		else
		{
			debug_putchar('\n');
			main_quit();
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
			os_runtime_error(OS_RUNERR_TYPE_WARNING, BIT(OS_RUNERR_RESP_OKAY), "Console buffer overflow\n");
			return;
		}

		debug_console_begin = next_begin;
	}

	debug_console_buffer[debug_console_end] = ch;
	debug_console_end = next_end;
	debug_console_dirty = true;
}

void
debug_vprintf(const char *fmt, va_list ap)
{
	char msg[2048];
	size_t length = os_vsnprintf(msg, sizeof(msg), fmt, ap);
#if DEBUG_TTY
	fputs(msg, stderr);
#else
	os_debug_log(msg);
#endif // DEBUG_TTY
	for (size_t offset = 0; offset < length; ++offset)
		debug_putchar(msg[offset]);
}

void __printflike(1, 2)
debug_printf(const char *fmt, ...)
{
	va_list ap;
	va_start(ap, fmt);
	debug_vprintf(fmt, ap);
	va_end(ap);
}

// TODO: Rename emu_trace?
void __printflike(2, 3)
debug_tracef(const char *tag, const char *fmt, ...)
{
	va_list ap;
	va_start(ap, fmt);
	char trace[2048];
	size_t length = os_snprintf(trace, sizeof(trace), "@%07d [%s] ", emu_usec, tag);
	length+= os_vsnprintf(trace + length, sizeof(trace) - length, fmt, ap);
	va_end(ap);

	if (!debug_trace_file)
		debug_printf("%s\n", trace);
	else
	{
		fputs(trace, debug_trace_file);
		fputc('\n', debug_trace_file);
	}
}

bool
debug_runtime_error(bool allow_ignore, bool *always_ignore_flagp, const char *msg)
{
	if (always_ignore_flagp && *always_ignore_flagp)
		return true;

	debug_printf("%s\n", msg);

	if (debug_mode == DEBUG_STOP)
		return true;

	u_int resp_mask = BIT(OS_RUNERR_RESP_ABORT);
	if (rom_loaded)
		resp_mask |= BIT(OS_RUNERR_RESP_DEBUG);
	if (allow_ignore)
	{
		resp_mask |= BIT(OS_RUNERR_RESP_IGNORE);
		if (always_ignore_flagp)
			resp_mask |= BIT(OS_RUNERR_RESP_ALWAYS_IGNORE);
	}

	switch (os_runtime_error(OS_RUNERR_TYPE_EMULATION, resp_mask, msg))
	{
		case OS_RUNERR_RESP_OKAY:
		case OS_RUNERR_RESP_IGNORE:
			return true;

		case OS_RUNERR_RESP_ALWAYS_IGNORE:
			*always_ignore_flagp = true;
			return true;

		case OS_RUNERR_RESP_DEBUG:
			debug_stop();
			return false;

		case OS_RUNERR_RESP_ABORT:
			exit(1);
	}
	return false;
}

// TODO: Rename emu_runtime_errorf()?
bool __printflike(2, 3)
debug_runtime_errorf(bool *always_ignore_flagp, const char *fmt, ...)
{
	if (always_ignore_flagp && *always_ignore_flagp)
		return true;

	va_list ap;
	va_start(ap, fmt);
	char msg[1024];
	os_vsnprintf(msg, sizeof(msg), fmt, ap);
	va_end(ap);

	return debug_runtime_error(true, always_ignore_flagp, msg);
}

// TODO: Rename emu_fatal_errorf()?
bool __printflike(1, 2)
debug_fatal_errorf(const char *fmt, ...)
{
	va_list ap;
	va_start(ap, fmt);
	char msg[1024];
	os_vsnprintf(msg, sizeof(msg), fmt, ap);
	va_end(ap);

	return debug_runtime_error(false, NULL, msg);
}

void
debug_frame_begin(void)
{
	enum tk_scancode dummy_scancode; // Hint for makeheaders
	(void)dummy_scancode;

	// TODO: Visual Studio keyboard shortcuts
	if (debug_is_stopped())
	{
		if (igIsKeyPressed(TK_SCANCODE_F10, true))
			debug_step_over();
		else if (igIsKeyPressed(TK_SCANCODE_F11, true))
			debug_step_into();
	}
	if (igIsKeyPressed(TK_SCANCODE_F5, false))
		debug_toggle_stopped();
	if (debug_is_stopped() && igIsKeyPressed(TK_SCANCODE_F8, true))
		debug_next_frame();

	imgui_key_toggle(TK_SCANCODE_GRAVE, &debug_show_console, true);

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
					igPushStyleColor(ImGuiCol_Text, (struct ImVec4){0.5, 0.5, 1, 1});
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

	if ((igIsKeyDown(OS_SHORTCUT_LKEY) || igIsKeyDown(OS_SHORTCUT_RKEY)) && igIsKeyPressed(TK_SCANCODE_K, false))
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
				// TODO: Reimplement traps using events
				/*
				if (igBeginMenu("Trap", true))
				{
					igMenuItemPtr("VIP draw start", NULL, &vip_trap_draw_start, true);

					igEndMenu();
				}
				*/

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

			if (debug_mode == DEBUG_STOP)
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

		#if HAVE_LIBEDIT
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
		#endif // HAVE_LIBEDIT
		}
		igEnd();
	}

	if (clear_each_frame && debug_mode != DEBUG_STOP)
		debug_clear_console = true;
}

void
debug_emu_menu(void)
{
	if (igMenuItem("Step over", "F10", false, debug_is_stopped()))
		debug_step_over();
	if (igMenuItem("Step into", "F11", false, debug_is_stopped()))
		debug_step_into();

	igSeparator();

	for (u_int i = 0; i < COUNT_OF(debug_traces); ++i)
		igMenuItemPtr(debug_traces[i].dt_label, NULL, debug_traces[i].dt_tracep, true);

	igEndMenu();
}
