#include "Types.hh"
#include "Emu.hh"
#include "OS.hh"
#include "ROM.hh"
#include "Memory.hh"
#include "CPU.hh"
#include "CPU.inl"
#include "VVBDis.Gen.hh"
#include <cstdlib>
#ifdef __APPLE__
# include <unistd.h> // getopt()
#endif // __APPLE__
#include <cassert>
#include <new>

struct func
{
	func(debug_symbol *debug_sym) : f_debug_sym(debug_sym)
	{
		assert(debug_sym);
	}

	const struct debug_symbol *f_debug_sym;
	struct func_caller
	{
		func_caller(u_int32_t addr) : fc_addr(addr) { }

		u_int32_t fc_addr;
		struct func_caller *fc_next = nullptr;
	} *f_callers = nullptr;
	u_int f_call_count = 0;
	struct func *f_next = nullptr;
};
static func *funcs = nullptr;

static int verbose = 0;
static const u_int32_t rom_addr = MEM_SEG2ADDR(Memory::SEG_ROM);
static u_int32_t rom_end;
static u_int32_t text_begin = MEM_SEG2ADDR(Memory::SEG_ROM), text_end;
static const u_int32_t vect_begin = 0xfffffe00, vect_end = 0xfffffffe;

void
main_fatal_error(os_runerr_type type, const char *fmt, ...)
{
	(void)type;
	va_list ap;
	va_start(ap, fmt);
	fputs("\n*** ", stderr);
	vfprintf(stderr, fmt, ap);
	va_end(ap);
	exit(1);
}

static bool
func_addr_valid(u_int32_t func_addr)
{
	if ((func_addr & 1) != 0)
		return false;
	if (func_addr >= rom_addr && func_addr <= rom_end)
		return true;
	else if (func_addr >= text_begin && func_addr <= text_end)
		return true;
	return false;
}

static void
upsert_func(const char *basename, u_int32_t func_addr, u_int *func_sym_indexp, u_int32_t caller_addr)
{
	if (verbose >= 2)
		fprintf(stderr, "Upsert func 0x%08x basename %s, caller 0x%08x\n", func_addr, basename, caller_addr);

	if (!func_addr_valid(func_addr))
	{
		if (verbose >= 1)
			fprintf(stderr, "Not adding invalid JMP target 0x%08x\n", func_addr);
		return;
	}

	struct func **prevp = &funcs;
	struct func *func = NULL, *next_func;

	for (next_func = *prevp; next_func; next_func = next_func->f_next)
	{
		if (next_func->f_debug_sym->ds_addr > func_addr)
			break;
		else if (next_func->f_debug_sym->ds_addr == func_addr)
		{
			// Match found
			func = next_func;
			break;
		}
		prevp = &(next_func->f_next);
	}

	if (!func)
	{
		u_int32_t offset;
		struct debug_symbol *sym = debug_resolve_addr(func_addr, &offset);
		if (!sym || offset > 0)
		{
			char func_name[32];
			do
			{
				snprintf(func_name, sizeof(func_name), "%s%u", basename, *func_sym_indexp);
				++(*func_sym_indexp);
			} while (debug_locate_symbol(func_name) != DEBUG_ADDR_NONE);
			sym = debug_create_symbol(func_name, func_addr, false);
			rom_add_symbol(sym);
		}

		func = new struct func(sym);
		func->f_next = next_func;
		*prevp = func;
	}

	func::func_caller **prev_callerp;
	for (prev_callerp = &(func->f_callers); *prev_callerp; prev_callerp = &((*prev_callerp)->fc_next))
		;

	func::func_caller *caller = new func::func_caller(caller_addr);
	*prev_callerp = caller;

	if (verbose >= 2)
		fprintf(stderr, "Added caller 0x%08x to function %s at 0x%08x\n",
				caller->fc_addr, func->f_debug_sym->ds_name, func->f_debug_sym->ds_addr);

	++func->f_call_count;
}

static void
create_entry_func(u_int32_t entry_addr)
{
	u_int32_t offset;
	struct debug_symbol *entry_sym = debug_resolve_addr(entry_addr, &offset);
	assert(entry_sym);
	assert(offset == 0);
	struct func *entry_func = new func(entry_sym);
	struct func **prevp;
	for (prevp = &(funcs); *prevp; prevp = &((*prevp)->f_next))
		;
	*prevp = entry_func;
	entry_func->f_next = NULL;
}

static void
show_func(const struct debug_symbol *sym, const struct func *func)
{
	puts("\n;;;;;;;;;;;;;;;;;;;;;;");
	printf(";; %-16s ;;\n", sym->ds_name);
	puts(";;;;;;;;;;;;;;;;;;;;;;");
	if (func)
	{
		printf(";; Called from %u unique address%s\n",
		       func->f_call_count, (func->f_call_count == 1) ? "" : "es");
		for (func::func_caller *caller = func->f_callers; caller; caller = caller->fc_next)
		{
			debug_str_t addr_s;
			printf(";;\t%s\n", debug_format_addr(caller->fc_addr, addr_s));
		}
		puts(";;");
	}
}

static void
show_call_graph(const struct func *func)
{
	for (func::func_caller *caller = func->f_callers; caller; caller = caller->fc_next)
	{
		u_int32_t offset;
		struct debug_symbol *caller_sym = debug_resolve_addr(caller->fc_addr, &offset);
		if (!caller_sym)
		{
			debug_str_t addr_s;
			fprintf(stderr, "Could not resolve caller address %s\n", debug_format_addr(caller->fc_addr, addr_s));
			continue;
		}

		struct func *caller_func;
		for (caller_func = funcs; caller_func; caller_func = caller_func->f_next)
			if (caller_func->f_debug_sym == caller_sym)
				break;

		if (!caller_func)
		{
			fprintf(stderr, "Could not find caller func for symbol %s\n", caller_sym->ds_name);
			continue;
		}

		printf("\t\"%s\" -> \"%s\";\n", caller_sym->ds_name, func->f_debug_sym->ds_name);
	}
}

static void
fetch_inst(union cpu_inst *inst, u_int32_t pc)
{
	if (!cpu_fetch<true>(pc, inst))
		main_fatal_error(OS_RUNERR_TYPE_EMULATION, "Could not fetch instruction at 0x%08x", pc);
}

static bool
inst_is_branch(const union cpu_inst *inst, u_int32_t pc, struct func *next_func, const struct debug_disasm_context *context, u_int32_t *targetp)
{
	if (inst->ci_iii.iii_opcode == OP_BCOND)
	{
		u_int32_t disp = cpu_extend9(inst->ci_iii.iii_disp9);
		*targetp = pc + disp;
		return true;
	}
	else if (inst->ci_i.i_opcode == OP_JMP && inst->ci_i.i_reg1 != 31)
	{
		if (pc >= vect_begin) // Always assume longjump from vector addresses
			return false;

		const union cpu_reg *jmp_reg;
		if ((jmp_reg = debug_get_reg(context, inst->ci_i.i_reg1)))
		{
			*targetp = jmp_reg->u;

			if (next_func && *targetp >= next_func->f_debug_sym->ds_addr)
				return false;

			return true;
		}
	}
	else if (inst->ci_i.i_opcode == OP_JR)
	{
		u_int32_t disp = cpu_inst_disp26(inst);
		*targetp = pc + disp;
		return true;
	}

	return false;
}

static void
incr_pc(u_int32_t *pcp, union cpu_inst *inst)
{
	size_t inst_size = cpu_inst_size(inst);
	if (inst_size > 0xffffffff - *pcp)
	{
		*pcp = 0xffffffff;
		return;
	}
	*pcp+= inst_size;
}

static void
show_disasm(union cpu_inst *inst, u_int32_t pc, struct debug_disasm_context *context)
{
	debug_str_t addr_s;
	printf(DEBUG_ADDR_FMT ":", debug_format_addr((pc), addr_s));
	printf(" %s\n", debug_disasm(inst, pc, context));
}

static void
scan_area(const u_int32_t begin, const u_int32_t end)
{
	u_int32_t pc = begin;
	static u_int func_sym_index = 0;
	static u_int entry_sym_index = 0;
	struct debug_disasm_context context;
	os_bzero(&context, sizeof(context));
	while (pc < end)
	{
		union cpu_inst inst;
		fetch_inst(&inst, pc);
		debug_disasm(&inst, pc, &context);

#if 0
		u_int32_t caller_addr;
		if (pc >= end - 0x1ff)
		{
			// Adjust PC for interrupt vectors
			caller_addr = 0xfffffffe - (end - pc);
		}
		else
			caller_addr = pc;
#endif // 0

		switch (static_cast<cpu_opcode>(inst.ci_i.i_opcode))
		{
			default:
				break;
			//case OP_JR:
			case OP_JAL:
			{
				u_int32_t disp = cpu_inst_disp26(&inst);
				u_int32_t func_addr = pc + disp;
				upsert_func("func", func_addr, &func_sym_index, /*caller_addr*/pc);
				break;
			}
			case OP_JMP:
			{
				const union cpu_reg *jmp_reg;

				if (verbose >= 2)
					fprintf(stderr, "Found JMP at 0x%08x: %s\n", /*caller_addr*/pc, debug_disasm(&inst, /*caller_addr*/pc, NULL));
				if (inst.ci_i.i_reg1 == 31)
				{
					if (verbose >= 2)
						fputs("JMP [lp] is return, skipping\n", stderr);
				}
				else if (pc >= vect_begin)
				{
					if ((jmp_reg = debug_get_reg(&context, inst.ci_i.i_reg1)))
					{
						upsert_func("entry", jmp_reg->u, &entry_sym_index, /*caller_addr*/pc);
						os_bzero(&context, sizeof(context));
					}
					else if (verbose >= 1)
						fprintf(stderr, "Can't read %s for JMP target, skipping\n", debug_rnames[inst.ci_i.i_reg1]);
				}
				break;
			}
		}

		incr_pc(&pc, &inst);
	}
}

static void
disasm_area(u_int32_t begin, u_int32_t end)
{
	struct debug_symbol *sym = NULL;
	struct debug_disasm_context context;
	os_bzero(&context, sizeof(context));
	u_int32_t pc = begin;
	while (pc < end)
	{
		u_int32_t offset;
		struct debug_symbol *next_sym = debug_resolve_addr(pc, &offset);
		if (next_sym != sym)
		{
			sym = next_sym;

			if (offset == 2)
			{
				printf(";; Realigning by -2 bytes\n");
				pc-= 2;
				offset = 0;
			}

			if (offset == 0)
			{
				struct func *func;
				for (func = funcs; func; func = func->f_next)
				{
					if (func->f_debug_sym == sym)
						break;
				}
				show_func(sym, func);
				os_bzero(&context, sizeof(context));
			}
		}
		union cpu_inst inst;
		fetch_inst(&inst, pc);
		show_disasm(&inst, pc, &context);
		incr_pc(&pc, &inst);
	}
}

static void
disasm_func(struct func *func)
{
	struct func *next_func = func->f_next;
	show_func(func->f_debug_sym, func);

	u_int32_t pc = func->f_debug_sym->ds_addr;
	u_int32_t end = ((CPU_MAX_PC - pc) >= 16384UL) ? pc + 16384UL : CPU_MAX_PC; // Maximum function length

	u_int32_t last_branch = 0;
	struct debug_disasm_context context;
	os_bzero(&context, sizeof(context));
	while (pc < end)
	{
		union cpu_inst inst;
		fetch_inst(&inst, pc);

		if (inst.ci_hwords[0] == 0xffff && inst.ci_hwords[1] == 0xffff)
		{
			printf(";; Stopping at improbable instruction 0xffff 0xffff\n");
			break;
		}

		show_disasm(&inst, pc, &context);

		if (verbose)
			fflush(stdout);

		u_int32_t target;
		if (inst_is_branch(&inst, pc, next_func, &context, &target))
		{
			if (verbose >= 2)
				fprintf(stderr, "Branch target at 0x%08x: 0x%08x\n", pc, target);

			if (target > last_branch)
			{
				if (verbose)
					fprintf(stderr, "Moving last branch to 0x%08x\n", target);
				last_branch = target;
			}
		}
		else if ((inst.ci_i.i_opcode == OP_JMP ||
				  inst.ci_i.i_opcode == OP_RETI ||
				  inst.ci_i.i_opcode == OP_TRAP) &&
				pc >= last_branch)
			break;

		incr_pc(&pc, &inst);

		u_int32_t offset;
		if ((next_func && pc == next_func->f_debug_sym->ds_addr) ||
				(debug_resolve_addr(pc, &offset) != func->f_debug_sym))
		{
			printf(";; Warning: Hit end of %s without seeing last JR/JMP/RETI/TRAP\n",
					func->f_debug_sym->ds_name);
			printf(";; last_branch = 0x%08x\n", last_branch);
			break;
		}
	}
}

bool main_fixed_rate = false; // TODO: Remove

void
main_update_caption(const char *stats)
{
	(void)stats;
}

// TODO: Remove
void
main_quit(void)
{
}

// TODO: Remove
void
main_open_rom(void)
{
}

// TODO: Remove
void
main_close_rom(void)
{
}

static void
usage(void)
{
	fprintf(stderr, "usage: %s [-asv] [-b <base-addr>] <file.vb> | <file.isx>\n", os_getprogname());
	fprintf(stderr, "\t-a\t\tDisassemble all sections, not just called functions\n");
	fputs("\t-b <base-addr>\tSet the base load address\n", stderr);
	fputs("\t-d <name>\tDisassemble only the named function (entire text is still scanned for cross-reference)\n", stderr);
	fputs("\t-s\t\tShow all symbols\n", stderr);
	fputs("\t-v\t\tIncrease verbosity level\n", stderr);
	exit(64); // EX_USAGE
}

int
main(int ac, char * const *av)
{
	extern int optind;
	bool show_syms = false;
	bool show_graph = false;
	bool funcs_only = true;
	debug_trace_file = stderr;
	const char *disasm_name = NULL;
	int status = 0;

	int ch;
	while ((ch = getopt(ac, av, "ab:d:gsv")) != -1)
		switch (ch)
		{
			default:
				usage();

			case 'a':
				funcs_only = false;
				break;

			case 'b':
			{
				char *endp;
				text_begin = strtoul(optarg, &endp, 0);
				if (*endp != '\0')
				{
					fprintf(stderr, "Can't parse base address %s\n", optarg);
					usage();
				}
				break;
			}

			case 'd':
				disasm_name = optarg;
				break;

			case 'g':
				show_graph = true;
				break;

			case 's':
				show_syms = true;
				break;

			case 'v':
				++verbose;
				break;
		}
	ac-= optind;
	av+= optind;

	if (ac != 1)
		usage();

	emu_init_debug();

	if (!rom_load(av[0]))
		return 1;

	rom_end = min_uint(rom_addr + mem.Segments[Memory::SEG_ROM].GetSize() - 2, CPU_MAX_PC);
	assert(rom_end > rom_addr);

	text_end = debug_locate_symbol("text");
	if (text_end == DEBUG_ADDR_NONE)
	{
		text_end = min_uint(text_begin + mem.Segments[Memory::SEG_ROM].GetSize() - 2, CPU_MAX_PC);
		if (verbose > 0)
			fprintf(stderr, "No text symbol found, using 0x%08x\n", text_end);
	}
	assert(text_end > text_begin);

	if (verbose > 0)
		fprintf(stderr, "rom_addr: 0x%08x, rom_end: 0x%08x, text_begin: 0x%08x, text_end: 0x%08x\n",
				rom_addr, rom_end, text_begin, text_end);

	create_entry_func(0xfffffe00);
	create_entry_func(0xfffffe10);
	create_entry_func(0xfffffe20);
	create_entry_func(0xfffffe30);
	create_entry_func(0xfffffe40);
	create_entry_func(0xffffff60);
	create_entry_func(0xffffff80);
	create_entry_func(0xffffff90);
	create_entry_func(0xffffffa0);
	create_entry_func(0xffffffb0);
	create_entry_func(0xffffffc0);
	create_entry_func(0xffffffd0);
	create_entry_func(0xfffffff0);

	scan_area(text_begin, text_end);
	scan_area(vect_begin, vect_end);

	if (show_syms)
	{
		puts("Symbols:");
		for (const struct debug_symbol *sym = debug_get_symbols(); sym; sym = sym->ds_next)
		{
			debug_str_t sym_s;
			printf("\t%s\n", debug_format_symbol(sym, sym_s));
		}
	}

	if (show_graph)
	{
		puts("digraph calls {");
		puts("\trankdir=LR;");
		for (struct func *func = funcs; func; func = func->f_next)
			show_call_graph(func);
		puts("}");
	}
	else if (disasm_name)
	{
		struct func *func = NULL;
		for (func = funcs; func; func = func->f_next)
		{
			fprintf(stderr, "func %s\n", func->f_debug_sym->ds_name);
			if (!strcmp(disasm_name, func->f_debug_sym->ds_name))
				break;
		}

		if (func)
			disasm_func(func);
		else
		{
			fprintf(stderr, "No function named %s found to disassemble\n", disasm_name);
			status = 1;
		}
	}
	else if (funcs_only)
	{
		for (struct func *func = funcs; func; func = func->f_next)
			disasm_func(func);
	}
	else
	{
		disasm_area(text_begin, text_end);
		disasm_area(vect_begin, vect_end);
	}

	rom_unload();

	return status;
}
