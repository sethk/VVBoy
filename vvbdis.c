#include <err.h>
#include <stdlib.h>
#include <strings.h>
#include <unistd.h>
#include <assert.h>
#include "vvbdis.h"

static struct func
{
	const struct debug_symbol *f_debug_sym;
	struct func_caller
	{
		u_int32_t fc_addr;
		struct func_caller *fc_next;
	} *f_callers;
	u_int f_call_count;
	struct func *f_next;
} *funcs = NULL;

static int verbose = 0;

static struct func *
create_func(const struct debug_symbol *sym)
{
	struct func *func = malloc(sizeof(*func));
	if (!func)
		err(1, "Allocate function");
	func->f_callers = NULL;
	func->f_call_count = 0;
	func->f_debug_sym = sym;
	return func;
}

static void
upsert_func(const char *basename, u_int32_t func_addr, u_int *func_sym_indexp, u_int32_t caller_addr)
{
	if (func_addr < 0x07000000 || func_addr >= 0x07000000 + mem_segs[MEM_SEG_ROM].ms_size)
	{
		if (verbose >= 1)
			fprintf(stderr, "Not adding JMP target outside of ROM at 0x%08x\n", func_addr);
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
			} while (debug_locate_symbol(func_name) != 0xffffffff);
			sym = debug_create_symbol(func_name, func_addr);
			rom_add_symbol(sym);
		}

		func = create_func(sym);
		func->f_next = next_func;
		*prevp = func;
	}

	struct func_caller **prev_callerp;
	for (prev_callerp = &(func->f_callers); *prev_callerp; prev_callerp = &((*prev_callerp)->fc_next))
		;
	struct func_caller *caller = malloc(sizeof(*caller));
	if (!caller)
		err(1, "Allocate function caller");
	caller->fc_addr = caller_addr;
	caller->fc_next = NULL;
	*prev_callerp = caller;

	++func->f_call_count;
}

static void
create_entry_func(u_int32_t entry_addr)
{
	u_int32_t rom_addr = 0x07000000 + (entry_addr & mem_segs[MEM_SEG_ROM].ms_addrmask);
	u_int32_t offset;
	struct debug_symbol *entry_sym = debug_resolve_addr(rom_addr, &offset);
	assert(entry_sym);
	assert(offset == 0);
	struct func *entry_func = create_func(entry_sym);
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
		for (struct func_caller *caller = func->f_callers; caller; caller = caller->fc_next)
		{
			debug_str_t addr_s;
			printf(";;\t%s\n", debug_format_addr(caller->fc_addr, addr_s));
		}
		puts(";;");
	}
}

static void
fetch_inst(union cpu_inst *inst, u_int32_t pc)
{
	if (!cpu_fetch(pc, inst))
		errx(1, "Could not fetch instruction");
}

static void
show_disasm(union cpu_inst *inst, u_int32_t pc)
{
	debug_str_t addr_s;
	printf("%-26s:", debug_format_addr((pc), addr_s));
	printf(" %s\n", debug_disasm(inst, pc, NULL));
}

static void
usage(void)
{
	fprintf(stderr, "usage: %s [-av] <file.vb> | <file.isx>\n", getprogname());
	fprintf(stderr, "\t-a\tDisassemble all sections, not just called functions\n");
	fprintf(stderr, "\t-a\tIncrease verbosity level\n");
	exit(64); // EX_USAGE
}

int
main(int ac, char * const *av)
{
	bool funcs_only = true;

	int ch;
	while ((ch = getopt(ac, av, "av")) != -1)
		switch (ch)
		{
			default:
				usage();

			case 'a':
				funcs_only = false;
				break;

			case 'v':
				++verbose;
				break;
		}
	ac-= optind;
	av+= optind;

	if (ac != 1)
		usage();

	if (!rom_load(av[0]))
		return 1;

	create_entry_func(0xfffffe00);
	create_entry_func(0xfffffe10);
	create_entry_func(0xfffffe20);
	create_entry_func(0xfffffe30);
	create_entry_func(0xfffffe40);
	create_entry_func(0xfffffff0);

	u_int32_t begin = MEM_SEG2ADDR((enum mem_segment)MEM_SEG_ROM);
	u_int32_t end = begin + mem_segs[MEM_SEG_ROM].ms_size;
	u_int32_t pc = begin;
	static u_int func_sym_index = 0;
	static u_int entry_sym_index = 0;
	union cpu_inst prev_inst1, prev_inst2;
	bzero(&prev_inst1, sizeof(prev_inst1));
	bzero(&prev_inst2, sizeof(prev_inst2));
	while (pc < end)
	{
		union cpu_inst inst;
		fetch_inst(&inst, pc);

		switch ((enum cpu_opcode)inst.ci_i.i_opcode)
		{
			default:
				break;
			case OP_JR:
			case OP_JAL:
			{
				u_int32_t disp = cpu_inst_disp26(&inst);
				u_int32_t func_addr = pc + disp;
				upsert_func("func", func_addr, &func_sym_index, pc);
				break;
			}
			case OP_JMP:
			{
				if (verbose >= 2)
					fprintf(stderr, "Found JMP at 0x%08x: %s\n", pc, debug_disasm(&inst, pc, NULL));
				if (inst.ci_v.v_reg1 == 31)
				{
					if (verbose >= 2)
						fputs("JMP [lp] is return, skipping\n", stderr);
				}
				else if (prev_inst2.ci_v.v_opcode == OP_MOVHI && prev_inst2.ci_v.v_reg1 == 0)
				{
					u_int reg2 = prev_inst2.ci_v.v_reg2;
					if (prev_inst1.ci_v.v_opcode == OP_MOVEA && prev_inst1.ci_v.v_reg1 == reg2)
					{
						if (inst.ci_i.i_reg1 == prev_inst2.ci_v.v_reg2)
						{
							u_int32_t high = prev_inst2.ci_v.v_imm16 << 16;
							int32_t imm = cpu_extend16(prev_inst1.ci_v.v_imm16);
							u_int32_t func_addr = high + imm;
							upsert_func("entry", func_addr, &entry_sym_index, pc);
							break;
						}
					}
					else if (verbose >= 1)
					{
						fputs("JMP not preceded by MOVEA\n", stderr);
						fprintf(stderr, "prev_inst1: %s\n", debug_disasm(&prev_inst1, 0x0, NULL));
					}
				}
				else if (verbose >= 1)
				{
					fputs("JMP not preceded by MOVHI, skipping\n", stderr);
					fprintf(stderr, "prev_inst2: %s\n", debug_disasm(&prev_inst2, 0x0, NULL));
				}
			}
		}

		prev_inst2 = prev_inst1;
		prev_inst1 = inst;
		pc+= cpu_inst_size(&inst);
	}

	if (funcs_only)
	{
		struct func *next_func;
		for (struct func *func = funcs; func; func = next_func)
		{
			next_func = func->f_next;
			show_func(func->f_debug_sym, func);

			pc = func->f_debug_sym->ds_addr;
			u_int32_t last_branch = 0;
			while (pc < end)
			{
				union cpu_inst inst;
				fetch_inst(&inst, pc);
				show_disasm(&inst, pc);

				if (inst.ci_i.i_opcode == OP_BCOND)
				{
					u_int32_t disp = cpu_extend9(inst.ci_iii.iii_disp9);
					u_int32_t target = pc + disp;
					if (target > last_branch)
						last_branch = target;
				}
				else if ((inst.ci_i.i_opcode == OP_JR ||
						  inst.ci_i.i_opcode == OP_JMP ||
						  inst.ci_i.i_opcode == OP_RETI ||
				          inst.ci_i.i_opcode == OP_TRAP) &&
						pc >= last_branch)
					break;

				pc+= cpu_inst_size(&inst);

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
	}
	else
	{
		struct debug_symbol *sym = NULL;
		pc = begin;
		while (pc < end)
		{
			u_int32_t offset;
			struct debug_symbol *next_sym = debug_resolve_addr(pc, &offset);
			if (next_sym != sym)
			{
				sym = next_sym;
				if (offset == 0)
				{
					struct func *func;
					for (func = funcs; func; func = func->f_next)
					{
						if (func->f_debug_sym == sym)
							break;
					}
					show_func(sym, func);
				}
			}
			union cpu_inst inst;
			fetch_inst(&inst, pc);
			show_disasm(&inst, pc);
			pc+= cpu_inst_size(&inst);
		}
	}

	while (funcs)
	{
		struct func *func = funcs;
		struct func_caller *callers = func->f_callers;
		while (callers)
		{
			struct func_caller *caller = callers;
			callers = caller->fc_next;
			free(caller);
		}
		funcs = func->f_next;
		free(func);
	}

	rom_unload();

	return 0;
}
