#include <err.h>
#include <stdlib.h>
#include <strings.h>
#include "vvbdis.h"

static struct func
{
	struct debug_symbol *f_debug_sym;
	u_int f_call_count;
	struct func *f_next;
} *funcs = NULL;

static void
create_func(const char *basename, u_int32_t func_addr, u_int *func_sym_indexp)
{
	struct func **prevp = &funcs;
	struct func *func;

	for (func = *prevp; func; func = func->f_next)
	{
		if (func->f_debug_sym->ds_addr == func_addr)
			break;
		prevp = &(func->f_next);
	}

	if (!func)
	{
		func = malloc(sizeof(*func));
		if (!func)
			err(1, "Allocate function");
		func->f_call_count = 0;
		*prevp = func;

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
		func->f_debug_sym = sym;
		func->f_next = NULL;
	}

	++func->f_call_count;
}

int
main(int ac, char * const *av)
{
	if (ac != 2)
	{
		fprintf(stderr, "usage: %s <file.vb> | <file.isx>\n", av[0]);
		return 64; // EX_USAGE
	}

	if (!rom_load(av[1]))
		return 1;

	u_int32_t begin = MEM_SEG2ADDR((enum mem_segment)MEM_SEG_ROM);
	u_int32_t end = begin + mem_segs[MEM_SEG_ROM].ms_size;
	fprintf(stderr, "Scanning for functions...\n");
	u_int32_t pc = begin;
	static u_int func_sym_index = 0;
	static u_int entry_sym_index = 0;
	union cpu_inst prev_inst1, prev_inst2;
	bzero(&prev_inst1, sizeof(prev_inst1));
	bzero(&prev_inst2, sizeof(prev_inst2));
	while (pc < end)
	{
		union cpu_inst inst;
		if (!cpu_fetch(pc, &inst))
			err(1, "Could not fetch instruction");

		switch ((enum cpu_opcode)inst.ci_i.i_opcode)
		{
			default:
				break;
			case OP_JAL:
			{
				u_int32_t disp = cpu_inst_disp26(&inst);
				u_int32_t func_addr = pc + disp;
				create_func("func", func_addr, &func_sym_index);
				break;
			}
			case OP_JMP:
			{
				if (prev_inst2.ci_v.v_opcode == OP_MOVHI && prev_inst2.ci_v.v_reg1 == 0)
				{
					u_int reg2 = prev_inst2.ci_v.v_reg2;
					if (prev_inst1.ci_v.v_opcode == OP_MOVEA && prev_inst1.ci_v.v_reg1 == reg2)
					{
						if (inst.ci_i.i_reg1 == prev_inst2.ci_v.v_reg2)
						{
							u_int32_t high = prev_inst2.ci_v.v_imm16 << 16;
							int32_t imm = cpu_extend16(prev_inst1.ci_v.v_imm16);
							u_int32_t func_addr = high + imm;
							create_func("entry", func_addr, &entry_sym_index);
							break;
						}
					}
				}
			}
		}

		prev_inst2 = prev_inst1;
		prev_inst1 = inst;
		pc+= cpu_inst_size(&inst);
	}

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
				printf(";;;;;;;;;;;;;;;;;;;;;;\n");
				printf(";; %-16s ;;\n", sym->ds_name);
				printf(";;;;;;;;;;;;;;;;;;;;;;\n");
				if (func)
					printf(";; Called from %u unique address%s\n",
					       func->f_call_count, (func->f_call_count == 1) ? "" : "es");
			}
		}
		debug_str_t addr_s;
		printf("%-26s:", debug_format_addr(pc, addr_s));
		debug_disasm_at(&pc);
	}

	while (funcs)
	{
		struct func *func = funcs;
		funcs = func->f_next;
		free(func);
	}

	rom_unload();

	return 0;
}
