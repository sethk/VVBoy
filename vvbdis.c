#include "vvbdis.h"

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

	u_int32_t pc = MEM_SEG2ADDR((enum mem_segment)MEM_SEG_ROM);
	u_int32_t end = pc + mem_segs[MEM_SEG_ROM].ms_size;
	while (pc < end)
	{
		printf("%08x:", pc);
		debug_disasm_at(&pc);
	}

	rom_unload();
	return 0;
}
