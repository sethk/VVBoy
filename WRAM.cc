#include "Types.hh"
#include "OS.hh"
#include "Memory.hh"
#include "ROM.hh"
#include "WRAM.Gen.hh"

#define WRAM_SIZE 0x1000000

bool
wram_init(void)
{
	return mem.Segments[Memory::SEG_WRAM].Allocate(WRAM_SIZE, os_perm_mask::READ | os_perm_mask::WRITE);
}

void
wram_init_debug()
{
	debug_create_symbol("GLOBAL", 0x05000000, true);
	debug_create_symbol("STACK", 0x0500dfff, true);
}

void
wram_fini(void)
{
	mem.Segments[Memory::SEG_WRAM].Free();
}
