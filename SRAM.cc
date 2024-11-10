#include "Memory.hh"
#include "SRAM.Gen.hh"

bool
sram_init(void)
{
	os_perm_mask dummy_perm;
	(void)dummy_perm;

	// TODO: load save file
	return mem.Segments[Memory::SEG_SRAM].Allocate(8 << 10, os_perm_mask::READ | os_perm_mask::WRITE);
}

bool
sram_mem_prepare(Memory::Request *request)
{
	u_int32_t offset = MEM_ADDR2OFF(request->mr_emu);
	u_int32_t extent = offset + request->mr_size;

	if (extent > mem.Segments[Memory::SEG_SRAM].GetSize())
	{
		if (!mem.Segments[Memory::SEG_SRAM].Reallocate(Memory::SizeCeil(extent)))
			return false;
	}

	request->mr_host = mem.Segments[Memory::SEG_SRAM].GetData() + offset;
	request->mr_perms = os_perm_mask::RDWR;
	request->mr_wait = 2;
	return true;
}

void
sram_fini(void)
{
	mem.Segments[Memory::SEG_SRAM].Free();
	// TODO: write save file
}
