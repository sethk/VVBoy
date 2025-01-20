#pragma once

//#include "Memory.hh"
#include "Emu.hh"

template<bool CheckedMem>
bool
sram_mem_prepare(Memory::Request<CheckedMem> *request)
{
	u_int32_t offset = MEM_ADDR2OFF(request->mr_emu);
	u_int32_t extent = offset + request->mr_size;

	if (extent > mem.Segments[Memory::SEG_SRAM].GetSize())
	{
		if (!mem.Segments[Memory::SEG_SRAM].Reallocate(Memory::SizeCeil(extent)))
			return false;
	}

	request->mr_host = mem.Segments[Memory::SEG_SRAM].GetData() + offset;

	if constexpr (CheckedMem)
		request->mr_perms = os_perm_mask::RDWR;

	return true;
}
