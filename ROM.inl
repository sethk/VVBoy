#include "ROM.hh"
#include "Memory.hh"

typedef char debug_str_t[96];
extern const char * debug_format_addr(u_int32_t addr, debug_str_t s);
bool __printflike(2, 3) debug_runtime_errorf(bool *always_ignore_flagp, const char *fmt, ...);
# define DEBUG_ADDR_FMT "%-26s"

template<bool CheckedMem>
union cpu_inst *
rom_get_inst_ptr(u_int32_t pc)
{
	if constexpr (CheckedMem)
	{
		if (MEM_ADDR2SEG(pc) != Memory::SEG_ROM)
		{
			debug_str_t addr_s;
			if (!debug_runtime_errorf(NULL, "Tried to read instruction from non-ROM addr " DEBUG_ADDR_FMT,
						debug_format_addr(pc, addr_s)))
				return nullptr;
		}
	}

	u_int32_t offset = pc & mem.Segments[Memory::SEG_ROM].GetAddrMask();
	return reinterpret_cast<union cpu_inst *>(mem.Segments[Memory::SEG_ROM].GetData() + offset);
}
