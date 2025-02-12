#pragma once

#include "Types.hh"

enum isx_symbol_type : u_int8_t
{
	ISX_SYMBOL_CONST = 0,
	ISX_SYMBOL_POINTER = 16,
	ISX_SYMBOL_END = 214,
	ISX_SYMBOL_INVALID = 255
};

template<bool CheckedMem> union cpu_inst *rom_get_inst_ptr(u_int32_t pc);
