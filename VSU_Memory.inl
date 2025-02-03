#pragma once

#include "VSU.hh"
#include "Memory.hh"

#include <cassert>

extern vsu_ram vsu_ram;
extern vsu_regs vsu_regs;

extern bool debug_runtime_error(bool allow_ignore, bool *always_ignore_flagp, const char *msg);
extern bool __printflike(2, 3) debug_runtime_errorf(bool *always_ignore_flagp, const char *fmt, ...);
extern bool __printflike(1, 2) debug_fatal_errorf(const char *fmt, ...);

extern void vsu_sound_start(u_int sound);
extern void vsu_sound_stop(u_int sound);

template<bool CheckedMem>
bool
vsu_mem_prepare(Memory::Request<CheckedMem> &request)
{
	if constexpr (CheckedMem)
	{
		if (request.mr_size != 1)
		{
			static bool ignore_size = false;
			if (!debug_runtime_errorf(&ignore_size, "Invalid VSU access size %u @ 0x%08x\n",
									  request.mr_size, request.mr_emu))
				return false;
		}
	}
	request.mr_size = 1;

	// TODO: More granularity on perms
	if (request.mr_emu < 0x01000400)
	{
		if (request.mr_emu >= 0x01000300)
		{
			u_int32_t mirror = request.mr_emu & 0x010003ff;

			//if constexpr (CheckedMem)
			{
				static bool always_ignore = false;
				if (!debug_runtime_errorf(&always_ignore, "Mirroring VSU RAM at 0x%08x -> 0x%x", request.mr_emu, mirror))
					return false;
			}

			request.mr_emu = mirror;
		}

		request.mr_host = (u_int8_t *)&vsu_ram + ((request.mr_emu >> 2) & 0xff);

		if constexpr (CheckedMem)
			request.mr_perms = os_perm_mask::RDWR;
	}
	else if (request.mr_emu < 0x01000600)
	{
		request.mr_host = (u_int8_t *)&vsu_regs + ((request.mr_emu >> 2) & 0x7f);

		if constexpr (CheckedMem)
			request.mr_perms = os_perm_mask::RDWR;
	}
	else
		return false;

	return true;
}

template<bool CheckedMem>
void
vsu_mem_write(const Memory::Request<CheckedMem> &request, const void *src)
{
	u_int8_t value = *(u_int8_t *)src;
	*(u_int8_t *)request.mr_host = value;
	if ((request.mr_emu & 0b10000111111) == 0b10000000000)
	{
		u_int sound = (request.mr_emu >> 6) & 0b111;
		if (sound == 6)
		{
			// SSTOP
			if (value & 1)
			{
				for (u_int i = 0; i < 6; ++i)
					vsu_sound_stop(i);
			}
		}
		else
		{
			assert(sound < 6);
			// SxINT
			if (value & 0x80)
				vsu_sound_start(sound);
			else
				vsu_sound_stop(sound);
		}
	}
}
