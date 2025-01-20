#include "VIP.hh"

#include <cassert>

extern struct vip_vrm vip_vrm;
extern struct vip_dram vip_dram;
extern struct vip_regs vip_regs;
typedef char debug_str_t[96];
extern const char *debug_format_addr(u_int32_t addr, debug_str_t s);

template<bool CheckedMem>
bool
vip_mem_prepare(Memory::Request<CheckedMem> *request)
{
	if ((request->mr_ops & os_perm_mask::READ) != os_perm_mask::NONE)
		request->mr_wait = 8;
	else
		request->mr_wait = 4;

	static bool ignore_mirror = false;
	if (request->mr_emu & 0xfff80000)
	{
		u_int32_t mirror = request->mr_emu & 0x7ffff;
		if (!debug_runtime_errorf(&ignore_mirror, "Mirroring VIP address 0x%08x -> 0x%08x\n", request->mr_emu, mirror))
			return false;

		request->mr_emu = mirror;
	}

	if (request->mr_emu < 0x20000)
		request->mr_host = (u_int8_t *)&vip_vrm + request->mr_emu;
	else if (request->mr_emu < 0x40000)
		request->mr_host = (u_int8_t *)&vip_dram + (request->mr_emu & 0x1ffff);
	else if (request->mr_emu < 0x5f800)
	{
		static bool ignore_junk = false;
		if (!debug_runtime_errorf(&ignore_junk, "Accessing VIP junk memory at 0x%08x", request->mr_emu))
			return false;
		assert(request->mr_size <= 4);
		static u_int32_t junk;
		request->mr_host = &junk;
	}
	else if (request->mr_emu < 0x60000)
	{
		if constexpr (CheckedMem)
		{
			if (request->mr_size & 1)
			{
				static bool always_ignore = false;
				if (!debug_runtime_errorf(&always_ignore, "Invalid VIP access size %u", request->mr_size))
					return false;
			}
			if (request->mr_emu & 1)
			{
				static bool always_ignore = false;
				if (!debug_runtime_errorf(&always_ignore, "VIP address alignment error at 0x%08x", request->mr_emu))
					return false;
			}

			u_int reg_num = (request->mr_emu & 0x7f) >> 1;

			if constexpr (CheckedMem)
			{
				switch (reg_num)
				{
					case 0x00:
					case 0x10:
					case 0x18:
					case 0x20:
						request->mr_perms = os_perm_mask::READ;
						break;
					case 0x02:
					case 0x11:
					case 0x12:
					case 0x13:
					case 0x14:
					case 0x15:
					case 0x17:
					case 0x21:
						request->mr_perms = os_perm_mask::WRITE;
						break;
				}

				u_int16_t *regp = (u_int16_t *)&vip_regs + reg_num;
				assert(regp == (u_int16_t *)((u_int8_t *)&vip_regs + (request->mr_emu & 0x7e)));
			}
		}

		request->mr_host = (u_int8_t *)&vip_regs + (request->mr_emu & 0x7e);
	}
	else if (request->mr_emu >= 0x78000 && request->mr_emu < 0x7a000)
		request->mr_host = (u_int8_t *)&(vip_vrm.vv_chr0) + (request->mr_emu - 0x78000);
	else if (request->mr_emu >= 0x7a000 && request->mr_emu < 0x7c000)
		request->mr_host = (u_int8_t *)&(vip_vrm.vv_chr1) + (request->mr_emu - 0x7a000);
	else if (request->mr_emu >= 0x7c000 && request->mr_emu < 0x7e000)
		request->mr_host = (u_int8_t *)&(vip_vrm.vv_chr2) + (request->mr_emu - 0x7c000);
	else if (request->mr_emu >= 0x7e000 && request->mr_emu < 0x80000)
		request->mr_host = (u_int8_t *)&(vip_vrm.vv_chr3) + (request->mr_emu - 0x7e000);
	else
		return false;

	return true;
}
