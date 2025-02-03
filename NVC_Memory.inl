#pragma once

#include "NVC.hh"
#include "Memory.hh"

extern bool debug_trace_nvc_tim;
extern void debug_stop(void);
extern bool __printflike(2, 3) debug_runtime_errorf(bool *always_ignore_flagp, const char *fmt, ...);

template<bool CheckedMem>
bool
nvc_mem_prepare(struct Memory::Request<CheckedMem> &request)
{
	if constexpr (CheckedMem)
	{
		if (request.mr_size != 1)
		{
			static bool ignore_size = false;
			if (!debug_runtime_errorf(&ignore_size, "Invalid NVC access size %u @ 0x%08x",
									  request.mr_size, request.mr_emu))
				return false;
		}
	}
	request.mr_size = 1;

	if (request.mr_emu <= 0x02000028)
	{
		if constexpr (CheckedMem)
		{
			switch (request.mr_emu)
			{
				case 0x02000024:
				case 0x02000028:
				case 0x0200001c:
				case 0x02000018:
				case 0x02000014:
				case 0x02000010:
				case 0x02000008:
				case 0x02000004:
				case 0x02000000:
					request.mr_perms = os_perm_mask::READ | os_perm_mask::WRITE;
					break;
				case 0x02000020:
					request.mr_perms = os_perm_mask::READ | os_perm_mask::WRITE;
					break;
				default:
					request.mr_perms = os_perm_mask::NONE;
			}
		}
		request.mr_host = (u_int8_t *) &nvc_regs + ((request.mr_emu & 0x3f) >> 2);
	}
	else
	{
		debug_runtime_errorf(NULL, "NVC bus error at 0x%08x", request.mr_emu);
		debug_stop();
		return false;
	}

	return true;
}

template<bool CheckedMem>
void
nvc_mem_write(const Memory::Request<CheckedMem> &request, const void *src)
{
	switch (request.mr_emu)
	{
		case 0x02000020:
		{
			const struct nvc_regs::nvc_tcr *new_tcr = (struct nvc_regs::nvc_tcr *)src;

			nvc_regs.nr_tcr.t_z_int = new_tcr->t_z_int;

			if (nvc_regs.nr_tcr.t_clk_sel != new_tcr->t_clk_sel)
			{
				if (nvc_regs.nr_tcr.t_enb)
				{
					static bool ignore_sel = false;
					debug_runtime_errorf(&ignore_sel, "T-Clk-Sel changed while timer enabled");
				}
				nvc_regs.nr_tcr.t_clk_sel = new_tcr->t_clk_sel;
			}

			if (!nvc_regs.nr_tcr.t_enb && new_tcr->t_enb)
			{
				nvc_regs.nr_tcr.t_enb = 1;
				nvc_timer_set(nvc_timer.nt_preset);

				if (debug_trace_nvc_tim)
					nvc_trace_timer("Timer enabled");
			}
			else if (nvc_regs.nr_tcr.t_enb && !new_tcr->t_enb)
			{
				nvc_regs.nr_tcr.t_enb = 0;

				if (debug_trace_nvc_tim)
					nvc_trace_timer("Timer disabled");
			}

			if (nvc_regs.nr_tcr.t_z_stat && new_tcr->t_z_stat_clr)
			{
				nvc_regs.nr_tcr.t_z_stat = 0;
				if (debug_trace_nvc_tim)
					nvc_trace_timer("Cleared timer zero status");
			}
			break;
		}
		case 0x0200001c:
			nvc_timer.nt_preset = (nvc_timer.nt_preset & 0xff) | *(u_int8_t *)src << 8;
			if (debug_trace_nvc_tim)
				nvc_trace_timer("Set timer high");
			break;
		case 0x02000018:
			nvc_timer.nt_preset = (nvc_timer.nt_preset & 0xff00) | *(u_int8_t *)src;
			if (debug_trace_nvc_tim)
				nvc_trace_timer("Set timer low");
			break;

		default:
			*(u_int8_t *)request.mr_host = *(u_int8_t *)src;
	}
}
