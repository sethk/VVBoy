#pragma once

#include "NVC.hh"
#include "CPU.inl"

template<bool CheckedMem>
bool
nvc_step(void)
{
	if (nvc_regs.nr_tcr.t_enb && emu_usec == nvc_timer.nt_next_tick)
	{
		nvc_regs.nr_tlr = nvc_timer.nt_next_count & 0xff;
		nvc_regs.nr_thr = nvc_timer.nt_next_count >> 8;

		if (nvc_timer.nt_next_count > 0)
			nvc_timer_set(nvc_timer.nt_next_count - 1);
		else
		{
			nvc_regs.nr_tcr.t_z_stat = 1;
			nvc_timer_set(nvc_timer.nt_preset);

			if (debug_trace_nvc_tim)
				nvc_trace_timer("Timer expired");
			if (nvc_regs.nr_tcr.t_z_int)
				cpu_intr(NVC_INTTIM);

			events_fire(NVC_EVENT_TIMER_EXPIRED, 0, 0);
		}
	}

	for (u_int x = 0; x < nvc_cycles_per_usec; ++x)
		if (!cpu_step<CheckedMem>())
			return false;

	return true;
}
