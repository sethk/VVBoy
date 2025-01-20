#pragma once

#include "Types.hh"

struct emu_stats_t
{
	u_int64_t ms_start_usec;
	u_int ms_frames;
	u_int ms_scans;
	u_int ms_insts;
	u_int ms_intrs;
};

extern u_int32_t emu_usec;
extern struct emu_stats_t emu_stats;
