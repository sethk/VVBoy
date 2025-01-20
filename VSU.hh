#pragma once

#include "Types.hh"

struct vsu_ram
{
	u_int8_t vr_waves[5][32];
	u_int8_t vr_snd5mod[32];
	u_int8_t vr_rfu[64];
};

struct vsu_regs
{
	//_Alignas(4)?
	struct vsu_sound_regs
	{
		struct
		{
			u_int8_t vi_data : 5;
			u_int8_t vi_mode : 1;
			u_int8_t vi_rfu1 : 1;
			u_int8_t vi_start : 1;
		} vsr_int;				// 00
		struct
		{
			u_int8_t vl_rlevel : 4;
			u_int8_t vl_llevel : 4;
		} vsr_lrv;				// 04
		u_int8_t vsr_fql;		// 08
		struct
		{
			u_int8_t vf_fqh : 3;
			u_int8_t vf_rfu1 : 5;
		} vsr_fqh;				// 0C
		struct
		{
			u_int8_t ve_step : 3;
			u_int8_t ve_ud : 1;
			u_int8_t ve_init : 4;
		} vsr_ev0;				// 10
		struct
		{
			u_int8_t ve_on : 1;
			u_int8_t ve_rs : 1;
			u_int8_t ve_rfu1 : 2;
			u_int8_t ve_modswp : 1;
			u_int8_t ve_short : 1;
			u_int8_t ve_ed : 1;
			u_int8_t ve_rfu2 : 1;
		} vsr_ev1;				// 14
		union
		{
			struct
			{
				u_int8_t vr_addr : 4;
				u_int8_t vr_rfu1 : 4;
			} vsr_ram;
		};						// 18
		struct
		{
			u_int8_t vs_shifts : 3;
			u_int8_t vs_ud : 1;
			u_int8_t vs_time : 3;
			u_int8_t vs_clk : 1;
		} vsr_swp;				// 1C
		u_int32_t vs_rfu[2];	// 20
	} vr_sounds[6];
	struct
	{
		u_int8_t vs_stop : 1;
		u_int8_t vs_rfu1 : 7;
	} vr_stop;					// 180
	u_int8_t vr_rfu1[7];
	u_int32_t vr_rfu2[6];
};
