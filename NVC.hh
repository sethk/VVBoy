#pragma once

#include "Types.hh"
#include "Events.hh"

//_Alignas(4)
struct nvc_regs
{
	u_int8_t nr_ccr;
	u_int8_t nr_ccsr;
	u_int8_t nr_cdtr;
	u_int8_t nr_cdrr;
	u_int8_t nr_sdlr;
	u_int8_t nr_sdhr;
	u_int8_t nr_tlr;
	u_int8_t nr_thr;
	struct nvc_tcr
	{
		u_int8_t t_enb : 1,
				 t_z_stat : 1,
				 t_z_stat_clr : 1,
				 t_z_int : 1,
				 t_clk_sel : 1;
	} nr_tcr;
	u_int8_t nr_wcr;
	struct
	{
		u_int8_t s_abt_dis : 1,
				 s_si_stat : 1,
				 s_hw_si : 1,
				 s_rfu1 : 1,
				 s_soft_ck : 1,
				 s_para_si : 1,
				 s_rfu2 : 1,
				 s_k_int_inh : 1;
	} nr_scr;
	//u_int8_t nr_padding[50];
};

extern struct nvc_regs nvc_regs;

enum nvc_intlevel
{
	NVC_INTKEY = 0,
	NVC_INTTIM = 1,
	NVC_INTCRO = 2,
	NVC_INTCOM = 3,
	NVC_INTVIP = 4,
	NVC_NUM_INTLEVEL
};

extern u_int nvc_cycles_per_usec;

struct nvc_timer
{
	u_int16_t nt_preset;
	u_int16_t nt_next_count;
	u_int nt_next_tick;
	u_int nt_tick_frac;
};

extern struct nvc_timer nvc_timer;
extern void nvc_timer_set(u_int16_t next_count);
extern void nvc_trace_timer(const char *desc);

enum nvc_event
{
	NVC_EVENT_TIMER_SET = EVENT_SUBSYS_BITS(EVENT_SUBSYS_NVC) | EVENT_WHICH_BITS(0),
	NVC_EVENT_TIMER_EXPIRED = EVENT_SUBSYS_BITS(EVENT_SUBSYS_NVC) | EVENT_WHICH_BITS(1),
	NVC_EVENT_KEY_DOWN = EVENT_SUBSYS_BITS(EVENT_SUBSYS_NVC) | EVENT_WHICH_BITS(2),
	NVC_EVENT_KEY_UP = EVENT_SUBSYS_BITS(EVENT_SUBSYS_NVC) | EVENT_WHICH_BITS(3)
};

