#include "types.h"
#include "nvc.h"

#if INTERFACE
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
	};

	enum nvc_intlevel
	{
		NVC_INTKEY = 0,
		NVC_INTTIM = 1,
		NVC_INTCRO = 2,
		NVC_INTCOM = 3,
		NVC_INTVIP = 4,
		NVC_NUM_INTLEVEL
	};
#endif // INTERFACE

enum nvc_key
{
	// TODO: BIT()
	KEY_PWR = (1 << 0),
	KEY_SGN = (1 << 1),
	KEY_A = (1 << 2),
	KEY_B = (1 << 3),
	KEY_RT = (1 << 4),
	KEY_LT = (1 << 5),
	KEY_RU = (1 << 6),
	KEY_RR = (1 << 7),
	KEY_LR = (1 << 8),
	KEY_LL = (1 << 9),
	KEY_LD = (1 << 10),
	KEY_LU = (1 << 11),
	KEY_STA = (1 << 12),
	KEY_SEL = (1 << 13),
	KEY_RL = (1 << 14),
	KEY_RD = (1 << 15)
};

struct nvc_regs nvc_regs;

static struct
{
	u_int16_t nt_preset;
	u_int16_t nt_next_count;
	u_int nt_next_tick;
	u_int nt_tick_frac;
} nvc_timer;
u_int nvc_cycles_per_usec = 20;
static u_int16_t nvc_keys;
const char * const nvc_intnames[(enum nvc_intlevel)NVC_NUM_INTLEVEL] =
		{
				[NVC_INTKEY] = "KEY",
				[NVC_INTTIM] = "TIM",
				[NVC_INTCRO] = "CRO",
				[NVC_INTCOM] = "COM",
				[NVC_INTVIP] = "VIP",
		};

enum nvc_event
{
	NVC_EVENT_TIMER_SET = EVENT_SUBSYS_BITS(EVENT_SUBSYS_NVC) | EVENT_WHICH_BITS(0),
	NVC_EVENT_TIMER_EXPIRED = EVENT_SUBSYS_BITS(EVENT_SUBSYS_NVC) | EVENT_WHICH_BITS(1),
	NVC_EVENT_KEY_DOWN = EVENT_SUBSYS_BITS(EVENT_SUBSYS_NVC) | EVENT_WHICH_BITS(2),
	NVC_EVENT_KEY_UP = EVENT_SUBSYS_BITS(EVENT_SUBSYS_NVC) | EVENT_WHICH_BITS(3)
};

bool
nvc_init(void)
{
	enum event_subsys dummy_subsys;
	(void)dummy_subsys; // Hint for makeheaders

	debug_create_symbol("SCR", 0x02000028, true);
	debug_create_symbol("WCR", 0x02000024, true);
	debug_create_symbol("TCR", 0x02000020, true);
	debug_create_symbol("THR", 0x0200001c, true);
	debug_create_symbol("TLR", 0x02000018, true);
	debug_create_symbol("SDHR", 0x02000014, true);
	debug_create_symbol("SDLR", 0x02000010, true);
	debug_create_symbol("CDRR", 0x0200000c, true);
	debug_create_symbol("CDTR", 0x02000008, true);
	debug_create_symbol("CCSR", 0x02000004, true);
	debug_create_symbol("CCR", 0x02000000, true);

	debug_create_symbol("vect.key", 0xfffffe00, true);
	debug_create_symbol("vect.tim", 0xfffffe10, true);
	debug_create_symbol("vect.cro", 0xfffffe20, true);
	debug_create_symbol("vect.com", 0xfffffe30, true);
	debug_create_symbol("vect.vip", 0xfffffe40, true);

	events_set_desc(NVC_EVENT_TIMER_SET, "Timer set");
	events_set_desc(NVC_EVENT_TIMER_EXPIRED, "Timer expired");
	events_set_desc(NVC_EVENT_KEY_DOWN, "Key 0x%x down");
	events_set_desc(NVC_EVENT_KEY_UP, "Key 0x%x up");
	return cpu_init();
}

void
nvc_fini(void)
{
	cpu_fini();
}

void
nvc_reset(void)
{
	nvc_regs.nr_scr.s_para_si = 0;
	nvc_regs.nr_scr.s_hw_si = 1;
	nvc_regs.nr_scr.s_rfu1 = 1;
	nvc_regs.nr_scr.s_rfu2 = 1;
	nvc_keys = KEY_SGN;
	nvc_regs.nr_tlr = nvc_regs.nr_thr = 0xff;
	nvc_timer.nt_preset = 0xffff;
	// TODO: Initialize other NVC interval registers
	cpu_reset();
}

void
nvc_test(void)
{
	debug_printf("Running NVC self-test\n");

	ASSERT_SIZEOF(nvc_regs, 11);
	mem_test_addr("nvc_sdlr", 0x02000010, 1, &(nvc_regs.nr_sdlr));
	mem_test_addr("nvc_sdhr", 0x02000014, 1, &(nvc_regs.nr_sdhr));
	mem_test_addr("nvc_tcr", 0x02000020, 1, &(nvc_regs.nr_tcr));
}

void
nvc_frame_begin(void)
{
#if 0
	if (igBeginMainMenuBar())
	{
		if (igBeginMenu("NVC", true))
		{
			igBeginChild("Clock", (struct ImVec2){300, 30}, false, 0);
			{
				igSliderInt("CPU cycles per µsec", (int *)&nvc_cycles_per_usec, 5, 30, NULL);
				igEndChild();
			}

			if (igBeginChild("Timer", (struct ImVec2){300, 30}, false, 0))
			{
				static int value = 0;
				igInputInt("Timer value", &value, 1, 100, 0);
				igSameLine(0, -1);
				if (igButton("Load", IMVEC2_ZERO))
				{
					nvc_regs.nr_tlr = value & 0xff;
					nvc_regs.nr_thr = value >> 8;
				}

			}
			igEndChild();

			igEndMenu();
		}

		igEndMainMenuBar();
	}
#endif // 0
}

static void
nvc_timer_set(u_int16_t next_count)
{
	u_int tick_usec;
	if (nvc_regs.nr_tcr.t_clk_sel)
	{
		tick_usec = 305;
		nvc_timer.nt_tick_frac+= 175781250;
	}
	else
	{
		tick_usec = 1525;
		nvc_timer.nt_tick_frac+= 878906250;
	}
	if (nvc_timer.nt_tick_frac > 1000000000)
	{
		++tick_usec;
		nvc_timer.nt_tick_frac -= 1000000000;
	}
	nvc_timer.nt_next_tick = (main_usec + tick_usec) % 1000000;
	nvc_timer.nt_next_count = next_count;
}

static char *
nvc_format_timer(debug_str_t s)
{
	debug_str_t tcr_s;
	os_snprintf(s, debug_str_len,
				"TCR = %s, THR:TLR = %02hhx:%02hhx, preset = 0x%04x, next count = 0x%04x, next tick = %u",
				debug_format_flags(tcr_s,
								   "T-Enb", nvc_regs.nr_tcr.t_enb,
								   "Z-Stat", nvc_regs.nr_tcr.t_z_stat,
								   "Z-Stat-Clr", nvc_regs.nr_tcr.t_z_stat_clr,
								   "Tim-Z-Int", nvc_regs.nr_tcr.t_z_int,
								   "T-Clk-Sel", nvc_regs.nr_tcr.t_clk_sel,
								   NULL),
				nvc_regs.nr_thr, nvc_regs.nr_tlr,
				nvc_timer.nt_preset,
				nvc_timer.nt_next_count,
				nvc_timer.nt_next_tick);
	return s;
}

static void
nvc_trace_timer(const char *desc)
{
	debug_str_t timer_s;
	debug_tracef("nvc.tim", "%s - %s", desc, nvc_format_timer(timer_s));
}

bool
nvc_step(void)
{
	if (nvc_regs.nr_tcr.t_enb && main_usec == nvc_timer.nt_next_tick)
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
		if (!cpu_step())
			return false;

	return true;
}

static void
nvc_input(enum nvc_key key, bool state)
{
	if (state)
		nvc_keys|= key;
	else
		nvc_keys&= ~key;

	events_fire((state) ? NVC_EVENT_KEY_DOWN : NVC_EVENT_KEY_UP, key, 0);

	//if ((main_usec % 512) == 0) // takes about 512 µs to read the controller data
	if (nvc_regs.nr_scr.s_hw_si)
	{
		nvc_regs.nr_scr.s_si_stat = 1;

		u_int32_t old_nvc_keys = (nvc_regs.nr_sdhr << 8) | nvc_regs.nr_sdlr;
		bool raise_intr = state && !nvc_regs.nr_scr.s_k_int_inh && !(old_nvc_keys & key);
		nvc_regs.nr_sdlr = nvc_keys & 0xff;
		nvc_regs.nr_sdhr = nvc_keys >> 8;
		if (debug_trace_nvc)
			debug_tracef("nvc", "Serial data 0x%08x -> 0x%08x, raise intr = %d", old_nvc_keys, nvc_keys, raise_intr);

		nvc_regs.nr_scr.s_si_stat = 0;

		if (raise_intr)
			cpu_intr(NVC_INTKEY);
	}
	else
	{
		static bool ignore_sw_si = false;
		debug_runtime_errorf(&ignore_sw_si, "NVC: Software serial mode unimplemented");
	}
}

bool
nvc_input_key(enum tk_scancode scancode, bool state)
{
	switch (scancode)
	{
		case TK_SCANCODE_LSHIFT: nvc_input(KEY_LT, state); return true;
		case TK_SCANCODE_W: nvc_input(KEY_LU, state); return true;
		case TK_SCANCODE_A: nvc_input(KEY_LL, state); return true;
		case TK_SCANCODE_S: nvc_input(KEY_LD, state); return true;
		case TK_SCANCODE_D: nvc_input(KEY_LR, state); return true;
		case TK_SCANCODE_APOSTROPHE: nvc_input(KEY_SEL, state); return true;
		case TK_SCANCODE_RETURN: nvc_input(KEY_STA, state); return true;
		case TK_SCANCODE_RSHIFT: nvc_input(KEY_RT, state); return true;
		case TK_SCANCODE_UP: nvc_input(KEY_RU, state); return true;
		case TK_SCANCODE_LEFT: nvc_input(KEY_RL, state); return true;
		case TK_SCANCODE_DOWN: nvc_input(KEY_RD, state); return true;
		case TK_SCANCODE_RIGHT: nvc_input(KEY_RR, state); return true;
		case TK_SCANCODE_RALT: nvc_input(KEY_A, state); return true;
		case TK_SCANCODE_RGUI: nvc_input(KEY_B, state); return true;
		default: return false;
	}
}

void
nvc_input_button(enum tk_button button, bool state)
{
	switch (button)
	{
		case TK_BUTTON_LSHOULDER: nvc_input(KEY_LT, state); break;
		case TK_BUTTON_DPAD_UP: nvc_input(KEY_LU, state); break;
		case TK_BUTTON_DPAD_LEFT: nvc_input(KEY_LL, state); break;
		case TK_BUTTON_DPAD_DOWN: nvc_input(KEY_LD, state); break;
		case TK_BUTTON_DPAD_RIGHT: nvc_input(KEY_LR, state); break;
		case TK_BUTTON_BACK: nvc_input(KEY_SEL, state); break;
		case TK_BUTTON_START: nvc_input(KEY_STA, state); break;
		case TK_BUTTON_RSHOULDER: nvc_input(KEY_RT, state); break;
		case TK_BUTTON_A: nvc_input(KEY_A, state); break;
		case TK_BUTTON_B: nvc_input(KEY_B, state); break;
	}
}

void
nvc_input_axis(enum tk_axis axis, float value)
{
	static const float dead_zone = 0.25f;
	switch (axis)
	{
		case TK_AXIS_LEFTX:
			if (value > dead_zone)
				nvc_input(KEY_LR, true);
			else if (value < -dead_zone)
				nvc_input(KEY_LL, true);
			else
			{
				nvc_input(KEY_LR, false);
				nvc_input(KEY_LL, false);
			}
			break;
		case TK_AXIS_LEFTY:
			if (value > dead_zone)
				nvc_input(KEY_LD, true);
			else if (value < -dead_zone)
				nvc_input(KEY_LU, true);
			else
			{
				nvc_input(KEY_LD, false);
				nvc_input(KEY_LU, false);
			}
			break;
		case TK_AXIS_RIGHTX:
			if (value > dead_zone)
				nvc_input(KEY_RR, true);
			else if (value < -dead_zone)
				nvc_input(KEY_RL, true);
			else
			{
				nvc_input(KEY_RR, false);
				nvc_input(KEY_RL, false);
			}
			break;
		case TK_AXIS_RIGHTY:
			if (value > dead_zone)
				nvc_input(KEY_RD, true);
			else if (value < -dead_zone)
				nvc_input(KEY_RU, true);
			else
			{
				nvc_input(KEY_RD, false);
				nvc_input(KEY_RU, false);
			}
			break;
	}
}

bool
nvc_mem_prepare(struct mem_request *request)
{
	enum os_perm dummy_perm;
	(void)dummy_perm; // Hint for makeheaders

	if (request->mr_size != 1)
	{
		static bool ignore_size = false;
		if (!debug_runtime_errorf(&ignore_size, "Invalid NVC access size %u @ 0x%08x\n",
		                          request->mr_size, request->mr_emu))
			return false;
		request->mr_size = 1;
	}
	if (request->mr_emu <= 0x02000028)
	{
		switch (request->mr_emu)
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
				request->mr_perms = OS_PERM_READ | OS_PERM_WRITE;
				break;
			case 0x02000020:
				request->mr_perms = OS_PERM_READ | OS_PERM_WRITE;
				break;
			default:
				request->mr_perms = 0;
		}
		request->mr_host = (u_int8_t *) &nvc_regs + ((request->mr_emu & 0x3f) >> 2);
	}
	else
	{
		debug_runtime_errorf(NULL, "NVC bus error at 0x%08x", request->mr_emu);
		debug_stop();
		return false;
	}

	return true;
}

void
nvc_mem_write(const struct mem_request *request, const void *src)
{
	switch (request->mr_emu)
	{
		case 0x02000020:
		{
			const struct nvc_tcr *new_tcr = (struct nvc_tcr *)src;

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
			*(u_int8_t *)request->mr_host = *(u_int8_t *)src;
	}
}
