#include "types.h"
#include "emu.h"

#if INTERFACE
	struct emu_stats_t
	{
		u_int64_t ms_start_usec;
		u_int ms_frames;
		u_int ms_scans;
		u_int ms_insts;
		u_int ms_intrs;
	};
#endif // INTERFACE

u_int32_t emu_usec;
bool emu_trace = false;
float emu_time_scale = 1.0f;
struct emu_stats_t emu_stats;

bool
emu_init(void)
{
	return (events_init() &&
			mem_init() &&
			sram_init() &&
			wram_init() &&
			vip_init() &&
			vsu_init() &&
			nvc_init() &&
			debug_init());
}

void
emu_init_debug()
{
	wram_init_debug();
	vip_init_debug();
	vsu_init_debug();
	nvc_init_debug();
}

void
emu_fini(void)
{
	debug_fini();
	nvc_fini();
	vsu_fini();
	vip_fini();
	wram_fini();
	sram_fini();
	mem_fini();
	events_fini();
}

static void
emu_restart_clock(void)
{
	u_int64_t usec = os_get_usec();
	if (emu_stats.ms_insts > 0)
	{
		char stats_s[100];
		u_int64_t delta_usecs = usec - emu_stats.ms_start_usec;
		float delta_secs = delta_usecs * 1e-6f;
		float fps = (float)emu_stats.ms_frames / delta_secs;
		float emu_fps = (float)emu_stats.ms_scans / delta_secs;
		if (emu_trace)
			debug_tracef("emu", "%u frames in %llu µs (%g FPS), %u scans (%g FPS), %u instructions, %u interrupts",
						 emu_stats.ms_frames, delta_usecs, fps,
						 emu_stats.ms_scans, emu_fps,
						 emu_stats.ms_insts,
						 emu_stats.ms_intrs);
		os_snprintf(stats_s, sizeof(stats_s), "%.3g FPS, %.3g EMU FPS", fps, emu_fps);
		main_update_caption(stats_s);
	}

	emu_stats.ms_start_usec = usec;
	emu_stats.ms_frames = 0;
	emu_stats.ms_scans = 0;
	emu_stats.ms_insts = 0;
	emu_stats.ms_intrs = 0;

	emu_usec = 0;

	events_clear();
}

void
emu_reset(void)
{
	emu_restart_clock();

	vip_reset();
	vsu_reset();
	nvc_reset();
}

void
emu_test(void)
{
	//mem_test();
	nvc_test();
	vsu_test();
	vip_test();
	cpu_test();
}

bool
emu_step(void)
{
	if (!nvc_step())
		return false;

	vip_step();
	vsu_step();

	if (++emu_usec == 1000000)
		emu_restart_clock();

	return true;
}

void
emu_noop(int sig __unused)
{
}

#if DEBUG_TTY
	void
	emu_block_sigint(void)
	{
		sigset_t sigset;
		sigemptyset(&sigset);
		sigaddset(&sigset, SIGINT);
		signal(SIGINT, emu_noop);

		sigprocmask(SIG_BLOCK, &sigset, NULL);
	}

	void
	emu_unblock_sigint(void)
	{
		sigset_t sigset;
		sigemptyset(&sigset);
		sigaddset(&sigset, SIGINT);
		sigprocmask(SIG_UNBLOCK, &sigset, NULL);

		signal(SIGINT, SIG_DFL);
	}
#endif // DEBUG_TTY

void
emu_draw(void)
{
	if (imgui_shown)
		imgui_draw_win();
	else
		gl_draw(0, 0, tk_draw_width, tk_draw_height);
}

void
emu_frame(u_int delta_usecs)
{
	debug_frame_begin();
	nvc_frame_begin();
	vip_frame_begin();

	if (emu_trace)
		debug_tracef("emu", "Begin frame, delta_usecs=%u", delta_usecs);

	if (emu_time_scale != 1.0)
		delta_usecs = lround(delta_usecs * emu_time_scale);

	while (delta_usecs-- != 0 && emu_step());

#if DEBUG_TTY
	// Check SIGINT -> Debugger
	sigset_t sigpend;
	sigpending(&sigpend);
	if (sigismember(&sigpend, SIGINT))
		debug_stop();
#endif // DEBUG_TTY

	if (emu_trace)
		debug_tracef("emu", "End frame");

	vip_frame_end();
	vsu_frame_end();

	emu_draw();

	debug_frame_end();
	events_frame_end();

	++emu_stats.ms_frames;
}

