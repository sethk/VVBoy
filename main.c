#include "types.h"
#include "main.h"

#if INTERFACE
	struct main_stats_t
	{
		u_int64_t ms_start_usec;
		u_int ms_frames;
		u_int ms_scans;
		u_int ms_insts;
		u_int ms_intrs;
	};
#endif // INTERFACE

u_int32_t main_usec;
bool main_trace = false;
bool main_fixed_rate = false;
float main_time_scale = 1.0f;
struct main_stats_t main_stats;

bool
main_init(void)
{
	return (os_init() &&
			events_init() &&
			mem_init() &&
			sram_init() &&
			wram_init() &&
			vip_init() &&
			vsu_init() &&
			nvc_init() &&
			debug_init() &&
			imgui_init() &&
	        tk_init() &&
	        gl_init());
}

void
main_fini(void)
{
	gl_fini();
	tk_fini();
	imgui_fini();
	debug_fini();
	nvc_fini();
	vsu_fini();
	vip_fini();
	wram_fini();
	sram_fini();
	mem_fini();
	events_fini();
	os_fini();
}

void
main_fatal_error(enum os_runerr_type type, const char *fmt, ...)
{
	va_list ap;
	va_start(ap, fmt);
	os_runtime_verror(type, BIT(OS_RUNERR_RESP_ABORT), fmt, ap);
	va_end(ap);
	abort();
}

void
main_update_caption(const char *stats)
{
	char caption[100] = "VVBoy";
	size_t offset = sizeof("VVBoy") - 1;
	if (rom_loaded)
	{
		offset+= os_snprintf(caption + offset, sizeof(caption) - offset, ": %s", rom_name);
		if (stats)
			offset+= os_snprintf(caption + offset, sizeof(caption) - offset, " [%s]", stats);
		if (debug_is_stopped())
			offset+= os_snprintf(caption + offset, sizeof(caption) - offset, " (Stopped)");
		else if (main_time_scale != 1.0)
			offset += os_snprintf(caption + offset, sizeof(caption) - offset, " *Time Scale %gx*", main_time_scale);
	}
	tk_update_caption(caption);
}

static void
main_restart_clock(void)
{
	u_int64_t usec = os_get_usec();
	if (main_stats.ms_insts > 0)
	{
		char stats_s[100];
		u_int64_t delta_usecs = usec - main_stats.ms_start_usec;
		float delta_secs = delta_usecs * 1e-6f;
		float fps = (float)main_stats.ms_frames / delta_secs;
		float emu_fps = (float)main_stats.ms_scans / delta_secs;
		if (main_trace)
			debug_tracef("main", "%u frames in %llu µs (%g FPS), %u scans (%g FPS), %u instructions, %u interrupts",
						 main_stats.ms_frames, delta_usecs, fps,
						 main_stats.ms_scans, emu_fps,
						 main_stats.ms_insts,
						 main_stats.ms_intrs);
		os_snprintf(stats_s, sizeof(stats_s), "%.3g FPS, %.3g EMU FPS", fps, emu_fps);
		main_update_caption(stats_s);
	}

	main_stats.ms_start_usec = usec;
	main_stats.ms_frames = 0;
	main_stats.ms_scans = 0;
	main_stats.ms_insts = 0;
	main_stats.ms_intrs = 0;

	main_usec = 0;

	events_clear();
}

void
main_reset(void)
{
	main_restart_clock();

	vip_reset();
	vsu_reset();
	nvc_reset();
}

bool
main_step(void)
{
	if (!nvc_step())
		return false;

	vip_step();
	vsu_step();

	if (++main_usec == 1000000)
		main_restart_clock();

	return true;
}

void
main_noop(int sig __unused)
{
}

#if DEBUG_TTY
	void
	main_block_sigint(void)
	{
		sigset_t sigset;
		sigemptyset(&sigset);
		sigaddset(&sigset, SIGINT);
		signal(SIGINT, main_noop);

		sigprocmask(SIG_BLOCK, &sigset, NULL);
	}

	void
	main_unblock_sigint(void)
	{
		sigset_t sigset;
		sigemptyset(&sigset);
		sigaddset(&sigset, SIGINT);
		sigprocmask(SIG_UNBLOCK, &sigset, NULL);

		signal(SIGINT, SIG_DFL);
	}
#endif // DEBUG_TTY

void
main_draw(void)
{
	if (imgui_shown)
		imgui_draw_main();
	else
		gl_draw(0, 0, tk_draw_width, tk_draw_height);
}

void
main_frame(u_int delta_usecs)
{
	tk_frame_begin();

	gl_clear();

	imgui_frame_begin();

	if (rom_loaded)
	{
		debug_frame_begin();
		nvc_frame_begin();
		vip_frame_begin();

		if (main_trace)
			debug_tracef("main", "Begin frame, delta_usecs=%u", delta_usecs);

		if (main_time_scale != 1.0)
			delta_usecs = lround(delta_usecs * main_time_scale);

		while (delta_usecs-- != 0 && main_step());

	#if DEBUG_TTY
		// Check SIGINT -> Debugger
		sigset_t sigpend;
		sigpending(&sigpend);
		if (sigismember(&sigpend, SIGINT))
			debug_stop();
	#endif // DEBUG_TTY

		if (main_trace)
			debug_tracef("main", "End frame");

		vip_frame_end();
		vsu_frame_end();

		main_draw();

		debug_frame_end();
		events_frame_end();
	}

	imgui_frame_end();

	tk_frame_end();

	++main_stats.ms_frames;
}

