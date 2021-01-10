#include "types.h"
#include "vvboy.h"

#include <stdlib.h>
#include <signal.h>
#ifdef __APPLE__
# include <unistd.h> // getopt()
#endif // __APPLE__
#include <math.h>

static bool main_running = true;
bool main_fixed_rate = false;
static const u_int main_min_fps = 25;
static const u_int main_max_fps = 100;

void
main_fatal_error(enum os_runerr_type type, const char *fmt, ...)
{
	va_list ap;
	va_start(ap, fmt);
	os_runtime_verror(type, BIT(OS_RUNERR_RESP_ABORT), fmt, ap);
	va_end(ap);
	exit(1);
}

static bool
main_init(void)
{
	return (os_init() && emu_init() && imgui_init() && tk_init() && gl_init());
}

static void
main_fini(void)
{
	gl_fini();
	tk_fini();
	imgui_fini();
	emu_fini();
	os_fini();
}

void
main_quit(void)
{
	main_running = false;
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
		else if (emu_time_scale != 1.0)
			offset += os_snprintf(caption + offset, sizeof(caption) - offset, " *Time Scale %gx*", emu_time_scale);
	}
	tk_update_caption(caption);
}

static bool
main_load_rom(const char *fn)
{
	if (rom_load(fn))
	{
		main_update_caption(NULL);
		imgui_shown = false;
		return true;
	}

	return false;
}

void
main_close_rom(void)
{
	rom_unload();
	main_update_caption(NULL);
	imgui_shown = true;
}

void
main_open_rom(void)
{
	if (rom_loaded)
		rom_unload();

	static const char * const exts[] = {"vb", "isx"};
	os_choose_file("ROM Files", exts, COUNT_OF(exts), main_load_rom);
}

static void
main_loop(void)
{
	static u_int64_t last_frame_usec = 0;
	/*static*/ const u_int max_frame_usecs = 1000000 / main_min_fps;
	/*static*/ const u_int min_frame_usecs = 1000000 / main_max_fps;

	while (main_running)
	{
		if (!tk_poll_input())
			return;

		u_int delta_usecs;

		if (main_fixed_rate)
			delta_usecs = 20000;
		else
		{
			u_int64_t frame_usec = os_get_usec();
			if (last_frame_usec)
				delta_usecs = clamp_uint64(frame_usec - last_frame_usec, min_frame_usecs, max_frame_usecs);
			else
				delta_usecs = min_frame_usecs;
			last_frame_usec = frame_usec;
		}

		tk_frame_begin();

		gl_clear();

		imgui_frame_begin();

		if (rom_loaded)
			emu_frame(delta_usecs);

		imgui_frame_end();

		tk_frame_end();
	}
}

int
main(int ac, char * const *av)
{
	int ch;
	extern int optind;
	bool help = false;
	bool debugging = false;
	bool linebuf = false;
	static const char *trace_path = NULL;
	static const char *usage_fmt = "usage: %s [-d] [ -t <subsystem> ] [ -T <trace.log> ] [ <file.vb> | <file.isx> ]\n";
	while ((ch = getopt(ac, av, "dt:T:")) != -1)
		switch (ch)
		{
			case '?':
				help = true;
			case 'd':
				debugging = true;
				break;
			case 'l':
				linebuf = true;
				break;
			case 't':
				if (!debug_toggle_trace(optarg))
					help = true;
				break;
			case 'T':
				trace_path = optarg;
				break;
		}
	ac-= optind;
	av+= optind;

	if (ac > 1 || help)
	{
		os_runtime_error(OS_RUNERR_TYPE_WARNING, BIT(OS_RUNERR_RESP_OKAY), usage_fmt, os_getprogname());
		return 64; // EX_USAGE
	}

	if (trace_path)
	{
		debug_trace_file = fopen(trace_path, "w");
		if (!debug_trace_file)
			os_runtime_error(OS_RUNERR_TYPE_OSERR, BIT(OS_RUNERR_RESP_ABORT), "Can't open trace file %s", trace_path);
	#ifndef WIN32
		if (linebuf && setlinebuf(debug_trace_file) != 0)
			os_runtime_error(OS_RUNERR_TYPE_OSERR, BIT(OS_RUNERR_RESP_ABORT), "Can't set trace line-buffered");
	#endif // !WIN32
	}

	if (ac == 1)
	{
		if (!main_load_rom(av[0]))
			return 1;
	}

	if (!main_init())
		return 1;

	main_update_caption(NULL);

	emu_reset();

	nvc_test();
	vsu_test();
	vip_test();
	cpu_test();

	if (debugging)
		debug_stop();

#if DEBUG_TTY
	main_block_sigint();
#endif // DEBUG_TTY

	main_loop();

#if DEBUG_TTY
	main_unblock_sigint();
#endif // DEBUG_TYY

	if (rom_loaded)
		rom_unload();
	main_fini();

	if (debug_trace_file != NULL)
		fclose(debug_trace_file);

	return 0;
}
