#include "vvboy.h"

#include <unistd.h>
#include <err.h>
#include <sysexits.h>
#include <stdlib.h>
#include <signal.h>
#include <math.h>

extern inline u_int maxu(u_int a, u_int b) { return a > b ? a : b; }
extern inline u_int minu(u_int a, u_int b) { return a < b ? a : b; }
extern inline u_int clampu(u_int x, u_int min, u_int max) { return minu(maxu(x, min), max); }

static bool main_running = true;
static const u_int main_min_fps = 25;
static const u_int main_max_fps = 100;

void
main_quit(void)
{
	main_running = false;
}

static void
main_loop(void)
{
	static u_int last_frame_usec = 0;
	static const u_int max_frame_usecs = 1e6 / main_min_fps;
	static const u_int min_frame_usecs = 1e6 / main_max_fps;

	while (main_running)
	{
		if (!tk_poll_input())
			return;

		u_int delta_usecs;

		if (main_fixed_rate)
			delta_usecs = 20000;
		else
		{
			u_int frame_usec = tk_get_usec();
			if (last_frame_usec)
				delta_usecs = clampu(frame_usec - last_frame_usec, min_frame_usecs, max_frame_usecs);
			else
				delta_usecs = min_frame_usecs;
			last_frame_usec = frame_usec;
		}

		main_frame(delta_usecs);

		//usleep(10000);
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
	static const char *usage_fmt = "usage: %s [-d] [ -t <subsystem> ] [ -T <trace.log> ] { <file.vb> | <file.isx> }\n";
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

	if (ac != 1 || help)
	{
		fprintf(stderr, usage_fmt, getprogname());
		return EX_USAGE;
	}

	if (trace_path)
	{
		debug_trace_file = fopen(trace_path, "w");
		if (!debug_trace_file)
			err(EX_CANTCREAT, "Can't open trace file %s", trace_path);
		if (linebuf && setlinebuf(debug_trace_file) != 0)
			err(EX_OSERR, "Can't set trace line-buffered");
	}

	if (!rom_load(av[0]))
		return EX_NOINPUT;

	if (!main_init())
		return EX_OSERR;

	main_update_caption(NULL);

	main_reset();

	nvc_test();
	vsu_test();
	vip_test();
	cpu_test();

	if (debugging)
		debug_stop();

	main_block_sigint();

	main_loop();

	main_unblock_sigint();

	rom_unload();
	main_fini();

	if (debug_trace_file != NULL)
		fclose(debug_trace_file);

	return 0;
}
