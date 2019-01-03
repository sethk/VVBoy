#include "vvboy.h"

#include <unistd.h>
#include <err.h>
#include <sysexits.h>
#include <stdlib.h>

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
	tk_main();
	main_unblock_sigint();

	rom_unload();
	main_fini();

	if (debug_trace_file != NULL)
		fclose(debug_trace_file);

	return 0;
}
