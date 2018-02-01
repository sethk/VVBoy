#include "vvboy.h"

#include <unistd.h>
#include <err.h>
#include <sysexits.h>
#include <stdlib.h>
#include <signal.h>

int
main(int ac, char * const *av)
{
	int ch;
	extern int optind;
	bool help = false;
	bool debug_boot = false;
	bool self_test = false;
	static const char *usage_fmt = "usage: %s [-dtCV] [-T <trace.log> ] { <file.vb> | <file.isx> }\n";
	while ((ch = getopt(ac, av, "dtCVT:")) != -1)
		switch (ch)
		{
			case '?':
				help = true;
			case 'd':
				debug_boot = true;
				break;
			case 't':
				self_test = true;
				break;
			case 'C':
				debug_trace_cpu = true;
				break;
			case 'V':
				debug_trace_vip = true;
				break;
			case 'T':
				debug_trace_file = fopen(optarg, "w");
				if (!debug_trace_file)
					err(EX_CANTCREAT, "Can't open trace file %s", optarg);
				if (setlinebuf(debug_trace_file) != 0)
					err(EX_OSERR, "Can't set trace line-buffered");
				break;
		}
	ac-= optind;
	av+= optind;

	if (ac != 1 || help)
	{
		fprintf(stderr, usage_fmt, getprogname());
		return EX_USAGE;
	}

	if (!rom_load(av[0]))
		return EX_NOINPUT;

	if (!main_init())
		return EX_OSERR;

	main_reset();

	if (self_test)
	{
		nvc_test();
		vsu_test();
		vip_test();
		cpu_test();
	}

	if (debug_boot)
		debug_run();

	sigset_t sigset;
	sigemptyset(&sigset);
	sigaddset(&sigset, SIGINT);
	signal(SIGINT, main_noop);

	sigprocmask(SIG_BLOCK, &sigset, NULL);
	tk_main();
	sigprocmask(SIG_UNBLOCK, &sigset, NULL);

	rom_unload();
	main_fini();

	if (debug_trace_file != NULL)
		fclose(debug_trace_file);

	return 0;
}
