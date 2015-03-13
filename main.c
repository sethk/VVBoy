#include "main.h"
#include <sys/stat.h>
#include <sys/mman.h>
#include <sys/fcntl.h>
#include <unistd.h>
#include <math.h>
#include <stdlib.h>
#include <strings.h>
#include <stdio.h>
#include <signal.h>
#include <sysexits.h>
#include <stdbool.h>
#include <assert.h>
#include <err.h>
#include <histedit.h>

static bool
validate_seg_size(size_t size)
{
	double log2size = log2(size);
	return (remainder(log2size, 1.0) == 0.0);
}

/* MEM */

struct mem_seg_desc mem_segs[MEM_NSEGS];

static const char *mem_seg_names[MEM_NSEGS] =
{
	[MEM_SEG_VIP] = "VIP",
	[MEM_SEG_VSU] = "VSU",
	[MEM_SEG_HWCTL] = "HWCTL",
	[3] = "Not Used (0x03000000-0x03ffffff)",
	[MEM_SEG_CARTEX] = "CARTEX",
	[MEM_SEG_WRAM] = "WRAM",
	[MEM_SEG_SRAM] = "SRAM",
	[MEM_SEG_ROM] = "ROM"
};

static bool
mem_seg_alloc(enum mem_segment seg, size_t size)
{
	assert(validate_seg_size(size));
	mem_segs[seg].ms_ptr = malloc(size);
	if (!mem_segs[seg].ms_ptr)
	{
		warn("Could not allocate 0x%lx bytes for segment %s", size, mem_seg_names[seg]);
		return false;
	}
	mem_segs[seg].ms_size = size;
	mem_segs[seg].ms_addrmask = size - 1;

	return true;
}

static bool
mem_seg_realloc(enum mem_segment seg, size_t size)
{
	assert(validate_seg_size(size));
	mem_segs[seg].ms_ptr = realloc(mem_segs[seg].ms_ptr, size);
	if (!mem_segs[seg].ms_ptr)
	{
		warn("Could not reallocate 0x%lx bytes for segment %s", size, mem_seg_names[seg]);
		return false;
	}
	mem_segs[seg].ms_size = size;
	mem_segs[seg].ms_addrmask = size - 1;
	return true;
}

static void
mem_seg_free(enum mem_segment seg)
{
	free(mem_segs[seg].ms_ptr);
	mem_segs[seg].ms_ptr = NULL;
}

static u_int32_t
ceil_seg_size(u_int32_t size)
{
	// http://graphics.stanford.edu/~seander/bithacks.html#RoundUpPowerOf2Float
	--size;
	size|= size >> 1;
	size|= size >> 2;
	size|= size >> 4;
	size|= size >> 8;
	size|= size >> 16;
	return ++size;
}

#define MEM_ADDR2SEG(a) (((a) & 0x07000000) >> 24)
#define MEM_ADDR2OFF(a) ((a) & 0x00ffffff)

static bool
mem_read(u_int32_t addr, void *dest, size_t size)
{
	assert(size > 0);
	enum mem_segment seg = MEM_ADDR2SEG(addr);
	if (mem_segs[seg].ms_size)
	{
		u_int32_t offset = addr & mem_segs[seg].ms_addrmask;

		if (seg == MEM_SEG_SRAM && MEM_ADDR2OFF(addr) + size > mem_segs[seg].ms_size)
		{
			if (!mem_seg_realloc(MEM_SEG_SRAM, ceil_seg_size(offset + size)))
				return false;
			offset = addr & mem_segs[MEM_SEG_SRAM].ms_addrmask;
		}

		const void *src = mem_segs[seg].ms_ptr + offset;
		switch (size)
		{
			case 1:
				*(u_int8_t *)dest = *(u_int8_t *)src;
				return true;
			case 2:
				*(u_int16_t *)dest = *(u_int16_t *)src;
				return true;
			case 4:
				*(u_int32_t *)dest = *(u_int32_t *)src;
				return true;
			default:
				bcopy(src, dest, size);
				return true;
		}
	}
	else
	{
		// TODO: SEGV
		return false;
	}
}

static bool
mem_write(u_int32_t addr, const void *src, size_t size)
{
	assert(size > 0);
	enum mem_segment seg = MEM_ADDR2SEG(addr);
	if (mem_segs[seg].ms_size)
	{
		u_int32_t offset = addr & mem_segs[seg].ms_addrmask;

		if (seg == MEM_SEG_SRAM && MEM_ADDR2OFF(addr) + size > mem_segs[seg].ms_size)
		{
			if (!mem_seg_realloc(MEM_SEG_SRAM, ceil_seg_size(offset + size)))
				return false;
			offset = addr & mem_segs[MEM_SEG_SRAM].ms_addrmask;
		}

		void *dest = mem_segs[seg].ms_ptr + offset;
		switch (size)
		{
			case 1:
				*(u_int8_t *)dest = *(u_int8_t *)src;
				return true;
			case 2:
				*(u_int16_t *)dest = *(u_int16_t *)src;
				return true;
			case 4:
				*(u_int32_t *)dest = *(u_int32_t *)src;
				return true;
			default:
				bcopy(src, dest, size);
				return true;
		}
	}
	else
	{
		// TODO: SEGV
		return false;
	}
}

/* ROM */
#define ROM_MIN_SIZE 1024lu

#define IS_POWER_OF_2(n) (((n) & ((n) - 1)) == 0)

static bool
rom_read(const char *fn, int fd)
{
	struct stat st;
	if (fstat(fd, &st) == -1)
	{
		warn("stat()");
		return false;
	}

	if (st.st_size < ROM_MIN_SIZE)
	{
		warnx("ROM file ‘%s’ is smaller than minimum size (0x%lx)", fn, ROM_MIN_SIZE);
		return false;
	}

	if (!IS_POWER_OF_2(st.st_size))
	{
		warnx("Size of ROM file ‘%s’, 0x%llx, is not a power of 2", fn, st.st_size);
		return false;
	}

	mem_segs[MEM_SEG_ROM].ms_size = st.st_size;
	mem_segs[MEM_SEG_ROM].ms_ptr = mmap(NULL, st.st_size, PROT_READ, MAP_FILE | MAP_PRIVATE, fd, 0);
	if (!mem_segs[MEM_SEG_ROM].ms_ptr)
	{
		warn("mmap() ROM");
		return false;
	}
	mem_segs[MEM_SEG_ROM].ms_addrmask = st.st_size - 1;

	// TODO: check ROM info

	return true;
}

/* SRAM */
static bool
sram_init(void)
{
	// TODO: load save file
	return mem_seg_alloc(MEM_SEG_SRAM, 8 << 10);
}

static void
sram_fini(void)
{
	mem_seg_free(MEM_SEG_SRAM);
	// TODO: write save file
}

/* WRAM */
#define WRAM_SIZE 0x1000000

static bool
wram_init(void)
{
	return mem_seg_alloc(MEM_SEG_WRAM, WRAM_SIZE);
}

static void
wram_fini(void)
{
	mem_seg_free(MEM_SEG_WRAM);
}

/* ROM */
static bool
rom_load(const char *fn)
{
	int fd = open(fn, O_RDONLY);
	if (fd == -1)
	{
		warn("Could not open ‘%s’", fn);
		return false;
	}

	int status = rom_read(fn, fd);

	close(fd);

	return status;
}

static void
rom_unload(void)
{
	if (munmap(mem_segs[MEM_SEG_ROM].ms_ptr, mem_segs[MEM_SEG_ROM].ms_size) == -1)
		warn("munmap(mem_segs[MEM_SEG_ROM], ...) failed");
}

/* CPU */
static struct cpu_state
{
	u_int32_t cs_r[32];
	u_int32_t cs_pc;
	u_int32_t cs_psw;
	u_int32_t cs_ecr;
} cpu_state;

bool
cpu_init(void)
{
	cpu_state.cs_r[0] = 0; // Read-only

	return true;
}

void
cpu_fini(void)
{
	// TODO
}

void
cpu_reset(void)
{
	cpu_state.cs_pc = 0xfffffff0;
	cpu_state.cs_psw = 0x00008000;
	cpu_state.cs_ecr = 0x0000fff0;
}

void
cpu_step(void)
{
	// TODO read instruction
	// TODO execute instruction
	// TODO increment PC unless jumped
}

/* VIP */
bool
vip_init(void)
{
	// TODO
	return true;
}

void
vip_reset(void)
{
	// TODO
}

void
vip_step(void)
{
	// TODO
}

void
vip_fini(void)
{
	// TODO
}

/* VSU */
bool
vsu_init(void)
{
	// TODO
	return true;
}

void
vsu_reset(void)
{
	// TODO
}

void
vsu_step(void)
{
	// TODO
}

void
vsu_fini(void)
{
	// TODO
}

/* DEBUG */
static EditLine *s_editline;
static Tokenizer *s_token;

bool
debug_init(void)
{
	s_editline = el_init("vvboy", stdin, stdout, stderr);
	if (!s_editline)
	{
		warnx("Could not initialize editline");
		return false;
	}
	s_token = tok_init(NULL);
	if (!s_token)
	{
		warnx("Could not initialize tokenizer");
		return false;
	}

	return true;
}

void
debug_fini(void)
{
	el_end(s_editline);
}

void
debug_intr(void)
{
	while (1)
	{
		tok_reset(s_token);
		int count;
		const char *line = el_gets(s_editline, &count);
		if (line)
		{
			int argc;
			const char **argv;
			if (tok_str(s_token, line, &argc, &argv) == 0 && argc > 0)
			{
				if (!strcmp(argv[0], "?") || !strcmp(argv[0], "help"))
				{
					puts("Debugger commands:");
					puts("? or help\tDisplay this help");
					puts("q or quit\tQuit the emulator");
					puts("c or cont\tContinue execution");
				}
				else if (!strcmp(argv[0], "q") || !strcmp(argv[0], "quit") || !strcmp(argv[0], "exit"))
				{
					main_exit();
					break;
				}
				else if (!strcmp(argv[0], "c") || !strcmp(argv[0], "cont"))
					break;
				else
					printf("Unknown command “%s” -- type ‘?’ for help\n", argv[0]);
			}
		}
		else
			putchar('\n');
	}
}

/* MAIN */
void
main_reset(void)
{
	cpu_reset();
	vip_reset();
	vsu_reset();
}

void
main_step(void)
{
	cpu_step();
	vip_step();
	vsu_step();
}

static bool s_running = false;

void
main_exit(void)
{
	s_running = false;
}

int
main_usage(void)
{
	fprintf(stderr, "usage: %s [-t] <file.vb>\n", getprogname());
	return EX_USAGE;
}

void
main_noop(int sig)
{
}

int
main(int ac, char * const *av)
{
	int ch;
	extern int optind;
	while ((ch = getopt(ac, av, "")) != -1)
		switch (ch)
		{
			case '?':
				return main_usage();
		}
	ac-= optind;
	av+= optind;

	if (ac != 1)
		return main_usage();

	if (!rom_load(av[0]))
		return EX_NOINPUT;

	if (!sram_init() || !wram_init() || !cpu_init() || !vip_init() || !vsu_init() || !debug_init())
		return EX_OSERR;

	main_reset();

	sigset_t sigset;
	sigemptyset(&sigset);
	sigaddset(&sigset, SIGINT);
	signal(SIGINT, main_noop);

	sigprocmask(SIG_BLOCK, &sigset, NULL);
	s_running = true;
	while (s_running)
	{
		main_step();

		sigset_t sigpend;
		sigpending(&sigpend);
		if (sigismember(&sigpend, SIGINT))
		{
			sigprocmask(SIG_UNBLOCK, &sigpend, NULL);
			signal(SIGINT, SIG_DFL);

			putchar('\n');
			debug_intr();
			signal(SIGINT, main_noop);
			sigprocmask(SIG_BLOCK, &sigpend, NULL);
		}
	}
	sigprocmask(SIG_UNBLOCK, &sigset, NULL);

	debug_fini();
	vsu_fini();
	vip_fini();
	cpu_fini();
	wram_fini();
	sram_fini();
	rom_unload();
}
