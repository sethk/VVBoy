#include "main.h"
#include <sys/stat.h>
#include <sys/mman.h>
#include <sys/fcntl.h>
#include <sys/errno.h>
#include <sys/param.h>
#include <unistd.h>
#include <math.h>
#include <stdlib.h>
#include <strings.h>
#include <stdio.h>
#include <signal.h>
#include <sysexits.h>
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
mem_seg_mmap(enum mem_segment seg, size_t size, int fd)
{
	mem_segs[seg].ms_size = size;
	mem_segs[seg].ms_ptr = mmap(NULL, size, PROT_READ, MAP_FILE | MAP_PRIVATE, fd, 0);
	if (!mem_segs[seg].ms_ptr)
	{
		warn("mmap() %s", mem_seg_names[seg]);
		return false;
	}
	mem_segs[seg].ms_addrmask = size - 1;
	mem_segs[seg].ms_is_mmap = true;
	return true;
}

static bool
mem_seg_realloc(enum mem_segment seg, size_t size)
{
	assert(!mem_segs[seg].ms_is_mmap);
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
	if (!mem_segs[seg].ms_is_mmap)
		free(mem_segs[seg].ms_ptr);
	else
	{
		if (munmap(mem_segs[seg].ms_ptr, mem_segs[seg].ms_size) == -1)
			warn("munmap(mem_segs[%s], ...) failed", mem_seg_names[seg]);
		mem_segs[seg].ms_is_mmap = false;
	}
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
#define ROM_BASE_ADDR 0x07000000
#define ROM_MIN_SIZE 1024lu
#define ROM_MAX_SIZE 0x01000000

#define IS_POWER_OF_2(n) (((n) & ((n) - 1)) == 0)

struct rom_file
{
	int rf_fdesc;
	off_t rf_size;
	char *rf_path;
};

static void
rom_close(struct rom_file *file)
{
	close(file->rf_fdesc);
	if (file->rf_path)
		free(file->rf_path);
}

static bool
rom_open(const char *fn, struct rom_file *file)
{
	bzero(file, sizeof(file));

	file->rf_fdesc = open(fn, O_RDONLY);
	if (file->rf_fdesc == -1)
	{
		warn("Could not open ‘%s’", fn);
		return false;
	}

	struct stat st;
	if (fstat(file->rf_fdesc, &st) == -1)
	{
		warn("stat() ‘%s’", fn);
		rom_close(file);
		return false;
	}
	file->rf_size = st.st_size;

	file->rf_path = strdup(fn);
	if (!file->rf_path)
		err(EX_OSERR, "Alloc path");

	return true;
}

static bool
rom_read(struct rom_file *file)
{
	if (file->rf_size < ROM_MIN_SIZE)
	{
		warnx("ROM file ‘%s’ is smaller than minimum size (0x%lx)", file->rf_path, ROM_MIN_SIZE);
		return false;
	}

	if (!IS_POWER_OF_2(file->rf_size))
	{
		warnx("Size of ROM file ‘%s’, 0x%llx, is not a power of 2", file->rf_path, file->rf_size);
		return false;
	}

	if (!mem_seg_mmap(MEM_SEG_ROM, file->rf_size, file->rf_fdesc))
		return false;

	// TODO: check ROM info

	return true;
}

static bool
rom_read_buffer(struct rom_file *file, void *buf, size_t size, const char *desc)
{
	ssize_t nread = read(file->rf_fdesc, buf, size);
	if (nread == size)
		return true;
	else
	{
		warnx("Read %s from ‘%s’: %s", desc, file->rf_path, (nread == -1) ? strerror(errno) : "Unexpected EOF");
		return false;
	}
}

static bool
rom_seek(struct rom_file *file, off_t off, int whence)
{
	if (lseek(file->rf_fdesc, off, whence) != -1)
		return true;
	else
	{
		warn("Seek ‘%s’", file->rf_path);
		return false;
	}
}

enum isx_tag
{
	ISX_TAG_LOAD = 0x11,
	ISX_TAG_DEBUG1 = 0x14,
	ISX_TAG_DEBUG2 = 0x13,
	ISX_TAG_DEBUG3 = 0x20
};

struct isx_chunk_header
{
	u_char ich_tag;
	int32_t ich_addr;
	u_int32_t ich_size;
} __attribute__((packed));

static bool
isx_is_eof(struct rom_file *file)
{
	return (lseek(file->rf_fdesc, 0, SEEK_CUR) == file->rf_size);
}

static bool
isx_read_chunk_header(struct rom_file *file, struct isx_chunk_header *header)
{
	if (!rom_read_buffer(file, &(header->ich_tag), sizeof(header->ich_tag), "ISX chunk header tag"))
		return false;

	if (header->ich_tag == ISX_TAG_LOAD)
		return rom_read_buffer(file,
				(char *)header + sizeof(header->ich_tag),
				sizeof(*header) - sizeof(header->ich_tag),
				"ISX chunk header");
	else
		return true;
}

static bool
rom_read_isx(struct rom_file *file)
{
	static const char ISX_MAGIC[] = {'I', 'S', 'X'};
	char magic[sizeof(ISX_MAGIC)];
	if (!rom_read_buffer(file, magic, sizeof(ISX_MAGIC), "ISX magic"))
		return false;
	if (bcmp(magic, ISX_MAGIC, sizeof(ISX_MAGIC)))
	{
		warnx("Invalid ISX magic in ‘%s’", file->rf_path);
		return false;
	}

	// Seek over rest of header:
	if (!rom_seek(file, 32, SEEK_SET))
		return false;

	u_int32_t rom_size = 0;
	while (!isx_is_eof(file))
	{
		struct isx_chunk_header header;
		if (!isx_read_chunk_header(file, &header))
			return false;

		if (header.ich_tag == ISX_TAG_LOAD)
		{
			if (header.ich_addr < 0)
				rom_size+= -header.ich_addr;
			else if (MEM_ADDR2SEG(header.ich_addr) == MEM_SEG_ROM)
			{
				size_t loaded_size = MEM_ADDR2OFF(header.ich_addr) + header.ich_size;
				rom_size = MAX(rom_size, loaded_size);
			}
			else
			{
				warnx("Invalid chunk load addr 0x%08x in ISX file ‘%s’", (u_int32_t)header.ich_addr, file->rf_path);
				return false;
			}

			if (!rom_seek(file, header.ich_size, SEEK_CUR))
				return false;
		}
		else if (header.ich_tag == ISX_TAG_DEBUG1 || header.ich_tag == ISX_TAG_DEBUG2 || header.ich_tag == ISX_TAG_DEBUG3)
			break;
	}

	rom_size = ceil_seg_size(rom_size);
	rom_size = MAX(rom_size, ROM_MIN_SIZE);
	if (!mem_seg_alloc(MEM_SEG_ROM, rom_size))
		return false;

	memset(mem_segs[MEM_SEG_ROM].ms_ptr, 0xff, rom_size);

	if (!rom_seek(file, 32, SEEK_SET))
		return false;

	while (!isx_is_eof(file))
	{
		struct isx_chunk_header header;
		if (!isx_read_chunk_header(file, &header))
			return false;

		if (header.ich_tag == ISX_TAG_LOAD)
		{
			size_t offset;
			if (header.ich_addr < 0)
				offset = rom_size + header.ich_addr;
			else
				offset = MEM_ADDR2OFF(header.ich_addr);

			if (!rom_read_buffer(file, mem_segs[MEM_SEG_ROM].ms_ptr + offset, header.ich_size, "ISX chunk"))
				return false;
		}
		else if (header.ich_tag == ISX_TAG_DEBUG1 || header.ich_tag == ISX_TAG_DEBUG2 || header.ich_tag == ISX_TAG_DEBUG3)
			break;
	}

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
	char *ext = strrchr(fn, '.');
	bool is_isx = false;
	if (ext && !strcasecmp(ext, ".ISX"))
		is_isx = true;
	else if (!ext || strcasecmp(ext, ".VB"))
		warnx("Can‘t determine file type from ‘%s’, assuming ROM file", fn);

	struct rom_file file;
	if (!rom_open(fn, &file))
		return false;

	int status;
	if (is_isx)
		status = rom_read_isx(&file);
	else
		status = rom_read(&file);

	rom_close(&file);

	return status;
}

static void
rom_unload(void)
{
	mem_seg_free(MEM_SEG_ROM);
}

/* CPU */
static struct cpu_state
{
	u_int32_t cs_r[32];
	u_int32_t cs_pc;
	u_int32_t cs_psw;
	u_int32_t cs_ecr;
} cpu_state;

union cpu_inst
{
	u_int16_t ci_hwords[2];
	struct
	{
		u_int i_reg1 : 5;
		u_int i_reg2 : 5;
		u_int i_opcode : 6;
	} ci_i;
};

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

static size_t
cpu_inst_size(union cpu_inst *inst)
{
	return (inst->ci_i.i_opcode < 0x28) ? 2 : 4;
}

void
cpu_fetch(u_int32_t addr, union cpu_inst *inst)
{
	mem_read(addr, &(inst->ci_hwords[0]), 2);
	if (cpu_inst_size(inst) == 4)
		mem_read(addr + 2, &(inst->ci_hwords[1]), 2);
}

void
cpu_step(void)
{
	union cpu_inst inst;
	cpu_fetch(cpu_state.cs_pc, &inst);
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

static char *
debug_prompt(EditLine *editline)
{
	return "vvboy> ";
}

bool
debug_init(void)
{
	s_editline = el_init("vvboy", stdin, stdout, stderr);
	if (!s_editline)
	{
		warnx("Could not initialize editline");
		return false;
	}
	el_set(s_editline, EL_PROMPT, debug_prompt);

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

static char *
debug_format_binary(u_int n, u_int nbits)
{
	static char bin[33];
	char *end = bin;
	assert(nbits < sizeof(bin) - 1);
	while (nbits--)
	{
		*end++ = (n & 1) ? '1' : '0';
		n>>= 1;
	}
	*end = '\0';
	return bin;
}

static char *
debug_disasm(union cpu_inst *inst)
{
	static char dis[32];
	snprintf(dis, sizeof(dis), "%s", debug_format_binary(inst->ci_i.i_opcode, 6));
	return dis;
}

void
debug_intr(void)
{
	while (1)
	{
		union cpu_inst inst;
		cpu_fetch(cpu_state.cs_pc, &inst);
		printf("frame 0: 0x%08x: %s\n", cpu_state.cs_pc, debug_disasm(&inst));

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
					puts("x [<format>] <addr>\tExamine memory at <addr>");
				}
				else if (!strcmp(argv[0], "q") || !strcmp(argv[0], "quit") || !strcmp(argv[0], "exit"))
				{
					main_exit();
					break;
				}
				else if (!strcmp(argv[0], "c") || !strcmp(argv[0], "cont"))
					break;
				else if (!strcmp(argv[0], "x"))
				{
					u_int32_t addr;
					if (argc >= 2)
						addr = strtol(argv[1], NULL, 0);
				}
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
	fprintf(stderr, "usage: %s [-d] { <file.vb> | <file.isx> }\n", getprogname());
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
	bool debug_boot = false;
	while ((ch = getopt(ac, av, "d")) != -1)
		switch (ch)
		{
			case '?':
				return main_usage();
			case 'd':
				debug_boot = true;
				break;
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

	s_running = true;

	if (debug_boot)
		debug_intr();

	sigset_t sigset;
	sigemptyset(&sigset);
	sigaddset(&sigset, SIGINT);
	signal(SIGINT, main_noop);

	sigprocmask(SIG_BLOCK, &sigset, NULL);
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
