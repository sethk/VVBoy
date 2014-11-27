#include "main.h"
#include <stdio.h>
#include <sysexits.h>
#include <stdbool.h>

static bool
validate_seg_size(size_t size)
{
	double log2size = log2(size);
	return (remainder(log2size, 1.0) == 0.0);
}

/* MEM */
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

#define MEM_ADDR2SEG(a) (((a) & 0x07000000) >> 24)
#define MEM_ADDR2OFF(a) ((a) & 0x00ffffff)

static bool
mem_read(u_int32_t addr, void *dest, size_t size)
{
	assert(size > 0);
	enum mem_segment seg = MEM_ADDR2SEG(addr);
	if (mem_segs[seg].ms_size)
	{
		if (seg == MEM_SEG_SRAM && MEM_ADDR2OFF(addr) + size > mem_segs[seg].ms_size)
			mem_seg_realloc(MEM_SEG_SRAM, ceil_seg_size(offset + size));
		u_int32_t offset = addr & mem_segs[seg].ms_addrmask;
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
	enum mem_segment seg = ADDR2SEG(addr);
	if (mem_segs[seg].ms_size)
	{
		if (seg == MEM_SEG_SRAM && MEM_ADDR2OFF(addr) + size > mem_segs[seg].ms_size)
			mem_seg_realloc(MEM_SEG_SRAM, ceil_seg_size(offset + size));
		u_int32_t offset = addr & mem_segs[seg].ms_addrmask;
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
#define ROM_MIN_SIZE 1024

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
		warnx("ROM file ‘%s’ is smaller than minimum size (0x%lx)", ROM_MIN_SIZE);
		return false;
	}

	if (!is_power_of_2(st.st_size))
	{
		warnx("Size of ROM file ‘%s’, 0x%lx, is not a power of 2", st.st_size, fn);
		return false;
	}

	mem_segs[MEM_SEG_ROM].ms_size = st.st_size;
	mem_segs[MEM_SEG_ROM].ms_ptr = mmap(NULL, st.st_size, PROT_READ, MAP_FILE | MAP_PRIVATE, fd);
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

static bool
rom_unload(void)
{
	if (munmap(mem_segs[MEM_SEG_ROM].ms_ptr, mem_segs[MEM_SEG_ROM].ms_size) == -1)
		warn("munmap(mem_segs[MEM_SEG_ROM], ...) failed");
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
main(int ac, const char *av)
{
	if (ac != 2)
	{
		fprintf(stderr, "usage: %s <file.vb>\n", getprogname());
		return EX_USAGE;
	}

	if (!rom_load(av[1]))
		return EX_NOINPUT;

	if (!sram_init() || !wram_init() || !cpu_init() || !vip_init() || !vsu_init())
		return EX_OSERR;

	main_reset();

	g_running = true;
	while (g_running)
	{
		// TODO: block SIGINT
		main_step();
		// TODO: unblock SIGINT

		// TODO: if ^C pending: debug_intr()
	}

	vsu_fini();
	vip_fini();
	cpu_fini();
	wram_fini();
	sram_fini();
	rom_unload();
}
