#include <unistd.h>
#include <stdlib.h>
#include <stdbool.h>
#include <strings.h>
#include <fcntl.h>
#include <err.h>
#include <sys/stat.h>
#include <sysexits.h>
#include <sys/errno.h>
#include <signal.h>
#include <sys/param.h>

#include "rom.h"

#if INTERFACE
enum isx_symbol_type
	{
		ISX_SYMBOL_CONST = 0,
		ISX_SYMBOL_POINTER = 16,
		ISX_SYMBOL_END = 214
	};
#endif // INTERFACE

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

static FILE *rom_symbol_fp = NULL;
static char *rom_symbol_fn = NULL;

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
	bzero(file, sizeof(*file));

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
	if (file->rf_size < (off_t)ROM_MIN_SIZE)
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
	mem_segs[MEM_SEG_ROM].ms_perms = PROT_READ | PROT_EXEC;

	// TODO: check ROM info

	return true;
}

static bool
rom_read_buffer(struct rom_file *file, void *buf, size_t size, const char *desc)
{
	ssize_t nread = read(file->rf_fdesc, buf, size);
	if (nread == (ssize_t)size)
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
	ISX_TAG_DEBUG = 0x14
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

// TODO: memory leaks
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
		else if (header.ich_tag == ISX_TAG_DEBUG)
			break;
	}

	rom_size = mem_size_ceil(rom_size);
	rom_size = MAX(rom_size, ROM_MIN_SIZE);
	if (!mem_seg_alloc(MEM_SEG_ROM, rom_size, PROT_READ | PROT_EXEC))
		return false;

	union cpu_inst halt_inst = {.ci_i = {.i_opcode = (enum cpu_opcode)OP_TRAP}};
	u_int16_t pattern[2];
	pattern[0] = halt_inst.ci_hwords[0];
	pattern[1] = halt_inst.ci_hwords[1];
	memset_pattern4(mem_segs[MEM_SEG_ROM].ms_ptr, pattern, rom_size);

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
		else if (header.ich_tag == ISX_TAG_DEBUG)
		{
			u_int16_t num_syms;
			if (!rom_read_buffer(file, &num_syms, sizeof(num_syms), "ISX debug num syms"))
				return false;

			while (num_syms)
			{
				u_int8_t symlen;
				if (!rom_read_buffer(file, &symlen, sizeof(symlen), "ISX debug sym length"))
					return false;

				struct debug_symbol *debug_sym = calloc(1, sizeof(*debug_sym));
				if (!debug_sym)
				{
					warn("Could not alloc ISX debug sym");
					return false;
				}
				debug_sym->ds_name = malloc(symlen + 1);
				if (!debug_sym->ds_name)
				{
					warn("Could not alloc ISX debug sym name");
					debug_destroy_symbol(debug_sym);
					return false;
				}

				if (!rom_read_buffer(file, debug_sym->ds_name, symlen + 1, "ISX debug sym name"))
				{
					debug_destroy_symbol(debug_sym);
					return false;
				}

				u_int8_t type;
				if (!rom_read_buffer(file, &type, sizeof(type), "ISX debug sym type"))
				{
					debug_destroy_symbol(debug_sym);
					return false;
				}
				debug_sym->ds_type = type;

				if (!rom_read_buffer(file, &(debug_sym->ds_addr), sizeof(debug_sym->ds_addr), "ISX debug sym address"))
					return false;

#if 0
				fprintf(stderr, "ISX debug symbol: %s = 0x%08x, unk = %hhu\n", debug_sym->ds_name, debug_sym->ds_addr, type);
#endif // 0

				debug_add_symbol(debug_sym);

				num_syms--;
			}

			break;
		}
		else
		{
			debug_runtime_errorf(NULL, "ISX chunk type 0x%hhx @ 0x%08llx\n",
			                     header.ich_tag, lseek(file->rf_fdesc, 0, SEEK_CUR));
			char *debug_info = malloc(2048);
			if (!rom_read_buffer(file, debug_info, 2048, "ISX chunk data"))
				return false;
			raise(SIGTRAP);
			free(debug_info);
		}
	}

	return true;
}

bool
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

	size_t base_len = (ext) ? ext - fn : strlen(fn);
	rom_symbol_fn = malloc(base_len + sizeof(".sym"));
	if (!rom_symbol_fn)
		err(EX_OSERR, "Alloc filename");
	sprintf(rom_symbol_fn, "%.*s.sym", (int)base_len, fn);
	rom_symbol_fp = fopen(rom_symbol_fn, "r+");
	if (rom_symbol_fp)
	{
		u_int line_num = 0;
		char line[64];
		while (fgets(line, sizeof(line), rom_symbol_fp))
		{
			++line_num;
			u_int32_t addr;
			char name[33];
			if (sscanf(line, "%x %32s", &addr, name) == 2)
				debug_create_symbol(name, addr);
			else
				warnx("%s:%u: Could not parse line", rom_symbol_fn, line_num);
		}
		if (ferror(rom_symbol_fp))
			warn("Read from symbol file %s", rom_symbol_fn);
	}
	else if (errno != ENOENT)
		warn("Could not open symbol file %s", rom_symbol_fn);

	debug_add_syms();

	return status;
}

void
rom_add_symbol(const struct debug_symbol *sym)
{
	if (!rom_symbol_fp && rom_symbol_fn)
	{
		debug_tracef("rom", "Created symbol file %s\n", rom_symbol_fn);
		rom_symbol_fp = fopen(rom_symbol_fn, "a");
		if (!rom_symbol_fp)
			warn("Could not open symbol file %s", rom_symbol_fn);
	}

	if (rom_symbol_fp)
		fprintf(rom_symbol_fp, "%08x %s\n", sym->ds_addr, sym->ds_name);
}

void
rom_unload(void)
{
	mem_seg_free(MEM_SEG_ROM);
	if (rom_symbol_fp)
		fclose(rom_symbol_fp);
	if (rom_symbol_fn)
		free(rom_symbol_fn);

	debug_clear_syms();
}
