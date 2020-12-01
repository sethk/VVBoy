#include "types.h"
#include "rom.h"
#include <stdlib.h>
#include <string.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <signal.h>

#if INTERFACE
	enum isx_symbol_type
	{
		ISX_SYMBOL_CONST = 0,
		ISX_SYMBOL_POINTER = 16,
		ISX_SYMBOL_END = 214
	};
#endif // INTERFACE

char *rom_name = NULL;
bool rom_loaded = false;

#define ROM_BASE_ADDR 0x07000000
#define ROM_MIN_SIZE 1024lu
#define ROM_MAX_SIZE 0x01000000

#define IS_POWER_OF_2(n) (((n) & ((n) - 1)) == 0)

struct rom_file
{
	os_file_handle_t rf_handle;
	off_t rf_size;
	char *rf_path;
};

static FILE *rom_symbol_fp = NULL;
static char *rom_symbol_fn = NULL;

static void
rom_close(struct rom_file *file)
{
	os_file_close(file->rf_handle);
	if (file->rf_path)
		free(file->rf_path);
}

static bool
rom_open(const char *fn, struct rom_file *file)
{
	os_bzero(file, sizeof(*file));

	file->rf_handle = os_file_open(fn, OS_PERM_READ);
	if (file->rf_handle == OS_FILE_HANDLE_INVALID)
	{
		os_runtime_error(OS_RUNERR_TYPE_OSERR, BIT(OS_RUNERR_RESP_OKAY), "Could not open ‘%s’", fn);
		return false;
	}

	if (!os_file_getsize(file->rf_handle, &file->rf_size))
	{
		os_runtime_error(OS_RUNERR_TYPE_OSERR, BIT(OS_RUNERR_RESP_OKAY), "os_file_getsize() ‘%s’", fn);
		rom_close(file);
		return false;
	}

	file->rf_path = strdup(fn);
	if (!file->rf_path)
		main_fatal_error(OS_RUNERR_TYPE_OSERR, "Alloc path");

	return true;
}

static bool
rom_read(struct rom_file *file)
{
	if (file->rf_size < (off_t)ROM_MIN_SIZE)
	{
		os_runtime_error(OS_RUNERR_TYPE_WARNING, BIT(OS_RUNERR_RESP_OKAY), "ROM file ‘%s’ is smaller than minimum size (0x%lx)", file->rf_path, ROM_MIN_SIZE);
		return false;
	}

	if (!IS_POWER_OF_2(file->rf_size))
	{
		os_runtime_error(OS_RUNERR_TYPE_WARNING, BIT(OS_RUNERR_RESP_OKAY), "Size of ROM file ‘%s’, 0x%llx, is not a power of 2", file->rf_path, file->rf_size);
		return false;
	}

	if (!mem_seg_mmap(MEM_SEG_ROM, file->rf_size, file->rf_handle))
		return false;
	mem_segs[MEM_SEG_ROM].ms_perms = OS_PERM_READ | OS_PERM_EXEC;

	// TODO: check ROM info

	return true;
}

static bool
rom_read_buffer(struct rom_file *file, void *buf, size_t size, const char *desc)
{
	size_t nread = os_file_read(file->rf_handle, buf, size);
	if (nread == (int64_t)size)
		return true;
	else
	{
		os_runtime_error(OS_RUNERR_TYPE_WARNING, BIT(OS_RUNERR_RESP_OKAY), "Read %s from ‘%s’: %s", desc, file->rf_path, (nread == -1) ? strerror(errno) : "Unexpected EOF");
		return false;
	}
}

static bool
rom_seek(struct rom_file *file, off_t off, int whence)
{
	if (os_file_seek(file->rf_handle, off, whence) != -1)
		return true;
	else
	{
		os_runtime_error(OS_RUNERR_TYPE_OSERR, BIT(OS_RUNERR_RESP_OKAY), "Seek ‘%s’", file->rf_path);
		return false;
	}
}

enum isx_tag
{
	ISX_TAG_LOAD = 0x11,
	ISX_TAG_DEBUG = 0x14
};

#pragma pack(push, 1)
struct isx_chunk_header
{
	u_char ich_tag;
	int32_t ich_addr;
	u_int32_t ich_size;
};
#pragma pack(pop)

static bool
isx_is_eof(struct rom_file *file)
{
	return (os_file_seek(file->rf_handle, 0, OS_SEEK_CUR) == file->rf_size);
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
	if (os_bcmp(magic, ISX_MAGIC, sizeof(ISX_MAGIC)))
	{
		os_runtime_error(OS_RUNERR_TYPE_WARNING, BIT(OS_RUNERR_RESP_OKAY), "Invalid ISX magic in ‘%s’", file->rf_path);
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
				rom_size = max_uint(rom_size, loaded_size);
			}
			else
			{
				os_runtime_error(OS_RUNERR_TYPE_WARNING, BIT(OS_RUNERR_RESP_OKAY),
								 "Invalid chunk load addr 0x%08x in ISX file ‘%s’",
								 (u_int32_t)header.ich_addr, file->rf_path);
				return false;
			}

			if (!rom_seek(file, header.ich_size, SEEK_CUR))
				return false;
		}
		else if (header.ich_tag == ISX_TAG_DEBUG)
			break;
	}

	rom_size = mem_size_ceil(rom_size);
	rom_size = max_uint(rom_size, ROM_MIN_SIZE);
	if (!mem_seg_alloc(MEM_SEG_ROM, rom_size, OS_PERM_READ | OS_PERM_EXEC))
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
					os_runtime_error(OS_RUNERR_TYPE_OSERR, BIT(OS_RUNERR_RESP_OKAY), "Could not alloc ISX debug sym");
					return false;
				}
				debug_sym->ds_name = malloc(symlen + 1);
				if (!debug_sym->ds_name)
				{
					os_runtime_error(OS_RUNERR_TYPE_OSERR, BIT(OS_RUNERR_RESP_OKAY), "Could not alloc ISX debug sym name");
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
				debug_printf("ISX debug symbol: %s = 0x%08x, unk = %hhu\n",
							 debug_sym->ds_name, debug_sym->ds_addr, type);
#endif // 0

				debug_add_symbol(debug_sym);

				num_syms--;
			}

			break;
		}
		else
		{
			debug_runtime_errorf(NULL, "ISX chunk type 0x%hhx @ 0x%08llx\n",
								 header.ich_tag, os_file_seek(file->rf_handle, 0, OS_SEEK_CUR));
			char *debug_info = malloc(2048);
			if (!rom_read_buffer(file, debug_info, 2048, "ISX chunk data"))
				return false;
			os_debug_trap();
			free(debug_info);
		}
	}

	return true;
}

bool
rom_load(const char *fn)
{
	assert_sizeof(struct isx_chunk_header, 9);

	char *ext = strrchr(fn, '.');
	bool is_isx = false;
	if (ext && !stricmp(ext, ".ISX"))
		is_isx = true;
	else if (!ext || stricmp(ext, ".VB"))
		os_runtime_error(OS_RUNERR_TYPE_WARNING, BIT(OS_RUNERR_RESP_OKAY), "Can‘t determine file type from ‘%s’, assuming ROM file", fn);

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
	{
		os_runtime_error(OS_RUNERR_TYPE_OSERR, BIT(OS_RUNERR_RESP_OKAY), "Alloc filename");
		return false;
	}
	os_snprintf(rom_symbol_fn, base_len + sizeof(".sym"), "%.*s.sym", (int)base_len, fn);
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
				debug_create_symbol(name, addr, false);
			else
				os_runtime_error(OS_RUNERR_TYPE_WARNING, BIT(OS_RUNERR_RESP_OKAY), "%s:%u: Could not parse line", rom_symbol_fn, line_num);
		}
		if (ferror(rom_symbol_fp))
			os_runtime_error(OS_RUNERR_TYPE_OSERR, BIT(OS_RUNERR_RESP_OKAY), "Read from symbol file %s", rom_symbol_fn);
	}
	else if (errno != ENOENT)
		os_runtime_error(OS_RUNERR_TYPE_OSERR, BIT(OS_RUNERR_RESP_OKAY), "Could not open symbol file %s", rom_symbol_fn);

	const char *sep = strrchr(fn, '/');
	const char *name = (sep) ? sep + 1 : fn;
	size_t name_len = (ext) ? ext - name : strlen(name);
	rom_name = malloc(name_len + 1);
	os_bcopy(name, rom_name, name_len);
	rom_name[name_len] = '\0';
	rom_loaded = true;

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
			os_runtime_error(OS_RUNERR_TYPE_OSERR, BIT(OS_RUNERR_RESP_OKAY), "Could not open symbol file %s", rom_symbol_fn);
	}

	if (rom_symbol_fp)
		fprintf(rom_symbol_fp, "%08x %s\n", sym->ds_addr, sym->ds_name);
}

const void *
rom_get_read_ptr(u_int32_t addr)
{
	u_int32_t offset = addr & mem_segs[MEM_SEG_ROM].ms_addrmask;
	return mem_segs[MEM_SEG_ROM].ms_ptr + offset;
}

void
rom_unload(void)
{
	mem_seg_free(MEM_SEG_ROM);
	if (rom_symbol_fp)
		fclose(rom_symbol_fp);
	if (rom_symbol_fn)
		free(rom_symbol_fn);

	if (rom_name)
	{
		free(rom_name);
		rom_name = NULL;
	}

	debug_clear_rom_syms();

	rom_loaded = false;
}
