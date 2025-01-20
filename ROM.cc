#include "ROM.hh"
#include "Memory.hh"
#include "OS.hh"
#include "ROM.Gen.hh"
#include "CPU.hh"
#include <cstdlib>
#include <cstring>
#include <fcntl.h>
#include <sys/stat.h>
#include <csignal>
#include <new>

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
	file->rf_handle = OS_FILE_HANDLE_INVALID;

	if (file->rf_path)
	{
		free(file->rf_path);
		file->rf_path = nullptr;
	}
}

static bool
rom_open(const char *fn, struct rom_file *file)
{
	ASSERT_SIZEOF(isx_symbol_type, 1);

	os_bzero(file, sizeof(*file));

	file->rf_handle = os_file_open(fn, os_perm_mask::READ);
	if (file->rf_handle == OS_FILE_HANDLE_INVALID)
	{
		os_runtime_error(OS_RUNERR_TYPE_OSERR, os_runerr_resp_mask::OKAY, "Could not open ‘%s’", fn);
		return false;
	}

	if (!os_file_getsize(file->rf_handle, &file->rf_size))
	{
		os_runtime_error(OS_RUNERR_TYPE_OSERR, os_runerr_resp_mask::OKAY, "os_file_getsize() ‘%s’", fn);
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
		os_runtime_error(OS_RUNERR_TYPE_WARNING, os_runerr_resp_mask::OKAY, "ROM file ‘%s’ is smaller than minimum size (0x%lx)", file->rf_path, ROM_MIN_SIZE);
		return false;
	}

	if (!IS_POWER_OF_2(file->rf_size))
	{
		os_runtime_error(OS_RUNERR_TYPE_WARNING, os_runerr_resp_mask::OKAY, "Size of ROM file ‘%s’, 0x%llx, is not a power of 2", file->rf_path, file->rf_size);
		return false;
	}

	if (!mem.Segments[Memory::SEG_ROM].Map(file->rf_size, file->rf_handle, os_perm_mask::READ | os_perm_mask::EXEC))
		return false;

	// TODO: check ROM info

	return true;
}

static bool
rom_read_buffer(struct rom_file *file, void *buf, size_t size, const char *desc)
{
	size_t nread = os_file_read(file->rf_handle, buf, size);
	if (nread == size)
		return true;
	else
	{
		bool is_eof = os_file_iseof(file->rf_handle);
		os_runtime_error((is_eof) ? OS_RUNERR_TYPE_WARNING : OS_RUNERR_TYPE_OSERR, os_runerr_resp_mask::OKAY,
				"Read %s from ‘%s’%s", desc, file->rf_path, (is_eof) ? ": Unexpected EOF" : "");
		return false;
	}
}

static bool
rom_seek(struct rom_file *file, off_t off, os_seek_anchor whence)
{
	if (os_file_seek(file->rf_handle, off, whence) != -1)
		return true;
	else
	{
		os_runtime_error(OS_RUNERR_TYPE_OSERR, os_runerr_resp_mask::OKAY, "Seek ‘%s’", file->rf_path);
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
		os_runtime_error(OS_RUNERR_TYPE_WARNING, os_runerr_resp_mask::OKAY, "Invalid ISX magic in ‘%s’", file->rf_path);
		return false;
	}

	// Seek over rest of header:
	if (!rom_seek(file, 32, OS_SEEK_SET))
		return false;

	u_int32_t rom_size = 0;
	while (!os_file_iseof(file->rf_handle))
	{
		struct isx_chunk_header header;
		if (!isx_read_chunk_header(file, &header))
			return false;

		if (header.ich_tag == ISX_TAG_LOAD)
		{
			if (header.ich_addr < 0)
				rom_size+= -header.ich_addr;
			else if (MEM_ADDR2SEG(header.ich_addr) == Memory::SEG_ROM)
			{
				size_t loaded_size = MEM_ADDR2OFF(header.ich_addr) + header.ich_size;
				rom_size = max_uint(rom_size, loaded_size);
			}
			else
			{
				os_runtime_error(OS_RUNERR_TYPE_WARNING, os_runerr_resp_mask::OKAY,
								 "Invalid chunk load addr 0x%08x in ISX file ‘%s’",
								 (u_int32_t)header.ich_addr, file->rf_path);
				return false;
			}

			if (!rom_seek(file, header.ich_size, OS_SEEK_CUR))
				return false;
		}
		else if (header.ich_tag == ISX_TAG_DEBUG)
			break;
	}

	rom_size = Memory::SizeCeil(rom_size);
	rom_size = max_uint(rom_size, ROM_MIN_SIZE);
	if (!mem.Segments[Memory::SEG_ROM].Allocate(rom_size, os_perm_mask::READ | os_perm_mask::EXEC))
		return false;

	cpu_inst halt_inst = {.ci_i = {.i_opcode = static_cast<cpu_opcode>(OP_TRAP)}};
	u_int16_t pattern[2];
	pattern[0] = halt_inst.ci_hwords[0];
	pattern[1] = halt_inst.ci_hwords[1];
	mem.Segments[Memory::SEG_ROM].Fill(halt_inst.ci_word);

	if (!rom_seek(file, 32, OS_SEEK_SET))
		return false;

	while (!os_file_iseof(file->rf_handle))
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

			if (!rom_read_buffer(file, mem.Segments[Memory::SEG_ROM].GetData() + offset, header.ich_size, "ISX chunk"))
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

				struct debug_symbol *debug_sym = new debug_symbol;
				if (!debug_sym)
				{
					os_runtime_error(OS_RUNERR_TYPE_OSERR, os_runerr_resp_mask::OKAY, "Could not alloc ISX debug sym");
					return false;
				}
				os_bzero(debug_sym, sizeof(*debug_sym));
				debug_sym->ds_name = new char[symlen + 1];
				if (!debug_sym->ds_name)
				{
					os_runtime_error(OS_RUNERR_TYPE_OSERR, os_runerr_resp_mask::OKAY, "Could not alloc ISX debug sym name");
					debug_destroy_symbol(debug_sym);
					return false;
				}

				if (!rom_read_buffer(file, debug_sym->ds_name, symlen + 1, "ISX debug sym name"))
				{
					debug_destroy_symbol(debug_sym);
					return false;
				}

				isx_symbol_type type;
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
			char *debug_info = new(std::nothrow) char[2048];
			if (!rom_read_buffer(file, debug_info, 2048, "ISX chunk data"))
				return false;
			os_debug_trap();
			delete[] debug_info;
		}
	}

	return true;
}

bool
rom_load(const char *fn)
{
	ASSERT_SIZEOF(struct isx_chunk_header, 9);

	const char *ext = strrchr(fn, '.');
	bool is_isx = false;
	if (ext && !os_strcasecmp(ext, ".ISX"))
		is_isx = true;
	else if (!ext || os_strcasecmp(ext, ".VB"))
		os_runtime_error(OS_RUNERR_TYPE_WARNING, os_runerr_resp_mask::OKAY, "Can‘t determine file type from ‘%s’, assuming ROM file", fn);

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
	rom_symbol_fn = new(std::nothrow) char[base_len + sizeof(".sym")];
	if (!rom_symbol_fn)
	{
		os_runtime_error(OS_RUNERR_TYPE_OSERR, os_runerr_resp_mask::OKAY, "Alloc filename");
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
				os_runtime_error(OS_RUNERR_TYPE_WARNING, os_runerr_resp_mask::OKAY, "%s:%u: Could not parse line", rom_symbol_fn, line_num);
		}
		if (ferror(rom_symbol_fp))
			os_runtime_error(OS_RUNERR_TYPE_OSERR, os_runerr_resp_mask::OKAY, "Read from symbol file %s", rom_symbol_fn);
	}
	else if (os_file_exists(rom_symbol_fn))
		os_runtime_error(OS_RUNERR_TYPE_OSERR, os_runerr_resp_mask::OKAY, "Could not open symbol file %s", rom_symbol_fn);

	// FIXME: Windows path separators
	const char *sep = strrchr(fn, '/');
	const char *name = (sep) ? sep + 1 : fn;
	size_t name_len = (ext) ? ext - name : strlen(name);
	rom_name = new(std::nothrow) char[name_len + 1];
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
		debug_tracef("rom", "Created symbol file %s", rom_symbol_fn);
		rom_symbol_fp = fopen(rom_symbol_fn, "a");
		if (!rom_symbol_fp)
			os_runtime_error(OS_RUNERR_TYPE_OSERR, os_runerr_resp_mask::OKAY, "Could not open symbol file %s", rom_symbol_fn);
	}

	if (rom_symbol_fp)
		fprintf(rom_symbol_fp, "%08x %s\n", sym->ds_addr, sym->ds_name);
}

void
rom_unload(void)
{
	mem.Segments[Memory::SEG_ROM].Free();
	if (rom_symbol_fp)
	{
		fclose(rom_symbol_fp);
		rom_symbol_fp = nullptr;
	}
	if (rom_symbol_fn)
	{
		free(rom_symbol_fn);
		rom_symbol_fn = nullptr;
	}

	if (rom_name)
	{
		free(rom_name);
		rom_name = nullptr;
	}

	debug_clear_rom_syms();

	rom_loaded = false;
}
