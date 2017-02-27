#include "main.h"
#include <sys/stat.h>
#include <sys/mman.h>
#include <sys/fcntl.h>
#include <sys/errno.h>
#include <sys/param.h>
#include <libkern/OSByteOrder.h>
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

static bool __unused
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
		else if (header.ich_tag == ISX_TAG_DEBUG1)
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
					return false;
				}

				if (!rom_read_buffer(file, debug_sym->ds_name, symlen + 1, "ISX debug sym name"))
					return false;

				u_int8_t unk;
				if (!rom_read_buffer(file, &unk, sizeof(unk), "ISX unknown data"))
					return false;

				if (!rom_read_buffer(file, &(debug_sym->ds_addr), sizeof(debug_sym->ds_addr),
							"ISX debug symbol address"))
					return false;

				fprintf(stderr, "ISX debug symbol: %s = 0x%08x, unk = %hhd\n", debug_sym->ds_name, debug_sym->ds_addr, unk);

				debug_add_symbol(debug_sym);

				num_syms--;
			}

			break;
		}
		else if (header.ich_tag == ISX_TAG_DEBUG2 || header.ich_tag == ISX_TAG_DEBUG3)
		{
			char *debug_info = malloc(2048);
			if (!rom_read_buffer(file, debug_info, 2048, "ISX debug info"))
				return false;
			raise(SIGTRAP);
			free(debug_info);
		}
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

enum cpu_opcode
{
	OP_MOV   = 0b000000,
	OP_ADD   = 0b000001,
	OP_SUB   = 0b000010,
	OP_CMP   = 0b000011,
	OP_SHL   = 0b000100,
	OP_SHR   = 0b000101,
	OP_JMP   = 0b000110,
	OP_SAR   = 0b000111,
	OP_MUL   = 0b001000,
	OP_DIV   = 0b001001,
	OP_MULU  = 0b001010,
	OP_DIVU  = 0b001011,
	OP_OR    = 0b001100,
	OP_AND   = 0b001101,
	OP_XOR   = 0b001110,
	OP_NOT   = 0b001111,
	OP_MOV2  = 0b010000,
	OP_ADD2  = 0b010001,
	OP_SETF  = 0b010010,
	OP_CMP2  = 0b010011,
	OP_SHL2  = 0b010100,
	OP_SHR2  = 0b010101,
	OP_CLI   = 0b010110,
	OP_SAR2  = 0b010111,
	OP_TRAP  = 0b011000,
	OP_RETI  = 0b011001,
	OP_HALT  = 0b011010,
	OP_LDSR  = 0b011100,
	OP_STSR  = 0b011101,
	OP_SEI   = 0b011110,
	OP_BSTR  = 0b011111,
	// BCOND
	OP_MOVEA = 0b101000,
	OP_ADDI  = 0b101001,
	OP_JR    = 0b101010,
	OP_JAL   = 0b101011,
	OP_ORI   = 0b101100,
	OP_ANDI  = 0b101101,
	OP_XORI  = 0b101110,
	OP_MOVHI = 0b101111,
	OP_LD_B  = 0b110000,
	OP_LD_H  = 0b110001,
	OP_LD_W  = 0b110011,
	OP_ST_B  = 0b110100,
	OP_ST_H  = 0b110101,
	OP_ST_W  = 0b110111,
	OP_IN_B  = 0b111000,
	OP_IN_H  = 0b111001,
	OP_CAXI  = 0b111010,
	OP_IN_W  = 0b111011,
	OP_OUT_B = 0b111100,
	OP_OUT_H = 0b111101,
	OP_FLOAT = 0b111110,
	OP_OUT_W = 0b111111
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

enum cpu_psw_flags
{
	CPU_PSW_Z  = 1 << 0,
	CPU_PSW_S  = 1 << 1,
	CPU_PSW_OV = 1 << 2,
	CPU_PSW_CY = 1 << 3
};

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

static bool
cpu_fetch(u_int32_t addr, union cpu_inst *inst)
{
	if (!mem_read(addr, &(inst->ci_hwords[0]), 2))
		return false;
	inst->ci_hwords[0] = OSSwapLittleToHostInt16(inst->ci_hwords[0]);
	if (cpu_inst_size(inst) == 4)
	{
		if (!mem_read(addr + 2, &(inst->ci_hwords[1]), 2))
			return false;
		inst->ci_hwords[1] = OSSwapLittleToHostInt16(inst->ci_hwords[1]);
	}
	return true;
}

static bool
cpu_exec(const union cpu_inst inst)
{
	switch (inst.ci_i.i_opcode)
	{
		case OP_MOV:
			cpu_state.cs_r[inst.ci_i.i_reg2] = cpu_state.cs_r[inst.ci_i.i_reg1];
			break;
			/*
	OP_ADD   = 0b000001,
	OP_SUB   = 0b000010,
	OP_CMP   = 0b000011,
	OP_SHL   = 0b000100,
	OP_SHR   = 0b000101,
	*/
		case OP_JMP:
			cpu_state.cs_pc = cpu_state.cs_r[inst.ci_i.i_reg1];
			break;
			/*
	OP_SAR   = 0b000111,
	OP_MUL   = 0b001000,
	OP_DIV   = 0b001001,
	OP_MULU  = 0b001010,
	OP_DIVU  = 0b001011,
	OP_OR    = 0b001100,
	OP_AND   = 0b001101,
	OP_XOR   = 0b001110,
	OP_NOT   = 0b001111,
	*/
		case OP_MOV2:
		{
			u_int32_t imm = inst.ci_ii.ii_imm5;
			if ((imm & 0b10000) == 0b10000)
				imm|= 0xffffffe0;
			cpu_state.cs_r[inst.ci_ii.ii_reg2] = imm;
			break;
		}
		/*
	OP_ADD2  = 0b010001,
	OP_SETF  = 0b010010,
	OP_CMP2  = 0b010011,
	*/
		case OP_SHL2:
			if (inst.ci_ii.ii_imm5)
			{
				u_int32_t start = cpu_state.cs_r[inst.ci_ii.ii_reg2];
				u_int32_t shift = inst.ci_ii.ii_imm5;
				u_int32_t result = start << shift;
				if (((start >> (31 - shift)) & 1) == 1)
					cpu_state.cs_psw|= CPU_PSW_CY;
				else
					cpu_state.cs_psw&= ~CPU_PSW_CY;
				cpu_state.cs_psw&= ~CPU_PSW_OV;
				if ((result & 0x80000000) == 0x80000000)
					cpu_state.cs_psw|= CPU_PSW_S;
				else
					cpu_state.cs_psw&= ~CPU_PSW_S;
				if (result == 0)
					cpu_state.cs_psw|= CPU_PSW_Z;
				else
					cpu_state.cs_psw&= ~CPU_PSW_Z;
				cpu_state.cs_r[inst.ci_ii.ii_reg2] = result;
				break;
			}

			/*
	OP_SHR2  = 0b010101,
	OP_CLI   = 0b010110,
	OP_SAR2  = 0b010111,
	OP_TRAP  = 0b011000,
	OP_RETI  = 0b011001,
	OP_HALT  = 0b011010,
	OP_LDSR  = 0b011100,
	OP_STSR  = 0b011101,
	OP_SEI   = 0b011110,
	OP_BSTR  = 0b011111,
	// BCOND
	*/
		case OP_MOVEA:
		{
			u_int32_t imm = inst.ci_v.v_imm16;
			if ((imm & 0x8000) == 0x8000)
				imm|= 0xffff0000;
			cpu_state.cs_r[inst.ci_v.v_reg2] = cpu_state.cs_r[inst.ci_v.v_reg1] + imm;
			break;
		}
		case OP_ADDI:
		{
			u_int32_t imm = inst.ci_v.v_imm16;
			if ((imm & 0x8000) == 0x8000)
				imm|= 0xffff0000;
			u_int64_t result = (u_int64_t)cpu_state.cs_r[inst.ci_v.v_reg1] + imm;
			if (result == 0)
				cpu_state.cs_psw|= CPU_PSW_Z;
			else
				cpu_state.cs_psw&= ~CPU_PSW_Z;
			if ((result & 0x80000000) == 0x80000000)
				cpu_state.cs_psw|= CPU_PSW_S;
			else
				cpu_state.cs_psw&= ~CPU_PSW_S;
			if ((result & 0x80000000) != (cpu_state.cs_r[inst.ci_v.v_reg1] & 0x80000000))
				cpu_state.cs_psw|= CPU_PSW_OV;
			else
				cpu_state.cs_psw&= ~CPU_PSW_OV;
			if ((result & 0x100000000) == 0x100000000)
				cpu_state.cs_psw|= CPU_PSW_CY;
			else
				cpu_state.cs_psw&= ~CPU_PSW_CY;
			cpu_state.cs_r[inst.ci_v.v_reg2] = result;
			break;
		}
		/*
	OP_JR    = 0b101010,
	OP_JAL   = 0b101011,
	OP_ORI   = 0b101100,
	OP_ANDI  = 0b101101,
	OP_XORI  = 0b101110,
	*/
		case OP_MOVHI:
			cpu_state.cs_r[inst.ci_v.v_reg2] = cpu_state.cs_r[inst.ci_v.v_reg1] | (inst.ci_v.v_imm16 << 16);
			break;
			/*
	OP_LD_B  = 0b110000,
	*/
		case OP_LD_H:
		{
			u_int32_t addr = cpu_state.cs_r[inst.ci_vi.vi_reg1] + inst.ci_vi.vi_disp16;
			u_int16_t value;
			mem_read(addr, &value, sizeof(value));
			if ((value & 0x8000) == 0x8000)
				cpu_state.cs_r[inst.ci_vi.vi_reg2] = 0xffff0000 | value;
			else
				cpu_state.cs_r[inst.ci_vi.vi_reg2] = value;
			break;
		}
		case OP_LD_W:
		{
			u_int32_t addr = cpu_state.cs_r[inst.ci_vi.vi_reg1] + inst.ci_vi.vi_disp16;
			mem_read(addr, cpu_state.cs_r + inst.ci_vi.vi_reg2, sizeof(*cpu_state.cs_r));
			break;
		}
			 /*
	OP_ST_B  = 0b110100,
	*/
		case OP_ST_H:
		{
			u_int32_t addr = cpu_state.cs_r[inst.ci_vi.vi_reg1] + inst.ci_vi.vi_disp16;
			u_int16_t value = cpu_state.cs_r[inst.ci_vi.vi_reg2] & 0xffff;
			mem_write(addr, &value, sizeof(value));
		}
		case OP_ST_W:
		{
			u_int32_t addr = cpu_state.cs_r[inst.ci_vi.vi_reg1] + inst.ci_vi.vi_disp16;
			u_int32_t value = cpu_state.cs_r[inst.ci_vi.vi_reg2];
			mem_write(addr, &value, sizeof(value));
			break;
		}
			 /*
	OP_IN_B  = 0b111000,
	OP_IN_H  = 0b111001,
	OP_CAXI  = 0b111010,
	OP_IN_W  = 0b111011,
	OP_OUT_B = 0b111100,
	OP_OUT_H = 0b111101,
	OP_FLOAT = 0b111110,
	OP_OUT_W = 0b111111
	*/
		default:
			fputs("TODO: execute instruction\n", stderr);
			raise(SIGINT);
			return false;
	}
	return true;
}

static void
cpu_test_addi(int32_t left, int16_t right, int32_t result, bool overflow, bool carry)
{
	union cpu_inst inst;

	inst.ci_v.v_opcode = OP_ADDI;
	cpu_state.cs_r[1] = left;
	inst.ci_v.v_reg1 = 1;
	inst.ci_v.v_imm16 = right;
	cpu_state.cs_r[2] = 0xdeadc0de;
	inst.ci_v.v_reg2 = 2;
	cpu_exec(inst);
	bool ov = (cpu_state.cs_psw & CPU_PSW_OV) == CPU_PSW_OV;
	bool cy = (cpu_state.cs_psw & CPU_PSW_CY) == CPU_PSW_CY;
	if (cpu_state.cs_r[2] != result || ov != overflow || cy != carry)
		fprintf(stderr, "*** Test failure: r1 = 0x%08x; %s\n"
				"\tresult (0x%08x) should be 0x%08x\n"
				"\toverflow flag (%d) should be %s\n"
				"\tcarry flag (%d) should be %s\n",
				left, debug_disasm(&inst),
				cpu_state.cs_r[2], result,
				ov, (overflow) ? "set" : "reset",
				cy, (carry) ? "set" : "reset");
}

static void
cpu_test(void)
{
	fputs("Running CPU self-test\n", stderr);

	cpu_test_addi(1, 1, 2, false, false);
	cpu_test_addi(2147483647, 1, -2147483648, true, false);
	cpu_test_addi(2147483646, 1, 2147483647, false, false);
	cpu_test_addi(2147450881, 32767, -2147483648, true, false);
	cpu_test_addi(2147450880, 32767, 2147483647, false, false);
	cpu_test_addi(-1, -1, -2, false, true);
	cpu_test_addi(-2147483648, -1, 2147483647, true, true);

	cpu_reset();
}

void
cpu_step(void)
{
	union cpu_inst inst;
	if (!cpu_fetch(cpu_state.cs_pc, &inst))
	{
		fprintf(stderr, "TODO: bus error fetching inst from PC 0x%08x\n", cpu_state.cs_pc);
		return;
	}
	u_int32_t old_pc = cpu_state.cs_pc;

	if (!cpu_exec(inst))
		return;

	if (cpu_state.cs_pc == old_pc)
		cpu_state.cs_pc+= cpu_inst_size(&inst);
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

static struct debug_symbol *debug_syms = NULL;

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
	static char bin[35] = "0b";
	assert(nbits <= sizeof(bin) - 3);
	char *end = bin + 2 + nbits;
	*end-- = '\0';
	while (nbits--)
	{
		*end-- = (n & 1) ? '1' : '0';
		n>>= 1;
	}
	return bin;
}

void
debug_add_symbol(struct debug_symbol *debug_sym)
{
	debug_sym->ds_next = debug_syms;
	debug_syms = debug_sym;
}

char *
debug_disasm(const union cpu_inst *inst)
{
	static char dis[32];
	//snprintf(dis, sizeof(dis), "%s", debug_format_binary(inst->ci_hwords[0], 16));
	const char *mnemonic;
	switch (inst->ci_i.i_opcode)
	{
		case OP_MOV:
		case OP_MOV2:
			mnemonic = "MOV";
			break;
		case OP_JMP: mnemonic = "JMP"; break;
		case OP_SHL2: mnemonic = "SHL"; break;
		case OP_MOVHI: mnemonic = "MOVHI"; break;
		case OP_MOVEA: mnemonic = "MOVEA"; break;
		case OP_ADDI: mnemonic = "ADDI"; break;
		case OP_CAXI: mnemonic = "CAXI"; break;
		case OP_IN_B: mnemonic = "IN.B"; break;
		case OP_IN_H: mnemonic = "IN.H"; break;
		case OP_IN_W: mnemonic = "IN.W"; break;
		case OP_LD_B: mnemonic = "LD.B"; break;
		case OP_LD_H: mnemonic = "LD.H"; break;
		case OP_LD_W: mnemonic = "LD.W"; break;
		case OP_OUT_B: mnemonic = "OUT.B"; break;
		case OP_OUT_H: mnemonic = "OUT.H"; break;
		case OP_OUT_W: mnemonic = "OUT.W"; break;
		case OP_ST_B: mnemonic = "ST.B"; break;
		case OP_ST_H: mnemonic = "ST.H"; break;
		case OP_ST_W: mnemonic = "ST.W"; break;
		default:
		{
			static char unknown[32];
			snprintf(unknown, sizeof(unknown), "??? (%s)", debug_format_binary(inst->ci_i.i_opcode, 6));
			mnemonic = unknown;
		}
	}
	switch (inst->ci_i.i_opcode)
	{
		case OP_MOV:
		case OP_ADD:
		case OP_SUB:
		case OP_CMP:
		case OP_SHL:
		case OP_SHR:
		case OP_SAR:
		case OP_MUL:
		case OP_DIV:
		case OP_MULU:
		case OP_DIVU:
		case OP_OR:
		case OP_AND:
		case OP_XOR:
		case OP_NOT:
			snprintf(dis, sizeof(dis), "%s r%d, r%d", mnemonic, inst->ci_i.i_reg1, inst->ci_i.i_reg2);
			break;
		case OP_JMP:
			snprintf(dis, sizeof(dis), "%s [r%d]", mnemonic, inst->ci_i.i_reg1);
			break;
		case OP_MOV2:
		{
			u_int16_t imm = inst->ci_ii.ii_imm5;
			if ((imm & 0b10000) == 0b10000)
				imm|= 0xffffffe0;
			snprintf(dis, sizeof(dis), "%s %d, r%u", mnemonic, imm, inst->ci_ii.ii_reg2);
			break;
		}
		case OP_SHL2:
			snprintf(dis, sizeof(dis), "%s %i, r%u", mnemonic, inst->ci_ii.ii_imm5, inst->ci_ii.ii_reg2);
			break;
		case OP_MOVEA:
		case OP_MOVHI:
			snprintf(dis, sizeof(dis), "%s %hXh, r%d, r%d",
					mnemonic, inst->ci_v.v_imm16, inst->ci_v.v_reg1, inst->ci_v.v_reg2);
			break;
		case OP_ADDI:
			snprintf(dis, sizeof(dis), "%s %hd, r%d, r%d",
					mnemonic, inst->ci_v.v_imm16, inst->ci_v.v_reg1, inst->ci_v.v_reg2);
			break;
		case OP_CAXI:
		case OP_IN_B:
		case OP_IN_H:
		case OP_IN_W:
		case OP_LD_B:
		case OP_LD_H:
		case OP_LD_W:
		case OP_OUT_B:
		case OP_OUT_H:
		case OP_OUT_W:
		case OP_ST_B:
		case OP_ST_H:
		case OP_ST_W:
			snprintf(dis, sizeof(dis), "%s %hd[r%u], r%u",
					mnemonic, inst->ci_vi.vi_disp16, inst->ci_vi.vi_reg1, inst->ci_vi.vi_reg2);
			break;
		default:
			snprintf(dis, sizeof(dis), "TODO: %s", mnemonic);
	}
	return dis;
}

static const struct debug_help
{
	char dh_char;
	const char *dh_usage;
	const char *dh_desc;
} debug_help[] =
{
	{'?', "", "Display this help (aliases: help)"},
	{'q', "", "Quit the emulator (aliases: quit, exit)"},
	{'c', "", "Continue execution (aliases: cont)"},
	{'s', "", "Step into the next instruction (aliases: step)"},
	{'i', "", "Show CPU info (aliases: info)"},
	{'x', "<addr> [<format>] [<count>]", "Examine memory at <addr>\n"
		"\t\tFormats: h (hex), i (instructions)"},
	{'r', "", "Reset the CPU (aliases: reset)"}
};

static void
debug_print_help(const struct debug_help *help)
{
	printf("%c %s\t%s\n", help->dh_char, help->dh_usage, help->dh_desc);
}

static void
debug_usage(char ch)
{
	u_int helpIndex;
	for (helpIndex = 0; helpIndex < sizeof(debug_help) / sizeof(debug_help[0]); ++helpIndex)
	{
		if (debug_help[helpIndex].dh_char == ch)
		{
			debug_print_help(&(debug_help[helpIndex]));
			break;
		}
	}
	assert(helpIndex < sizeof(debug_help) / sizeof(debug_help[0]));
}

static bool
debug_mem_read(u_int32_t addr, void *dest, size_t size)
{
	if (mem_read(addr, dest, size))
		return true;
	else
	{
		warnx("Could not read %lu bytes from 0x%08x: Invalid address\n", size, addr);
		return false;
	}
}

static u_int32_t
debug_parse_addr(const char *s)
{
	if (!strcmp(s, "pc"))
		return cpu_state.cs_pc;
	else
	{
		char *endp;
		u_int32_t addr = strtol(s, &endp, 0);
		if (*endp != '\0')
			warnx("Invalid address “%s”\n", s);
		return addr;
	}
}

static char *
debug_format_addr(u_int32_t addr)
{
	static char s[64];
	static char human[32];
	struct debug_symbol *sym = debug_syms, *match = NULL;
	u_int32_t match_offset;

	while (sym)
	{
		if (sym->ds_addr <= addr)
		{
			u_int32_t offset = addr - sym->ds_addr;
			if (offset <= 8192 && (!match || match_offset > offset))
			{
				match = sym;
				match_offset = offset;
			}
		}

		sym = sym->ds_next;
	}

	if (match)
		snprintf(human, sizeof(human), "<%s+%u>", match->ds_name, match_offset);
	else
		*human = '\0';

	snprintf(s, sizeof(s), "0x%08x %-15s", addr, human);

	return s;
}

void
debug_intr(void)
{
	while (1)
	{
		union cpu_inst inst;
		if (cpu_fetch(cpu_state.cs_pc, &inst))
			printf("frame 0: %s: %s\n", debug_format_addr(cpu_state.cs_pc), debug_disasm(&inst));
		else
			printf("Could not read instruction at 0x%08x\n", cpu_state.cs_pc);

		tok_reset(s_token);
		int length;
		const char *line = el_gets(s_editline, &length);
		if (line)
		{
			int argc;
			const char **argv;
			if (tok_str(s_token, line, &argc, &argv) == 0 && argc > 0)
			{
				if (!strcmp(argv[0], "?") || !strcmp(argv[0], "help"))
				{
					puts("Debugger commands:");
					for (u_int helpIndex = 0; helpIndex < sizeof(debug_help) / sizeof(debug_help[0]); ++helpIndex)
						debug_print_help(&(debug_help[helpIndex]));
				}
				else if (!strcmp(argv[0], "q") || !strcmp(argv[0], "quit") || !strcmp(argv[0], "exit"))
				{
					main_exit();
					break;
				}
				else if (!strcmp(argv[0], "c") || !strcmp(argv[0], "cont"))
					break;
				else if (!strcmp(argv[0], "s") || !strcmp(argv[0], "step"))
					main_step();
				else if (!strcmp(argv[0], "i") || !strcmp(argv[0], "info"))
				{
					static const char *fmt = "\t%3s: %s";
					for (u_int regIndex = 0; regIndex < 32; ++regIndex)
					{
						char rname[5];
						snprintf(rname, sizeof(rname), "r%d", regIndex);
						printf(fmt, rname, debug_format_addr(cpu_state.cs_r[regIndex]));
						printf(" (%11i)", cpu_state.cs_r[regIndex]);
						if (regIndex % 2 == 1)
							putchar('\n');
					}
					printf(fmt, "pc", debug_format_addr(cpu_state.cs_pc));
					printf(fmt, "psw", debug_format_binary(cpu_state.cs_psw, 32));
					putchar('\n');
					printf(fmt, "ecr", debug_format_addr(cpu_state.cs_ecr));
					putchar('\n');
				}
				else if (!strcmp(argv[0], "x"))
				{
					if (argc >= 2)
					{
						u_int32_t addr = debug_parse_addr(argv[1]);
						const char *format = "h";
						u_int count = 1;
						if (argc >= 3)
							format = argv[2];
						if (argc >= 4)
							count = strtoul(argv[3], NULL, 0);

						for (u_int objIndex = 0; objIndex < count; ++objIndex)
						{
							printf("0x%08x:", addr);
							if (!strcmp(format, "h"))
							{
								u_int32_t dword;
								if (debug_mem_read(addr, &dword, sizeof(dword)))
									printf(" %08x\n", dword);
								addr+= sizeof(dword);
							}
							else if (!strcmp(format, "i"))
							{
								union cpu_inst inst;
								if (cpu_fetch(addr, &inst))
									printf(" %s\n", debug_disasm(&inst));
								else
									fputs("Could not fetch instruction\n", stderr);
								addr+= cpu_inst_size(&inst);
							}
							else
							{
								debug_usage('x');
								break;
							}
						}
					}
					else
						debug_usage('x');
				}
				else if (!strcmp(argv[0], "r") || !strcmp(argv[0], "reset"))
					cpu_reset();
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
	bool self_test = false;
	while ((ch = getopt(ac, av, "dt")) != -1)
		switch (ch)
		{
			case '?':
				return main_usage();
			case 'd':
				debug_boot = true;
				break;
			case 't':
				self_test = true;
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

	if (self_test)
		cpu_test();

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
