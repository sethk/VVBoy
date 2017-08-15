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
	[MEM_SEG_NVC] = "NVC",
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

		const void *src;
		if (seg == MEM_SEG_VIP)
		{
			if (!(src = vip_mem_emu2host(addr, size)))
				return false;
		}
		else
			src = mem_segs[seg].ms_ptr + offset;

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
		warnx("Bus error at 0x%08x", addr);
		debug_intr();
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

		void *dest;
		if (seg == MEM_SEG_VIP)
		{
			if (!(dest = vip_mem_emu2host(addr, size)))
				return false;
		}
		else
			dest = mem_segs[seg].ms_ptr + offset;

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
		fprintf(stderr, "No segment found for address 0x%08x\n", addr);
		debug_intr();
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

				#if 0
					fprintf(stderr, "ISX debug symbol: %s = 0x%08x, unk = %hhd\n", debug_sym->ds_name, debug_sym->ds_addr, unk);
				#endif // 0

				debug_add_symbol(debug_sym);

				num_syms--;
			}

			break;
		}
		else if (header.ich_tag == ISX_TAG_DEBUG2 || header.ich_tag == ISX_TAG_DEBUG3)
		{
			fprintf(stderr, "Debug info type 0x%hhx @ 0x%08llx\n", header.ich_tag, lseek(file->rf_fdesc, 0, SEEK_CUR));
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
union cpu_psw
{
	u_int32_t psw_word;
	struct
	{
		unsigned f_z : 1;
		unsigned f_s : 1;
		unsigned f_ov : 1;
		unsigned f_cy : 1;
		unsigned f_fpr : 1;
		unsigned f_fud : 1;
		unsigned f_fov : 1;
		unsigned f_fzd : 1;
		unsigned f_fiv : 1;
		unsigned f_fro : 1;
		unsigned reserved1 : 2;
		unsigned f_id : 1;
		unsigned f_ae : 1;
		unsigned f_ep : 1;
		unsigned f_np : 1;
		unsigned f_i : 4;
	} psw_flags;
};

static struct cpu_state
{
	cpu_regs_t cs_r;
	u_int32_t cs_pc;
	union cpu_psw cs_psw;
	struct cpu_ecr
	{
		int16_t ecr_eicc;
		int16_t ecr_fecc;
	} cs_ecr;
	u_int32_t cs_eipc;
	union cpu_psw cs_eipsw;
	u_int32_t cs_fepc;
	union cpu_psw cs_fepsw;
	u_int32_t cs_chcw;
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
	OP_BCOND = 0b100,
	  BCOND_BV  = 0b0000,
	  BCOND_BL  = 0b0001,
	  BCOND_BZ  = 0b0010,
	  BCOND_BNH = 0b0011,
	  BCOND_BN  = 0b0100,
	  BCOND_BR  = 0b0101,
	  BCOND_BLT = 0b0110,
	  BCOND_BLE = 0b0111,
	  BCOND_BNV = 0b1000,
	  BCOND_BNC = 0b1001,
	  BCOND_BNZ = 0b1010,
	  BCOND_BH  = 0b1011,
	  BCOND_BP  = 0b1100,
	  BCOND_NOP = 0b1101,
	  BCOND_BGE = 0b1110,
	  BCOND_BGT = 0b1111,
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
	// TODO: Nintendo extra instructions
	OP_OUT_W = 0b111111
};

enum cpu_regid
{
	REGID_PSW = 5,
	REGID_CHCW = 24
};

enum cpu_chcw_flags
{
	CPU_CHCW_ICE = (1 << 1)
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
	cpu_state.cs_psw.psw_word = 0;
	cpu_state.cs_psw.psw_flags.f_np = 1;
	cpu_state.cs_ecr.ecr_fecc = 0;
	cpu_state.cs_ecr.ecr_eicc = 0xfff0;
	cpu_state.cs_chcw = CPU_CHCW_ICE;
}

static size_t
cpu_inst_size(const union cpu_inst *inst)
{
	return (inst->ci_i.i_opcode < 0x28) ? 2 : 4;
}

static bool
cpu_fetch(u_int32_t addr, union cpu_inst *inst)
{
	if (!mem_read(addr, &(inst->ci_hwords[0]), 2))
	{
		printf("Could not read instruction at 0x%08x\n", addr);
		return false;
	}
	inst->ci_hwords[0] = OSSwapLittleToHostInt16(inst->ci_hwords[0]);
	if (cpu_inst_size(inst) == 4)
	{
		if (!mem_read(addr + 2, &(inst->ci_hwords[1]), 2))
		{
			printf("Could not read instruction at 0x%08x\n", addr + 2);
			return false;
		}
		inst->ci_hwords[1] = OSSwapLittleToHostInt16(inst->ci_hwords[1]);
	}
	return true;
}

static const u_int32_t sign_bit32 = 0x80000000;

static inline u_int32_t
cpu_extend9(u_int32_t s9)
{
	if ((s9 & 0x100) == 0x100)
		s9|= 0xfffffe00;
	return s9;
}

static inline u_int16_t
cpu_extend5to16(u_int16_t s5)
{
	if ((s5 & 0b10000) == 0b10000)
		s5|= 0xffe0;
	return s5;
}

static void
cpu_setfl(u_int64_t result, u_int32_t left, bool sign_agree)
{
	cpu_state.cs_psw.psw_flags.f_z = (result == 0);
	cpu_state.cs_psw.psw_flags.f_s = ((result & sign_bit32) == sign_bit32);
	cpu_state.cs_psw.psw_flags.f_cy = ((result & 0x100000000) == 0x100000000);
	if (sign_agree)
		cpu_state.cs_psw.psw_flags.f_ov = ((result & sign_bit32) != (left & sign_bit32));
	else
		cpu_state.cs_psw.psw_flags.f_ov = 0;
}

static u_int32_t
cpu_add(u_int32_t left, u_int32_t right)
{
	u_int64_t result = (u_int64_t)left + right;
	cpu_setfl(result, left, (left & sign_bit32) == (right & sign_bit32));
	return result;
}

static u_int32_t
cpu_sub(u_int32_t left, u_int32_t right)
{
	u_int64_t result = (u_int64_t)left - right;
	cpu_setfl(result, left, (left & sign_bit32) != (right & sign_bit32));
	return result;
}

static bool
cpu_exec(const union cpu_inst inst)
{
	switch (inst.ci_i.i_opcode)
	{
		case OP_MOV:
			cpu_state.cs_r[inst.ci_i.i_reg2] = cpu_state.cs_r[inst.ci_i.i_reg1];
			break;
		case OP_ADD:
			cpu_state.cs_r[inst.ci_i.i_reg2] =
					cpu_add(cpu_state.cs_r[inst.ci_i.i_reg2], cpu_state.cs_r[inst.ci_i.i_reg1]);
			break;
		case OP_SUB:
			cpu_state.cs_r[inst.ci_i.i_reg2] =
					cpu_sub(cpu_state.cs_r[inst.ci_i.i_reg2], cpu_state.cs_r[inst.ci_i.i_reg1]);
			break;
		case OP_CMP:
			cpu_sub(cpu_state.cs_r[inst.ci_i.i_reg2], cpu_state.cs_r[inst.ci_i.i_reg1]);
			break;
			/*
	OP_SHL   = 0b000100,
	OP_SHR   = 0b000101,
	*/
		case OP_JMP:
			cpu_state.cs_pc = cpu_state.cs_r[inst.ci_i.i_reg1];
			break;
			/*
	OP_SAR   = 0b000111,
	*/
		case OP_MUL:
		{
			int64_t result = (int64_t)(int32_t)cpu_state.cs_r[inst.ci_i.i_reg2] *
					(int32_t)cpu_state.cs_r[inst.ci_i.i_reg1];
			cpu_state.cs_psw.psw_flags.f_z = (result == 0);
			cpu_state.cs_psw.psw_flags.f_s = ((result & 0x8000000000000000) == 0x8000000000000000);
			u_int64_t signbits = result & 0xffffffff80000000;
			cpu_state.cs_psw.psw_flags.f_ov = (signbits != 0 && signbits != 0xffffffff80000000);
			cpu_state.cs_r[30] = (u_int64_t)result >> 32;
			cpu_state.cs_r[inst.ci_i.i_reg2] = result & 0xffffffff;
			break;
		}
			 /*
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
		case OP_ADD2:
		{
			u_int32_t imm = inst.ci_ii.ii_imm5;
			if ((imm & 0b10000) == 0b10000)
				imm|= 0xffffffe0;
			cpu_state.cs_r[inst.ci_ii.ii_reg2] = cpu_add(cpu_state.cs_r[inst.ci_ii.ii_reg2], imm);
			break;
		}
		/*
	OP_SETF  = 0b010010,
	*/
		case OP_CMP2:
		{
			u_int32_t imm = inst.ci_ii.ii_imm5;
			if ((imm & 0b10000) == 0b10000)
				imm|= 0xffffffe0;
			cpu_sub(cpu_state.cs_r[inst.ci_ii.ii_reg2], imm);
			break;
		}
		case OP_SHL2:
			if (inst.ci_ii.ii_imm5)
			{
				u_int32_t start = cpu_state.cs_r[inst.ci_ii.ii_reg2];
				u_int32_t shift = inst.ci_ii.ii_imm5;
				u_int32_t result = start << shift;
				cpu_state.cs_psw.psw_flags.f_cy = ((start >> (31 - shift)) & 1);
				cpu_state.cs_psw.psw_flags.f_ov = 0;
				cpu_state.cs_psw.psw_flags.f_s = ((result & sign_bit32) == sign_bit32);
				cpu_state.cs_psw.psw_flags.f_z = (result == 0);
				cpu_state.cs_r[inst.ci_ii.ii_reg2] = result;
			}
			break;

			/*
	OP_SHR2  = 0b010101,
	OP_CLI   = 0b010110,
	*/
		case OP_SAR2:
			if (inst.ci_ii.ii_imm5)
			{
				u_int32_t start = cpu_state.cs_r[inst.ci_ii.ii_reg2];
				u_int32_t shift = inst.ci_ii.ii_imm5;
				u_int32_t result = start >> shift;
				cpu_state.cs_psw.psw_flags.f_cy = ((start >> (shift - 1)) & 1);
				cpu_state.cs_psw.psw_flags.f_ov = 0;
				if ((start & sign_bit32) == sign_bit32)
				{
					result|= (0xffffffff << (32 - shift));
					cpu_state.cs_psw.psw_flags.f_s = 1;
				}
				else
					cpu_state.cs_psw.psw_flags.f_s = 0;
				cpu_state.cs_psw.psw_flags.f_z = (result == 0);
				cpu_state.cs_r[inst.ci_ii.ii_reg2] = result;
			}
			break;

			 /*
	OP_TRAP  = 0b011000,
	OP_RETI  = 0b011001,
	OP_HALT  = 0b011010,
	*/
		case OP_LDSR:
			switch (inst.ci_ii.ii_imm5)
			{
				case REGID_PSW:
					cpu_state.cs_psw.psw_word = cpu_state.cs_r[inst.ci_ii.ii_reg2];
					break;
				case REGID_CHCW:
				{
					u_int32_t chcw = cpu_state.cs_r[inst.ci_ii.ii_reg2];
					if (chcw & ~CPU_CHCW_ICE)
					{
						warnx("Unsupported CHCW commands");
						debug_intr();
						return false;
					}
					cpu_state.cs_chcw = chcw;
					break;
				}
				default:
					warnx("Unsupported regID %d", inst.ci_ii.ii_imm5);
					debug_intr();
					return false;
			}
			break;
			 /*
	OP_STSR  = 0b011101,
	OP_SEI   = 0b011110,
	OP_BSTR  = 0b011111,
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
			cpu_state.cs_r[inst.ci_v.v_reg2] = cpu_add(cpu_state.cs_r[inst.ci_v.v_reg1], imm);
			break;
		}
		/*
	OP_JR    = 0b101010,
	OP_JAL   = 0b101011,
	*/
		case OP_JAL:
		{
			u_int32_t disp = (inst.ci_iv.iv_disp10 << 16) | inst.ci_iv.iv_disp16;
			if ((disp & 0x2000000) == 0x2000000)
				disp|= 0xfd000000;
			cpu_state.cs_r[31] = cpu_state.cs_pc + 4;
			cpu_state.cs_pc+= disp;
			break;
		}
		case OP_ORI:
		{
			u_int32_t result = cpu_state.cs_r[inst.ci_v.v_reg1] | inst.ci_v.v_imm16;
			cpu_state.cs_psw.psw_flags.f_z = (result == 0);
			cpu_state.cs_psw.psw_flags.f_s = ((result & sign_bit32) == sign_bit32);
			cpu_state.cs_psw.psw_flags.f_ov = 0;
			cpu_state.cs_r[inst.ci_v.v_reg2] = result;
			break;
		}
		case OP_ANDI:
		{
			u_int32_t result = cpu_state.cs_r[inst.ci_v.v_reg1] & inst.ci_v.v_imm16;
			cpu_state.cs_psw.psw_flags.f_z = (result == 0);
			cpu_state.cs_psw.psw_flags.f_s = ((result & sign_bit32) == sign_bit32);
			cpu_state.cs_psw.psw_flags.f_ov = 0;
			cpu_state.cs_r[inst.ci_v.v_reg2] = result;
			break;
		}
			 /*
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
			if (!mem_read(addr, &value, sizeof(value)))
				return false;
			if ((value & 0x8000) == 0x8000)
				cpu_state.cs_r[inst.ci_vi.vi_reg2] = 0xffff0000 | value;
			else
				cpu_state.cs_r[inst.ci_vi.vi_reg2] = value;
			break;
		}
		case OP_LD_W:
		{
			u_int32_t addr = cpu_state.cs_r[inst.ci_vi.vi_reg1] + inst.ci_vi.vi_disp16;
			if (!mem_read(addr, cpu_state.cs_r + inst.ci_vi.vi_reg2, sizeof(*cpu_state.cs_r)))
				return false;
			break;
		}
			 /*
	OP_ST_B  = 0b110100,
	*/
		case OP_ST_H:
		{
			u_int32_t addr = cpu_state.cs_r[inst.ci_vi.vi_reg1] + inst.ci_vi.vi_disp16;
			u_int16_t value = cpu_state.cs_r[inst.ci_vi.vi_reg2] & 0xffff;
			if (!mem_write(addr, &value, sizeof(value)))
				return false;
			break;
		}
		case OP_ST_W:
		{
			u_int32_t addr = cpu_state.cs_r[inst.ci_vi.vi_reg1] + inst.ci_vi.vi_disp16;
			u_int32_t value = cpu_state.cs_r[inst.ci_vi.vi_reg2];
			if (!mem_write(addr, &value, sizeof(value)))
				return false;
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
			if (inst.ci_iii.iii_opcode == OP_BCOND)
			{
				bool branch;
				switch (inst.ci_iii.iii_cond)
				{
					/*
					BCOND_BV  = 0b0000,
					*/
					case BCOND_BL:
						branch = cpu_state.cs_psw.psw_flags.f_cy;
						break;
					case BCOND_BZ:
						branch = cpu_state.cs_psw.psw_flags.f_z;
						break;
					/*
					BCOND_BNH = 0b0011,
					BCOND_BN  = 0b0100,
					BCOND_BR  = 0b0101,
					*/
					case BCOND_BLT:
						branch = cpu_state.cs_psw.psw_flags.f_s ^ cpu_state.cs_psw.psw_flags.f_ov;
						break;
					/*
					BCOND_BLE = 0b0111,
					BCOND_BNV = 0b1000,
					BCOND_BNC = 0b1001,
					BCOND_BNZ = 0b1010,
					BCOND_BH  = 0b1011,
					BCOND_BP  = 0b1100,
					BCOND_NOP = 0b1101,
					BCOND_BGE = 0b1110,
					BCOND_BGT = 0b1111,
					*/
					default:
						fputs("Handle branch cond\n", stderr);
						debug_intr();
						return false;
				}
				if (branch)
				{
					u_int32_t disp = cpu_extend9(inst.ci_iii.iii_disp9);
					cpu_state.cs_pc+= disp;
				}
				break;
			}
			fputs("TODO: execute instruction\n", stderr);
			debug_intr();
			return false;
	}
	return true;
}

static void
cpu_assert_reg(const char *dis, unsigned reg, u_int32_t value)
{
	if (cpu_state.cs_r[reg] != value)
		fprintf(stderr, "*** Test failure: %s\n\tr%u (0x%08x) should be 0x%08x\n",
				dis, reg, cpu_state.cs_r[reg], value);
}

static void
cpu_assert_flag(const char *dis, const char *name, bool flag, bool value)
{
	if (flag != value)
		fprintf(stderr, "*** Test failure: %s\n\t%s flag (%d) should be %s\n",
				dis, name, flag, (value) ? "set" : "reset");
}

static void
cpu_assert_overflow(const char *dis, bool overflow)
{
	cpu_assert_flag(dis, "overflow", cpu_state.cs_psw.psw_flags.f_ov, overflow);
}

static void
cpu_assert_sign(const char *dis, bool sign)
{
	cpu_assert_flag(dis, "sign", cpu_state.cs_psw.psw_flags.f_s, sign);
}

static void
cpu_assert_carry(const char *dis, bool carry)
{
	cpu_assert_flag(dis, "carry", cpu_state.cs_psw.psw_flags.f_cy, carry);
}

static void
cpu_test_add(int32_t left, int32_t right, int32_t result, bool overflow, bool carry)
{
	union cpu_inst inst;
	inst.ci_v.v_opcode = OP_ADD;
	cpu_state.cs_r[2] = left;
	inst.ci_v.v_reg2 = 2;
	cpu_state.cs_r[1] = right;
	inst.ci_v.v_reg1 = 1;
	cpu_exec(inst);
	const char *dis = debug_disasm(&inst, 0, cpu_state.cs_r);
	cpu_assert_reg(dis, 2, result);
	cpu_assert_overflow(dis, overflow);
	cpu_assert_carry(dis, carry);
}

static void
cpu_test_sub(int32_t left, int32_t right, int32_t result, bool overflow, bool carry)
{
	union cpu_inst inst;
	inst.ci_i.i_opcode = OP_SUB;
	cpu_state.cs_r[2] = left;
	inst.ci_i.i_reg2 = 2;
	cpu_state.cs_r[1] = right;
	inst.ci_i.i_reg1 = 1;
	const char *dis = debug_disasm(&inst, 0, cpu_state.cs_r);
	cpu_exec(inst);
	cpu_assert_reg(dis, 2, result);
	cpu_assert_overflow(dis, overflow);
	cpu_assert_carry(dis, carry);
}

static void
cpu_test_mul(int32_t left, int32_t right, u_int32_t result, bool overflow, bool sign, u_int32_t carry)
{
	union cpu_inst inst;
	inst.ci_i.i_opcode = OP_MUL;
	cpu_state.cs_r[1] = left;
	inst.ci_i.i_reg1 = 1;
	cpu_state.cs_r[2] = right;
	inst.ci_i.i_reg2 = 2;
	cpu_state.cs_r[30] = 0xdeadc0de;
	const char *dis = debug_disasm(&inst, 0, cpu_state.cs_r);
	cpu_exec(inst);
	cpu_assert_reg(dis, 2, result);
	cpu_assert_overflow(dis, overflow);
	cpu_assert_sign(dis, sign);
	cpu_assert_reg(dis, 30, carry);
}

void
cpu_test(void)
{
	fputs("Running CPU self-test\n", stderr);

	cpu_test_add(1, 1, 2, false, false);
	cpu_test_add(2147483647, 1, -2147483648, true, false);
	cpu_test_add(1, 2147483647, -2147483648, true, false);
	cpu_test_add(2147483646, 1, 2147483647, false, false);
	cpu_test_add(1, 2147483646, 2147483647, false, false);
	cpu_test_add(2147450881, 32767, -2147483648, true, false);
	cpu_test_add(2147450880, 32767, 2147483647, false, false);
	cpu_test_add(-1, -1, -2, false, true);
	cpu_test_add(-2147483648, -1, 2147483647, true, true);

	cpu_test_sub(1, 0, 1, false, false);
	cpu_test_sub(1, 1, 0, false, false);
	cpu_test_sub(2, 1, 1, false, false);
	cpu_test_sub(0, 1, -1, false, true);
	cpu_test_sub(0, 2, -2, false, true);
	cpu_test_sub(-1, 0, -1, false, false);
	cpu_test_sub(-1, -2, 1, false, false);
	cpu_test_sub(-2147483648, 1, 2147483647, true, false);
	cpu_test_sub(2147483646, 2147483647, -1, false, true);
	cpu_test_sub(2147483647, -1, -2147483648, true, true);
	cpu_test_sub(2147483647, -2147483648, -1, true, true);
	cpu_test_sub(2147483647, -2147483647, -2, true, true);
	cpu_test_sub(0, 9, -9, false, true);

	cpu_test_mul(1, 1, 1, false, false, 0);
	cpu_test_mul(1, -1, -1, false, true, 0xffffffff);
	cpu_test_mul(-1, 1, -1, false, true, 0xffffffff);
	cpu_test_mul(0x7fffffff, 0x7fffffff, 1, true, false, 0x3fffffff);
	cpu_test_mul(0x40000000, 4, 0, true, false, 1);

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

	if (debug_tracing)
		debug_trace(&inst);

	if (!cpu_exec(inst))
		return;

	if (cpu_state.cs_pc == old_pc)
		cpu_state.cs_pc+= cpu_inst_size(&inst);
}

void
cpu_intr(u_int level)
{
	if (!cpu_state.cs_psw.psw_flags.f_np && !cpu_state.cs_psw.psw_flags.f_ep && !cpu_state.cs_psw.psw_flags.f_id)
	{
		if (level >= cpu_state.cs_psw.psw_flags.f_i)
		{
			cpu_state.cs_eipc = cpu_state.cs_pc;
			cpu_state.cs_eipsw = cpu_state.cs_eipsw;
			cpu_state.cs_ecr.ecr_eicc = 0xfe00 | (level << 4);
			cpu_state.cs_psw.psw_flags.f_ep = 1;
			cpu_state.cs_psw.psw_flags.f_id = 1;
			cpu_state.cs_psw.psw_flags.f_ae = 0;
			cpu_state.cs_psw.psw_flags.f_i = MIN(level + 1, 15);
			cpu_state.cs_pc = cpu_state.cs_ecr.ecr_eicc;
		}
	}
}

/* Scanner */
bool
scanner_init(void)
{
	// TODO
	return true;
}

void
scanner_step(void)
{
	// TODO: Update FCLK
	// TODO: Refresh left or right image from FBs
}

void
scanner_fini(void)
{
	// TODO
}

/* VIP */
struct vip_chr
{
	u_int16_t chr_rows[8];
};

static struct
{
	u_int8_t vv_left0[0x6000];
	struct vip_chr vv_chr0[512];
	u_int8_t vv_left1[0x6000];
	struct vip_chr vv_chr1[512];
	u_int8_t vv_right0[0x6000];
	struct vip_chr vv_chr2[512];
	u_int8_t vv_right1[0x6000];
	struct vip_chr vv_chr3[512];
} vip_vrm;

static struct
{
	u_int8_t vd_bgseg[0x1d800];
	u_int8_t vd_winattr[0x400];
	u_int8_t vd_coltbl[0x1400];
	u_int8_t vd_oam[0x1000];
} vip_dram;

struct vip_intreg
{
	unsigned vi_scanerr : 1,
			 vi_lfbend : 1,
			 vi_rfbend : 1,
			 vi_gamestart : 1,
			 vi_framestart : 1,
			 vi_unused : 8,
			 vi_sbhit : 1,
			 vi_xpend : 1,
			 vi_timeerr : 1;
} __attribute__((packed));

struct vip_dpctrl
{
	unsigned vd_dprst: 1;
	unsigned vd_disp : 1;
	unsigned vd_dpbsy_l_fb0 : 1;
	unsigned vd_dpbsy_r_fb0 : 1;
	unsigned vd_dpbsy_l_fb1 : 1;
	unsigned vd_dpbsy_r_fb1 : 1;
	unsigned vd_scanrdy : 1;
	unsigned vd_fclk : 1;
	unsigned vd_re : 1;
	unsigned vd_synce : 1;
	unsigned vd_lock : 1;
	unsigned vd_unused : 5;
} __attribute__((packed));

struct vip_xpctrl
{
	unsigned vx_xprst : 1;
	unsigned vx_xpen : 1;
	unsigned vx_xpbsy_fb0 : 1;
	unsigned vx_xpbsy_fb1 : 1;
	unsigned vx_overtime : 1;
	unsigned vx_unused : 3;
	unsigned vx_sbcount : 5; // AKA sbcmp
	unsigned vx_unused2 : 2;
	unsigned vx_sbout : 1;
} __attribute__((packed));

static struct
{
	struct vip_intreg vr_intpnd;
	struct vip_intreg vr_intenb;
	struct vip_intreg vr_intclr;
	u_int16_t vr_undef1[13];
	struct vip_dpctrl vr_dpstts;
	struct vip_dpctrl vr_dpctrl;
	u_int16_t vr_brta;
	u_int16_t vr_brtb;
	u_int16_t vr_brtc;
	u_int16_t vr_rest;
	u_int16_t vr_frmcyc;
	u_int16_t vr_undef2;
	u_int16_t vr_cta;
	u_int16_t vr_undef3[7];
	struct vip_xpctrl vr_xpstts;
	struct vip_xpctrl vr_xpctrl;
	u_int16_t vr_ver;
	u_int16_t vr_undef4;
	u_int16_t vr_spt[4];
	u_int16_t vr_undef5[8];
	u_int16_t vr_gplt[4];
	u_int16_t vr_jplt[4];
	u_int16_t vr_bkcol;
} vip_regs;

bool
vip_init(void)
{
	mem_segs[MEM_SEG_VIP].ms_size = 0x80000;
	mem_segs[MEM_SEG_VIP].ms_addrmask = 0x7ffff;
	bzero(&vip_regs, sizeof(vip_regs));
	debug_create_symbol("INTPND", 0x5f800);
	debug_create_symbol("INTENB", 0x5f802);
	debug_create_symbol("INTCLR", 0x5f804);
	vip_regs.vr_dpstts.vd_scanrdy = 1;
	debug_create_symbol("DPSTTS", 0x5f820);
	debug_create_symbol("DPCTRL", 0x5f822);
	debug_create_symbol("BRTA", 0x5f824);
	debug_create_symbol("BRTB", 0x5f826);
	debug_create_symbol("BRTC", 0x5f828);
	debug_create_symbol("REST", 0x5f82a);
	debug_create_symbol("FRMCYC", 0x5f82e);
	debug_create_symbol("CTA", 0x5f830);
	debug_create_symbol("XPSTTS", 0x5f840);
	debug_create_symbol("XPCTRL", 0x5f842);
	debug_create_symbol("VER", 0x5f844);
	debug_create_symbol("SPT0", 0x5f848);
	debug_create_symbol("SPT1", 0x5f84a);
	debug_create_symbol("SPT2", 0x5f84c);
	debug_create_symbol("SPT3", 0x5f84e);
	debug_create_symbol("GPLT0", 0x5f860);
	debug_create_symbol("GPLT1", 0x5f862);
	debug_create_symbol("GPLT2", 0x5f864);
	debug_create_symbol("GPLT3", 0x5f866);
	debug_create_symbol("JPLT0", 0x5f86a);
	debug_create_symbol("JPLT2", 0x5f86c);
	debug_create_symbol("JPLT3", 0x5f86e);
	debug_create_symbol("BKCOL", 0x5f870);
	debug_create_symbol("CHR", 0x78000);

	if (!scanner_init())
		return false;

	return true;
}

void
vip_reset(void)
{
	// TODO: set initial reg states
}

/*
static void
vip_draw_side(void)
{
	// TODO: Draw background color
	// TODO: For each world 31 to 0
		// TODO: Draw BG or OBJ
}
*/

void
vip_step(void)
{
	/*
	scanner_step();
	if (vip_regs.vr_xpstts.vx_xpbsy_fb0)
	{
		vip_draw_side();
	}
	else if (vip_regs.vr_xpstts.vx_xpbsy_fb1)
	{
		vip_draw_side();
	}
	else
	{
		if (vip_regs.vr_xpctrl.vx_xpen)
		{
			vip_regs.vr_xpstts.vx_xpen = 1;
	}
	*/
}

void
vip_fini(void)
{
	scanner_fini();
	// TODO
}

void *
vip_mem_emu2host(u_int32_t addr, size_t size)
{
	// TODO: Set read/write permissions
	if (size != 2)
	{
		fprintf(stderr, "Invalid VIP access size %lu\n", size);
		return NULL;
	}
	if (addr & 1)
	{
		fprintf(stderr, "VIP address alignment error at 0x%08x\n", addr);
		return NULL;
	}
	if (addr < 0x20000)
		return (u_int8_t *)&vip_vrm + addr;
	else if (addr < 0x40000)
		return (u_int8_t *)&vip_dram + (addr & 0x1ffff);
	else if ((addr & 0xfff00) == 0x5f800)
		return (u_int8_t *)&vip_regs + (addr & 0x7e);
	else if (addr >= 0x78000 && addr < 0x7a000)
		return (u_int8_t *)&(vip_vrm.vv_chr0) + (addr - 0x78000);
	else if (addr >= 0x7a000 && addr < 0x7c000)
		return (u_int8_t *)&(vip_vrm.vv_chr1) + (addr - 0x7a000);
	else if (addr >= 0x7c000 && addr < 0x7e000)
		return (u_int8_t *)&(vip_vrm.vv_chr2) + (addr - 0x7c000);
	else if (addr >= 0x7e000 && addr < 0x80000)
		return (u_int8_t *)&(vip_vrm.vv_chr3) + (addr - 0x7e000);
	else
	{
		// TODO: map VIP seg
		fprintf(stderr, "VIP bus error at 0x%08x\n", addr);
		debug_intr();
		return NULL;
	}
}

void
vip_test(void)
{
	fputs("Running VIP self-test\n", stderr);

	assert(sizeof(vip_vrm) == 0x20000);
	assert(sizeof(vip_dram) == 0x20000);
	assert(sizeof(vip_regs) == 0x72);
	assert(vip_mem_emu2host(0x5f800, 2) == &(vip_regs.vr_intpnd));
	assert(vip_mem_emu2host(0x5f820, 2) == &(vip_regs.vr_dpstts));
	assert(vip_mem_emu2host(0x5f870, 2) == &(vip_regs.vr_bkcol));
	assert(vip_mem_emu2host(0x78000, 2) == &(vip_vrm.vv_chr0));
	assert(vip_mem_emu2host(0x7e000, 2) == &(vip_vrm.vv_chr3));
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

/* NVC */
// TODO: struct nvc_regs ...
bool
nvc_init(void)
{
	return cpu_init();
}

void
nvc_fini(void)
{
	cpu_fini();
}

void
nvc_reset(void)
{
	// TODO: Initialize NVC interval registers
	cpu_reset();
}

void
nvc_step(void)
{
	// TODO: Update timer
	cpu_step();
}

/* DEBUG */
static EditLine *s_editline;
static History *s_history;
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
	el_source(s_editline, NULL);

	s_history = history_init();
	if (!s_history)
	{
		warnx("Could not initialize history editing");
		return false;
	}
	HistEvent event;
	history(s_history, &event, H_SETSIZE, INT_MAX);
	el_set(s_editline, EL_HIST, history, s_history);

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
	history_end(s_history);
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

static const size_t debug_str_len = 64;
typedef char debug_str_t[debug_str_len];

static const char *
debug_format_addr(u_int32_t addr, debug_str_t s)
{
	char human[32];
	struct debug_symbol *sym = debug_syms;
	const char *match_name = NULL;
	u_int32_t match_offset;

	while (sym)
	{
		if (sym->ds_addr <= addr)
		{
			u_int32_t offset = addr - sym->ds_addr;
			if (offset <= 8192 && (!match_name || match_offset > offset))
			{
				match_name = sym->ds_name;
				match_offset = offset;
			}
		}

		sym = sym->ds_next;
	}

	if (!match_name)
	{
		enum mem_segment seg = MEM_ADDR2SEG(addr);
		if (mem_seg_names[seg] && mem_segs[seg].ms_size)
		{
			match_name = mem_seg_names[seg];
			match_offset = addr & mem_segs[seg].ms_addrmask;
		}
	}

	if (match_name)
	{
		if (match_offset)
			snprintf(human, sizeof(human), "<%s+%u>", match_name, match_offset);
		else
			snprintf(human, sizeof(human), "<%s>", match_name);
	}
	else
		*human = '\0';

	snprintf(s, debug_str_len, "0x%08x %-15s", addr, human);

	return s;
}

void
debug_add_symbol(struct debug_symbol *debug_sym)
{
	debug_sym->ds_next = debug_syms;
	debug_syms = debug_sym;
}

void
debug_create_symbol(const char *name, u_int32_t addr)
{
	struct debug_symbol *debug_sym = calloc(1, sizeof(*debug_sym));
	if (!debug_sym)
		err(1, "Could not allocate debug symbol");
	debug_sym->ds_name = strdup(name);
	if (!debug_sym->ds_name)
		err(1, "Could not copy symbol name");
	debug_sym->ds_addr = addr;
	debug_add_symbol(debug_sym);
}

static void
debug_disasm_vi(debug_str_t dis, const union cpu_inst *inst, const char *mnemonic, const cpu_regs_t regs)
{
	snprintf(dis, debug_str_len, "%s %hd[r%u], r%u",
			mnemonic, inst->ci_vi.vi_disp16, inst->ci_vi.vi_reg1, inst->ci_vi.vi_reg2);
	if (regs)
	{
		u_int32_t addr = regs[inst->ci_vi.vi_reg1] + inst->ci_vi.vi_disp16;
		size_t dislen = strlen(dis);
		debug_str_t addr_s;
		debug_format_addr(addr, addr_s);
		switch (inst->ci_vi.vi_opcode)
		{
			case OP_CAXI:
				snprintf(dis + dislen, debug_str_len - dislen,
						"\t; [%s] <- r30 if oldval = r%u", addr_s, inst->ci_vi.vi_reg2);
				break;
			case OP_LD_B:
			case OP_LD_H:
			case OP_LD_W:
				snprintf(dis + dislen, debug_str_len - dislen, "\t; [%s] -> r%u", addr_s, inst->ci_vi.vi_reg2);
				break;
			case OP_ST_B:
			{
				u_int8_t value = regs[inst->ci_vi.vi_reg2] & 0xff;
				snprintf(dis + dislen, debug_str_len - dislen, "\t; [%s] <- 0x%02hhx", addr_s, value);
				break;
			}
			case OP_ST_H:
			{
				u_int16_t value = regs[inst->ci_vi.vi_reg2] & 0xffff;
				snprintf(dis + dislen, debug_str_len - dislen, "\t; [%s] <- 0x%04hx", addr_s, value);
				break;
			}
			case OP_ST_W:
			{
				u_int32_t value = regs[inst->ci_vi.vi_reg2];
				snprintf(dis + dislen, debug_str_len - dislen, "\t; [%s] <- 0x%08x", addr_s, value);
				break;
			}
		}
	}
}

char *
debug_disasm_s(const union cpu_inst *inst, u_int32_t pc, const cpu_regs_t regs, debug_str_t dis)
{
	const char *mnemonic;
	switch (inst->ci_i.i_opcode)
	{
		case OP_ADD:
		case OP_ADD2:
			mnemonic = "ADD";
			break;
		case OP_MOV:
		case OP_MOV2:
			mnemonic = "MOV";
			break;
		case OP_SUB: mnemonic = "SUB"; break;
		case OP_CMP:
		case OP_CMP2:
			mnemonic = "CMP";
			break;
		case OP_JMP: mnemonic = "JMP"; break;
		case OP_SHL2: mnemonic = "SHL"; break;
		case OP_SAR:
		case OP_SAR2:
			mnemonic = "SAR";
			break;
		case OP_MUL:
			mnemonic = "MUL";
			break;
		case OP_LDSR: mnemonic = "LDSR"; break;
		case OP_MOVHI: mnemonic = "MOVHI"; break;
		case OP_MOVEA: mnemonic = "MOVEA"; break;
		case OP_ADDI: mnemonic = "ADDI"; break;
		case OP_JAL: mnemonic = "JAL"; break;
		case OP_ORI: mnemonic = "ORI"; break;
		case OP_ANDI: mnemonic = "ANDI"; break;
		default:
		{
			if (inst->ci_iii.iii_opcode == OP_BCOND)
			{
				switch (inst->ci_iii.iii_cond)
				{
					case BCOND_BV: mnemonic = "BV"; break;
					case BCOND_BL: mnemonic = "BL"; break;
					case BCOND_BZ: mnemonic = "BZ"; break;
					case BCOND_BNH: mnemonic = "BNH"; break;
					case BCOND_BN: mnemonic = "BN"; break;
					case BCOND_BR: mnemonic = "BR"; break;
					case BCOND_BLT: mnemonic = "BLT"; break;
					case BCOND_BLE: mnemonic = "BLE"; break;
					case BCOND_BNV: mnemonic = "BNV"; break;
					case BCOND_BNZ: mnemonic = "BNZ"; break;
					case BCOND_BH: mnemonic = "BH"; break;
					case BCOND_BP: mnemonic = "BP"; break;
					case BCOND_NOP: mnemonic = "NOP"; break;
					case BCOND_BGE: mnemonic = "BGE"; break;
					case BCOND_BGT: mnemonic = "BGT"; break;
				}
				break;
			}
			static char unknown[32];
			snprintf(unknown, sizeof(unknown), "??? (%s)", debug_format_binary(inst->ci_i.i_opcode, 6));
			mnemonic = unknown;
		}
	}
	switch (inst->ci_i.i_opcode)
	{
		case OP_MUL:
			if (regs)
				snprintf(dis, debug_str_len, "%s r%d, r%d ; %i * %i",
						mnemonic, inst->ci_i.i_reg1, inst->ci_i.i_reg2,
						(int32_t)regs[inst->ci_i.i_reg2], (int32_t)regs[inst->ci_i.i_reg1]);
			else
				snprintf(dis, debug_str_len, "%s r%d, r%d", mnemonic, inst->ci_i.i_reg1, inst->ci_i.i_reg2);
			break;
		case OP_SUB:
			if (regs)
				snprintf(dis, debug_str_len, "%s r%d, r%d ; %i - %i | 0x%08x - 0x%08x",
						mnemonic, inst->ci_i.i_reg1, inst->ci_i.i_reg2,
						(int32_t)regs[inst->ci_i.i_reg2], (int32_t)regs[inst->ci_i.i_reg1],
						regs[inst->ci_i.i_reg2], regs[inst->ci_i.i_reg1]);
			else
				snprintf(dis, debug_str_len, "%s r%d, r%d", mnemonic, inst->ci_i.i_reg1, inst->ci_i.i_reg2);
			break;
		case OP_MOV:
		case OP_ADD:
		case OP_CMP:
		case OP_SHL:
		case OP_SHR:
		case OP_SAR:
		case OP_DIV:
		case OP_MULU:
		case OP_DIVU:
		case OP_OR:
		case OP_AND:
		case OP_XOR:
		case OP_NOT:
			snprintf(dis, debug_str_len, "%s r%d, r%d", mnemonic, inst->ci_i.i_reg1, inst->ci_i.i_reg2);
			break;
		case OP_JMP:
			if (regs)
			{
				debug_str_t addr_s;
				snprintf(dis, debug_str_len, "%s [r%u]\t\t; pc <- %s",
						mnemonic, inst->ci_i.i_reg1, debug_format_addr(regs[inst->ci_i.i_reg1], addr_s));
			}
			else
				snprintf(dis, debug_str_len, "%s [r%d]", mnemonic, inst->ci_i.i_reg1);
			break;
		case OP_ADD2:
		case OP_MOV2:
		{
			u_int16_t imm = cpu_extend5to16(inst->ci_ii.ii_imm5);
			snprintf(dis, debug_str_len, "%s %hi, r%u", mnemonic, imm, inst->ci_ii.ii_reg2);
			break;
		}
		case OP_CMP2:
		{
			u_int16_t imm = cpu_extend5to16(inst->ci_ii.ii_imm5);
			if (regs)
				snprintf(dis, debug_str_len, "%s %hi, r%u\t\t; %d <=> %hi",
						mnemonic, imm, inst->ci_ii.ii_reg2, regs[inst->ci_ii.ii_reg2], imm);
			else
				snprintf(dis, debug_str_len, "%s %hi, r%u", mnemonic, imm, inst->ci_ii.ii_reg2);
			break;
		}
		case OP_SHL2:
		case OP_SAR2:
		case OP_LDSR:
			snprintf(dis, debug_str_len, "%s %i, r%u", mnemonic, inst->ci_ii.ii_imm5, inst->ci_ii.ii_reg2);
			break;
		case OP_JAL:
		{
			u_int32_t disp = (inst->ci_iv.iv_disp10 << 16) | inst->ci_iv.iv_disp16;
			if ((disp & 0x2000000) == 0x2000000)
				disp|= 0xfd000000;
			if (pc)
			{
				debug_str_t addr_s;
				snprintf(dis, debug_str_len, "%s %i\t\t; %s", mnemonic, disp, debug_format_addr(pc + disp, addr_s));
			}
			else
				snprintf(dis, debug_str_len, "%s %i", mnemonic, disp);
			break;
		}
		case OP_MOVEA:
		case OP_MOVHI:
		case OP_ORI:
		case OP_ANDI:
			snprintf(dis, debug_str_len, "%s %hXh, r%d, r%d",
					mnemonic, inst->ci_v.v_imm16, inst->ci_v.v_reg1, inst->ci_v.v_reg2);
			break;
		case OP_ADDI:
			snprintf(dis, debug_str_len, "%s %hd, r%d, r%d",
					mnemonic, inst->ci_v.v_imm16, inst->ci_v.v_reg1, inst->ci_v.v_reg2);
			break;
		case OP_CAXI:
			debug_disasm_vi(dis, inst, "CAXI", regs);
			break;
		case OP_IN_B:
			debug_disasm_vi(dis, inst, "IN.B", regs);
			break;
		case OP_IN_H:
			debug_disasm_vi(dis, inst, "IN.H", regs);
			break;
		case OP_IN_W:
			debug_disasm_vi(dis, inst, "IN.W", regs);
			break;
		case OP_LD_B:
			debug_disasm_vi(dis, inst, "LD.B", regs);
			break;
		case OP_LD_H:
			debug_disasm_vi(dis, inst, "LD.H", regs);
			break;
		case OP_LD_W:
			debug_disasm_vi(dis, inst, "LD.W", regs);
			break;
		case OP_OUT_B:
			debug_disasm_vi(dis, inst, "OUT.B", regs);
			break;
		case OP_OUT_H:
			debug_disasm_vi(dis, inst, "OUT.H", regs);
			break;
		case OP_OUT_W:
			debug_disasm_vi(dis, inst, "OUT.W", regs);
			break;
		case OP_ST_B:
			debug_disasm_vi(dis, inst, "ST.B", regs);
			break;
		case OP_ST_H:
			debug_disasm_vi(dis, inst, "ST.H", regs);
			break;
		case OP_ST_W:
			debug_disasm_vi(dis, inst, "ST.W", regs);
			break;
		default:
			if (inst->ci_iii.iii_opcode == OP_BCOND)
			{
				u_int32_t disp = cpu_extend9(inst->ci_iii.iii_disp9);
				if (pc)
				{
					debug_str_t addr_s;
					snprintf(dis, debug_str_len, "%s %i\t\t; pc <- %s",
							mnemonic, disp, debug_format_addr(pc + disp, addr_s));
				}
				else
					snprintf(dis, debug_str_len, "%s %i", mnemonic, disp);
				break;
			}
			snprintf(dis, debug_str_len, "TODO: %s", mnemonic);
	}
	return dis;
}

char *
debug_disasm(const union cpu_inst *inst, u_int32_t pc, const cpu_regs_t regs)
{
	static debug_str_t dis;
	return debug_disasm_s(inst, pc, regs, dis);
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
	{'x', "<addr> [<format>[<size>]] [<count>]", "Examine memory at <addr>\n"
		"\t\tFormats: h (hex), i (instructions), b (binary), C (VIP CHR)\n"
		"\t\tSizes: b (byte), h (half-word), w (word)\n"
		"\t\tAddresses can be numeric or [<reg#>], <offset>[<reg#>], <sym>, <sym>+<offset>"},
	{'r', "", "Reset the CPU (aliases: reset)"},
	{'v', "", "Show VIP info (aliases: vip)"},
	{'d', "[<addr>]", "Disassemble from <addr> (defaults to [pc]) (aliases: dis)"}
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
		warnx("Could not read %lu bytes from 0x%08x: Invalid address", size, addr);
		return false;
	}
}

static u_int32_t
debug_locate_symbol(const char *s)
{
	for (struct debug_symbol *sym = debug_syms; sym; sym = sym->ds_next)
		if (!strcmp(sym->ds_name, s))
			return sym->ds_addr;
	warnx("Symbol not found: %s", s);
	return 0;
}

static bool
debug_parse_addr(const char *s, u_int32_t *addrp)
{
	size_t len = strlen(s);
	int base, disp = 0;
	int reg_num;
	int nparsed;

	if ((sscanf(s, "%i[pc]%n", &disp, &nparsed) == 1 && nparsed == len) ||
			(sscanf(s, "[pc]%n", &nparsed) == 0 && nparsed == len))
		base = cpu_state.cs_pc;
	else if ((sscanf(s, "%i[r%2d]%n", &disp, &reg_num, &nparsed) == 2 && nparsed == len) ||
			(sscanf(s, "[r%2d]%n", &reg_num, &nparsed) == 1 && nparsed == len))
		base = cpu_state.cs_r[reg_num & 0x1f];
	else
	{
		char sym_name[64 + 1], sign[2];
		int num_parsed;
		num_parsed = sscanf(s, "%64[^+-]%n%1[+-]%i%n", sym_name, &nparsed, sign, &disp, &nparsed);
		if (num_parsed >= 1 && nparsed == len)
		{
			if (!(base = debug_locate_symbol(sym_name)))
				return false;
			if (num_parsed >= 2 && *sign == '-')
				disp = -disp;
		}
		else
		{
			warnx("Invalid address format “%s”", s);
			return false;
		}
	}
	*addrp = base + disp;
	return true;
}

static bool
debug_disasm_at(u_int32_t *addrp, bool stop_at_return)
{
	union cpu_inst inst;
	if (!cpu_fetch(*addrp, &inst))
		return false;
	printf(" %s\n", debug_disasm(&inst, *addrp, NULL));

	if (stop_at_return && inst.ci_i.i_opcode == OP_JMP && inst.ci_i.i_reg1 == 31)
		return false;

	*addrp+= cpu_inst_size(&inst);
	return true;
}

static bool debugging = false;

void
debug_intr(void)
{
	if (!debugging)
		raise(SIGINT);
}

static char *
debug_format_flags(debug_str_t s, ...)
{
	va_list ap;
	va_start(ap, s);
	const char *name;
	size_t len = 0;
	s[0] = '\0';
	while ((name = va_arg(ap, typeof(name))))
	{
		u_int flag = va_arg(ap, typeof(flag));
		if (flag)
			len+= snprintf(s + len, debug_str_len - len, "%s%s", (len > 0) ? "|" : "", name);
	}
	va_end(ap);
	return s;
}

static void
debug_print_psw(union cpu_psw psw, const char *name)
{
	debug_str_t psw_s;
	printf("\t%s: 0x%08x (%s) (interrupt level %d)",
			name,
			cpu_state.cs_psw.psw_word,
			debug_format_flags(psw_s,
				"Z", cpu_state.cs_psw.psw_flags.f_z,
				"S", cpu_state.cs_psw.psw_flags.f_s,
				"OV", cpu_state.cs_psw.psw_flags.f_ov,
				"CY", cpu_state.cs_psw.psw_flags.f_cy,
				"FPR", cpu_state.cs_psw.psw_flags.f_fpr,
				"FUD", cpu_state.cs_psw.psw_flags.f_fud,
				"FOV", cpu_state.cs_psw.psw_flags.f_fov,
				"FZD", cpu_state.cs_psw.psw_flags.f_fzd,
				"FIV", cpu_state.cs_psw.psw_flags.f_fiv,
				"FRO", cpu_state.cs_psw.psw_flags.f_fro,
				"ID", cpu_state.cs_psw.psw_flags.f_id,
				"AE", cpu_state.cs_psw.psw_flags.f_ae,
				"EP", cpu_state.cs_psw.psw_flags.f_ep,
				"NP", cpu_state.cs_psw.psw_flags.f_np,
				NULL),
			cpu_state.cs_psw.psw_flags.f_i);
}

static void
debug_print_intreg(struct vip_intreg vi, const char *name)
{
	debug_str_t flags_str;
	printf("%s: (%s)",
			name,
			debug_format_flags(flags_str,
				"SCANERR", vi.vi_scanerr,
				"LFBEND", vi.vi_lfbend,
				"RFBEND", vi.vi_rfbend,
				"GAMESTART", vi.vi_gamestart,
				"FRAMESTART", vi.vi_framestart,
				"SBHIT", vi.vi_sbhit,
				"XPEND", vi.vi_xpend,
				"TIMEERR", vi.vi_timeerr,
				NULL));
}

static void
debug_print_dpctrl(struct vip_dpctrl vd, const char *name)
{
	debug_str_t flags_str;
	printf("%s: (%s)",
			name,
			debug_format_flags(flags_str,
				"DISP", vd.vd_disp,
				"DPBSY:L:FB0", vd.vd_dpbsy_l_fb0,
				"DPBSY:R:FB0", vd.vd_dpbsy_r_fb0,
				"DPBSY:L:FB1", vd.vd_dpbsy_l_fb1,
				"DPBSY:R:FB1", vd.vd_dpbsy_r_fb1,
				"SCANRDY", vd.vd_scanrdy,
				"FCLK", vd.vd_fclk,
				"RE", vd.vd_re,
				"SYNCE", vd.vd_synce,
				"LOCK", vd.vd_lock,
				NULL));
}

static void
debug_print_xpctrl(struct vip_xpctrl vx, const char *name)
{
	debug_str_t flags_str;
	printf("%s: (%s)",
			name,
			debug_format_flags(flags_str,
				"XPRST", vx.vx_xprst,
				"XPEN", vx.vx_xpen,
				"XPBSY:FB0", vx.vx_xpbsy_fb0,
				"XPBSY:FB1", vx.vx_xpbsy_fb1,
				"OVERTIME", vx.vx_overtime,
				"SBOUT", vx.vx_sbout,
				NULL));
}

void
debug_run(void)
{
	debugging = true;
	while (1)
	{
		union cpu_inst inst;
		if (cpu_fetch(cpu_state.cs_pc, &inst))
		{
			debug_str_t addr_s;
			printf("frame 0: %s: %s\n",
					debug_format_addr(cpu_state.cs_pc, addr_s), debug_disasm(&inst, cpu_state.cs_pc, cpu_state.cs_r));
		}

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
					cpu_step();
				else if (!strcmp(argv[0], "i") || !strcmp(argv[0], "info"))
				{
					static const char *fmt = "\t%5s: %s";
					debug_str_t addr_s;
					for (u_int regIndex = 0; regIndex < 32; ++regIndex)
					{
						char rname[5];
						snprintf(rname, sizeof(rname), "r%d", regIndex);
						printf(fmt, rname, debug_format_addr(cpu_state.cs_r[regIndex], addr_s));
						printf(" (%11i)", cpu_state.cs_r[regIndex]);
						if (regIndex % 2 == 1)
							putchar('\n');
					}
					printf(fmt, "pc", debug_format_addr(cpu_state.cs_pc, addr_s));
					debug_print_psw(cpu_state.cs_psw, "  psw");
					putchar('\n');
					printf("\t  ecr: (eicc: 0x%04hx, fecc: 0x%04hx)\n",
							cpu_state.cs_ecr.ecr_eicc, cpu_state.cs_ecr.ecr_fecc);
					printf(fmt, "eipc", debug_format_addr(cpu_state.cs_eipc, addr_s));
					debug_print_psw(cpu_state.cs_eipsw, "eipsw");
					putchar('\n');
					printf(fmt, "fepc", debug_format_addr(cpu_state.cs_fepc, addr_s));
					debug_print_psw(cpu_state.cs_fepsw, "fepsw");
					putchar('\n');
				}
				else if (!strcmp(argv[0], "x"))
				{
					if (argc >= 2)
					{
						u_int32_t addr;
						if (!debug_parse_addr(argv[1], &addr))
							continue;
						const char *format = "h";
						u_int count = 1;
						if (argc >= 3)
							format = argv[2];
						if (argc >= 4)
							count = strtoul(argv[3], NULL, 0);

						size_t int_size = 4;
						if ((format[0] == 'h' || format[0] == 'b') && strlen(format) == 2)
						{
							switch (format[1])
							{
								case 'b':
									int_size = 1;
									break;
								case 'h':
									int_size = 2;
									break;
								case 'w':
									int_size = 4;
									break;
							}
						}

						for (u_int objIndex = 0; objIndex < count; ++objIndex)
						{
							debug_str_t addr_s;
							printf("%s:", debug_format_addr(addr, addr_s));
							if (format[0] == 'h' && strlen(format) <= 2)
							{
								u_int value;
								if (debug_mem_read(addr, &value, int_size))
									printf(" 0x%0*x\n", (int)int_size << 1, value);
								addr+= int_size;
							}
							else if (!strcmp(format, "i"))
							{
								if (!debug_disasm_at(&addr, false))
									break;
							}
							else if (format[0] == 'b' && strlen(format) <= 2)
							{
								u_int value;
								if (debug_mem_read(addr, &value, int_size))
									printf(" %s\n", debug_format_binary(value, int_size << 3));
								addr+= sizeof(value);
							}
							else if (!strcmp(format, "C"))
							{
								putchar('\n');
								for (u_int rindex = 0; rindex < 8; ++rindex)
								{
									u_int16_t chr_row;
									if (!debug_mem_read(addr, &(chr_row), sizeof(chr_row)))
										break;
									//static const char *shading = " ░▒▓";
									static const char *shading = " -=#";
									for (u_int cindex = 0; cindex < 8; ++cindex)
									{
										putchar(shading[chr_row & 0x3]);
										chr_row>>= 2;
									}
									putchar('\n');
									addr+= sizeof(chr_row);
								}
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
				else if (!strcmp(argv[0], "v") || !strcmp(argv[0], "vip"))
				{
					debug_print_intreg(vip_regs.vr_intpnd, "INTPND");
					fputs(", ", stdout);
					debug_print_intreg(vip_regs.vr_intenb, "INTENB");
					fputs(", ", stdout);
					debug_print_intreg(vip_regs.vr_intclr, "INTCLR");
					putchar('\n');
					debug_print_dpctrl(vip_regs.vr_dpstts, "DPSTTS");
					fputs(", ", stdout);
					debug_print_dpctrl(vip_regs.vr_dpctrl, "DPCTRL");
					putchar('\n');
					debug_print_xpctrl(vip_regs.vr_xpstts, "XPSTTS");
					printf(" SBCOUNT=%d", vip_regs.vr_xpstts.vx_sbcount);
					fputs(", ", stdout);
					debug_print_xpctrl(vip_regs.vr_xpctrl, "XPCTRL");
					printf(" SBCMP=%d", vip_regs.vr_xpctrl.vx_sbcount);
					putchar('\n');
					printf("BRTA: %d, BRTB: %d, BRTC: %d, REST: %d\n",
							vip_regs.vr_brta, vip_regs.vr_brtb, vip_regs.vr_brtc, vip_regs.vr_rest);
					printf("FRMCYC: %d\n", vip_regs.vr_frmcyc);
				}
				else if (!strcmp(argv[0], "d") || !strcmp(argv[0], "dis"))
				{
					u_int32_t pc;
					if (argc >= 2)
					{
						if (!debug_parse_addr(argv[1], &pc))
							continue;
					}
					else
						pc = cpu_state.cs_pc;

					u_int32_t end = pc + MIN(8192, 0xffffffff - pc);
					while (pc < end)
					{
						debug_str_t addr_s;
						printf("%s:", debug_format_addr(pc, addr_s));
						if (!debug_disasm_at(&pc, true))
							break;
					}
				}
				else
					printf("Unknown command “%s” -- type ‘?’ for help\n", argv[0]);

				HistEvent hist_event;
				if (history(s_history, &hist_event, H_ENTER, line) == -1)
					warn("Could not save editline history");
			}
		}
		else
		{
			putchar('\n');
			main_exit();
			break;
		}
	}
	debugging = false;
}

void
debug_trace(const union cpu_inst *inst)
{
	debug_str_t addr_s;
	printf("%s: %s\n",
			debug_format_addr(cpu_state.cs_pc, addr_s), debug_disasm(inst, cpu_state.cs_pc, cpu_state.cs_r));
}

/* MAIN */
bool
main_init(void)
{
	return (sram_init() && wram_init() && vip_init() && vsu_init() && nvc_init() && debug_init());
}

void
main_fini(void)
{
	debug_fini();
	nvc_fini();
	vsu_fini();
	vip_fini();
	wram_fini();
	sram_fini();
}

void
main_reset(void)
{
	vip_reset();
	vsu_reset();
	nvc_reset();
}

void
main_step(void)
{
	vip_step();
	vsu_step();
	nvc_step();
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

	if (!main_init())
		return EX_OSERR;

	main_reset();

	s_running = true;

	if (self_test)
	{
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
			debug_run();
			signal(SIGINT, main_noop);
			sigprocmask(SIG_BLOCK, &sigpend, NULL);
		}
	}
	sigprocmask(SIG_UNBLOCK, &sigset, NULL);

	main_fini();
	rom_unload();
}
