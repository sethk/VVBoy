#include "types.h"
#include "mem.h"

#if INTERFACE
	enum mem_segment
	{
		MEM_SEG_VIP = 0,
		MEM_SEG_VSU = 1,
		MEM_SEG_NVC = 2,
		MEM_SEG_CARTEX = 4,
		MEM_SEG_WRAM = 5,
		MEM_SEG_SRAM = 6,
		MEM_SEG_ROM = 7,
		MEM_NSEGS = 8
	};

	struct mem_seg_desc
	{
		u_int ms_size;
		os_mmap_handle_t ms_handle;
		u_int8_t *ms_ptr;
		u_int32_t ms_addrmask;
		enum os_perm ms_perms;
		bool ms_is_mmap;
	};

	struct mem_request
	{
		u_int32_t mr_emu;
		u_int mr_size;
		int mr_ops;
		void *mr_host;
		int mr_perms;
		u_int32_t mr_mask;
		u_int mr_wait;
	};

#	define MEM_ADDR2SEG(a) (((a) & 0x07000000) >> 24)
#	define MEM_ADDR2OFF(a) ((a) & 0x00ffffff)
#	define MEM_SEG2ADDR(s) ((s) << 24)

#endif // INTERFACE

#include <stdlib.h>
#include <math.h>
#include <assert.h>

#define INIT_DEAD_MEM 1
#define DEAD_MEM_PATTERN (0) // (0xdeadc0de)

struct mem_seg_desc mem_segs[(enum mem_segment)MEM_NSEGS];

bool mem_checks = false;

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

#ifndef NDEBUG
static bool
validate_seg_size(u_int size)
{
	double log2size = log2(size);
	return (remainder(log2size, 1.0) == 0.0);
}
#endif // !NDEBUG

bool
mem_init(void)
{
	return true;
}

void
mem_fini(void)
{
}

bool
mem_seg_alloc(enum mem_segment seg, u_int size, int perms)
{
	assert(validate_seg_size(size));
	mem_segs[seg].ms_ptr = malloc(size);
	if (!mem_segs[seg].ms_ptr)
	{
		os_runtime_error(OS_RUNERR_TYPE_OSERR, BIT(OS_RUNERR_RESP_OKAY),
				"Could not allocate 0x%x bytes for segment %s", size, mem_seg_names[seg]);
		return false;
	}
	mem_segs[seg].ms_size = size;
	mem_segs[seg].ms_addrmask = size - 1;
	mem_segs[seg].ms_perms = perms;

#ifndef NDEBUG
	bool init_dead_mem = INIT_DEAD_MEM;
	char *dead_mem_env = getenv("INIT_DEAD_MEM");
	if (dead_mem_env)
		init_dead_mem = atoi(dead_mem_env);
	if (init_dead_mem)
	{
		u_int32_t pattern = DEAD_MEM_PATTERN;
		memset_pattern4(mem_segs[MEM_SEG_WRAM].ms_ptr, &pattern, mem_segs[MEM_SEG_WRAM].ms_size);
	}
#endif // !NDEBUG

	return true;
}

bool
mem_seg_mmap(enum mem_segment seg, u_int size, os_file_handle_t handle)
{
	mem_segs[seg].ms_size = size;
	mem_segs[seg].ms_handle = os_mmap_file(handle, size, OS_PERM_READ, (void **)&mem_segs[seg].ms_ptr);
	if (!mem_segs[seg].ms_ptr)
	{
		os_runtime_error(OS_RUNERR_TYPE_OSERR, BIT(OS_RUNERR_RESP_OKAY), "os_mmap_file() %s", mem_seg_names[seg]);
		return false;
	}
	mem_segs[seg].ms_addrmask = size - 1;
	mem_segs[seg].ms_is_mmap = true;
	return true;
}

static bool
mem_seg_realloc(enum mem_segment seg, u_int size)
{
	assert(!mem_segs[seg].ms_is_mmap);
	assert(validate_seg_size(size));
	mem_segs[seg].ms_ptr = realloc(mem_segs[seg].ms_ptr, size);
	if (!mem_segs[seg].ms_ptr)
	{
		os_runtime_error(OS_RUNERR_TYPE_OSERR, BIT(OS_RUNERR_RESP_OKAY), "Could not reallocate 0x%x bytes for segment %s", size, mem_seg_names[seg]);
		return false;
	}
	mem_segs[seg].ms_size = size;
	mem_segs[seg].ms_addrmask = size - 1;
	return true;
}

void
mem_seg_free(enum mem_segment seg)
{
	if (!mem_segs[seg].ms_is_mmap)
		free(mem_segs[seg].ms_ptr);
	else
	{
		if (!os_munmap_file(mem_segs[seg].ms_handle, mem_segs[seg].ms_ptr, mem_segs[seg].ms_size))
			os_runtime_error(OS_RUNERR_TYPE_OSERR, BIT(OS_RUNERR_RESP_OKAY),
					"os_munmap_file(mem_segs[%s], ...) failed",
					mem_seg_names[seg]);
		mem_segs[seg].ms_is_mmap = false;
	}
	mem_segs[seg].ms_ptr = NULL;
}

u_int32_t
mem_size_ceil(u_int32_t size)
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

static bool
mem_prepare(struct mem_request *request)
{
	enum mem_segment seg = MEM_ADDR2SEG(request->mr_emu);
	if (seg == MEM_SEG_VIP)
		return vip_mem_prepare(request);
	else if (seg == MEM_SEG_VSU)
		return vsu_mem_prepare(request);
	else if (seg == MEM_SEG_NVC)
		return nvc_mem_prepare(request);
	else if (mem_segs[seg].ms_size)
	{
		u_int32_t offset = request->mr_emu & mem_segs[seg].ms_addrmask;

		if (seg == MEM_SEG_SRAM && MEM_ADDR2OFF(request->mr_emu) + request->mr_size > mem_segs[seg].ms_size)
		{
			if (!mem_seg_realloc(MEM_SEG_SRAM, mem_size_ceil(offset + request->mr_size)))
				return false;
			offset = request->mr_emu & mem_segs[MEM_SEG_SRAM].ms_addrmask;
		}

		request->mr_host = mem_segs[seg].ms_ptr + offset;
		request->mr_perms = mem_segs[seg].ms_perms;
		return true;
	}
	else
		return false;
}

/*
void *
mem_emu2host(u_int32_t addr, u_int size)
{
	struct mem_request request = {.mr_emu = addr, .mr_size = size, .mr_ops = 0};
	if (!mem_prepare(&request))
		return NULL;
	return request.mr_host;
}
*/

static bool
mem_perm_error(const struct mem_request *request, bool *always_ignorep)
{
	debug_str_t addr_s, ops_s, perms_s;
	debug_str_t msg;
	os_snprintf(msg, sizeof(msg), "Invalid memory operation at %s, mem ops = %s, perms = %s",
			debug_format_addr(request->mr_emu, addr_s),
			debug_format_perms(request->mr_ops, ops_s),
			debug_format_perms(request->mr_perms, perms_s));

	bool allow_ignore = ((request->mr_ops & OS_PERM_READ) == 0);
	return debug_runtime_error(allow_ignore, always_ignorep, msg);
}

static bool
mem_bus_error(u_int32_t addr)
{
	return debug_fatal_errorf("Bus error at 0x%08x", addr);
}

const void *
mem_get_read_ptr(u_int32_t addr, u_int size, u_int *mem_waitp)
{
	enum mem_segment seg = MEM_ADDR2SEG(addr);
	switch (seg)
	{
		case MEM_SEG_VIP:
		{
			struct mem_request request = {.mr_emu = addr, .mr_size = size, .mr_ops = 0};
			if (!vip_mem_prepare(&request))
				return NULL;
			*mem_waitp = request.mr_wait;
			return request.mr_host;
		}
		case MEM_SEG_VSU:
		{
			struct mem_request request = {.mr_emu = addr, .mr_size = size, .mr_ops = 0};
			if (!vsu_mem_prepare(&request))
				return NULL;
			*mem_waitp = request.mr_wait;
			return request.mr_host;
		}
		case MEM_SEG_NVC:
		{
			struct mem_request request = {.mr_emu = addr, .mr_size = size, .mr_ops = 0};
			if (!nvc_mem_prepare(&request))
				return NULL;
			*mem_waitp = request.mr_wait;
			return request.mr_host;
		}
		case MEM_SEG_SRAM:
		{
			u_int32_t offset = MEM_ADDR2OFF(addr);
			if (offset + size > mem_segs[seg].ms_size)
			{
				if (!mem_seg_realloc(MEM_SEG_SRAM, mem_size_ceil(offset + size)))
					return NULL;
			}
			*mem_waitp = 2;
			return mem_segs[seg].ms_ptr + offset;
		}
		default:
		{
			if (!mem_segs[seg].ms_size)
			{
				mem_bus_error(addr);
				return NULL;
			}

			u_int32_t offset = addr & mem_segs[seg].ms_addrmask;

			if (mem_checks && !(mem_segs[seg].ms_perms & OS_PERM_READ))
			{
				struct mem_request request =
				{
					.mr_emu = addr,
					.mr_ops = OS_PERM_READ,
					.mr_perms = mem_segs[seg].ms_perms
				};
				mem_perm_error(&request, NULL);
				return NULL;
			}

			*mem_waitp = 2;
			return mem_segs[seg].ms_ptr + offset;
		}
	}
}

bool
mem_read(u_int32_t addr, void *dest, u_int size, bool is_exec, u_int *mem_waitp)
{
	assert(size > 0);
	struct mem_request request =
			{
					.mr_emu = addr,
					.mr_size = size,
					.mr_perms = OS_PERM_READ | OS_PERM_WRITE,
					.mr_mask = 0xffffffff,
					.mr_wait = 2
			};
	request.mr_ops = OS_PERM_READ;
	if (is_exec)
		request.mr_ops|= OS_PERM_EXEC;

	if (!mem_prepare(&request))
		return mem_bus_error(addr);

	if ((request.mr_perms & request.mr_ops) != request.mr_ops)
		return mem_perm_error(&request, NULL);

	if (debug_trace_mem_read && !is_exec)
	{
		debug_str_t addr_s;
		debug_str_t hex_s;
		debug_tracef("mem.read", "%s <- [" DEBUG_ADDR_FMT "]",
		             debug_format_hex(request.mr_host, size, hex_s),
		             debug_format_addr(addr, addr_s));
	}

	switch (size)
	{
		case 1:
			*(u_int8_t *)dest = *(u_int8_t *)request.mr_host;
			break;
		case 2:
			*(u_int16_t *)dest = *(u_int16_t *)request.mr_host;
			break;
		case 4:
			*(u_int32_t *)dest = *(u_int32_t *)request.mr_host;
			break;
		default:
			os_bcopy(request.mr_host, dest, size);
	}

	*mem_waitp = request.mr_wait;
	return true;
}

static void *
mem_get_write_ptr(u_int32_t addr, u_int size, u_int32_t *maskp)
{
	assert(size > 0);
	struct mem_request request =
	{
			.mr_emu = addr,
			.mr_size = size,
			.mr_perms = OS_PERM_READ | OS_PERM_WRITE | OS_PERM_EXEC,
			.mr_ops = OS_PERM_WRITE,
			.mr_mask = 0xffffffff,
			.mr_wait = 2
	};

	if (!mem_prepare(&request))
	{
		// TODO: SEGV
		mem_bus_error(addr);
		return NULL;
	}

	*maskp = request.mr_mask;
	return request.mr_host;
}

bool
mem_write(u_int32_t addr, const void *src, u_int size, u_int *mem_waitp)
{
	assert(size > 0);
	struct mem_request request =
	{
			.mr_emu = addr,
			.mr_size = size,
			.mr_perms = OS_PERM_READ | OS_PERM_WRITE | OS_PERM_EXEC,
			.mr_ops = OS_PERM_WRITE,
			.mr_mask = 0xffffffff,
			.mr_wait = 2
	};

	if (!mem_prepare(&request))
	{
		// TODO: SEGV
		return mem_bus_error(addr);
	}

	if ((request.mr_perms & OS_PERM_WRITE) == 0)
	{
		static bool ignore_writes = false;
		return mem_perm_error(&request, &ignore_writes);
	}

	if (debug_trace_mem_write)
	{
		debug_str_t addr_s;
		debug_str_t hex_s;
		debug_tracef("mem.write", "[" DEBUG_ADDR_FMT "] <- %s",
		             debug_format_addr(addr, addr_s), debug_format_hex(src, size, hex_s));
	}

	enum mem_segment seg = MEM_ADDR2SEG(addr);
	if (seg == MEM_SEG_VSU)
		vsu_mem_write(&request, src);
	else if (seg == MEM_SEG_NVC)
		nvc_mem_write(&request, src);
	else switch (size)
	{
		case 1:
			*(u_int8_t *)request.mr_host =
					(*(u_int8_t *)request.mr_host & ~request.mr_mask) | (*(u_int8_t *)src & request.mr_mask);
			break;
		case 2:
			*(u_int16_t *)request.mr_host =
					(*(u_int16_t *)request.mr_host & ~request.mr_mask) | (*(u_int16_t *)src & request.mr_mask);
			break;
		case 4:
			*(u_int32_t *)request.mr_host =
					(*(u_int32_t *)request.mr_host & ~request.mr_mask) | (*(u_int32_t *)src & request.mr_mask);
			break;
		default:
			os_bcopy(src, request.mr_host, size);
	}

	*mem_waitp = request.mr_wait;
	return true;
}

void
mem_test_addr_ro(const char *name, u_int32_t emu_addr, u_int size, void *expected)
{
	u_int mem_wait;
	const void *addr = mem_get_read_ptr(emu_addr, size, &mem_wait);
	if (addr != expected)
		debug_fatal_errorf("mem_get_read_ptr(%s@0x%08x) is %p but should be %p (offset %ld)",
				name, emu_addr, addr, expected, (intptr_t)expected - (intptr_t)addr);
}

void
mem_test_addr(const char *name, u_int32_t emu_addr, u_int size, void *expected)
{
	mem_test_addr_ro(name, emu_addr, size, expected);
	u_int32_t mask;
	void *addr = mem_get_write_ptr(emu_addr, size, &mask);
	if (addr != expected)
	{
		debug_fatal_errorf("mem_get_write_ptr(%s@0x%08x) is %p but should be %p (offset %ld)",
				name, emu_addr, addr, expected, (intptr_t)expected - (intptr_t)addr);
	}
}
