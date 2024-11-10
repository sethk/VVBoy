#include "Types.hh"
#include "Memory.hh"

// TODO:
extern bool vip_mem_prepare(Memory::Request *request);
extern bool vsu_mem_prepare(Memory::Request *request);
extern bool nvc_mem_prepare(Memory::Request *request);
extern bool sram_mem_prepare(Memory::Request *request);

extern void vsu_mem_write(const Memory::Request *request, const void *src);
extern void nvc_mem_write(const Memory::Request *request, const void *src);

#include "Memory.Gen.hh"

#include <cstdlib>
#include <cmath>
#include <cassert>

#define INIT_DEAD_MEM 1
#define DEAD_MEM_PATTERN (0) // (0xdeadc0de)

Memory::Memory()
{
	Segments[SEG_VIP].SetName("VIP");
	Segments[SEG_VSU].SetName("VSU");
	Segments[SEG_NVC].SetName("NVC");
	Segments[SEG_UNUSED].SetName("Not Used (0x03000000-0x03ffffff)");
	Segments[SEG_CARTEX].SetName("CARTEX");
	Segments[SEG_WRAM].SetName("WRAM");
	Segments[SEG_SRAM].SetName("SRAM");
	Segments[SEG_ROM].SetName("ROM");
}

bool
Memory::Segment::ValidSize(u_int size)
{
	return (size <= MaxSegSize && size == SizeCeil(size));
}

bool
Memory::Initialize()
{
#if notyet
	PageSize = os_get_pagesize();

	ZeroPage = os_pages_map(PageSize, os_perm_mask::READ);
	if (!ZeroPage)
	{
		os_runtime_error(OS_RUNERR_TYPE_OSERR, os_resp_mask::ABORT, "Could not map zero page");
		return false;
	}
#endif // notyet

	return true;
}

void
Memory::Finalize(void)
{
#if notyet
	if (ZeroPage)
		os_pages_unmap(ZeroPage, PageSize);
#endif // notyet
}

bool
Memory::Segment::Allocate(u_int size, os_perm_mask perms)
{
	assert(ValidSize(size));
	ms_ptr = static_cast<uint8_t *>(malloc(size));
	if (!ms_ptr)
	{
		os_runtime_error(OS_RUNERR_TYPE_OSERR, os_runerr_resp_mask::OKAY,
				"Could not allocate 0x%x bytes for segment %s", size, ms_name);
		return false;
	}
	SetLayout(size);
	ms_perms = perms;

#ifndef NDEBUG
	bool init_dead_mem = INIT_DEAD_MEM;
	char *dead_mem_env = getenv("INIT_DEAD_MEM");
	if (dead_mem_env)
		init_dead_mem = atoi(dead_mem_env);
	if (init_dead_mem)
		Fill(DEAD_MEM_PATTERN);
#endif // !NDEBUG

	return true;
}

bool
Memory::Segment::Map(u_int size, os_file_handle_t handle, os_perm_mask perms)
{
	ms_handle = os_mmap_file(handle, size, os_perm_mask::READ, (void **)&ms_ptr);
	if (!ms_ptr)
	{
		os_runtime_error(OS_RUNERR_TYPE_OSERR, os_runerr_resp_mask::OKAY, "os_mmap_file() %s", ms_name);
		return false;
	}
	SetLayout(size);
	ms_perms = perms;
	ms_is_mmap = true;
	return true;
}

bool
Memory::Segment::Reallocate(u_int size)
{
	assert(!ms_is_mmap);
	assert(ValidSize(size));
	ms_ptr = static_cast<uint8_t *>(realloc(ms_ptr, size));
	if (!ms_ptr)
	{
		os_runtime_error(OS_RUNERR_TYPE_OSERR, os_runerr_resp_mask::OKAY, "Could not reallocate 0x%x bytes for segment %s", size, ms_name);
		return false;
	}
	SetLayout(size);
	return true;
}

void
Memory::Segment::Free()
{
	if (!ms_is_mmap)
		free(ms_ptr);
	else
	{
		if (!os_munmap_file(ms_handle, ms_ptr, ms_size))
			os_runtime_error(OS_RUNERR_TYPE_OSERR, os_runerr_resp_mask::OKAY,
					"os_munmap_file(mem_segs[%s], ...) failed",
					ms_name);
		ms_is_mmap = false;
	}
	ms_ptr = nullptr;
}

void Memory::Segment::Fill(u_int32_t pattern)
{
	memset_pattern4(ms_ptr, &pattern, ms_size);
}

void
Memory::Segment::SetLayout(u_int size)
{
	assert(size == SizeCeil(size));
	SetLayout(size, size - 1);
}

void
Memory::Segment::SetLayout(u_int size, u_int32_t addrmask)
{
	assert(size <= MaxSegSize);
	assert(addrmask < size);

	ms_size = size;
	ms_addrmask = addrmask;
}

u_int32_t
Memory::SizeCeil(u_int32_t size)
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

bool
Memory::Prepare(Request *request)
{
	SegDesc seg = MEM_ADDR2SEG(request->mr_emu);
	if (seg == SEG_VIP)
		return vip_mem_prepare(request);
	else if (seg == SEG_VSU)
		return vsu_mem_prepare(request);
	else if (seg == SEG_NVC)
		return nvc_mem_prepare(request);
	else if (seg == SEG_SRAM)
		return sram_mem_prepare(request);
	else if (Segments[seg].GetSize())
	{
		u_int32_t offset = request->mr_emu & Segments[seg].GetAddrMask();

		request->mr_host = const_cast<u_int8_t *>(Segments[seg].GetData() + offset);
		request->mr_perms = Segments[seg].GetPerms();
		return true;
	}
	else
		return false;
}

/*
void *
Memory::Emu2Host(u_int32_t addr, u_int size)
{
	Request request = {.mr_emu = addr, .mr_size = size, .mr_ops = 0};
	if (!mem_prepare(&request))
		return NULL;
	return request.mr_host;
}
*/

bool
Memory::Request::PermsError(bool *always_ignorep) const
{
	debug_str_t addr_s, ops_s, perms_s;
	debug_str_t msg;
	os_snprintf(msg, sizeof(msg), "Invalid memory operation at %s, mem ops = %s, perms = %s",
			debug_format_addr(mr_emu, addr_s),
			debug_format_perms(mr_ops, ops_s),
			debug_format_perms(mr_perms, perms_s));

	bool allow_ignore = ((mr_ops & os_perm_mask::READ) == os_perm_mask::NONE);
	return debug_runtime_error(allow_ignore, always_ignorep, msg);
}

bool
Memory::BusError(u_int32_t addr) const
{
	return debug_fatal_errorf("Bus error at 0x%08x", addr);
}

const void *
Memory::GetReadPtr(u_int32_t addr, u_int size, u_int *mem_waitp) const
{
	SegDesc seg = MEM_ADDR2SEG(addr);
	switch (seg)
	{
		case SEG_VIP:
		{
			Request request = {.mr_emu = addr, .mr_size = size, .mr_ops = os_perm_mask::READ};
			if (!vip_mem_prepare(&request))
				return NULL;
			*mem_waitp = request.mr_wait;
			return request.mr_host;
		}
		case SEG_VSU:
		{
			Request request = {.mr_emu = addr, .mr_size = size, .mr_ops = os_perm_mask::READ};
			if (!vsu_mem_prepare(&request))
				return NULL;
			*mem_waitp = request.mr_wait;
			return request.mr_host;
		}
		case SEG_NVC:
		{
			Request request = {.mr_emu = addr, .mr_size = size, .mr_ops = os_perm_mask::READ};
			if (!nvc_mem_prepare(&request))
				return NULL;
			*mem_waitp = request.mr_wait;
			return request.mr_host;
		}
		case SEG_SRAM:
		{
			Request request = {.mr_emu = addr, .mr_size = size, .mr_ops = os_perm_mask::READ};
			if (!sram_mem_prepare(&request))
				return nullptr;
			*mem_waitp = request.mr_wait;
			return request.mr_host;
		}
		default:
		{
			if (!Segments[seg].GetSize())
			{
				BusError(addr);
				return NULL;
			}

			u_int32_t offset = addr & Segments[seg].GetAddrMask();

			if (EnableChecks && (Segments[seg].GetPerms() & os_perm_mask::READ) == os_perm_mask::NONE)
			{
				Request request =
				{
					.mr_emu = addr,
					.mr_ops = os_perm_mask::READ,
					.mr_perms = Segments[seg].GetPerms()
				};
				request.PermsError(NULL);
				return NULL;
			}

			*mem_waitp = 2;
			return Segments[seg].GetData() + offset;
		}
	}
}

bool
Memory::Read(u_int32_t addr, void *dest, u_int size, bool is_exec, u_int *mem_waitp) const
{
	assert(size > 0);
	struct Request request =
	{
		.mr_emu = addr,
		.mr_size = size,
		.mr_perms = os_perm_mask::READ | os_perm_mask::WRITE,
		.mr_mask = 0xffffffff,
		.mr_wait = 2
	};
	request.mr_ops = os_perm_mask::READ;
	if (is_exec)
		request.mr_ops|= os_perm_mask::EXEC;

	if (!const_cast<Memory *>(this)->Prepare(&request))
		return BusError(addr);

	if ((request.mr_perms & request.mr_ops) != request.mr_ops)
		return request.PermsError(NULL);

	if (debug_trace_mem_read && !is_exec)
	{
		debug_str_t addr_s;
		debug_str_t hex_s;
		debug_tracef("mem.read", "%s <- [" DEBUG_ADDR_FMT "]",
		             debug_format_hex(static_cast<u_int8_t *>(request.mr_host), size, hex_s),
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

void *
Memory::GetWritePtr(u_int32_t addr, u_int size, u_int32_t *maskp)
{
	assert(size > 0);
	Memory::Request request =
	{
		.mr_emu = addr,
		.mr_size = size,
		.mr_perms = os_perm_mask::READ | os_perm_mask::WRITE | os_perm_mask::EXEC,
		.mr_ops = os_perm_mask::WRITE,
		.mr_mask = 0xffffffff,
		.mr_wait = 2
	};

	if (!Prepare(&request))
	{
		// TODO: SEGV
		BusError(addr);
		return NULL;
	}

	*maskp = request.mr_mask;
	return request.mr_host;
}

bool
Memory::Write(u_int32_t addr, const void *src, u_int size, u_int *mem_waitp)
{
	assert(size > 0);
	Memory::Request request =
	{
		.mr_emu = addr,
		.mr_size = size,
		.mr_perms = os_perm_mask::READ | os_perm_mask::WRITE | os_perm_mask::EXEC,
		.mr_ops = os_perm_mask::WRITE,
		.mr_mask = 0xffffffff,
		.mr_wait = 2
	};

	if (!Prepare(&request))
	{
		// TODO: SEGV
		return BusError(addr);
	}

	if ((request.mr_perms & os_perm_mask::WRITE) == os_perm_mask::NONE)
	{
		static bool ignore_writes = false;
		return request.PermsError(&ignore_writes);
	}

	if (debug_trace_mem_write)
	{
		debug_str_t addr_s;
		debug_str_t hex_s;
		debug_tracef("mem.write", "[" DEBUG_ADDR_FMT "] <- %s",
		             debug_format_addr(addr, addr_s), debug_format_hex(static_cast<const u_int8_t *>(src), size, hex_s));
	}

	SegDesc seg = MEM_ADDR2SEG(addr);
	if (seg == Memory::SEG_VSU)
		vsu_mem_write(&request, src);
	else if (seg == Memory::SEG_NVC)
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
Memory::TestAddrRO(const char *name, u_int32_t emu_addr, u_int size, void *expected) const
{
	u_int mem_wait;
	const void *addr = GetReadPtr(emu_addr, size, &mem_wait);
	if (addr != expected)
		debug_fatal_errorf("mem_get_read_ptr(%s@0x%08x) is %p but should be %p (offset %ld)",
				name, emu_addr, addr, expected, (intptr_t)expected - (intptr_t)addr);
}

void
Memory::TestAddr(const char *name, u_int32_t emu_addr, u_int size, void *expected)
{
	TestAddrRO(name, emu_addr, size, expected);

	u_int32_t mask;
	void *addr = GetWritePtr(emu_addr, size, &mask);
	if (addr != expected)
		debug_fatal_errorf("mem_get_write_ptr(%s@0x%08x) is %p but should be %p (offset %ld)",
				name, emu_addr, addr, expected, (intptr_t)expected - (intptr_t)addr);
}
