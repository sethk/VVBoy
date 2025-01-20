#include "Types.hh"
#include "Memory.inl"

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

bool Memory::Request<true>::PermsError(bool *always_ignorep) const
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

void
Memory::TestAddrRO(const char *name, u_int32_t emu_addr, u_int size, void *expected) const
{
	Request<true> request(emu_addr, size, os_perm_mask::READ);
	if (!const_cast<Memory *>(this)->Prepare(&request))
	{
		BusError(emu_addr);
		return;
	}

	if (request.mr_host != expected)
		debug_fatal_errorf("TestAddrRO(%s, 0x%08x, %u) is %p but should be %p (offset %ld)",
				name, emu_addr, size, request.mr_host, expected, (intptr_t)expected - (intptr_t)request.mr_host);

	if (!request.CheckAccess())
		debug_fatal_errorf("TestAddrRO(%s, 0x%08x, %u) should allow read access but does not",
				name, emu_addr, size);
}

void
Memory::TestAddr(const char *name, u_int32_t emu_addr, u_int size, void *expected)
{
	Request<true> request(emu_addr, size, os_perm_mask::WRITE);
	if (!const_cast<Memory *>(this)->Prepare(&request))
	{
		BusError(emu_addr);
		return;
	}

	if (request.mr_host != expected)
		debug_fatal_errorf("TestAddr(%s, 0x%08x, %u) is %p but should be %p (offset %ld)",
				name, emu_addr, size, request.mr_host, expected, (intptr_t)expected - (intptr_t)request.mr_host);

	if (!request.CheckAccess())
		debug_fatal_errorf("TestAddr(%s, 0x%08x, %u) should allow write access but does not",
				name, emu_addr, size);

	TestAddrRO(name, emu_addr, size, expected);
}
