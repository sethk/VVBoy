#include "Memory.hh"

#include <cassert>
#include <algorithm>

// TODO:
template<bool CheckedMem> extern bool vip_mem_prepare(Memory::Request<CheckedMem> *request);
template<bool CheckedMem> extern bool vsu_mem_prepare(Memory::Request<CheckedMem> *request);
template<bool CheckedMem> extern bool nvc_mem_prepare(Memory::Request<CheckedMem> *request);
template<bool CheckedMem> extern bool vip_mem_prepare(Memory::Request<CheckedMem> *request);
template<bool CheckedMem> extern bool sram_mem_prepare(Memory::Request<CheckedMem> *request);
template<bool CheckedMem> extern bool vsu_mem_prepare(Memory::Request<CheckedMem> *request);
template<bool CheckedMem> void vsu_mem_write(const Memory::Request<CheckedMem> *request, const void *src);
template<bool CheckedMem> void nvc_mem_write(const Memory::Request<CheckedMem> *request, const void *src);

typedef char debug_str_t[96];
extern bool debug_trace_mem_read;
extern bool debug_trace_mem_write;
# define DEBUG_ADDR_FMT "%-26s"
extern char * debug_format_hex(const u_int8_t *bytes, u_int byte_size, debug_str_t s);
extern const char * debug_format_addr(u_int32_t addr, debug_str_t s);
extern void __printflike(2, 3) debug_tracef(const char *tag, const char *fmt, ...);

template<bool IsChecked>
bool Memory::Prepare(Request<IsChecked> *request)
{
	const SegDesc seg = MEM_ADDR2SEG(request->mr_emu);

	switch (seg)
	{
		case SEG_VIP: return vip_mem_prepare<IsChecked>(request);
		case SEG_VSU: return vsu_mem_prepare<IsChecked>(request);
		case SEG_NVC: return nvc_mem_prepare(request);
		case SEG_SRAM: return sram_mem_prepare(request);

		default:
			const u_int32_t offset = request->mr_emu & Segments[seg].GetAddrMask();

			if constexpr (IsChecked)
			{
				const u_int32_t extent = offset + request->mr_size;

				if (extent > Segments[seg].GetSize())
					return false;
			}

			request->mr_host = const_cast<u_int8_t *>(Segments[seg].GetData() + offset);

			if constexpr (IsChecked)
				request->mr_perms = Segments[seg].GetPerms();

			return true;
	}
}

template<bool IsChecked>
bool Memory::ReadString(u_int32_t addr, void *dest, u_int size, u_int *mem_waitp) const
{
	assert(size > 0);
	Request<IsChecked> request(addr, size, os_perm_mask::READ);

	if (!const_cast<Memory *>(this)->Prepare(&request))
		return BusError(addr);

	if (!request.CheckAccess())
		return request.PermsError(nullptr);

	if (debug_trace_mem_read)
	{
		u_int offset = 0;
		do
		{
			const u_int sub_size = std::min(size - offset, 4u);

			debug_str_t addr_s;
			debug_str_t hex_s;
			debug_tracef("mem.readstr", "%s <- [" DEBUG_ADDR_FMT "]",
						 debug_format_hex(static_cast<u_int8_t *>(request.mr_host) + offset, sub_size, hex_s),
						 debug_format_addr(addr + offset, addr_s));

			offset+= sub_size;
		}
		while (offset < size);
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

template<bool IsChecked, typename T, typename>
bool Memory::Read(u_int32_t addr, T &dest, u_int *mem_waitp) const
{
	constexpr size_t size = sizeof(T);
	static_assert(size > 0, "Zero-sized read");

	Request<IsChecked> request(addr, size, os_perm_mask::READ);

	if (!const_cast<Memory *>(this)->Prepare(&request))
		return BusError(addr);

	if (!request.CheckAccess())
		return request.PermsError(nullptr);

	extern bool debug_trace_mem_read;

	if (debug_trace_mem_read)
	{
		extern char *debug_format_hex(const u_int8_t *bytes, u_int byte_size, debug_str_t s);
		extern const char *debug_format_addr(u_int32_t addr, debug_str_t s);
		extern void __printflike(2, 3) debug_tracef(const char *tag, const char *fmt, ...);

# define DEBUG_ADDR_FMT "%-26s"

		debug_str_t addr_s;
		debug_str_t hex_s;
		debug_tracef("mem.read", "%s <- [" DEBUG_ADDR_FMT "]",
					 debug_format_hex(static_cast<u_int8_t *>(request.mr_host), size, hex_s),
					 debug_format_addr(addr, addr_s));
	}

	dest = *static_cast<T *>(request.mr_host);

	*mem_waitp = request.mr_wait;
	return true;
}

template<bool IsChecked, typename T, typename>
bool Memory::Write(u_int32_t addr, const T &src, u_int *mem_waitp)
{
	constexpr size_t size = sizeof(T);
	static_assert(size > 0, "Zero-sized write");
	Request<IsChecked> request(addr, size, os_perm_mask::WRITE);

	if (!Prepare(&request))
	{
		// TODO: SEGV
		return BusError(addr);
	}

	if (!request.CheckAccess())
		return request.PermsError(&IgnoreWriteErrors);

	if (debug_trace_mem_write)
	{
		debug_str_t addr_s;
		debug_str_t hex_s;
		debug_tracef("mem.write", "[" DEBUG_ADDR_FMT "] <- %s",
		             debug_format_addr(addr, addr_s),
					 debug_format_hex(reinterpret_cast<const u_int8_t *>(&src), size, hex_s));
	}

	SegDesc seg = MEM_ADDR2SEG(addr);
	if (seg == Memory::SEG_VSU)
		vsu_mem_write<IsChecked>(&request, &src);
	else if (seg == Memory::SEG_NVC)
		nvc_mem_write<IsChecked>(&request, &src);
	else
		*static_cast<T *>(request.mr_host) = src;

	*mem_waitp = request.mr_wait;
	return true;
}

template<bool IsChecked>
bool Memory::WriteString(u_int32_t addr, const void *src, u_int size, u_int *mem_waitp)
{
	assert(size > 0);
	Request<IsChecked> request(addr, size, os_perm_mask::WRITE);

	if (!Prepare(&request))
	{
		// TODO: SEGV
		return BusError(addr);
	}

	if (!request.CheckAccess())
		return request.PermsError(&IgnoreWriteErrors);

	if (debug_trace_mem_write)
	{
		u_int offset = 0;
		do
		{
			const u_int sub_size = std::min(size - offset, 4u);

			debug_str_t addr_s;
			debug_str_t hex_s;
			debug_tracef("mem.writestr", "[" DEBUG_ADDR_FMT "] <- %s",
					debug_format_addr(addr + offset, addr_s),
					debug_format_hex(reinterpret_cast<const u_int8_t *>(&src) + offset, sub_size, hex_s));

			offset+= sub_size;
		}
		while (offset < size);
	}

	SegDesc seg = MEM_ADDR2SEG(addr);
	if (seg == Memory::SEG_VSU)
		vsu_mem_write(&request, src);
	else if (seg == Memory::SEG_NVC)
		nvc_mem_write(&request, src);
	else switch (size)
	{
        case 1:
            *(u_int8_t *)request.mr_host = *(u_int8_t *)src;
            break;
        case 2:
            *(u_int16_t *)request.mr_host = *(u_int16_t *)src;
            break;
        case 4:
            *(u_int32_t *)request.mr_host = *(u_int32_t *)src;
            break;
        default:
            os_bcopy(src, request.mr_host, size);
    }

    *mem_waitp = request.mr_wait;
    return true;
}
