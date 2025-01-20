#pragma once

#include "Types.hh"
#include "OS.hh"

#include <type_traits>

class Memory
{
public:
	enum SegDesc
	{
		SEG_VIP = 0,
		SEG_VSU = 1,
		SEG_NVC = 2,
		SEG_UNUSED = 3,
		SEG_CARTEX = 4,
		SEG_WRAM = 5,
		SEG_SRAM = 6,
		SEG_ROM = 7,
		NUM_SEGS = 8
	};

	class Segment
	{
		u_int ms_size;
		os_mmap_handle_t ms_handle;
		u_int8_t *ms_ptr; // TODO: std::byte
		u_int32_t ms_addrmask;
		os_perm_mask ms_perms;
		bool ms_is_mmap;
		const char *ms_name = "Unknown";

	public:
		bool Allocate(u_int size, os_perm_mask perms);
		bool Reallocate(u_int size);
		bool Map(u_int size, os_file_handle_t handle, os_perm_mask perms);
		void Free();

		void SetLayout(u_int size);
		void SetLayout(u_int size, u_int32_t addrmask);

		u_int GetSize() const { return ms_size; }
		u_int8_t *GetData() { return ms_ptr; }
		const u_int8_t *GetData() const { return ms_ptr; }

		u_int32_t GetAddrMask() const { return ms_addrmask; }
		os_perm_mask GetPerms() const { return ms_perms; }

		void Fill(u_int32_t pattern);

	private:
		void SetName(const char *name) { ms_name = name; }
		friend class ::Memory;

		static bool ValidSize(u_int size);
	};

	template<bool IsChecked>
	struct Request
	{
		Request(
			u_int32_t emu_addr,
			u_int size,
			os_perm_mask /*ops*/,
			u_int wait = 2,
			os_perm_mask perms = os_perm_mask::RDWR,
			u_int32_t mask = 0xffffffff
		);

		bool CheckAccess() const;
		bool PermsError(bool *always_ignorep) const;
	};

	template<>
	struct Request<false>
	{
		Request(
			u_int32_t emu_addr,
			u_int size,
			os_perm_mask ops,
			u_int wait = 2,
			os_perm_mask /*perms*/ = os_perm_mask::RDWR,
			u_int32_t /*mask*/ = 0xffffffff
		)
			: mr_emu(emu_addr), mr_size(size), mr_ops(ops), mr_wait(wait)
		{ }

		u_int32_t mr_emu;
		u_int mr_size;
		os_perm_mask mr_ops;
		void *mr_host;
		u_int mr_wait;

		bool CheckAccess() const { return true; }
		bool PermsError(bool * /*always_ignorep*/) const { return true; }
	};

	template<>
	struct Request<true> : Request<false>
	{
		Request(
			u_int32_t emu_addr,
			u_int size,
			os_perm_mask ops,
			u_int wait = 2,
			os_perm_mask perms = os_perm_mask::RDWR,
			u_int32_t mask = 0xffffffff
		)
			: Request<false>(emu_addr, size, ops, wait, perms, mask)
			, mr_perms(perms)
		{ }

		os_perm_mask mr_perms;

		bool CheckAccess() const
		{
			return ((mr_perms & mr_ops) == mr_ops);
		}

		bool PermsError(bool *always_ignorep) const;
	};

public:
	Memory();

	bool Initialize();
	void Finalize();

	template<bool IsChecked, typename T,
			typename = typename std::enable_if<!std::is_pointer<T>::value>::type>
	bool Read(u_int32_t addr, T &dest, u_int *mem_waitp) const;

	template<bool IsChecked>
	bool ReadString(u_int32_t addr, void *dest, u_int size, u_int *mem_waitp) const;

	template<bool IsChecked, typename T,
			typename = typename std::enable_if<!std::is_pointer<T>::value>::type>
	bool Write(u_int32_t addr, const T &src, u_int *mem_waitp);

	template<bool IsChecked>
	bool WriteString(u_int32_t addr, const void *src, u_int size, u_int *mem_waitp);

	void TestAddr(const char *name, u_int32_t emu_addr, u_int size, void *expected);
	void TestAddrRO(const char *name, u_int32_t emu_addr, u_int size, void *expected) const;
	void TestAddrWO(const char *name, u_int32_t emu_addr, u_int size, void *expected) const;

	static u_int32_t SizeCeil(u_int32_t size);

private:
	template<bool IsChecked>
	bool Prepare(Request<IsChecked> &request);
	bool BusError(u_int32_t addr) const;

public:
#if notyet
	size_t PageSize;
	u_int8_t *ZeroPage = nullptr;
#endif // notyet

	Segment Segments[SegDesc::NUM_SEGS];
	bool EnableChecks = false;
	bool IgnoreWriteErrors = false;
};

constexpr u_int32_t MaxSegSize = 0x01000000;
constexpr u_int32_t MaxAddrMask = MaxSegSize - 1;

#define MEM_ADDR2SEG(a) static_cast<Memory::SegDesc>(((a) & 0x07000000) >> 24)
#define MEM_ADDR2OFF(a) ((a) & MaxAddrMask)
#define MEM_SEG2ADDR(s) ((s) << 24)

extern class Memory mem;
