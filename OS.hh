#pragma once

#include <cstdio>
#include <cstdarg>

enum class os_perm
{
	READ,
	WRITE,
	EXEC
};

enum class os_perm_mask
{
	NONE = 0,
	READ = BIT(os_perm::READ),
	WRITE = BIT(os_perm::WRITE),
	RDWR = READ | WRITE,
	EXEC = BIT(os_perm::EXEC)
};

DEFINE_ENUM_BITOPS(os_perm_mask, u_int)

enum os_seek_anchor
{
	OS_SEEK_SET,
	OS_SEEK_CUR,
	OS_SEEK_END
};

enum os_runerr_type : u_int
{
	OS_RUNERR_TYPE_OSERR,
	OS_RUNERR_TYPE_WARNING,
	OS_RUNERR_TYPE_EMULATION
};

enum os_runerr_resp
{
	OS_RUNERR_RESP_OKAY,
	OS_RUNERR_RESP_IGNORE,
	OS_RUNERR_RESP_ALWAYS_IGNORE,
	OS_RUNERR_RESP_DEBUG,
	OS_RUNERR_RESP_ABORT, // TODO: Reset instead?
	OS_RUNERR_NUM_RESP UNUSED_ENUM
};

enum class os_runerr_resp_mask
{
	NONE = 0,
	OKAY = BIT(OS_RUNERR_RESP_OKAY),
	IGNORE = BIT(OS_RUNERR_RESP_IGNORE),
	ALWAYS_IGNORE = BIT(OS_RUNERR_RESP_ALWAYS_IGNORE),
	DEBUG = BIT(OS_RUNERR_RESP_DEBUG),
	ABORT = BIT(OS_RUNERR_RESP_ABORT)
};

DEFINE_ENUM_BITOPS(os_runerr_resp_mask, u_int)

typedef FILE *os_file_handle_t;
typedef void *os_mmap_handle_t;
bool os_file_exists(const char *path);
bool os_file_getsize(os_file_handle_t handle,off_t *psize);
bool os_file_iseof(os_file_handle_t handle);
bool os_init(void);
bool os_munmap_file(os_mmap_handle_t handle,void *ptr,size_t size);
os_runerr_resp os_runtime_error(os_runerr_type type,os_runerr_resp_mask resp_mask,const char *fmt,...);
os_runerr_resp os_runtime_verror(os_runerr_type type,os_runerr_resp_mask resp_mask,const char *fmt,va_list ap);
extern os_file_handle_t debug_trace_file;
off_t os_file_seek(os_file_handle_t handle, off_t offset, os_seek_anchor anchor);
os_file_handle_t os_file_open(const char *fn,os_perm_mask perms);
os_mmap_handle_t os_mmap_file(os_file_handle_t file_handle,size_t size,os_perm_mask perms,void **pmap);
size_t os_file_read(os_file_handle_t handle,void *buffer,size_t size);
u_int64_t os_get_usec(void);
void os_choose_file(const char *const exts[],u_int num_exts,bool(*selected_fp)(const char *path));
void os_choose_file(const char *desc,const char *const exts[],u_int num_exts,bool(*selected_fp)(const char *path));
void os_debug_log(const char *msg);
void os_debug_trap(void);
void os_file_close(os_file_handle_t handle);
void os_fini(void);
size_t os_get_pagesize();
void *os_pages_map(size_t size, os_perm_mask perms, void *addr_hint = nullptr);
void os_pages_unmap(void *addr, size_t size);

#ifdef __APPLE__
#	include "OS_macOS.hh"
#else
#	error Not ported to this platform yet
#endif
