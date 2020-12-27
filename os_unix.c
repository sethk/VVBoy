#include "types.h"
#include "os_unix.h"

#if INTERFACE
#	include <stdio.h>

	typedef FILE *os_file_handle_t;
#define OS_FILE_HANDLE_INVALID NULL
	typedef void *os_mmap_handle_t;
#define OS_MMAP_HANDLE_INVALID NULL

#	include <strings.h>
#	define os_bcopy bcopy
#	define os_bcmp bcmp
#	define os_bzero bzero
#	define os_strcasecmp strcasecmp
#	define os_snprintf snprintf
#	define os_vsnprintf vsnprintf

#	include <search.h>
	typedef node_t os_tnode_t;
#endif // INTERFACE

#include <sys/time.h>
#include <sys/stat.h>
#include <sys/fcntl.h>
#include <sys/errno.h>
#include <sys/param.h>
#include <unistd.h>
#include <signal.h>

u_int64_t
os_get_usec(void)
{
	struct timeval tv;
	if (gettimeofday(&tv, NULL) == -1)
		main_fatal_error(OS_RUNERR_TYPE_OSERR, "gettimeofday() failed");

	return tv.tv_sec * 1000000 + tv.tv_usec;
}

os_file_handle_t
os_file_open(const char *fn, enum os_perm perm)
{
	const char *mode;
	switch (perm)
	{
		case OS_PERM_READ: mode = "r"; break;
		case OS_PERM_WRITE: mode = "w"; break;
		case OS_PERM_RDWR: mode = "w+"; break;
		case OS_PERM_EXEC:
		default:
		   os_debug_trap();
	}
	return fopen(fn, mode);
}

void
os_file_close(os_file_handle_t handle)
{
	fclose(handle);
}

bool
os_file_exists(const char *path)
{
	struct stat st;
	if (stat(path, &st) != -1)
		return true;
	
	if (errno != ENOENT)
		os_runtime_error(OS_RUNERR_TYPE_OSERR, BIT(OS_RUNERR_RESP_OKAY), "Could not stat %s", path);

	return false;
}

bool
os_file_iseof(os_file_handle_t handle)
{
	return (feof(handle) != 0);
}

bool
os_file_getsize(os_file_handle_t handle, off_t *psize)
{
	struct stat st;
	if (fstat(fileno(handle), &st) == -1)
		return false;

	*psize = st.st_size;
	return true;
}

size_t
os_file_read(os_file_handle_t handle, void *buffer, size_t size)
{
	return fread(buffer, 1, size, handle);
}

off_t
os_file_seek(os_file_handle_t handle, off_t offset, enum os_seek_anchor anchor)
{
	int whence;
	switch (anchor)
	{
		case OS_SEEK_SET: whence = SEEK_SET; break;
		case OS_SEEK_CUR: whence = SEEK_CUR; break;
		case OS_SEEK_END: whence = SEEK_END; break;
	}
	if (fseek(handle, offset, whence) == -1)
		return -1;

	return ftello(handle);
}

os_mmap_handle_t
os_mmap_file(os_file_handle_t file_handle, size_t size, enum os_perm perms, void **pmap)
{
	int prot = 0;
	if (perms & BIT(OS_PERM_READ))
		prot|= PROT_READ;
	if (perms & BIT(OS_PERM_WRITE))
		prot|= PROT_WRITE;
	if (perms & BIT(OS_PERM_EXEC))
		prot|= PROT_EXEC;

	*pmap = mmap(NULL, size, prot, MAP_FILE | MAP_PRIVATE, fileno(file_handle), 0);
	return *pmap;
}

bool
os_munmap_file(os_mmap_handle_t handle, void *ptr, size_t size)
{
	(void)handle;

	if (ptr && munmap(ptr, size) == -1)
		return false;

	return true;
}

void
os_debug_trap(void)
{
	raise(SIGTRAP);
}
