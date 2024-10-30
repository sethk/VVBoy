#include "Types.hh"
#include "OS.hh"
#include "OS_Unix.Gen.hh"

#if INTERFACE
#endif // INTERFACE

#include <sys/time.h>
#include <sys/stat.h>
#include <sys/fcntl.h>
#include <sys/errno.h>
#include <sys/param.h>
#include <sys/mman.h>
#include <unistd.h>
#include <csignal>

u_int64_t
os_get_usec(void)
{
	struct timeval tv;
	if (gettimeofday(&tv, NULL) == -1)
		main_fatal_error(OS_RUNERR_TYPE_OSERR, "gettimeofday() failed");

	return tv.tv_sec * 1000000 + tv.tv_usec;
}

os_file_handle_t
os_file_open(const char *fn, os_perm_mask perms)
{
	const char *mode;
	switch (perms)
	{
		case os_perm_mask::READ: mode = "r"; break;
		case os_perm_mask::WRITE: mode = "w"; break;
		case os_perm_mask::RDWR: mode = "w+"; break;
		case os_perm_mask::EXEC:
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
		os_runtime_error(OS_RUNERR_TYPE_OSERR, os_runerr_resp_mask::OKAY, "Could not stat %s", path);

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
os_file_seek(os_file_handle_t handle, off_t offset, os_seek_anchor anchor)
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
os_mmap_file(os_file_handle_t file_handle, size_t size, os_perm_mask perms, void **pmap)
{
	int prot = 0;
	if ((perms & os_perm_mask::READ) != os_perm_mask::NONE)
		prot|= PROT_READ;
	if ((perms & os_perm_mask::WRITE) != os_perm_mask::NONE)
		prot|= PROT_WRITE;
	if ((perms & os_perm_mask::EXEC) != os_perm_mask::NONE)
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
