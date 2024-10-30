#pragma once

#include <stdio.h>

typedef FILE *os_file_handle_t;
#define OS_FILE_HANDLE_INVALID NULL
	typedef void *os_mmap_handle_t;
#define OS_MMAP_HANDLE_INVALID NULL

#include <strings.h>
#define os_bcopy bcopy
#define os_bcmp bcmp
#define os_bzero bzero
#define os_strcasecmp strcasecmp
#define os_snprintf snprintf
#define os_vsnprintf vsnprintf

typedef node_t os_tnode_t;
