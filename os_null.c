#if INTERFACE
# include <sys/types.h>
# include <stdbool.h>
#endif // INTERFACE
#include "os_null.h"
#include <stdlib.h>

void os_choose_file(const char * const exts[], u_int num_exts, bool (*selected_fp)(const char *path))
{
	(void)exts;
	(void)num_exts;
	(void)selected_fp;
	abort();
}

enum debug_error_state
os_runtime_error(const char *msg, bool allow_always_ignore)
{
	(void)allow_always_ignore;
	fprintf(stderr, "\n*** %s\n", msg);
	return ERROR_ABORT;
}
