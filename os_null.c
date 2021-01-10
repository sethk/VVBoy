#include "types.h"
#include "os_null.h"
#include <stdlib.h>
#include <stdio.h>

void
os_choose_file(const char * const exts[], u_int num_exts, bool (*selected_fp)(const char *path))
{
	(void)exts;
	(void)num_exts;
	(void)selected_fp;
	abort();
}

enum os_runerr_resp
os_runtime_error(enum os_runerr_type type, enum os_runerr_resp resp_mask, const char *fmt, ...)
{
	va_list ap;
	va_start(ap, fmt);
	enum os_runerr_resp resp = os_runtime_verror(type, resp_mask, fmt, ap);
	va_end(ap);
	return resp;
}

enum os_runerr_resp
os_runtime_verror(enum os_runerr_type type, enum os_runerr_resp resp_mask, const char *fmt, va_list ap)
{
	(void)type;
	(void)resp_mask;
	fputs("\n*** ", stderr);
	vfprintf(stderr, fmt, ap);
	return OS_RUNERR_RESP_ABORT;
}
