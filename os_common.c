#include "types.h"
#include "os_common.h"

#if INTERFACE
#	include <stdarg.h>

	enum os_perm
	{
		OS_PERM_READ = BIT(0),
		OS_PERM_WRITE = BIT(1),
		OS_PERM_RDWR = OS_PERM_READ | OS_PERM_WRITE,
		OS_PERM_EXEC = BIT(2)
	};

	enum os_seek_anchor
	{
		OS_SEEK_SET,
		OS_SEEK_CUR,
		OS_SEEK_END
	};

	enum os_runerr_type
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
		OS_RUNERR_RESP_ABORT,
		OS_RUNERR_NUM_RESP UNUSED_ENUM
	};
#endif // INTERFACE

enum os_runerr_resp
os_runtime_error(enum os_runerr_type type, enum os_runerr_resp resp_mask, const char *fmt, ...)
{
	va_list ap;
	va_start(ap, fmt);
	enum os_runerr_resp resp = os_runtime_verror(type, resp_mask, fmt, ap);
	va_end(ap);
	return resp;
}

