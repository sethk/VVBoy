#include "Types.hh"
#include "OS.hh"
#include "OS_Common.Gen.hh"

os_runerr_resp
os_runtime_error(os_runerr_type type, os_runerr_resp_mask resp_mask, const char *fmt, ...)
{
	va_list ap;
	va_start(ap, fmt);
	os_runerr_resp resp = os_runtime_verror(type, resp_mask, fmt, ap);
	va_end(ap);
	return resp;
}

