#include <sys/time.h>
#include <err.h>
#include <stdio.h>
#include "tk_null.h"

struct timeval start_time;

bool
tk_init(void)
{
	if (gettimeofday(&start_time, NULL) == -1)
	{
		warn("gettimeofday()");
		return false;
	}

	return true;
}

u_int32_t
tk_get_ticks(void)
{
	struct timeval now;
	if (gettimeofday(&now, NULL) == -1)
		warn("gettimeofday()");
	return (now.tv_sec - start_time.tv_sec) * 1000 + (now.tv_usec - start_time.tv_usec) / 1000;
}

void
tk_step(void)
{
}

void
tk_blit(const u_int8_t *fb, bool right)
{
}

void
tk_debug_draw(u_int x, u_int y, u_int32_t argb)
{
}

void
tk_debug_flip(void)
{
}

void
tk_main(void)
{
}

void
tk_quit(void)
{
}

void tk_fini(void)
{
}

enum tk_error_state
tk_runtime_error(const char *msg, bool allow_always_ignore)
{
	fprintf(stderr, "\n*** %s\n", msg);
	return ERROR_ABORT;
}
