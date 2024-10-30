#include <sys/time.h>
#include <cerr>
#include <cstdio>
#include "TK_Null.Gen.hh"

u_int tk_win_width, tk_win_height;
int tk_draw_width, tk_draw_height;
float tk_draw_scale;

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

void
tk_update_caption(const char *caption __unused)
{
}

u_int32_t
tk_get_usec(void)
{
	struct timeval now;
	if (gettimeofday(&now, NULL) == -1)
		warn("gettimeofday()");
	return (now.tv_sec - start_time.tv_sec) * 1000000 + (now.tv_usec - start_time.tv_usec);
}

void
tk_frame_begin(void)
{
}

void
tk_frame_end(void)
{
}

void
tk_main(void)
{
}

void tk_fini(void)
{
}
