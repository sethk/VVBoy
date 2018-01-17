#include "tk_null.h"

bool
tk_init(void)
{
	return true;
}

void
tk_step(void)
{
}

void
tk_blit(const u_int8_t *fb, bool right)
{
}

enum tk_keys
tk_poll(void)
{
	return 0;
}

void tk_fini(void)
{
}
