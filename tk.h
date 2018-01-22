#include <sys/types.h>
#include <stdbool.h>

enum tk_keys
{
	KEY_PWR = (1 << 0),
	KEY_SGN = (1 << 1),
	KEY_A = (1 << 2),
	KEY_B = (1 << 3),
	KEY_RT = (1 << 4),
	KEY_LT = (1 << 5),
	KEY_RU = (1 << 6),
	KEY_RR = (1 << 7),
	KEY_LR = (1 << 8),
	KEY_LL = (1 << 9),
	KEY_LD = (1 << 10),
	KEY_LU = (1 << 11),
	KEY_STA = (1 << 12),
	KEY_SEL = (1 << 13),
	KEY_RL = (1 << 14),
	KEY_RD = (1 << 15)
};

extern bool tk_init(void);
extern u_int32_t tk_get_ticks(void);
extern void tk_delay(u_int ticks);
extern void tk_main(void);
extern void tk_blit(const u_int8_t *fb, bool right);
extern void tk_debug_draw(u_int x, u_int y, u_int32_t argb);
extern void tk_debug_flip(void);
extern enum tk_keys tk_poll(void);
extern void tk_fini(void);
