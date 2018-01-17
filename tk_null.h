/* This file was automatically generated.  Do not edit! */
#include <sys/types.h>
#include <stdbool.h>
void tk_fini(void);
void tk_fini(void);
enum tk_keys {
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
typedef enum tk_keys tk_keys;
enum tk_keys tk_poll(void);
enum tk_keys tk_poll(void);
void tk_blit(const u_int8_t *fb,bool right);
void tk_blit(const u_int8_t *fb,bool right);
void tk_step(void);
void tk_step(void);
bool tk_init(void);
bool tk_init(void);
