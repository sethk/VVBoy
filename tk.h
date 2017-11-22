# include <sys/types.h>
# include <stdbool.h>

extern bool tk_init(void);
extern void tk_step(void);
extern void tk_blit(const u_int8_t *fb,bool right);
extern enum nvc_key tk_poll(void);
extern void tk_fini(void);
