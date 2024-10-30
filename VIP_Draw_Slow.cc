#if INTERFACE
# include <sys/types.h>
#endif // INTERFACE

#include <cstring>
#include <cassert>
#include <cmath>

#include "vip_draw_slow.h"

#pragma GCC diagnostic warning "-Wunused-parameter"
#pragma GCC diagnostic warning "-Wunused-function"
#pragma GCC diagnostic warning "-Wunused-variable"

static u_int32_t
vip_fb_read_argb_slow(const u_int8_t *fb, u_int16_t x, u_int16_t y, u_int8_t repeat)
{
	assert(repeat == 0);
	u_int8_t pixel = vip_fb_read_slow(fb, x, y);
	u_int32_t intensity = 0;
	if (vip_use_bright)
	{
		switch (pixel)
		{
			case 3:
				assert(255 - intensity >= vip_regs.vr_brtc);
				intensity = vip_regs.vr_brtc + 1;
				/*FALLTHRU*/
			case 2:
				assert(255 - intensity >= vip_regs.vr_brtb);
				intensity += vip_regs.vr_brtb + 1;
				/*FALLTHRU*/
			case 1:
				assert(255 - intensity >= vip_regs.vr_brta);
				intensity += vip_regs.vr_brta + 1;
				/*FALLTHRU*/
			case 0:
				break;
		}
		intensity = (intensity * (repeat + 1) * 256) / VIP_MAX_BRIGHT;
		assert(intensity <= 0xff);
	}
	else // For debugging
		intensity = pixel | (pixel << 2) | (pixel << 4) | (pixel << 6);

	return 0xff000000 | (intensity << 16) | (intensity << 8) | intensity;
}

void
vip_fb_convert_slow(const u_int8_t *fb, const struct vip_ctc *clm_tbl, u_int32_t *argb)
{
	for (u_int x = 0; x < 384; ++x)
	{
		const struct vip_ctc *ctc = &(clm_tbl[17 + x / 4]);
		for (u_int y = 0; y < 224; ++y)
			argb[x * 224 + y] = vip_fb_read_argb_slow(fb, x, y, ctc->vc_repeat);
	}
}
