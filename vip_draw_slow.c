#if INTERFACE
# include <sys/types.h>
#endif // INTERFACE

#include <string.h>
#include <assert.h>
#include <math.h>

#include "vip_draw_slow.h"

#pragma GCC diagnostic warning "-Wunused-parameter"
#pragma GCC diagnostic warning "-Wunused-function"
#pragma GCC diagnostic warning "-Wunused-variable"

static void
vip_fb_write(u_int8_t *fb, u_int16_t x, u_int16_t y, u_int8_t value)
{
	assert(y < 224);
	assert(x < 384);
	u_int offset = x * 224 + y;
	u_int shift = (offset % 4) * 2;
	u_int8_t mask = ~(0b11 << shift);
	fb[offset / 4] = (fb[offset / 4] & mask) | (value << shift);
}

static void
vip_fb_write_clip(u_int8_t *fb, u_int16_t x, u_int16_t y, u_int8_t value)
{
	if (x < 384 && y < 224)
		vip_fb_write(fb, x, y, value);
}

void
vip_draw_start(u_int fb_index)
{
	u_int8_t *left_fb, *right_fb;

	if (fb_index == 0)
	{
		left_fb = vip_vrm.vv_left0;
		right_fb = vip_vrm.vv_right0;
	}
	else
	{
		left_fb = vip_vrm.vv_left1;
		right_fb = vip_vrm.vv_right1;
	}

	u_int8_t bg_pixel = vip_regs.vr_bkcol & 0b11;
	bg_pixel|= bg_pixel << 2;
	bg_pixel|= bg_pixel << 4;
	memset(left_fb, bg_pixel, sizeof(vip_vrm.vv_left0));
	memset(right_fb, bg_pixel, sizeof(vip_vrm.vv_right0));
}

static u_int8_t
vip_bgmap_read_slow(const struct vip_bgsc *bgmap_base,
                    const struct vip_world_att *vwa,
                    u_int win_x, u_int win_y,
                    bool right,
                    union vip_params *vp,
                    bool *opaquep)
{
	int x, y;
	if ((enum vip_world_bgm)vwa->vwa_bgm == WORLD_BGM_AFFINE)
	{
		float mx = (float)vp->vp_affine.va_mx / (1 << 3);
		float my = (float)vp->vp_affine.va_my / (1 << 3);
		float dx = (float)vp->vp_affine.va_dx / (1 << 9);
		float dy = (float)vp->vp_affine.va_dy / (1 << 9);
		int bias_x = win_x;
		//assert(vp->vp_affine.va_mp > -256 && vp->vp_affine.va_mp < 255);
		if ((vp->vp_affine.va_mp >= 0) == right)
			bias_x+= vp->vp_affine.va_mp;
		x = (int)lroundf(mx + dx * bias_x);
		y = (int)lroundf(my + dy * bias_x);
	}
	else
	{
		if (right)
			x = vwa->vwa_mx + vwa->vwa_mp + win_x;
		else
			x = vwa->vwa_mx - vwa->vwa_mp + win_x;
		y = vwa->vwa_my + win_y;

		if (vwa->vwa_bgm == WORLD_BGM_H_BIAS)
		{
			if (right)
				x += vp->vp_hbias.vh_hofstr;
			else
				x += vp->vp_hbias.vh_hofstl;
		}
	}

	u_int width_chrs = (vwa->vwa_scy + 1) * vip_bgseg_width,
			height_chrs = (vwa->vwa_scx + 1) * vip_bgseg_height;
	int bg_x = (u_int)x / 8, bg_y = (u_int)y / 8;
	u_int chr_x = (u_int)x % 8, chr_y = (u_int)y % 8;
	const struct vip_bgsc *vb;
	if (bg_x >= 0 && (u_int)bg_x < width_chrs && bg_y >= 0 && (u_int)bg_y < height_chrs)
		vb = &(bgmap_base[bg_y * width_chrs + bg_x]);
	else if (vwa->vwa_over)
		vb = &(bgmap_base[vwa->vwa_over_chrno]);
	else
		vb = &(bgmap_base[(bg_y % height_chrs) * width_chrs + (bg_x % width_chrs)]);

	return vip_bgsc_read_slow(vb, chr_x, chr_y, opaquep);
}

static u_int8_t
vip_bgmap_read(const struct vip_bgsc *bgmap_base, const struct vip_world_att *vwa, int x, int y, bool *opaquep)
{
	u_int width_chrs = (vwa->vwa_scy + 1) * vip_bgseg_width,
			height_chrs = (vwa->vwa_scx + 1) * vip_bgseg_height;
	int bg_x = (u_int)x / 8, bg_y = (u_int)y / 8;
	u_int chr_x = (u_int)x % 8, chr_y = (u_int)y % 8;
	const struct vip_bgsc *vb;
	if (bg_x >= 0 && (u_int)bg_x < width_chrs && bg_y >= 0 && (u_int)bg_y < height_chrs)
		vb = &(bgmap_base[bg_y * width_chrs + bg_x]);
	else if (vwa->vwa_over)
		vb = &(bgmap_base[vwa->vwa_over_chrno]);
	else
		vb = &(bgmap_base[(bg_y % height_chrs) * width_chrs + (bg_x % width_chrs)]);

	return vip_bgsc_read_slow(vb, chr_x, chr_y, opaquep);
}

static void __unused
vip_draw_bgmap_row_slow(const struct vip_world_att *vwa,
                        u_int16_t *param_tbl,
                        struct vip_bgsc *bgmap_base,
                        u_int win_y,
                        u_int scr_y,
                        u_int8_t *left_fb, u_int8_t *right_fb)
{
	union vip_params *params;
	if (vwa->vwa_bgm == WORLD_BGM_H_BIAS)
		params = (union vip_params *)((struct vip_hbias *)param_tbl + win_y);
	else if (vwa->vwa_bgm == WORLD_BGM_AFFINE)
		params = (union vip_params *)((struct vip_affine *)param_tbl + win_y);

	for (u_int win_x = 0; win_x <= vwa->vwa_w; ++win_x)
	{
		if (vwa->vwa_lon)
		{
			bool opaque;
			u_int8_t pixel = vip_bgmap_read_slow(bgmap_base, vwa, win_x, win_y, false, params, &opaque);
			if (opaque)
				vip_fb_write_clip(left_fb, vwa->vwa_gx - vwa->vwa_gp + win_x, scr_y, pixel);
		}
		if (vwa->vwa_ron)
		{
			bool opaque;
			u_int8_t pixel = vip_bgmap_read_slow(bgmap_base, vwa, win_x, win_y, true, params, &opaque);
			if (opaque)
				vip_fb_write_clip(right_fb, vwa->vwa_gx + vwa->vwa_gp + win_x, scr_y, pixel);
		}
	}
}

static void
vip_draw_bgmap_row(const struct vip_bgsc *bgmap_base,
                   const struct vip_world_att *vwa,
                   u_int y, u_int scr_y,
                   const struct vip_hspan *hspan,
                   u_int8_t *fb)
{
	u_int width = hspan->vhs_width;
	int x = hspan->vhs_win_x;
	u_int scr_x = hspan->vhs_scr_x;
	while (width > 0)
	{
		bool opaque;
		u_int8_t pixel = vip_bgmap_read(bgmap_base, vwa, x, y, &opaque);
		if (opaque)
			vip_fb_write(fb, scr_x, scr_y, pixel);
		++x;
		++scr_x;
		--width;
	}
}

static void
vip_draw_bgmap(const struct vip_bgsc *bgmap_base,
               const struct vip_world_att *vwa,
               const struct vip_vspan *vspan,
               const struct vip_hspan *hspan,
               u_int8_t *fb)
{
	u_int height = vspan->vvs_height;
	u_int y = vwa->vwa_my + vspan->vvs_win_y;
	u_int scr_y = vspan->vvs_scr_y;
	while (height > 0)
	{
		vip_draw_bgmap_row(bgmap_base, vwa, y, scr_y, hspan, fb);
		++y;
		++scr_y;
		--height;
	}
}

static void
vip_draw_obj_row(const struct vip_oam *obj,
                 struct vip_chr *vc,
                 u_int chr_y, u_int scr_y,
                 u_int8_t *left_fb, u_int8_t *right_fb)
{
	int16_t jp = cpu_extend14to16(obj->vo_jp);
	int scr_l_x = obj->vo_jx - jp, scr_r_x = obj->vo_jx + jp;
	u_int8_t plt = vip_regs.vr_jplt[obj->vo_jplts];
	for (u_int chr_x = 0; chr_x < 8; ++chr_x)
	{
		u_int8_t pixel = vip_chr_read_slow(vc, chr_x, chr_y, obj->vo_jhflp, obj->vo_jvflp);
		if (pixel)
		{
			pixel = (plt >> (pixel << 1)) & 0b11;
			if (obj->vo_jlon)
				vip_fb_write_clip(left_fb, scr_l_x + chr_x, scr_y, pixel);
			if (obj->vo_jron)
				vip_fb_write_clip(right_fb, scr_r_x + chr_x, scr_y, pixel);
		}
	}
}

void
vip_draw_finish(u_int fb_index __unused)
{
}

void
vip_draw_8rows(u_int8_t *left_fb, u_int8_t *right_fb, const u_int min_scr_y)
{
	u_int obj_group = 4;
	u_int world_index = 31;
	do
	{
		struct vip_world_att *vwa = &(vip_dram.vd_world_atts[world_index]);

		if (vwa->vwa_end)
			break;

		if (vwa->vwa_bgm == WORLD_BGM_OBJ)
		{
			if (obj_group == 0)
			{
				debug_runtime_errorf(NULL, "VIP already searched 4 OBJ groups for worlds");
				break;
			}
			--obj_group;
		}

		if (!vwa->vwa_lon && !vwa->vwa_ron)
			continue;

		if ((vip_world_mask & (1u << world_index)) == 0)
			continue;

		if ((vip_bgm_types & (1u << vwa->vwa_bgm)) == 0)
			continue;

		if (debug_trace_vip)
		{
			char buf[1024];
			debug_format_world_att(buf, sizeof(buf), vwa);
			debug_tracef("vip", "WORLD_ATT[%u]: %s\n", world_index, buf);
		}

		if (vwa->vwa_bgm == WORLD_BGM_OBJ)
		{
			int start_index;
			if (obj_group > 0)
				start_index = (vip_regs.vr_spt[obj_group - 1] + 1) & 0x3ff;
			else
				start_index = 0;

			for (int obj_index = vip_regs.vr_spt[obj_group] & 0x3ff; obj_index >= start_index; --obj_index)
			{
				assert(obj_index >= 0 && obj_index < 1024);
				struct vip_oam *obj = &(vip_dram.vd_oam[obj_index]);

				if (!obj->vo_jlon && !obj->vo_jron)
					continue;

				if (debug_trace_vip)
				{
					debug_str_t oamstr;
					debug_format_oam(oamstr, obj);
					debug_tracef("vip", "OBJ[%u]: %s\n", obj->vo_jca, oamstr);
				}

				struct vip_vspan vspan;
				if (vip_clip_vspan(min_scr_y, 8, obj->vo_jy, 8, &vspan))
				{
					struct vip_chr *vc = VIP_CHR_FIND(obj->vo_jca);
					while (vspan.vvs_height > 0)
					{
						vip_draw_obj_row(obj, vc, vspan.vvs_win_y, vspan.vvs_scr_y, left_fb, right_fb);
						++vspan.vvs_scr_y;
						++vspan.vvs_win_y;
						--vspan.vvs_height;
					}
				}
			}
		}
		else
		{
			struct vip_vspan vspan;
			if (vip_clip_vspan(min_scr_y, 8, vwa->vwa_gy, vwa->vwa_h + 1, &vspan))
			{
				switch (vwa->vwa_bgm)
				{
					case WORLD_BGM_NORMAL:
					{
						struct vip_bgsc *bgmap_base = vip_dram.vd_shared.s_bgsegs[vwa->vwa_bgmap_base];

						struct vip_hspan left_hspan;
						if (vwa->vwa_lon && vip_clip_hspan(vwa->vwa_gx - vwa->vwa_gp,
						                                   vwa->vwa_mx - vwa->vwa_mp,
						                                   vwa->vwa_w + 1,
						                                   &left_hspan))
							vip_draw_bgmap(bgmap_base, vwa, &vspan, &left_hspan, left_fb);
						struct vip_hspan right_hspan;
						if (vwa->vwa_ron && vip_clip_hspan(vwa->vwa_gx + vwa->vwa_gp,
						                                   vwa->vwa_mx + vwa->vwa_mp,
						                                   vwa->vwa_w + 1,
						                                   &right_hspan))
							vip_draw_bgmap(bgmap_base, vwa, &vspan, &right_hspan, right_fb);
						break;
					}

					case WORLD_BGM_H_BIAS:
					case WORLD_BGM_AFFINE:
					{
						struct vip_bgsc *bgmap_base = vip_dram.vd_shared.s_bgsegs[vwa->vwa_bgmap_base];
						u_int16_t *param_tbl;
						if (vwa->vwa_bgm == WORLD_BGM_H_BIAS || vwa->vwa_bgm == WORLD_BGM_AFFINE)
							param_tbl = vip_dram.vd_shared.s_param_tbl + vwa->vwa_param_base;

						while (vspan.vvs_height > 0)
						{
							vip_draw_bgmap_row_slow(vwa,
							                        param_tbl,
							                        bgmap_base,
							                        vspan.vvs_win_y, vspan.vvs_scr_y,
							                        left_fb, right_fb);
							++vspan.vvs_scr_y;
							++vspan.vvs_win_y;
							--vspan.vvs_height;
						}
						break;
					}
				}
			}
		}
	} while (--world_index > 0);
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

void
vip_fb_convert(const u_int8_t *fb, const struct vip_ctc *clm_tbl, u_int32_t *argb)
{
	const struct vip_ctc *ctc = clm_tbl + 17;
	for (u_int col_group = 0; col_group < 96; ++col_group)
	{
		u_int32_t lut[4];
		lut[0] = 0xff000000;
		if (vip_use_bright)
		{
			u_int8_t int_lut[3];
			int_lut[0] = vip_regs.vr_brta + 1;
			int_lut[1] = int_lut[0] + vip_regs.vr_brtb + 1;
			int_lut[2] = int_lut[1] + vip_regs.vr_brtc + 1;
			for (u_int i = 0; i < 3; ++i)
			{
				u_int32_t intensity = (int_lut[i] * (ctc->vc_repeat + 1) * 256) / VIP_MAX_BRIGHT;
				static bool ignore_intensity = false;
				if (intensity > 0xff)
					debug_runtime_errorf(&ignore_intensity,
					                     "Column intensity too high (%u) in column group %u, pixel value %u\n"
					                     "BRTA=%u, BRTB=%u, BRTC=%u, REST=%u, CTC LENGTH=%u, REPEAT=%u",
					                     intensity, col_group, i,
					                     vip_regs.vr_brta, vip_regs.vr_brtb, vip_regs.vr_brtc, vip_regs.vr_rest,
					                     ctc->vc_length, ctc->vc_repeat);
				lut[1 + i] = 0xff000000 | (intensity << 16) | (intensity << 8) | intensity;
			}
		}
		else
		{
			lut[1] = 0xff555555;
			lut[2] = 0xffaaaaaa;
			lut[3] = 0xffffffff;
		}

		for (u_int col_offset = 0; col_offset < 4; ++col_offset)
		{
			for (u_int row_group = 0; row_group < 56; ++row_group)
			{
				*argb++ = lut[*fb & 0x3];
				*argb++ = lut[(*fb >> 2) & 0x3];
				*argb++ = lut[(*fb >> 4) & 0x3];
				*argb++ = lut[(*fb >> 6) & 0x3];
				++fb;
			}
		}
		++ctc;
	}
}
