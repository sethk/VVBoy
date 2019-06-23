#if INTERFACE
# include <stdbool.h>
#endif // INTERFACE
#include "events.h"
#include "vip.h"
#include <strings.h>
#include <assert.h>
#define CIMGUI_DEFINE_ENUMS_AND_STRUCTS
#include <cimgui/cimgui.h>
#include <SDL_scancode.h>

#if INTERFACE
	struct vip_chr
	{
		u_int16_t vc_rows[8];
	};

	struct vip_bgsc
	{
		unsigned vb_chrno : 11 __attribute__((packed));
		unsigned vb_rfu1 : 1 __attribute__((packed));
		unsigned vb_bvflp : 1 __attribute__((packed));
		unsigned vb_bhflp : 1 __attribute__((packed));
		unsigned vb_gplts : 2 __attribute__((packed));
	};

	struct vip_oam
	{
		int16_t vo_jx;
		unsigned vo_jp : 14 __attribute__((packed));
		unsigned vo_jron : 1 __attribute__((packed));
		unsigned vo_jlon : 1 __attribute__((packed));
		int16_t vo_jy;
		unsigned vo_jca : 11 __attribute__((packed));
		unsigned vo_rfu1 : 1 __attribute__((packed));
		unsigned vo_jvflp : 1 __attribute__((packed));
		unsigned vo_jhflp : 1 __attribute__((packed));
		unsigned vo_jplts : 2 __attribute__((packed));
	};

	struct vip_world_att
	{
		unsigned vwa_bgmap_base : 4 __attribute__((packed));
		unsigned vwa_rfu1 : 2 __attribute__((packed));
		unsigned vwa_end : 1 __attribute__((packed));
		unsigned vwa_over : 1 __attribute__((packed));
		unsigned vwa_scy : 2 __attribute__((packed));
		unsigned vwa_scx : 2 __attribute__((packed));
		unsigned vwa_bgm : 2 __attribute__((packed));
		unsigned vwa_ron : 1 __attribute__((packed));
		unsigned vwa_lon : 1 __attribute__((packed));
		int16_t vwa_gx;
		int16_t vwa_gp;
		int16_t vwa_gy;
		int16_t vwa_mx;
		int16_t vwa_mp;
		u_int16_t vwa_my;
		u_int16_t vwa_w;
		u_int16_t vwa_h;
		u_int16_t vwa_param_base;
		u_int16_t vwa_over_chrno;
		u_int16_t vwa_max_scr_y;
		u_int16_t vwa_first_obj;
		u_int16_t vwa_last_obj;
		u_int16_t vwa_reserved[2];
	};

	struct vip_ctc
	{
		u_int8_t vc_length;
		u_int8_t vc_repeat;
	};
#endif // INTERFACE

struct vip_vrm
{
	u_int8_t vv_left0[0x6000];
	struct vip_chr vv_chr0[512];
	u_int8_t vv_left1[0x6000];
	struct vip_chr vv_chr1[512];
	u_int8_t vv_right0[0x6000];
	struct vip_chr vv_chr2[512];
	u_int8_t vv_right1[0x6000];
	struct vip_chr vv_chr3[512];
};

#define VIP_CHR_FIND(chrno) &(vip_vrm.vv_chr0[(((chrno) & 0x600) << 2) | (chrno) & 0x1ff])

#define vip_bgseg_width (64)
#define vip_bgseg_height (64)

typedef struct vip_bgsc vip_bgseg_t[vip_bgseg_width * vip_bgseg_height];

struct vip_affine
{
	int16_t va_mx;
	int16_t va_mp;
	int16_t va_my;
	int16_t va_dx;
	int16_t va_dy;
	u_int16_t va_rfu[3];
};

enum vip_world_bgm
{
	WORLD_BGM_NORMAL = 0b00,
	WORLD_BGM_H_BIAS = 0b01,
	WORLD_BGM_AFFINE = 0b10,
	WORLD_BGM_OBJ = 0b11
};

struct vip_hbias
{
	int16_t vh_hofstl, vh_hofstr;
};

union vip_params
{
	struct vip_hbias vp_hbias;
	struct vip_affine vp_affine;
};

struct vip_dram
{
	union
	{
		vip_bgseg_t s_bgsegs[14];
		u_int16_t s_param_tbl[0xec00];
	} vd_shared;
	struct vip_world_att vd_world_atts[32];
	struct vip_ctc vd_left_clm_tbl[256];
	struct vip_ctc vd_right_clm_tbl[256];
	struct vip_oam vd_oam[1024];
};

enum vip_intflag
{
	VIP_SCANERR = (1 << 0),
	VIP_LFBEND = (1 << 1),
	VIP_RFBEND = (1 << 2),
	VIP_GAMESTART = (1 << 3),
	VIP_FRAMESTART = (1 << 4),
	VIP_SBHIT = (1 << 13),
	VIP_XPEND = (1 << 14),
	VIP_TIMEERR = (1 << 15)
};

struct vip_dpctrl
{
	unsigned vd_dprst: 1 __attribute__((packed));
	unsigned vd_disp : 1 __attribute__((packed));
	unsigned vd_dpbsy_l_fb0 : 1 __attribute__((packed));
	unsigned vd_dpbsy_r_fb0 : 1 __attribute__((packed));
	unsigned vd_dpbsy_l_fb1 : 1 __attribute__((packed));
	unsigned vd_dpbsy_r_fb1 : 1 __attribute__((packed));
	unsigned vd_scanrdy : 1 __attribute__((packed));
	unsigned vd_fclk : 1 __attribute__((packed));
	unsigned vd_re : 1 __attribute__((packed));
	unsigned vd_synce : 1 __attribute__((packed));
	unsigned vd_lock : 1 __attribute__((packed));
	unsigned vd_unused : 5 __attribute__((packed));
};

struct vip_xpctrl
{
	unsigned vx_xprst : 1 __attribute__((packed));
	unsigned vx_xpen : 1 __attribute__((packed));
	unsigned vx_xpbsy_fb0 : 1 __attribute__((packed));
	unsigned vx_xpbsy_fb1 : 1 __attribute__((packed));
	unsigned vx_overtime : 1 __attribute__((packed));
	unsigned vx_unused : 3 __attribute__((packed));
	unsigned vx_sbcount : 5 __attribute__((packed)); // AKA sbcmp
	unsigned vx_unused2 : 2 __attribute__((packed));
	unsigned vx_sbout : 1 __attribute__((packed));
};

struct vip_regs
{
	u_int16_t vr_intpnd;
	u_int16_t vr_intenb;
	u_int16_t vr_intclr;
	u_int16_t vr_rfu1[13];
	struct vip_dpctrl vr_dpstts;
	struct vip_dpctrl vr_dpctrl;
	u_int8_t vr_brta;
	u_int8_t vr_rfu2;
	u_int8_t vr_brtb;
	u_int8_t vr_rfu3;
	u_int8_t vr_brtc;
	u_int8_t vr_rfu4;
	u_int8_t vr_rest;
	u_int8_t vr_rfu5;
	u_int16_t vr_frmcyc;
	u_int16_t vr_undef2;
	u_int16_t vr_cta;
	u_int16_t vr_undef3[7];
	struct vip_xpctrl vr_xpstts;
	struct vip_xpctrl vr_xpctrl;
	u_int16_t vr_ver;
	u_int16_t vr_undef4;
	u_int16_t vr_spt[4];
	u_int16_t vr_undef5[8];
	u_int16_t vr_gplt[4];
	u_int16_t vr_jplt[4];
	u_int16_t vr_bkcol;
};

#define VIP_MAX_BRIGHT (212)

struct vip_vspan
{
	u_int vvs_scr_y;
	u_int vvs_win_y;
	u_int vvs_height;
};

struct vip_hspan
{
	u_int vhs_scr_x;
	int vhs_win_x;
	u_int vhs_width;
};

static const enum vip_intflag vip_dpints =
		VIP_SCANERR | VIP_LFBEND | VIP_RFBEND | VIP_GAMESTART | VIP_FRAMESTART | VIP_TIMEERR;
static const enum vip_intflag vip_xpints = VIP_SBHIT | VIP_XPEND | VIP_TIMEERR;

bool vip_scan_accurate = false;
u_int32_t vip_world_mask = ~0;
u_int vip_xp_interval = 250;

static struct vip_vrm vip_vrm;
static struct vip_dram vip_dram;
static struct vip_regs vip_regs;
static bool vip_worlds_open = false;
static bool vip_bgseg_open = false;
static bool vip_chr_open = false;
static bool vip_oam_open = false;
static bool vip_fb_open = false;
static bool vip_rows_open = false;
static u_int32_t vip_row_mask = (1 << 28) - 1;
static u_int8_t vip_bgm_types = 0xf;
static bool vip_use_bright = true;

static const char * const vip_bgm_strings[4] =
{
		[WORLD_BGM_NORMAL] = "NORMAL",
		[WORLD_BGM_AFFINE] = "AFFINE",
		[WORLD_BGM_H_BIAS] = "H_BIAS",
		[WORLD_BGM_OBJ] = "OBJ",
};
static u_int vip_disp_index = 0;
static u_int vip_frame_cycles = 0;

enum vip_event
{
	VIP_EVENT_FRAMESTART = EVENT_SUBSYS_BITS(EVENT_SUBSYS_VIP) | EVENT_WHICH_BITS(0),
	VIP_EVENT_GAMESTART = EVENT_SUBSYS_BITS(EVENT_SUBSYS_VIP) | EVENT_WHICH_BITS(1),
	VIP_EVENT_DRAW_ENABLE = EVENT_SUBSYS_BITS(EVENT_SUBSYS_VIP) | EVENT_WHICH_BITS(2),
	VIP_EVENT_DRAW_DISABLE = EVENT_SUBSYS_BITS(EVENT_SUBSYS_VIP) | EVENT_WHICH_BITS(3),
	VIP_EVENT_DRAW_START = EVENT_SUBSYS_BITS(EVENT_SUBSYS_VIP) | EVENT_START_BIT | EVENT_WHICH_BITS(4),
	VIP_EVENT_DRAW_FINISH = EVENT_SUBSYS_BITS(EVENT_SUBSYS_VIP) | EVENT_FINISH_BIT | EVENT_WHICH_BITS(4),
	VIP_EVENT_CLEAR_START = EVENT_SUBSYS_BITS(EVENT_SUBSYS_VIP) | EVENT_START_BIT | EVENT_WHICH_BITS(5),
	VIP_EVENT_CLEAR_FINISH = EVENT_SUBSYS_BITS(EVENT_SUBSYS_VIP) | EVENT_FINISH_BIT | EVENT_WHICH_BITS(5)
};

enum scan_event
{
	SCAN_EVENT_LDISP_START = EVENT_SUBSYS_BITS(EVENT_SUBSYS_SCAN) | EVENT_START_BIT | EVENT_WHICH_BITS(0),
	SCAN_EVENT_LDISP_FINISH = EVENT_SUBSYS_BITS(EVENT_SUBSYS_SCAN) | EVENT_FINISH_BIT | EVENT_WHICH_BITS(0),
	SCAN_EVENT_RDISP_START = EVENT_SUBSYS_BITS(EVENT_SUBSYS_SCAN) | EVENT_START_BIT | EVENT_WHICH_BITS(1),
	SCAN_EVENT_RDISP_FINISH = EVENT_SUBSYS_BITS(EVENT_SUBSYS_SCAN) | EVENT_FINISH_BIT | EVENT_WHICH_BITS(1)
};

bool
vip_init(void)
{
	events_set_desc(VIP_EVENT_FRAMESTART, "FRAMESTART FRMCYC=%i");
	events_set_desc(VIP_EVENT_GAMESTART, "GAMESTART");
	events_set_desc(VIP_EVENT_DRAW_ENABLE, "Draw enable");
	events_set_desc(VIP_EVENT_DRAW_DISABLE, "Draw disable");
	events_set_desc(VIP_EVENT_DRAW_START, "Draw FB%u");
	events_set_desc(VIP_EVENT_CLEAR_START, "Clear FB%u");
	events_set_desc(SCAN_EVENT_LDISP_START, "Display L:FB%u");
	events_set_desc(SCAN_EVENT_RDISP_START, "Display R:FB%u");
	mem_segs[MEM_SEG_VIP].ms_size = 0x80000;
	mem_segs[MEM_SEG_VIP].ms_addrmask = 0x7ffff;
	bzero(&vip_regs, sizeof(vip_regs));
	vip_regs.vr_dpstts.vd_scanrdy = 1;
	vip_disp_index = 0;

	return true;
}

void
vip_add_syms(void)
{
	debug_create_symbol("L:FB0", 0x00000);
	debug_create_symbol("L:FB1", 0x08000);
	debug_create_symbol("R:FB0", 0x10000);
	debug_create_symbol("R:FB1", 0x18000);
	debug_create_symbol("INTPND", 0x5f800);
	debug_create_symbol("INTENB", 0x5f802);
	debug_create_symbol("INTCLR", 0x5f804);
	debug_create_symbol("DPSTTS", 0x5f820);
	debug_create_symbol("DPCTRL", 0x5f822);
	debug_create_symbol("BRTA", 0x5f824);
	debug_create_symbol("BRTB", 0x5f826);
	debug_create_symbol("BRTC", 0x5f828);
	debug_create_symbol("REST", 0x5f82a);
	debug_create_symbol("FRMCYC", 0x5f82e);
	debug_create_symbol("CTA", 0x5f830);
	debug_create_symbol("XPSTTS", 0x5f840);
	debug_create_symbol("XPCTRL", 0x5f842);
	debug_create_symbol("VER", 0x5f844);
	debug_create_symbol("SPT0", 0x5f848);
	debug_create_symbol("SPT1", 0x5f84a);
	debug_create_symbol("SPT2", 0x5f84c);
	debug_create_symbol("SPT3", 0x5f84e);
	debug_create_symbol("GPLT0", 0x5f860);
	debug_create_symbol("GPLT1", 0x5f862);
	debug_create_symbol("GPLT2", 0x5f864);
	debug_create_symbol("GPLT3", 0x5f866);
	debug_create_symbol("JPLT0", 0x5f86a);
	debug_create_symbol("JPLT2", 0x5f86c);
	debug_create_symbol("JPLT3", 0x5f86e);
	debug_create_symbol("BKCOL", 0x5f870);
	debug_create_symbol_array("BGMAP", 0x20000, 13, 8192);
	debug_create_symbol_array("WORLD_ATT", 0x3d800, 32, 32);
	debug_create_symbol("CLM_TBL", 0x3dc00);
	debug_create_symbol("OAM", 0x3e000);
	debug_create_symbol("CHR", 0x78000);
}

void
vip_reset(void)
{
	// TODO: set initial reg states
}

static void
vip_raise(enum vip_intflag intflag)
{
	vip_regs.vr_intpnd|= intflag;
	if (vip_regs.vr_intenb & intflag)
	{
		if (debug_vip_intflags & intflag)
		{
			debug_printf("Stopped on VIP interrupt %u\n", intflag);
			debug_stop();
		}

		cpu_intr(NVC_INTVIP);
	}
}

static void
vip_clear_start(u_int fb_index)
{
	if (debug_trace_vip)
		debug_tracef("vip", "Clear FB%u start", fb_index);

	if (fb_index == 0)
		vip_regs.vr_xpstts.vx_xpbsy_fb0 = 1;
	else
		vip_regs.vr_xpstts.vx_xpbsy_fb1 = 1;

	events_fire(VIP_EVENT_CLEAR_START, fb_index, 0);
}

static void
vip_clear_finish(u_int fb_index)
{
	if (debug_trace_vip)
		debug_tracef("vip", "Clear FB%u finish", fb_index);

	if (fb_index == 0)
	{
		bzero(vip_vrm.vv_left0, sizeof(vip_vrm.vv_left0));
		bzero(vip_vrm.vv_right0, sizeof(vip_vrm.vv_right0));
		vip_regs.vr_xpstts.vx_xpbsy_fb0 = 0;
	}
	else
	{
		bzero(vip_vrm.vv_left1, sizeof(vip_vrm.vv_left1));
		bzero(vip_vrm.vv_right1, sizeof(vip_vrm.vv_right1));
		vip_regs.vr_xpstts.vx_xpbsy_fb1 = 0;
	}

	events_fire(VIP_EVENT_CLEAR_FINISH, fb_index, 0);
}

static struct vip_chr *
vip_chr_find_slow(u_int chrno)
{
	if (chrno < 512)
		return &(vip_vrm.vv_chr0[chrno]);
	else if (chrno < 1024)
		return &(vip_vrm.vv_chr1[chrno - 512]);
	else if (chrno < 1536)
		return &(vip_vrm.vv_chr2[chrno - 1024]);
	else if (chrno < 2048)
		return &(vip_vrm.vv_chr3[chrno - 1536]);
	else
	{
		debug_runtime_errorf(NULL, "VIP: Invalid CHR No. %u", chrno);
		return NULL;
	}
}

static u_int8_t
vip_chr_read_slow(const struct vip_chr *vc, u_int x, u_int y, bool hflip, bool vflip)
{
	assert(x < 8);
	assert(y < 8);
	if (hflip)
		x = 7 - x;
	if (vflip)
		y = 7 - y;
	return (vc->vc_rows[y] >> (x * 2)) & 0b11;
}

static u_int8_t
vip_fb_read_slow(const u_int8_t *fb, u_int16_t x, u_int16_t y)
{
	u_int offset = x * 256 + y;
	u_int shift = (offset % 4) * 2;
	return (fb[offset / 4] >> shift) & 0b11;
}

static u_int8_t
vip_bgsc_read_slow(const struct vip_bgsc *vb, u_int chr_x, u_int chr_y, bool *opaquep)
{
	struct vip_chr *vc = VIP_CHR_FIND(vb->vb_chrno);
	u_int8_t pixel = vip_chr_read_slow(vc, chr_x, chr_y, vb->vb_bhflp, vb->vb_bvflp);
	if (pixel)
	{
		*opaquep = true;
		u_int8_t plt = vip_regs.vr_gplt[vb->vb_gplts];
		return (plt >> (pixel << 1)) & 0b11;
	}
	else
	{
		*opaquep = false;
		return 0;
	}
}

static void
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

static void
vip_fb_write(u_int8_t *fb, u_int16_t x, u_int16_t y, u_int8_t value)
{
	assert(y < 224);
	assert(x < 384);
	u_int offset = x * 256 + y;
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

static void
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

static bool
vip_clip_vspan(u_int scr_clip_y, u_int scr_clip_height, int scr_y, u_int win_height, struct vip_vspan *vspan)
{
	int max_scr_y = scr_y + win_height;
	if (max_scr_y <= (int)scr_clip_y)
		return false;

	u_int max_clip_y = scr_clip_y + scr_clip_height;
	if (scr_y >= (int)max_clip_y)
		return false;

	if (max_scr_y > (int)max_clip_y)
		win_height = max_clip_y - scr_y;

	if (scr_y < (int)scr_clip_y)
	{
		vspan->vvs_scr_y = scr_clip_y;
		vspan->vvs_win_y = scr_clip_y - scr_y;
		vspan->vvs_height = win_height - vspan->vvs_win_y;
	}
	else
	{
		vspan->vvs_scr_y = (u_int)scr_y;
		vspan->vvs_win_y = 0;
		vspan->vvs_height = win_height;
	}
	return true;
}

static bool
vip_clip_hspan(int scr_x, int win_x, u_int win_width, struct vip_hspan *hspan)
{
	int max_scr_x = scr_x + win_width;
	if (max_scr_x <= 0)
		return false;

	if (scr_x >= 384)
		return false;

	if (max_scr_x > 384)
		win_width = 384 - scr_x;

	if (scr_x < 0)
	{
		hspan->vhs_scr_x = 0;
		hspan->vhs_win_x = win_x - scr_x;
		hspan->vhs_width = win_width + scr_x;
	}
	else
	{
		hspan->vhs_scr_x = (u_int)scr_x;
		hspan->vhs_win_x = win_x;
		hspan->vhs_width = win_width;
	}
	return true;
}

static void
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
			vip_format_world_att(buf, sizeof(buf), vwa);
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
					vip_format_oam(oamstr, obj);
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

static void
vip_draw_finish(u_int fb_index __unused)
{
}

static void
vip_update_sbcount(u_int sbcount)
{
	vip_regs.vr_xpstts.vx_sbcount = sbcount;
	if (vip_regs.vr_xpctrl.vx_sbcount == vip_regs.vr_xpstts.vx_sbcount)
		vip_raise(VIP_SBHIT);
}

static void
vip_frame_clock(void)
{
	enum vip_intflag intflags = VIP_FRAMESTART;

	if (debug_trace_vip)
		debug_tracef("vip", "FRAMESTART");

	events_fire(VIP_EVENT_FRAMESTART, vip_frame_cycles, 0);

	if (vip_frame_cycles == 0)
	{
		intflags|= VIP_GAMESTART;
		if (debug_trace_vip)
			debug_tracef("vip", "GAMESTART");

		events_fire(VIP_EVENT_GAMESTART, 0, 0);

		if (vip_regs.vr_xpctrl.vx_xprst)
		{
			if (debug_trace_vip)
				debug_tracef("vip", "XPRST");
			vip_regs.vr_intenb&= ~vip_xpints;
			vip_regs.vr_intpnd&= ~vip_xpints;
			vip_regs.vr_xpctrl.vx_xprst = 0;
			vip_regs.vr_xpstts.vx_xpen = 0;
			if (vip_disp_index == 0)
				vip_clear_start(1);
			else
				vip_clear_start(0);
		}
		else if (vip_regs.vr_xpctrl.vx_xpen != vip_regs.vr_xpstts.vx_xpen)
		{
			if (debug_trace_vip)
				debug_tracef("vip", "XPEN=%d", vip_regs.vr_xpctrl.vx_xpen);
			vip_regs.vr_xpstts.vx_xpen = vip_regs.vr_xpctrl.vx_xpen;

			events_fire((vip_regs.vr_xpstts.vx_xpen) ? VIP_EVENT_DRAW_ENABLE : VIP_EVENT_DRAW_DISABLE, 0, 0);
		}

		if (vip_regs.vr_xpstts.vx_xpen)
		{
			if (!vip_regs.vr_xpstts.vx_xpbsy_fb0 && !vip_regs.vr_xpstts.vx_xpbsy_fb1)
			{
				u_int fb_index = !vip_disp_index;

				if (debug_trace_vip)
					debug_tracef("vip", "Draw FB%u start", fb_index);

				if (fb_index == 0)
					vip_regs.vr_xpstts.vx_xpbsy_fb0 = 1;
				else
					vip_regs.vr_xpstts.vx_xpbsy_fb1 = 1;

				vip_draw_start(fb_index);
				vip_update_sbcount(0);

				events_fire(VIP_EVENT_DRAW_START, fb_index, 0);
			}
			// else TODO: OVERTIME
		}
	}
	if (vip_frame_cycles == vip_regs.vr_frmcyc)
		vip_frame_cycles = 0;
	else
		vip_frame_cycles++;

	vip_raise(intflags);
}

static void
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
			fb+= 8; // framebuffer columns are actually 256 rows
		}
		++ctc;
	}
}

static void
vip_scan_out(u_int fb_index, bool right)
{
	const u_int8_t *fb;
	if (fb_index == 0)
		fb = (right) ? vip_vrm.vv_right0 : vip_vrm.vv_left0;
	else
		fb = (right) ? vip_vrm.vv_right1 : vip_vrm.vv_left1;
	const struct vip_ctc *ctcs = (right) ? vip_dram.vd_right_clm_tbl : vip_dram.vd_left_clm_tbl;

	u_int32_t argb[224 * 384];
	vip_fb_convert(fb, ctcs, argb);
	gl_blit(argb, right);
}

static void
vip_xp_step(u_int fb_index)
{
	if (vip_regs.vr_xpstts.vx_sbout)
	{
		vip_regs.vr_xpstts.vx_sbout = 0;

		if (vip_regs.vr_xpstts.vx_sbcount < 27)
			vip_update_sbcount(vip_regs.vr_xpstts.vx_sbcount + 1);
		else
		{
			vip_draw_finish(fb_index);

			if (debug_trace_vip)
				debug_tracef("vip", "Draw FB%u finish", fb_index);

			if (fb_index == 0)
				vip_regs.vr_xpstts.vx_xpbsy_fb0 = 0;
			else
				vip_regs.vr_xpstts.vx_xpbsy_fb1 = 0;

			vip_regs.vr_xpstts.vx_sbcount = 0;
			vip_raise(VIP_XPEND);

			events_fire(VIP_EVENT_DRAW_FINISH, fb_index, 0);
		}
	}
	else
	{
		if (debug_trace_vip)
			debug_tracef("vip", "Draw FB%u SBCOUNT=%u", fb_index, vip_regs.vr_xpstts.vx_sbcount);

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

		if ((vip_row_mask & (1 << vip_regs.vr_xpstts.vx_sbcount)) != 0)
			vip_draw_8rows(left_fb, right_fb, vip_regs.vr_xpstts.vx_sbcount * 8);

		vip_regs.vr_xpstts.vx_sbout = 1;
	}
}

void
vip_step(void)
{
	static u_int scanner_usec = 0;

	if (vip_regs.vr_dpctrl.vd_dprst)
	{
		if (debug_trace_vip)
			debug_tracef("vip", "DPRST");
		vip_regs.vr_dpctrl.vd_dprst = 0;
		vip_regs.vr_intenb&= ~vip_dpints;
		vip_regs.vr_intpnd&= ~vip_dpints;
		vip_frame_cycles = 0;
	}
	else
	{
		if (vip_regs.vr_intclr & vip_regs.vr_intpnd)
		{
			vip_regs.vr_intpnd&= ~vip_regs.vr_intclr;
			vip_regs.vr_intclr = 0;
		}
		if (vip_regs.vr_dpctrl.vd_lock != vip_regs.vr_dpctrl.vd_lock)
		{
			debug_runtime_errorf(NULL, "VIP: LOCK=%d\n", vip_regs.vr_dpctrl.vd_lock);
			vip_regs.vr_dpstts.vd_lock = vip_regs.vr_dpctrl.vd_lock;
		}
		if (vip_regs.vr_dpctrl.vd_synce != vip_regs.vr_dpstts.vd_synce)
		{
			if (debug_trace_vip)
				debug_tracef("vip", "SYNCE=%d", vip_regs.vr_dpctrl.vd_synce);
			vip_regs.vr_dpstts.vd_synce = vip_regs.vr_dpctrl.vd_synce;
		}
		if (vip_regs.vr_dpctrl.vd_disp != vip_regs.vr_dpstts.vd_disp)
		{
			if (debug_trace_vip)
				debug_tracef("vip", "DISP=%d", vip_regs.vr_dpctrl.vd_disp);
			vip_regs.vr_dpstts.vd_disp = vip_regs.vr_dpctrl.vd_disp;
		}
	}

	if (scanner_usec == 0)
		vip_frame_clock();
	else if (scanner_usec == 1000 && !vip_regs.vr_xpstts.vx_xpen)
	{
		if (vip_regs.vr_xpstts.vx_xpbsy_fb0)
			vip_clear_finish(0);
		else if (vip_regs.vr_xpstts.vx_xpbsy_fb1)
			vip_clear_finish(1);
	}
	else if (scanner_usec == 2500 && vip_regs.vr_dpstts.vd_synce)
	{
		if (vip_regs.vr_dpstts.vd_disp)
		{
			if (vip_disp_index == 0)
			{
				vip_regs.vr_dpstts.vd_dpbsy_l_fb0 = 1;
				if (debug_trace_vip)
					debug_tracef("vip", "Display L:FB0 start");
			}
			else
			{
				vip_regs.vr_dpstts.vd_dpbsy_l_fb1 = 1;
				if (debug_trace_vip)
					debug_tracef("vip", "Display L:FB1 start");
			}

			if (vip_scan_accurate)
				vip_scan_out(vip_disp_index, false);

			events_fire(SCAN_EVENT_LDISP_START, vip_disp_index, 0);
		}
	}
	else if (scanner_usec == 7500 && vip_regs.vr_dpstts.vd_synce)
	{
		if (vip_regs.vr_dpstts.vd_disp)
		{
			if (vip_disp_index == 0)
			{
				vip_regs.vr_dpstts.vd_dpbsy_l_fb0 = 0;
				if (debug_trace_vip)
					debug_tracef("vip", "Display L:FB0 finish");
			}
			else
			{
				vip_regs.vr_dpstts.vd_dpbsy_l_fb1 = 0;
				if (debug_trace_vip)
					debug_tracef("vip", "Display L:FB1 finish");
			}
			vip_raise(VIP_LFBEND);

			events_fire(SCAN_EVENT_LDISP_FINISH, vip_disp_index, 0);
		}
	}
	else if (scanner_usec == 12500 && vip_regs.vr_dpstts.vd_synce)
	{
		if (vip_regs.vr_dpstts.vd_disp)
		{
			if (vip_disp_index == 0)
			{
				vip_regs.vr_dpstts.vd_dpbsy_r_fb0 = 1;
				if (debug_trace_vip)
					debug_tracef("vip", "Display R:FB0 start");
			}
			else
			{
				vip_regs.vr_dpstts.vd_dpbsy_r_fb1 = 1;
				if (debug_trace_vip)
					debug_tracef("vip", "Display R:FB1 start");
			}

			if (vip_scan_accurate)
				vip_scan_out(vip_disp_index, true);

			events_fire(SCAN_EVENT_RDISP_START, vip_disp_index, 0);
		}
	}
	else if (scanner_usec == 17500 && vip_regs.vr_dpstts.vd_synce)
	{
		if (vip_regs.vr_dpstts.vd_disp)
		{
			if (vip_disp_index == 0)
			{
				vip_regs.vr_dpstts.vd_dpbsy_r_fb0 = 0;
				if (debug_trace_vip)
					debug_tracef("vip", "Display R:FB0 finish");
			}
			else
			{
				vip_regs.vr_dpstts.vd_dpbsy_r_fb1 = 0;
				if (debug_trace_vip)
					debug_tracef("vip", "Display R:FB1 finish");
			}

			vip_raise(VIP_RFBEND);

			events_fire(SCAN_EVENT_RDISP_FINISH, vip_disp_index, 0);

			vip_disp_index = (vip_disp_index + 1) % 2;
			++main_stats.ms_scans;
		}
	}

	if (vip_regs.vr_xpstts.vx_xpen && (scanner_usec % vip_xp_interval) == 0)
	{
		if (vip_regs.vr_xpstts.vx_xpbsy_fb0)
			vip_xp_step(0);
		else if (vip_regs.vr_xpstts.vx_xpbsy_fb1)
			vip_xp_step(1);
	}

	if (scanner_usec == 19999)
		scanner_usec = 0;
	else
		++scanner_usec;
}

void
vip_fini(void)
{
	// TODO
}

bool
vip_mem_prepare(struct mem_request *request)
{
	if (request->mr_ops & PROT_READ)
		request->mr_wait = 8;
	else
		request->mr_wait = 4;

	static bool ignore_mirror = false;
	if (request->mr_emu & 0xfff80000)
	{
		u_int32_t mirror = request->mr_emu & 0x7ffff;
		if (!debug_runtime_errorf(&ignore_mirror, "Mirroring VIP address 0x%08x -> 0x%08x\n", request->mr_emu, mirror))
			return false;
		request->mr_emu = mirror;
	}

	if (request->mr_emu < 0x20000)
		request->mr_host = (u_int8_t *)&vip_vrm + request->mr_emu;
	else if (request->mr_emu < 0x40000)
		request->mr_host = (u_int8_t *)&vip_dram + (request->mr_emu & 0x1ffff);
	else if (request->mr_emu < 0x5f800)
	{
		static bool ignore_junk = false;
		if (!debug_runtime_errorf(&ignore_junk, "Accessing VIP junk memory at 0x%08x", request->mr_emu))
			return false;
		assert(request->mr_size <= 4);
		static u_int32_t junk;
		request->mr_host = &junk;
	}
	else if (request->mr_emu < 0x60000)
	{
		if (request->mr_size & 1)
		{
			static bool always_ignore = false;
			if (!debug_runtime_errorf(&always_ignore, "Invalid VIP access size %u", request->mr_size))
				return false;
		}
		if (request->mr_emu & 1)
		{
			static bool always_ignore = false;
			if (!debug_runtime_errorf(&always_ignore, "VIP address alignment error at 0x%08x", request->mr_emu))
				return false;
		}
		u_int reg_num = (request->mr_emu & 0x7f) >> 1;
		switch (reg_num)
		{
			case 0x00:
			case 0x10:
			case 0x18:
			case 0x20:
				request->mr_perms = PROT_READ;
				break;
			case 0x02:
			case 0x11:
			case 0x12:
			case 0x13:
			case 0x14:
			case 0x15:
			case 0x17:
			case 0x21:
			{
				request->mr_perms = PROT_WRITE;
				if (request->mr_ops & PROT_READ)
				{
					static bool ignore_read = false;
					debug_str_t addr_s;
					if (!debug_runtime_errorf(&ignore_read, "Trying to read write-only VIP register at %s",
					                          debug_format_addr(request->mr_emu, addr_s)))
						return false;
					request->mr_perms|= PROT_READ;
				}
				break;
			}
		}

#ifndef NDEBUG
		u_int16_t *regp = (u_int16_t *)&vip_regs + reg_num;
		assert(regp == (u_int16_t *)((u_int8_t *)&vip_regs + (request->mr_emu & 0x7e)));
#endif // !NDEBUG

		request->mr_host = (u_int8_t *)&vip_regs + (request->mr_emu & 0x7e);
	}
	else if (request->mr_emu >= 0x78000 && request->mr_emu < 0x7a000)
		request->mr_host = (u_int8_t *)&(vip_vrm.vv_chr0) + (request->mr_emu - 0x78000);
	else if (request->mr_emu >= 0x7a000 && request->mr_emu < 0x7c000)
		request->mr_host = (u_int8_t *)&(vip_vrm.vv_chr1) + (request->mr_emu - 0x7a000);
	else if (request->mr_emu >= 0x7c000 && request->mr_emu < 0x7e000)
		request->mr_host = (u_int8_t *)&(vip_vrm.vv_chr2) + (request->mr_emu - 0x7c000);
	else if (request->mr_emu >= 0x7e000 && request->mr_emu < 0x80000)
		request->mr_host = (u_int8_t *)&(vip_vrm.vv_chr3) + (request->mr_emu - 0x7e000);
	else
		return false;

	return true;
}

static void
vip_test_clip(int scr_clip_y,
              u_int scr_clip_height,
              int scr_y,
              u_int win_height,
              bool expect_overlap,
              u_int expect_scr_y,
              u_int expect_win_y,
              u_int expect_height)
{
	struct vip_vspan vspan;
	bool overlap = vip_clip_vspan(scr_clip_y, scr_clip_height, scr_y, win_height, &vspan);
	if (overlap != expect_overlap ||
			(overlap && (vspan.vvs_scr_y != expect_scr_y ||
					vspan.vvs_win_y != expect_win_y ||
					vspan.vvs_height != expect_height)))
	{
		debug_runtime_errorf(NULL, "vip_clip_vspan(scr_clip_y, scr_clip_height, scr_y, height) (%u, %u, %d, %u)"
		                           " -> overlap %d vspan{%u, %u, %u} should be overlap %d vspan{%u, %u, %u}",
		                     scr_clip_y, scr_clip_height, scr_y, win_height,
		                     overlap,
		                     vspan.vvs_scr_y, vspan.vvs_win_y, vspan.vvs_height,
		                     expect_overlap,
		                     expect_scr_y, expect_win_y, expect_height);
	}
}

void
vip_test(void)
{
	debug_printf("Running VIP self-test\n");

	static_assert(sizeof(vip_vrm) == 0x20000, "sizeof(vip_vrm) should be 0x20000");
	assert(sizeof(struct vip_oam) == 8);
	static_assert(sizeof(vip_dram) == 0x20000, "sizeof(vip_dram) should be 0x20000");
	assert(sizeof(vip_dram.vd_shared.s_bgsegs[0]) == 8192);
	assert(sizeof(vip_regs) == 0x72);
	mem_test_size("vip_world_att", sizeof(struct vip_world_att), 32);
	mem_test_addr("world_att[1]", debug_locate_symbol("WORLD_ATT:1"), 4, &(vip_dram.vd_world_atts[1]));
	mem_test_addr("BGSEG:2", 0x24000, 4, &(vip_dram.vd_shared.s_bgsegs[2]));
	mem_test_addr("PARAM_TBL+0x8800", 0x31000, 4, &(vip_dram.vd_shared.s_param_tbl[0x8800]));
	mem_test_addr("WORLD_ATTS", 0x3d800, 4, &(vip_dram.vd_world_atts));
	mem_test_addr("OAM", 0x3e000, 8, &(vip_dram.vd_oam));
	mem_test_addr("INTPND", 0x5f800, 2, &(vip_regs.vr_intpnd));
	mem_test_addr("DPSTTS", 0x5f820, 2, &(vip_regs.vr_dpstts));
	mem_test_addr("GPLT:3", 0x5f866, 2, &(vip_regs.vr_gplt[3]));
	mem_test_addr("BKCOL", 0x5f870, 2, &(vip_regs.vr_bkcol));
	mem_test_addr("CHR:0", 0x78000, 2, &(vip_vrm.vv_chr0));
	mem_test_addr("CHR:3", 0x7e000, 2, &(vip_vrm.vv_chr3));

	vip_test_clip(5, 5, 5, 5, true, 5, 0, 5);
	vip_test_clip(5, 5, 4, 6, true, 5, 1, 5);
	vip_test_clip(5, 5, 6, 4, true, 6, 0, 4);
	vip_test_clip(5, 5, 5, 4, true, 5, 0, 4);
	vip_test_clip(5, 5, 5, 6, true, 5, 0, 5);
	vip_test_clip(5, 5, 4, 5, true, 5, 1, 4);
	vip_test_clip(5, 5, 6, 3, true, 6, 0, 3);
	vip_test_clip(5, 5, 4, 6, true, 5, 1, 5);
	vip_test_clip(5, 5, 6, 5, true, 6, 0, 4);
	vip_test_clip(5, 5, 0, 5, false, 0, 0, 0);
	vip_test_clip(5, 5, 10, 5, false, 0, 0, 0);

	for (u_int chrno = 0; chrno < 2048; ++chrno)
	{
		struct vip_chr *slow_vc = vip_chr_find_slow(chrno);
		struct vip_chr *fast_vc = VIP_CHR_FIND(chrno);
		if (fast_vc != slow_vc)
			debug_runtime_errorf(NULL, "vip_chr_find_slow(%d) = %p, VIP_CHR_FIND() = %p", chrno, slow_vc, fast_vc);
	}
}

static void
vip_print_intreg(u_int16_t intreg, const char *name)
{
	debug_str_t flags_str;
	debug_printf("%s: (%s)",
	             name,
	             debug_format_flags(flags_str,
	                                "SCANERR", intreg & VIP_SCANERR,
	                                "LFBEND", intreg & VIP_LFBEND,
	                                "RFBEND", intreg & VIP_RFBEND,
	                                "GAMESTART", intreg & VIP_GAMESTART,
	                                "FRAMESTART", intreg & VIP_FRAMESTART,
	                                "SBHIT", intreg & VIP_SBHIT,
	                                "XPEND", intreg & VIP_XPEND,
	                                "TIMEERR", intreg & VIP_TIMEERR,
	                                NULL));
}

static void
vip_print_dpctrl(struct vip_dpctrl vd, const char *name)
{
	debug_str_t flags_str;
	debug_printf("%s: (%s)",
	             name,
	             debug_format_flags(flags_str,
	                                "DISP", vd.vd_disp,
	                                "DPBSY:L:FB0", vd.vd_dpbsy_l_fb0,
	                                "DPBSY:R:FB0", vd.vd_dpbsy_r_fb0,
	                                "DPBSY:L:FB1", vd.vd_dpbsy_l_fb1,
	                                "DPBSY:R:FB1", vd.vd_dpbsy_r_fb1,
	                                "SCANRDY", vd.vd_scanrdy,
	                                "FCLK", vd.vd_fclk,
	                                "RE", vd.vd_re,
	                                "SYNCE", vd.vd_synce,
	                                "LOCK", vd.vd_lock,
	                                NULL));
}

static void
vip_print_xpctrl(struct vip_xpctrl vx, const char *name)
{
	debug_str_t flags_str;
	debug_printf("%s: (%s)",
	             name,
	             debug_format_flags(flags_str,
	                                "XPRST", vx.vx_xprst,
	                                "XPEN", vx.vx_xpen,
	                                "XPBSY:FB0", vx.vx_xpbsy_fb0,
	                                "XPBSY:FB1", vx.vx_xpbsy_fb1,
	                                "OVERTIME", vx.vx_overtime,
	                                "SBOUT", vx.vx_sbout,
	                                NULL));
}

void
vip_print_bgsc(struct vip_bgsc *vb)
{
	debug_printf("CHR No: %u, BVFLP=%u, BHFLP=%u, GPLTS=%u\n",
	             vb->vb_chrno, vb->vb_bvflp, vb->vb_bhflp, vb->vb_gplts);
}

void
vip_format_world_att(char *buf, size_t buflen, const struct vip_world_att *vwa)
{
	debug_str_t flags_s;
	size_t bufoff = 0;
	const char *bgm_s;
	switch (vwa->vwa_bgm)
	{
		case WORLD_BGM_NORMAL: bgm_s = "NORMAL"; break;
		case WORLD_BGM_AFFINE: bgm_s = "AFFINE"; break;
		case WORLD_BGM_H_BIAS: bgm_s = "H_BIAS"; break;
		case WORLD_BGM_OBJ: bgm_s = "OBJ"; break;
	}
	bufoff+= snprintf(buf + bufoff, buflen - bufoff, "(%s) BGM=%s, SCX=%u, SCY=%u, BGMAP BASE=%u",
	                  debug_format_flags(flags_s,
	                                     "LON", vwa->vwa_lon,
	                                     "RON", vwa->vwa_ron,
	                                     "OVER", vwa->vwa_over,
	                                     "END", vwa->vwa_end,
	                                     NULL),
	                  bgm_s,
	                  vwa->vwa_scx,
	                  vwa->vwa_scy,
	                  vwa->vwa_bgmap_base);
	if (!vwa->vwa_end && (vwa->vwa_lon || vwa->vwa_ron) && vwa->vwa_bgm != WORLD_BGM_OBJ)
	{
		bufoff+= snprintf(buf + bufoff, buflen - bufoff,
		                  "\n\tGX=%hd, GP=%hd, GY=%hd, MX=%hd, MP=%hd, MY=%hu, W=%hu, H=%hu\n",
		                  vwa->vwa_gx, vwa->vwa_gp, vwa->vwa_gy, vwa->vwa_mx, vwa->vwa_mp, vwa->vwa_my, vwa->vwa_w, vwa->vwa_h);
		bufoff+= snprintf(buf + bufoff, buflen - bufoff,
		                  "\tPARAM BASE=%hu, OVERPLANE CHARACTER=%hu", vwa->vwa_param_base, vwa->vwa_over_chrno);
	}
}

void
vip_format_oam(debug_str_t s, const struct vip_oam *vop)
{
	snprintf(s, debug_str_len, "JX=%hd, JP=%hd, JRON=%u, JLON=%u, JY=%hd, JCA=%u"
			", JVFLP=%u, JHFLP=%u, JPLTS=%u",
	         vop->vo_jx, cpu_extend14to16(vop->vo_jp), vop->vo_jron, vop->vo_jlon, vop->vo_jy, vop->vo_jca,
	         vop->vo_jvflp, vop->vo_jhflp, vop->vo_jplts);
}

void
vip_print_regs()
{
	vip_print_intreg(vip_regs.vr_intpnd, "INTPND");
	debug_printf(", ");
	vip_print_intreg(vip_regs.vr_intenb, "INTENB");
	debug_printf(", ");
	vip_print_intreg(vip_regs.vr_intclr, "INTCLR");
	debug_putchar('\n');
	vip_print_dpctrl(vip_regs.vr_dpstts, "DPSTTS");
	debug_printf(", ");
	vip_print_dpctrl(vip_regs.vr_dpctrl, "DPCTRL");
	debug_putchar('\n');
	vip_print_xpctrl(vip_regs.vr_xpstts, "XPSTTS");
	debug_printf(" SBCOUNT=%d", vip_regs.vr_xpstts.vx_sbcount);
	debug_printf(", ");
	vip_print_xpctrl(vip_regs.vr_xpctrl, "XPCTRL");
	debug_printf(" SBCMP=%d", vip_regs.vr_xpctrl.vx_sbcount);
	debug_putchar('\n');
	debug_printf("BRTA: %hhu, BRTB: %hhu, BRTC: %hhu, REST: %hhu\n",
				 vip_regs.vr_brta, vip_regs.vr_brtb, vip_regs.vr_brtc, vip_regs.vr_rest);
	debug_printf("FRMCYC: %d\n", vip_regs.vr_frmcyc);
	u_int world_index = 31;
	do
	{
		const struct vip_world_att *vwa = &(vip_dram.vd_world_atts[world_index]);
		if (vwa->vwa_end)
			break;
		char buf[1024];
		vip_format_world_att(buf, sizeof(buf), vwa);
		debug_printf("WORLD_ATT[%u]: %s", world_index, buf);
	} while (world_index-- > 0);
}

void
vip_view_menu()
{
	igMenuItemPtr("Worlds...", "F1", &vip_worlds_open, true);
	igMenuItemPtr("Backgrounds...", "F2", &vip_bgseg_open, true);
	igMenuItemPtr("Characters...", "F3", &vip_chr_open, true);
	igMenuItemPtr("Objects...", "F4", &vip_oam_open, true);
	igMenuItemPtr("Frame buffers...", "F5", &vip_fb_open, true);
}

void
vip_settings_menu()
{
	igMenuItemPtr("Use global palette", NULL, &vip_use_bright, true);
	igMenuItemPtr("Accurate scanner timing", NULL, &vip_scan_accurate, true);
	igMenuItemPtr("Draw rows...", NULL, &vip_rows_open, true);
}

void
vip_frame_begin(void)
{
	imgui_key_toggle(SDL_SCANCODE_F1, &vip_worlds_open, true);
	imgui_key_toggle(SDL_SCANCODE_F2, &vip_bgseg_open, true);
	imgui_key_toggle(SDL_SCANCODE_F3, &vip_chr_open, true);
	imgui_key_toggle(SDL_SCANCODE_F4, &vip_oam_open, true);
	imgui_key_toggle(SDL_SCANCODE_F5, &vip_fb_open, true);

	if (vip_worlds_open)
	{
		igSetNextWindowSize((struct ImVec2){640, 500}, ImGuiCond_FirstUseEver);
		if (igBegin("VIP Worlds", &vip_worlds_open, 0))
		{
			igText("Draw types:");
			for (u_int i = 0; i < 4; ++i)
			{
				igSameLine(0, -1);

				u_int8_t mask = (1 << i);
				bool drawn = ((vip_bgm_types & mask) != 0);
				if (igCheckbox(vip_bgm_strings[i], &drawn))
				{
					if (drawn)
						vip_bgm_types |= mask;
					else
						vip_bgm_types &= ~mask;
				}
			}

			igSameLine(0, -1);
			if (igButton("Force draw enabled", IMVEC2_ZERO))
				vip_regs.vr_xpctrl.vx_xpen = 1;

			igSeparator();

			igColumns(5, "Worlds", true);
			igSeparator();
			igText("#");
			igSetColumnWidth(-1, 30);
			igNextColumn();
			bool show_all = (vip_world_mask == ~0u);
			if (igCheckbox("##Show worlds", &show_all))
			{
				if (show_all)
					vip_world_mask = ~0;
				else
					vip_world_mask = 0;
			}
			igSetColumnWidth(-1, 30);
			igNextColumn();
			igText("Flags");
			igSetColumnWidth(-1, 80);
			igNextColumn();
			igText("BGM");
			igSetColumnWidth(-1, 70);
			igNextColumn();
			igText("Description");
			igNextColumn();

			igSeparator();

			for (int i = 31; i >= 0; --i)
			{
				const struct vip_world_att *vwa = &(vip_dram.vd_world_atts[i]);
				igText("%u", i);
				igNextColumn();

				char label[32 + 1];
				snprintf(label, sizeof(label), "##World%d", i + 1);
				u_int32_t mask = 1 << i;
				bool shown = ((vip_world_mask & mask) != 0);
				if (igCheckbox(label, &shown))
				{
					if (shown)
						vip_world_mask |= mask;
					else
						vip_world_mask &= ~mask;
				}
				igNextColumn();

				debug_str_t flags_s;
				igTextDisabled("%s", debug_format_flags(flags_s,
				                                        "LON", vwa->vwa_lon,
				                                        "RON", vwa->vwa_ron,
				                                        "OVER", vwa->vwa_over,
				                                        "END", vwa->vwa_end,
				                                        NULL));
				igNextColumn();

				igTextDisabled("%s", vip_bgm_strings[vwa->vwa_bgm]);
				igNextColumn();

				char buf[1024];
				vip_format_world_att(buf, sizeof(buf), vwa);
				igTextDisabled("%s", buf);
				igNextColumn();
			}
			igColumns(1, NULL, false);
		}
		igEnd();
	}

	if (vip_rows_open)
	{
		igSetNextWindowSize((struct ImVec2){360, 0}, ImGuiCond_FirstUseEver);
		if (igBegin("VIP Rows", &vip_rows_open, ImGuiWindowFlags_NoResize))
		{
			igColumns(4, "Rows", false);
			for (u_int i = 0; i < 28; ++i)
			{
				char label[32 + 1];
				snprintf(label, sizeof(label), "%u-%u", i * 8 + 1, i * 8 + 8);
				u_int32_t mask = 1u << i;
				bool shown = ((vip_row_mask & mask) != 0);
				if (igCheckbox(label, &shown))
				{
					if (shown)
						vip_row_mask |= mask;
					else
						vip_row_mask &= ~mask;
				}
				igNextColumn();
			}
			igColumns(1, NULL, false);
			igSeparator();
			if (igButton("Draw All", IMVEC2_ZERO))
				vip_row_mask = (1 << 28) - 1;
			igSameLine(0.0, -1.0f);
			if (igButton("Draw None", IMVEC2_ZERO))
				vip_row_mask = 0;
		}
		igEnd();
	}

	if (vip_bgseg_open)
	{
		if (igBegin("VIP Backgrounds", &vip_bgseg_open, 0))
		{
			//gl_debug_clear(); // Opaque flag below
			static int segment = 0;
			igInputInt("Segment", &segment, 1, 100, ImGuiInputTextFlags_AutoSelectAll);
			if (segment < 0)
				segment = 13;
			else if (segment >= 14)
				segment = 0;

			struct vip_bgsc *vb = vip_dram.vd_shared.s_bgsegs[segment];
			for (u_int bg_y = 0; bg_y < 64; ++bg_y)
				for (u_int bg_x = 0; bg_x < 64; ++bg_x)
				{
					for (u_int chr_x = 0; chr_x < 8; ++chr_x)
						for (u_int chr_y = 0; chr_y < 8; ++chr_y)
						{
							bool opaque;
							u_int8_t pixel = vip_bgsc_read_slow(vb, chr_x, chr_y, &opaque);
							//if (opaque)
							gl_debug_draw(bg_x * 8 + chr_x, bg_y * 8 + chr_y, pixel);
						}
					++vb;
				}
			imgui_debug_image(TEXTURE_DEBUG_BGSEG, 512, 512);
		}
		igEnd();
	}

	if (vip_chr_open)
	{
		if (igBegin("VIP Character Map", &vip_chr_open, 0))
		{
			for (u_int c = 0; c < 2048; ++c)
			{
				const struct vip_chr *vc = VIP_CHR_FIND(c);
				u_int x = c % 64;
				u_int y = c / 64;
				for (u_int chr_x = 0; chr_x < 8; ++chr_x)
					for (u_int chr_y = 0; chr_y < 8; ++chr_y)
						gl_debug_draw(x * 8 + chr_x, y * 8 + chr_y,
						              vip_chr_read_slow(vc, chr_x, chr_y, false, false));
			}
			imgui_debug_image(TEXTURE_DEBUG_CHR, 512, 256);
		}
		igEnd();
	}

	if (vip_oam_open)
	{
		igSetNextWindowSize((struct ImVec2){640, 500}, ImGuiCond_FirstUseEver);
		if (igBegin("VIP Object Attributes", &vip_oam_open, 0))
		{
			for (int obj_group = 3; obj_group >= 0; --obj_group)
			{
				char label[32];
				snprintf(label, sizeof(label), "Group %u", obj_group);

				bool open = igTreeNodeEx(label, ImGuiTreeNodeFlags_DefaultOpen);
				igSameLine(0, -1);
				igText("SPT%u=%u", obj_group, vip_regs.vr_spt[obj_group]);
				if (open)
				{
					int end_index = vip_regs.vr_spt[obj_group] & 0x3ff;
					if (end_index != 0x3ff)
					{
						int start_index;
						if (obj_group > 0)
							start_index = (vip_regs.vr_spt[obj_group - 1] + 1) & 0x3ff;
						else
							start_index = 0;

						for (int obj_index = end_index; obj_index >= start_index; --obj_index)
						{
							struct vip_oam *obj = &(vip_dram.vd_oam[obj_index]);
							debug_str_t oam_s;
							vip_format_oam(oam_s, obj);
							igText("OAM[%u]: %s", obj_group, oam_s);
						}
					}

					igTreePop();
				}
			}
		}
		igEnd();
	}

	if (vip_fb_open)
	{
		if (igBegin("VIP Frame Buffers", &vip_fb_open, ImGuiWindowFlags_NoResize))
		{
			static int fb_index = 0;
			igCombo2("Buffer", &fb_index, "Left 0\0Right 0\0Left 1\0Right 1", 0);
			const u_int8_t *fb;
			switch (fb_index)
			{
				case 0: fb = vip_vrm.vv_left0; break;
				case 1: fb = vip_vrm.vv_right0; break;
				case 2: fb = vip_vrm.vv_left1; break;
				case 3: fb = vip_vrm.vv_right1; break;
			}
			for (u_int y = 0; y < 224; ++y)
				for (u_int x = 0; x < 384; ++x)
					gl_debug_draw(x, y, vip_fb_read_slow(fb, x, y));

			imgui_debug_image(TEXTURE_DEBUG_FB, 384, 224);
		}
		igEnd();
	}
}

void
vip_frame_end(void)
{
	if (!debug_is_stopped() && !vip_scan_accurate)
	{
		vip_scan_out(vip_disp_index, false);
		vip_scan_out(vip_disp_index, true);
	}
}
