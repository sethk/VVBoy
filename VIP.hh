#pragma once

#include "Types.hh"

struct vip_chr
{
	u_int16_t vc_rows[8];
};

struct vip_bgsc
{
	u_int16_t vb_chrno : 11;
	u_int16_t vb_rfu1 : 1;
	u_int16_t vb_bvflp : 1;
	u_int16_t vb_bhflp : 1;
	u_int16_t vb_gplts : 2;
};

struct vip_oam
{
	int16_t vo_jx;
	u_int16_t vo_jp : 14;
	u_int16_t vo_jron : 1;
	u_int16_t vo_jlon : 1;
	int16_t vo_jy;
	u_int16_t vo_jca : 11;
	u_int16_t vo_rfu1 : 1;
	u_int16_t vo_jvflp : 1;
	u_int16_t vo_jhflp : 1;
	u_int16_t vo_jplts : 2;
};

struct vip_world_att
{
	u_int16_t vwa_bgmap_base : 4;
	u_int16_t vwa_rfu1 : 2;
	u_int16_t vwa_end : 1;
	u_int16_t vwa_over : 1;
	u_int16_t vwa_scy : 2;
	u_int16_t vwa_scx : 2;
	u_int16_t vwa_bgm : 2;
	u_int16_t vwa_ron : 1;
	u_int16_t vwa_lon : 1;
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

