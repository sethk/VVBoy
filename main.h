#ifndef MAIN_H
#define MAIN_H

#include <sys/types.h>
#include <stdbool.h>

void main_reset(void);
void main_step(void);
void main_exit(void);

/* MEM */
enum mem_segment
{
	MEM_SEG_VIP = 0,
	MEM_SEG_VSU = 1,
	MEM_SEG_HWCTL = 2,
	MEM_SEG_CARTEX = 4,
	MEM_SEG_WRAM = 5,
	MEM_SEG_SRAM = 6,
	MEM_SEG_ROM = 7,
	MEM_NSEGS = 8
};

extern struct mem_seg_desc
{
	size_t ms_size;
	u_int8_t *ms_ptr;
	u_int32_t ms_addrmask;
	bool ms_is_mmap;
} mem_segs[MEM_NSEGS];

/* CPU */
union cpu_inst
{
	u_int16_t ci_hwords[2];
	struct
	{
		u_int i_reg1 : 5;
		u_int i_reg2 : 5;
		u_int i_opcode : 6;
	} ci_i;
	struct
	{
		u_int ii_imm5 : 5;
		u_int ii_reg2 : 5;
		u_int ii_opcode : 6;
	} ci_ii;
	struct
	{
		u_int v_reg1 : 5;
		u_int v_reg2 : 5;
		u_int v_opcode : 6;
		u_int16_t v_imm16;
	} ci_v;
	struct
	{
		u_int vi_reg1 : 5;
		u_int vi_reg2 : 5;
		u_int vi_opcode : 6;
		int16_t vi_disp16;
	} ci_vi;
};

/* DEBUG */
char *debug_disasm(const union cpu_inst *inst);

#endif /* MAIN_H */
