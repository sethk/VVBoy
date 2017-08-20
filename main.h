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
	MEM_SEG_NVC = 2,
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

/* NVC */
enum nvc_intlevel
{
	NVC_INTKEY = 0,
	NVC_INTTIM = 1,
	NVC_INTCRO = 2,
	NVC_INTCOM = 3,
	NVC_INTVIP = 4
};

/* CPU */
typedef u_int32_t cpu_regs_t[32];

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
		u_int iii_disp9 : 9;
		u_int iii_cond : 4;
		u_int iii_opcode : 3;
	} ci_iii;
	struct
	{
		u_int iv_disp10 : 10;
		u_int iv_opcode : 6;
		u_int iv_disp16 : 16;
	} ci_iv;
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

/* VIP */
void *vip_mem_emu2host(u_int32_t addr, size_t size);
void vip_frame_clock(void);
void vip_left_sync(void);
void vip_right_sync(void);

/* DEBUG */
struct debug_symbol
{
	char *ds_name;
	u_int32_t ds_addr;
	struct debug_symbol *ds_next;
};

bool trace_cpu = true;
bool trace_vip = true;
void debug_add_symbol(struct debug_symbol *debug_sym);
void debug_create_symbol(const char *name, u_int32_t addr);
char *debug_disasm(const union cpu_inst *inst, u_int32_t pc, const cpu_regs_t regs);
void debug_intr(void);
void debug_trace(const union cpu_inst *inst);

#endif /* MAIN_H */
