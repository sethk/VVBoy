#ifndef MAIN_H
#define MAIN_H

#include <sys/types.h>
#include <stdbool.h>

void main_reset(void);
void main_step(void);
void main_exit(void);

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

#endif /* MAIN_H */
