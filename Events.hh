#pragma once

#include "Types.hh"

enum event_subsys
{
	EVENT_SUBSYS_VIP,
	EVENT_SUBSYS_SCAN,
	EVENT_SUBSYS_VSU,
	EVENT_SUBSYS_NVC,
	EVENT_SUBSYS_CPU,
	EVENT_SUBSYS_DEBUG,
	EVENT_NUM_SUBSYS
};

	// TODO: Bitfield?
#define EVENT_WHICH_BITS(w) (w)
#define _EVENT_WHICH_MASK (0x3f)
#define EVENT_GET_WHICH(e) ((e) & _EVENT_WHICH_MASK)
#define EVENTS_MAX (_EVENT_WHICH_MASK + 1)
#define EVENT_SUBSYS_BITS(s) ((s) << 6)
#define EVENT_GET_SUBSYS(e) static_cast<event_subsys>(((e) >> 6) & 0xf)
#define EVENT_START_BIT (1 << 14) // TODO: BIT()
#define EVENT_FINISH_BIT (1 << 15) // TODO: BIT()
								   //
void events_fire(u_int16_t code, u_int32_t index, const void *user_data);
