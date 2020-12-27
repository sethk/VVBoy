#include "types.h"
#include "events.h"

#if INTERFACE

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
#   define EVENT_WHICH_BITS(w) (w)
#   define _EVENT_WHICH_MASK (0x3f)
#   define EVENT_GET_WHICH(e) ((e) & _EVENT_WHICH_MASK)
#   define EVENTS_MAX (_EVENT_WHICH_MASK + 1)
#   define EVENT_SUBSYS_BITS(s) ((s) << 6)
#   define EVENT_GET_SUBSYS(e) (((e) >> 6) & 0xf)
#   define EVENT_START_BIT (1 << 14) // TODO: BIT()
#   define EVENT_FINISH_BIT (1 << 15) // TODO: BIT()
#endif // INTERFACE

#include <assert.h>
#include <math.h>

struct event
{
	u_int e_usecs;
	u_int16_t e_code;
	u_int32_t e_index;
	const void *e_user_data;
	struct event *e_next_by_subsys, *e_prev_by_subsys;
};

bool events_shown;
static bool events_capturing = false;
static bool events_overflowed = false;
static struct event events[64 * 1024];
static u_int events_count;
static enum event_subsys dummy_event_subsys; // Trick makeheaders into understanding that the declarations below require EVENT_SUBSYS_*
static struct event *events_first_by_subsys[EVENT_NUM_SUBSYS];
static struct event *events_last_by_subsys[EVENT_NUM_SUBSYS];
static bool events_dirty = false;
static const char *events_subsys_names[EVENT_NUM_SUBSYS] =
		{
				[EVENT_SUBSYS_VIP] = "VIP",
				[EVENT_SUBSYS_SCAN] = "Scan",
				[EVENT_SUBSYS_VSU] = "VSU",
				[EVENT_SUBSYS_NVC] = "NVC",
				[EVENT_SUBSYS_CPU] = "CPU",
				[EVENT_SUBSYS_DEBUG] = "Debug",
		};
static const char *events_descs[EVENT_NUM_SUBSYS][EVENTS_MAX];
static struct ImVec4 events_subsys_colors[EVENT_NUM_SUBSYS] =
{
		{1, 0, 0, 1}, {0, 1, 0, 1}, {0, 0, 1, 1}, {1, 1, 0, 1}, {0, 1, 1, 1}, {1, 1, 1, 1}
};

static const float track_size_base = 25.f;
static const float default_zoom = 100.f;
static float zoom;
static struct ImVec2 track_size;

bool
events_init(void)
{
	(void)dummy_event_subsys;

	zoom = default_zoom;
	track_size = (struct ImVec2){ track_size_base * default_zoom, 0 };

	for (u_int subsys = 0; subsys < EVENT_NUM_SUBSYS; ++subsys)
		for (u_int which = 0; which < EVENTS_MAX; ++which)
			events_descs[subsys][which] = "???";
	return true;
}

void
events_fini(void)
{
}

void
events_set_desc(u_int16_t code, const char *fmt)
{
	enum event_subsys subsys = EVENT_GET_SUBSYS(code);
	u_int which = EVENT_GET_WHICH(code);
	events_descs[subsys][which] = fmt;
}

void
events_fire(u_int16_t code, u_int32_t index, const void *user_data)
{
	if (!events_capturing)
		return;

	if (events_count < sizeof(events) / sizeof(events[0]))
	{
		enum event_subsys subsys = EVENT_GET_SUBSYS(code);
		struct event *event = &(events[events_count]);
		if (!events_first_by_subsys[subsys])
			events_first_by_subsys[subsys] = event;
		if (events_last_by_subsys[subsys])
		{
			events_last_by_subsys[subsys]->e_next_by_subsys = event;
			event->e_prev_by_subsys = events_last_by_subsys[subsys];
		}
		else
			event->e_prev_by_subsys = NULL;
		events_last_by_subsys[subsys] = event;
		event->e_usecs = main_usec;
		event->e_code = code;
		event->e_index = index;
		event->e_user_data = user_data;
		event->e_next_by_subsys = NULL;
		++events_count;
		events_dirty = true;
	}
	else if (!events_overflowed)
	{
		events_overflowed = true;
		debug_printf("Events overflow\n");
	}
}

void
events_clear(void)
{
	if (!events_capturing)
		return;

	events_count = 0;
	for (enum event_subsys subsys = 0; subsys < EVENT_NUM_SUBSYS; ++subsys)
	{
		events_first_by_subsys[subsys] = NULL;
		events_last_by_subsys[subsys] = NULL;
	}
	events_dirty = true;
	events_overflowed = false;
}

void
events_frame_end(void)
{
	if (events_shown)
	{
		igSetNextWindowSize(IMVEC2(750, 450), ImGuiCond_FirstUseEver);
		if (igBegin("Events", &events_shown, 0))
		{
			igCheckbox("Capture", &events_capturing);

			static bool scroll_to_end = false;
			static float scroll_to_pos = -1;

			struct ImVec2 mouse_pos;
			igGetMousePos(&mouse_pos);

			static float last_scroll_x = 0;
			static float last_scroll_max_x = 0;
			float min_time = last_scroll_x / track_size.x;
			float max_time = last_scroll_max_x / track_size.x;
			igAlignTextToFramePadding();
			igText("@%.6f-%.6f s (%.6f s)", min_time, max_time, max_time - min_time);

			igSameLine(0, -1);
			static float old_track_width;
			igPushItemWidth(220);
			bool zoom_updated = igSliderFloat("Zoom", &zoom, 10, 10000.0, "%.0f%%", 2.0);
			igPopItemWidth();
			if (zoom_updated)
			{
				old_track_width = track_size.x;
				track_size.x = track_size_base * zoom;
			}

			struct ImVec2 min_track_vecs[EVENT_NUM_SUBSYS];
			struct ImDrawList *draw_list;

			igColumns(2, "Tracks and labels", false);
			{
				igPushStyleVar(ImGuiStyleVar_ItemSpacing, 3);
				track_size.y = igGetTextLineHeight();

				igSetColumnWidth(-1, 40);

				for (enum event_subsys subsys = 0; subsys < EVENT_NUM_SUBSYS; ++subsys)
					igText(events_subsys_names[subsys]);

				igNextColumn();

				struct ImVec2 track_scroll_size =
						{
								igGetContentRegionAvailWidth(),
								igGetTextLineHeightWithSpacing() * EVENT_NUM_SUBSYS + 15
						};

				igPushStyleVarVec(ImGuiStyleVar_WindowPadding, (struct ImVec2) {1, 1});
				igSetNextWindowContentSize(IMVEC2(track_size.x, 0));
				igBeginChild("Events timeline", track_scroll_size, true, ImGuiWindowFlags_HorizontalScrollbar);
				{
					draw_list = igGetWindowDrawList();

					struct ImVec2 current_track_size;
					current_track_size.x = (float)(main_usec / 1e6) * track_size.x;
					current_track_size.y = track_size.y;

					for (enum event_subsys subsys = 0; subsys < EVENT_NUM_SUBSYS; ++subsys)
					{
						igGetCursorScreenPos(&(min_track_vecs[subsys]));
						struct ImVec2 max_vect =
								{
										min_track_vecs[subsys].x + current_track_size.x,
										min_track_vecs[subsys].y + current_track_size.y
								};

						igPushIDInt(subsys);
						static struct ImVec4 track_color = {0.131f, 0.131f, 0.131f, 1.0f};
						if (igBeginPopupContextWindow("Track colors", 1, true))
						{
							igColorEdit3("Track color", (float *) &track_color, ImGuiColorEditFlags_Float);
							igColorEdit3("Event color##", (float *) &(events_subsys_colors[subsys]),
							             ImGuiColorEditFlags_Float);
							igEndPopup();
						}
						igPopID();

						ImDrawList_AddRectFilled(draw_list, min_track_vecs[subsys], max_vect,
						                         igGetColorU32Vec(&track_color), 0, 0);
						igDummy(&current_track_size);
					}

					if (scroll_to_end)
						igSetScrollX(fmaxf(current_track_size.x - track_scroll_size.x, 0));
					else if (scroll_to_pos > 0)
					{
						igSetScrollX(scroll_to_pos);
						scroll_to_pos = -1;
					}

					if (zoom_updated)
					{
						float old_scroll = igGetScrollX() / old_track_width;
						scroll_to_pos = old_scroll * track_size.x;
					}

					last_scroll_x = igGetScrollX();
					last_scroll_max_x = last_scroll_x + track_scroll_size.x;

					igEndChild();
					igPopStyleVar(1);
				}

				igPopStyleVar(1);
			}
			igColumns(1, NULL, false);

			if (igBeginChild("Events list scroll", IMVEC2_ZERO, true, 0))
			{
				igColumns(4, "Events list", true);
				igSetColumnWidth(0, 60);
				igSetColumnWidth(1, 140);
				igSetColumnWidth(2, 100);
				igText("Subsys");
				igNextColumn();
				igText("Time");
				igNextColumn();
				igText("Duration");
				igNextColumn();
				igText("Event");
				igNextColumn();
				igSeparator();

				float last_event_max_x = -1;
				enum event_subsys last_event_subsys;
				u_int last_event_usecs;

				for (u_int i = 0; i < events_count; ++i)
				{
					struct event *event = &(events[i]);
					enum event_subsys subsys = EVENT_GET_SUBSYS(event->e_code);
					u_int which = EVENT_GET_WHICH(event->e_code);
					igText(events_subsys_names[subsys]);
					igNextColumn();
					float time_frac = (float)event->e_usecs / 1e6f;
					char time_str[25];
					size_t time_str_len = os_snprintf(time_str, sizeof(time_str), "%.6f", time_frac);

					struct ImVec2 min_vec;
					min_vec.y = min_track_vecs[subsys].y;
					struct ImVec2 max_vec;
					max_vec.y = min_vec.y + track_size.y;
					char dur_str[15];
					enum {DRAW_RECT, DRAW_LINE, DRAW_NONE} draw_mode = DRAW_NONE;

					if (event->e_code & EVENT_START_BIT)
					{
						struct event *next_event = event->e_next_by_subsys;
						for (; next_event; next_event = next_event->e_next_by_subsys)
						{
							if (EVENT_GET_WHICH(next_event->e_code) == which && next_event->e_index == event->e_index)
								break;
						}

						min_vec.x = min_track_vecs[subsys].x + ceilf((track_size.x - 1) * time_frac);
						if (next_event)
						{
							int time_delta = next_event->e_usecs - event->e_usecs;
							float end_time_frac = (float)next_event->e_usecs / 1e6f;
							time_str_len+= os_snprintf(time_str + time_str_len, sizeof(time_str) - time_str_len, "-%.6f",
							                        end_time_frac);
							os_snprintf(dur_str, sizeof(dur_str), "%.3f ms", (float)time_delta / 1000);
							max_vec.x = min_track_vecs[subsys].x + floorf(track_size.x * end_time_frac);
						}
						else
						{
							os_snprintf(dur_str, sizeof(dur_str), "???");
							max_vec.x = min_track_vecs[subsys].x + track_size.x;
						}

						draw_mode = DRAW_RECT;
					}
					else if (event->e_code & EVENT_FINISH_BIT)
					{
						os_snprintf(time_str, sizeof(time_str), "??\?-%.6f", time_frac); // Haha, trigraphs
						// TODO: Check end of event from last batch
					}
					else
					{
						min_vec.x = min_track_vecs[subsys].x + floorf(track_size.x * time_frac);
						max_vec.x = min_vec.x;
						os_snprintf(dur_str, sizeof(dur_str), "--");
						draw_mode = DRAW_LINE;
					}

					if (draw_mode != DRAW_NONE)
					{
						if (last_event_max_x >= 0 && min_vec.x <= last_event_max_x &&
								(subsys == last_event_subsys || event->e_usecs > last_event_usecs))
						{
							min_vec.x = last_event_max_x + 1;
							max_vec.x = fmaxf(max_vec.x, min_vec.x);

							if (min_vec.x >= min_track_vecs[subsys].x + track_size.x)
								draw_mode = DRAW_NONE;
						}

						last_event_max_x = max_vec.x;
						last_event_subsys = subsys;
						last_event_usecs = event->e_usecs;
					}

					bool show_tooltip = false;
					switch (draw_mode)
					{
						case DRAW_RECT:
						{
							float rounding = fminf(3, max_vec.x - min_vec.x);
							ImDrawList_AddRectFilled(draw_list,
							                         min_vec, max_vec,
							                         igGetColorU32Vec(&(events_subsys_colors[subsys])),
							                         rounding, ImDrawCornerFlags_All);
							ImDrawList_AddRect(draw_list, min_vec, max_vec, 0xffffffff,
							                   rounding, ImDrawCornerFlags_All, 1);
							break;
						}
						case DRAW_LINE:
							ImDrawList_AddLine(draw_list, min_vec, max_vec,
							                   igGetColorU32Vec(&(events_subsys_colors[subsys])), 1);
							break;

						case DRAW_NONE:
							break;
					}

					show_tooltip = (mouse_pos.x >= min_vec.x - 2 && mouse_pos.x <= max_vec.x &&
					                mouse_pos.y >= min_vec.y && mouse_pos.y <= max_vec.y);

					igText(time_str);
					igNextColumn();
					igText(dur_str);
					igNextColumn();
					char desc[64];
					size_t desc_len = os_snprintf(desc, sizeof(desc), events_descs[subsys][which],
												  event->e_index, event->e_user_data);

					if (show_tooltip)
						igSetTooltip("%s\n@%s s\n%s\n%s", events_subsys_names[subsys], time_str, dur_str, desc);

					if (event->e_code & EVENT_START_BIT)
						desc_len+= os_snprintf(desc + desc_len, sizeof(desc) - desc_len, " start");
					else if (event->e_code & EVENT_FINISH_BIT)
						desc_len+= os_snprintf(desc + desc_len, sizeof(desc) - desc_len, " finish");
					igTextUnformatted(desc, desc + desc_len);
					igNextColumn();
				}

				if (scroll_to_end)
					//igSetScrollX(track_size.x);
					igSetScrollHere(1.0);

				igEndChild();
			}

			scroll_to_end = false;

			igEnd();

			if (events_dirty)
			{
				// 1 frame delay due to ImGui relayout
				scroll_to_end = true;
				events_dirty = false;
			}
		}
	}
}
