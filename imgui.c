#include "types.h"
#include "imgui.h"
#include <assert.h>

#if INTERFACE
#   define IMVEC2(x, y) ((struct ImVec2){(x), (y)})
#endif // INTERFACE

const struct ImVec2 IMVEC2_ZERO = {0, 0};

bool imgui_shown = true;
static int imgui_emu_x, imgui_emu_y;
static u_int imgui_emu_scale = 2;

struct ImGuiContext *imgui_context;
struct ImFont *imgui_font_fixed;

bool
imgui_init(void)
{
	imgui_context = igCreateContext(NULL);

	struct ImGuiIO *io = igGetIO();
	io->IniFilename = NULL;
	ImFontAtlas_AddFontFromFileTTF(io->Fonts, "Roboto-Medium.ttf", 16.0f, NULL, NULL);
	imgui_font_fixed = ImFontAtlas_AddFontDefault(io->Fonts, NULL);
	//io.Fonts->AddFontFromFileTTF("../../misc/fonts/Cousine-Regular.ttf", 15.0f);
	//io.Fonts->AddFontFromFileTTF("../../misc/fonts/DroidSans.ttf", 16.0f);
	//io.Fonts->AddFontFromFileTTF("../../misc/fonts/ProggyTiny.ttf", 10.0f);

	return true;
}

void
imgui_fini(void)
{
	igDestroyContext(imgui_context);
}

bool
imgui_key_toggle(int key_index, bool *togglep, bool show_on_active)
{
	if (igIsKeyPressed(key_index, false))
	{
		*togglep = !*togglep;
		if (show_on_active && *togglep)
		{
			imgui_shown = true;
			return true;
		}
	}
	return false;
}

void
imgui_frame_begin(void)
{
	enum tk_scancode dummy_scancode;
	(void)dummy_scancode; // Hint for makeheaders

	if (rom_loaded && (igIsKeyPressed(TK_SCANCODE_ESCAPE, false) /*|| igIsKeyPressed(TK_SCANCODE_SPACE, false)*/))
		imgui_shown = !imgui_shown;

	if (igIsKeyDown(OS_SHORTCUT_LKEY) || igIsKeyDown(OS_SHORTCUT_RKEY))
	{
		if (rom_loaded && igIsKeyPressed(TK_SCANCODE_R, false))
			emu_reset();
		else if (!rom_loaded && igIsKeyPressed(TK_SCANCODE_O, false))
			main_open_rom();
		if (igIsKeyPressed(TK_SCANCODE_1, false))
			imgui_emu_scale = 1;
		else if (igIsKeyPressed(TK_SCANCODE_2, false))
			imgui_emu_scale = 2;
	}

	if (!imgui_shown)
	{
		// TODO: ignore mouse
		return;
	}

	static bool demo_open = false;
	static bool show_timing = false;
	if (igBeginMainMenuBar())
	{
		if (igBeginMenu("File", true))
		{
			if (igMenuItem("Open ROM...", OS_SHORTCUT_KEY_NAME "+O", false, !rom_loaded))
				main_open_rom();

			if (igMenuItem("Close ROM", NULL, false, rom_loaded))
				main_close_rom();

			igSeparator();

			if (igMenuItem("Quit", OS_SHORTCUT_KEY_NAME "+Q", false, true))
				main_quit();

			igEndMenu();
		}

		if (igBeginMenu("Emulation", rom_loaded))
		{
			if (igMenuItem("Reset", OS_SHORTCUT_KEY_NAME "+R", false, true))
				emu_reset();

			igSeparator();

			if (igMenuItem("Pause", "F9", debug_is_stopped(), true))
				debug_toggle_stopped();

			if (igMenuItem("Advance frame", "F8", false, debug_is_stopped()))
				debug_next_frame();

			igSeparator();

			if (igBeginMenu("Debug", true))
				debug_emu_menu();

			igEndMenu();
		}

		if (igBeginMenu("View", rom_loaded))
		{
			igMenuItemPtr("Debug console...", "`", &debug_show_console, true);
			igMenuItemPtr("Events...", NULL, &events_shown, true);

			igSeparator();

			vip_view_menu();

			igSeparator();

			igMenuItemPtr("Sounds...", NULL, &vsu_sounds_open, true);
			igMenuItemPtr("Audio buffers...", NULL, &vsu_buffers_open, true);

			igEndMenu();
		}

		if (igBeginMenu("Settings", true))
		{
			if (igMenuItem("Window scale 100%", OS_SHORTCUT_KEY_NAME "+1", imgui_emu_scale == 1, true))
				imgui_emu_scale = 1;
			if (igMenuItem("Window scale 200%", OS_SHORTCUT_KEY_NAME "+2", imgui_emu_scale == 2, true))
				imgui_emu_scale = 2;

			igSeparator();

			igMenuItemPtr("Draw left eye", NULL, &gl_draw_left, true);
			igMenuItemPtr("Draw right eye", NULL, &gl_draw_right, true);

			igSeparator();

			bool sound_muted = vsu_is_muted_by_user();
			if (igMenuItemPtr("Mute audio", NULL, &sound_muted, tk_audio_enabled))
				vsu_set_muted_by_user(sound_muted);

			igSeparator();

			vip_settings_menu();

			igSeparator();

			igMenuItemPtr("Timing...", NULL, &show_timing, true);

			igSeparator();

			if (igMenuItem("Toggle GUI", /*"space/" */ "esc", true, rom_loaded))
				imgui_shown = false;

			igEndMenu();
		}

		if (igBeginMenu("Help", true))
		{
			if (igMenuItem("Show UI demo", NULL, false, true))
				demo_open = true;

			igEndMenu();
		}

		igEndMainMenuBar();
	}

	if (show_timing)
	{
		if (igBegin("Timing", &show_timing, ImGuiWindowFlags_NoResize | ImGuiWindowFlags_AlwaysAutoResize))
		{
			igCheckbox("Fixed timestep", &main_fixed_rate);

			igSliderFloat("Emulation speed", &emu_time_scale, 0.05, 2.0, "%.2f", 1);

			igSliderInt("CPU cycles per µsec", (int *)&nvc_cycles_per_usec, 1, 100, NULL);

			igCheckbox("Accurate instruction timing", &cpu_accurate_timing);

			igSliderInt("VIP drawing duration", (int *)&vip_xp_interval, 1, 1000, NULL);

			igEnd();
		}
	}

	if (demo_open)
		igShowDemoWindow(&demo_open);
}

static void
imgui_draw_emu(const struct ImDrawList *parent_list __unused, const struct ImDrawCmd *draw_cmd __unused)
{
	gl_save_state();
	gl_draw(imgui_emu_x * tk_draw_scale,
			imgui_emu_y * tk_draw_scale,
			384 * imgui_emu_scale * tk_draw_scale,
			224 * imgui_emu_scale * tk_draw_scale);
	gl_restore_state();
}

void
imgui_draw_win(void)
{
	char id[64];
	os_snprintf(id, sizeof(id), "%s##VVBoy", rom_name);
	igPushStyleVar(ImGuiStyleVar_WindowRounding, 0);
	igPushStyleVarVec(ImGuiStyleVar_WindowPadding, IMVEC2_ZERO);
	struct ImGuiStyle *style = igGetStyle();
	u_int width = 384 * imgui_emu_scale, height = 224 * imgui_emu_scale;
	struct ImVec2 content_size =
			{
					width + style->WindowBorderSize * 2,
					height + style->WindowBorderSize
			};
	igSetNextWindowPos((struct ImVec2){tk_win_width / 2.0, tk_win_height / 2.0},
					   ImGuiCond_FirstUseEver,
					   (struct ImVec2){0.5, 0.5});
	igSetNextWindowContentSize(content_size);
	if (igBegin(id, NULL, ImGuiWindowFlags_NoResize |
						  ImGuiWindowFlags_AlwaysAutoResize |
						  ImGuiWindowFlags_NoFocusOnAppearing))
	{
		struct ImVec2 view_pos;
		struct ImVec2 content_min;
		igGetWindowPos(&view_pos);
		igGetWindowContentRegionMin(&content_min);
		imgui_emu_x = view_pos.x + content_min.x + style->WindowBorderSize;
		imgui_emu_y = tk_win_height - (view_pos.y + content_min.y + height);
		ImDrawList_AddCallback(igGetWindowDrawList(), imgui_draw_emu, NULL);
	}
	igEnd();
	igPopStyleVar(2);
}

void
imgui_frame_end(void)
{
	if (imgui_shown)
		igRender();
	else
		igEndFrame();
}

void
imgui_debug_image(enum gl_texture texture, u_int width, u_int height)
{
	static const struct ImVec4 color = {1, 1, 1, 1};
	static const struct ImVec4 border_color = {0.5, 0.5, 0.5, 1};
	u_int texture_id = gl_debug_blit(texture);
	igImage((ImTextureID)(uintptr_t)texture_id,
	        (struct ImVec2) {width, height},
	        IMVEC2_ZERO, (struct ImVec2) {(float)width / 512, (float)height / 512},
	        color, border_color);
}
