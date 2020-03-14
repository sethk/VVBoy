#if INTERFACE
# include <sys/types.h>
# include <stdbool.h>
# include <SDL_scancode.h>
# include <SDL_gamecontroller.h>

	enum tk_scancode
	{
		TK_SCANCODE_F1 = SDL_SCANCODE_F1,
		TK_SCANCODE_F2 = SDL_SCANCODE_F2,
		TK_SCANCODE_F3 = SDL_SCANCODE_F3,
		TK_SCANCODE_F4 = SDL_SCANCODE_F4,
		TK_SCANCODE_F5 = SDL_SCANCODE_F5,
		TK_SCANCODE_F6 = SDL_SCANCODE_F6,
		TK_SCANCODE_F7 = SDL_SCANCODE_F7,
		TK_SCANCODE_F8 = SDL_SCANCODE_F8,
		TK_SCANCODE_F9 = SDL_SCANCODE_F9,
		TK_SCANCODE_GRAVE = SDL_SCANCODE_GRAVE,
		TK_SCANCODE_LGUI = SDL_SCANCODE_LGUI,
		TK_SCANCODE_RGUI = SDL_SCANCODE_RGUI,
		TK_SCANCODE_LSHIFT = SDL_SCANCODE_LSHIFT,
		TK_SCANCODE_W = SDL_SCANCODE_W,
		TK_SCANCODE_A = SDL_SCANCODE_A,
		TK_SCANCODE_S = SDL_SCANCODE_S,
		TK_SCANCODE_D = SDL_SCANCODE_D,
		TK_SCANCODE_K = SDL_SCANCODE_K,
		TK_SCANCODE_APOSTROPHE = SDL_SCANCODE_APOSTROPHE,
		TK_SCANCODE_RETURN = SDL_SCANCODE_RETURN,
		TK_SCANCODE_ESCAPE = SDL_SCANCODE_ESCAPE,
		TK_SCANCODE_R = SDL_SCANCODE_R,
		TK_SCANCODE_O = SDL_SCANCODE_O,
		TK_SCANCODE_1 = SDL_SCANCODE_1,
		TK_SCANCODE_2 = SDL_SCANCODE_2,
		TK_SCANCODE_RSHIFT = SDL_SCANCODE_RSHIFT,
		TK_SCANCODE_RALT = SDL_SCANCODE_RALT,
		TK_SCANCODE_UP = SDL_SCANCODE_UP,
		TK_SCANCODE_LEFT = SDL_SCANCODE_LEFT,
		TK_SCANCODE_DOWN = SDL_SCANCODE_DOWN,
		TK_SCANCODE_RIGHT = SDL_SCANCODE_RIGHT
	};

	enum tk_button
	{
		TK_BUTTON_LSHOULDER = SDL_CONTROLLER_BUTTON_LEFTSHOULDER,
		TK_BUTTON_DPAD_UP = SDL_CONTROLLER_BUTTON_DPAD_UP,
		TK_BUTTON_DPAD_LEFT = SDL_CONTROLLER_BUTTON_DPAD_LEFT,
		TK_BUTTON_DPAD_DOWN = SDL_CONTROLLER_BUTTON_DPAD_DOWN,
		TK_BUTTON_DPAD_RIGHT = SDL_CONTROLLER_BUTTON_DPAD_RIGHT,
		TK_BUTTON_BACK = SDL_CONTROLLER_BUTTON_BACK,
		TK_BUTTON_START = SDL_CONTROLLER_BUTTON_START,
		TK_BUTTON_RSHOULDER = SDL_CONTROLLER_BUTTON_RIGHTSHOULDER,
		TK_BUTTON_A = SDL_CONTROLLER_BUTTON_A,
		TK_BUTTON_B = SDL_CONTROLLER_BUTTON_B
	};

	enum tk_axis
	{
		TK_AXIS_RIGHTX = SDL_CONTROLLER_AXIS_RIGHTX,
		TK_AXIS_RIGHTY = SDL_CONTROLLER_AXIS_RIGHTY
	};
#endif // INTERFACE

#include "tk_sdl.h"

#include <SDL.h>
#include <SDL_syswm.h>
#define CIMGUI_DEFINE_ENUMS_AND_STRUCTS
#include "vendor/cimgui_sdl_opengl3/imgui_impl_sdl_gl3.h"
#include "assert.h"

#if !SDL_VERSION_ATLEAST(2, 0, 7)
# warning Problems with game controller GUIDs on macOS with version 2.0.5
#endif

#define VSYNC (true)

u_int tk_win_width, tk_win_height;
int tk_draw_width, tk_draw_height;
float tk_draw_scale;

static SDL_Window *sdl_window;
static SDL_GameController *sdl_controller;
static SDL_GLContext sdl_gl_context;

bool
tk_init(void)
{
	if (SDL_Init(SDL_INIT_VIDEO | SDL_INIT_TIMER | SDL_INIT_GAMECONTROLLER) < 0)
	{
		fprintf(stderr, "SDL: Failed to initialize: %s\n", SDL_GetError());
		return false;
	}

	SDL_GL_SetAttribute(SDL_GL_CONTEXT_FLAGS, SDL_GL_CONTEXT_FORWARD_COMPATIBLE_FLAG);
	SDL_GL_SetAttribute(SDL_GL_CONTEXT_PROFILE_MASK, SDL_GL_CONTEXT_PROFILE_CORE);
	SDL_GL_SetAttribute(SDL_GL_DOUBLEBUFFER, 1);
	SDL_GL_SetAttribute(SDL_GL_DEPTH_SIZE, 24);
	SDL_GL_SetAttribute(SDL_GL_STENCIL_SIZE, 8);
	SDL_GL_SetAttribute(SDL_GL_CONTEXT_MAJOR_VERSION, 3);
	SDL_GL_SetAttribute(SDL_GL_CONTEXT_MINOR_VERSION, 2);

	tk_win_width = 384 * 3;
	tk_win_height = 224 * 3;
	if (!(sdl_window = SDL_CreateWindow("VVBoy",
					SDL_WINDOWPOS_CENTERED, SDL_WINDOWPOS_CENTERED,
					tk_win_width, tk_win_height,
					SDL_WINDOW_OPENGL | SDL_WINDOW_ALLOW_HIGHDPI)))
	{
		fprintf(stderr, "SDL: Couldn't create window: %s", SDL_GetError());
		return false;
	}
	sdl_gl_context = SDL_GL_CreateContext(sdl_window);

	SDL_GL_SetSwapInterval(VSYNC);

	SDL_GL_GetDrawableSize(sdl_window, &tk_draw_width, &tk_draw_height);
	tk_draw_scale = tk_draw_width / tk_win_width;
	SDL_assert_always(fdimf(tk_draw_height / tk_win_height, tk_draw_scale) < 1e-6);

	ImGui_ImplSdlGL3_Init(sdl_window, NULL);

	if (SDL_GameControllerAddMappingsFromFile("gamecontrollerdb.txt") <= 0)
		SDL_ShowSimpleMessageBox(SDL_MESSAGEBOX_WARNING, "Warning", SDL_GetError(), sdl_window);

	int num_joysticks = SDL_NumJoysticks(), joy_index;
	for (joy_index = 0; joy_index < num_joysticks; ++joy_index)
		if (SDL_IsGameController(joy_index))
			break;

	if (joy_index < num_joysticks)
	{
		if ((sdl_controller = SDL_GameControllerOpen(0)))
			SDL_Log("Using game controller #%d: %s", joy_index, SDL_GameControllerNameForIndex(joy_index));
		else
			SDL_ShowSimpleMessageBox(SDL_MESSAGEBOX_WARNING, "Warning", SDL_GetError(), sdl_window);
	}
	else
	{
		char msg[1024];
		size_t msg_offset = 0;
		msg_offset+= snprintf(msg, sizeof(msg) - msg_offset, "No game controllers found\nJoysticks found:");
		for (joy_index = 0; joy_index < num_joysticks; ++joy_index)
		{
			char guid_s[33];
			SDL_JoystickGUID guid = SDL_JoystickGetDeviceGUID(joy_index);
			SDL_JoystickGetGUIDString(guid, guid_s, sizeof(guid_s));
			msg_offset += snprintf(msg + msg_offset, sizeof(msg) - msg_offset, "\n\tName: %s, GUID: %s",
			                       SDL_JoystickNameForIndex(joy_index),
			                       guid_s);
			SDL_ShowSimpleMessageBox(SDL_MESSAGEBOX_WARNING, "Warning", msg, sdl_window);
		}
	}

	return true;
}

void
tk_update_caption(const char *caption)
{
	SDL_SetWindowTitle(sdl_window, caption);
}

u_int32_t
tk_get_usec(void)
{
	return SDL_GetTicks() * 1000;
}

void
tk_frame_begin(void)
{
	ImGui_ImplSdlGL3_NewFrame(sdl_window);
}

void
tk_frame_end(void)
{
	struct ImDrawData *imgui_data = igGetDrawData();
	if (imgui_data)
		ImGui_ImplSdlGL3_RenderDrawData(imgui_data);

	SDL_GL_SwapWindow(sdl_window);
}

bool
tk_poll_input()
{
	struct ImGuiIO *imgui_io = igGetIO();
	SDL_Event event;
	while (SDL_PollEvent(&event))
	{
		ImGui_ImplSdlGL3_ProcessEvent(&event);

		switch (event.type)
		{
			case SDL_QUIT:
				return false;
				break;
			case SDL_KEYDOWN:
			case SDL_KEYUP:
			{
				if (imgui_io->WantCaptureKeyboard)
					break;

				if (event.key.repeat)
					break;
				nvc_input_key((enum tk_scancode)event.key.keysym.scancode, event.key.state);
				break;
			}
			case SDL_CONTROLLERBUTTONDOWN:
			case SDL_CONTROLLERBUTTONUP:
				nvc_input_button(event.cbutton.button, event.cbutton.state);
				break;
			case SDL_CONTROLLERAXISMOTION:
				nvc_input_axis((enum tk_axis)event.caxis.axis, event.caxis.value / 32767.f);
				break;
			default:
				break;
		}
	}

	return true;
}

void
tk_pump_input()
{
	SDL_PumpEvents();
}

void
tk_fini(void)
{
	ImGui_ImplSdlGL3_Shutdown();

	if (sdl_controller)
		SDL_GameControllerClose(sdl_controller);

	SDL_GL_DeleteContext(sdl_gl_context);
    SDL_DestroyWindow(sdl_window);

    SDL_Quit();
}

enum debug_error_state
tk_runtime_error(const char *msg, bool allow_always_ignore)
{
	static const SDL_MessageBoxButtonData all_buttons[] =
	{
			{
					.flags = 0,
					.buttonid = ERROR_ALWAYS_IGNORE,
					.text = "Always Ignore"
			},
			{
					.flags = SDL_MESSAGEBOX_BUTTON_RETURNKEY_DEFAULT,
					.buttonid = ERROR_IGNORE,
					.text = "Ignore"
			},
			{
					.flags = 0,
					.buttonid = ERROR_ABORT,
					.text = "Abort"
			},
			{
					.flags = SDL_MESSAGEBOX_BUTTON_ESCAPEKEY_DEFAULT,
					.buttonid = ERROR_DEBUG,
					.text = "Debug"
			},
	};
	const SDL_MessageBoxButtonData *buttons = all_buttons;
	u_int num_buttons = sizeof(all_buttons) / sizeof(all_buttons[0]);
	if (!allow_always_ignore)
	{
		++buttons;
		--num_buttons;
	}
	SDL_MessageBoxData data =
			{
					.flags = SDL_MESSAGEBOX_WARNING,
					.window = sdl_window,
					.title = "Emulation error",
					.message = msg,
					.numbuttons = num_buttons,
					.buttons = buttons,
					.colorScheme = NULL
			};
	int buttonid;
	SDL_ShowMessageBox(&data, &buttonid);
	return (enum debug_error_state)buttonid;
}

#if INTERFACE
# include <SDL_syswm.h>
#endif // INTERFACE

NSWindow *
tk_get_main_win()
{
	SDL_SysWMinfo info;
	SDL_VERSION(&info.version);
	SDL_assert_always(SDL_GetWindowWMInfo(sdl_window, &info));
	return info.info.cocoa.window;
}
