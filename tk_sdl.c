#if INTERFACE
# include <sys/types.h>
# include <stdbool.h>
#endif // INTERFACE

#include "tk_sdl.h"

#include <SDL.h>
#define CIMGUI_DEFINE_ENUMS_AND_STRUCTS
#include "vendor/cimgui_sdl_opengl3/imgui_impl_sdl_gl3.h"
#include "assert.h"

#if !SDL_VERSION_ATLEAST(2, 0, 7)
# warning Problems with game controller GUIDs on macOS with version 2.0.5
#endif

#define VSYNC (true)

u_int tk_width, tk_height;

static SDL_Window *sdl_window;
static SDL_GameController *sdl_controller;
static SDL_GLContext sdl_gl_context;

bool
tk_init(void)
{
	if (SDL_Init(SDL_INIT_VIDEO | SDL_INIT_TIMER | SDL_INIT_GAMECONTROLLER) < 0)
	{
		fprintf(stderr, "SDL: Failed to initialize: %s", SDL_GetError());
		return false;
	}

	SDL_GL_SetAttribute(SDL_GL_CONTEXT_FLAGS, SDL_GL_CONTEXT_FORWARD_COMPATIBLE_FLAG);
	SDL_GL_SetAttribute(SDL_GL_CONTEXT_PROFILE_MASK, SDL_GL_CONTEXT_PROFILE_CORE);
	SDL_GL_SetAttribute(SDL_GL_DOUBLEBUFFER, 1);
	SDL_GL_SetAttribute(SDL_GL_DEPTH_SIZE, 24);
	SDL_GL_SetAttribute(SDL_GL_STENCIL_SIZE, 8);
	SDL_GL_SetAttribute(SDL_GL_CONTEXT_MAJOR_VERSION, 3);
	SDL_GL_SetAttribute(SDL_GL_CONTEXT_MINOR_VERSION, 2);

	tk_width = 384 * 3;
	tk_height = 224 * 3;

	if (!(sdl_window = SDL_CreateWindow("VVBoy",
					SDL_WINDOWPOS_CENTERED, SDL_WINDOWPOS_CENTERED,
					tk_width, tk_height,
					SDL_WINDOW_OPENGL)))
	{
		fprintf(stderr, "SDL: Couldn't create window: %s", SDL_GetError());
		return false;
	}
	SDL_GL_SetSwapInterval(VSYNC);

	sdl_gl_context = SDL_GL_CreateContext(sdl_window);

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
				switch (event.key.keysym.scancode)
				{
					default: break;
					case SDL_SCANCODE_LSHIFT: nvc_input(KEY_LT, event.key.state); break;
					case SDL_SCANCODE_W: nvc_input(KEY_LU, event.key.state); break;
					case SDL_SCANCODE_A: nvc_input(KEY_LL, event.key.state); break;
					case SDL_SCANCODE_S: nvc_input(KEY_LD, event.key.state); break;
					case SDL_SCANCODE_D: nvc_input(KEY_LR, event.key.state); break;
					case SDL_SCANCODE_APOSTROPHE: nvc_input(KEY_SEL, event.key.state); break;
					case SDL_SCANCODE_RETURN: nvc_input(KEY_STA, event.key.state); break;
					case SDL_SCANCODE_RSHIFT: nvc_input(KEY_RT, event.key.state); break;
					case SDL_SCANCODE_UP: nvc_input(KEY_RU, event.key.state); break;
					case SDL_SCANCODE_LEFT: nvc_input(KEY_RL, event.key.state); break;
					case SDL_SCANCODE_DOWN: nvc_input(KEY_RD, event.key.state); break;
					case SDL_SCANCODE_RIGHT: nvc_input(KEY_RR, event.key.state); break;
					case SDL_SCANCODE_RALT: nvc_input(KEY_A, event.key.state); break;
					case SDL_SCANCODE_RGUI: nvc_input(KEY_B, event.key.state); break;
				}
				break;
			}
			case SDL_CONTROLLERBUTTONDOWN:
			case SDL_CONTROLLERBUTTONUP:
				switch (event.cbutton.button)
				{
					case SDL_CONTROLLER_BUTTON_LEFTSHOULDER: nvc_input(KEY_LT, event.cbutton.state); break;
					case SDL_CONTROLLER_BUTTON_DPAD_UP: nvc_input(KEY_LU, event.cbutton.state); break;
					case SDL_CONTROLLER_BUTTON_DPAD_LEFT: nvc_input(KEY_LL, event.cbutton.state); break;
					case SDL_CONTROLLER_BUTTON_DPAD_DOWN: nvc_input(KEY_LD, event.cbutton.state); break;
					case SDL_CONTROLLER_BUTTON_DPAD_RIGHT: nvc_input(KEY_LR, event.cbutton.state); break;
					case SDL_CONTROLLER_BUTTON_BACK: nvc_input(KEY_SEL, event.cbutton.state); break;
					case SDL_CONTROLLER_BUTTON_START: nvc_input(KEY_STA, event.cbutton.state); break;
					case SDL_CONTROLLER_BUTTON_RIGHTSHOULDER: nvc_input(KEY_RT, event.cbutton.state); break;
					case SDL_CONTROLLER_BUTTON_A: nvc_input(KEY_A, event.cbutton.state); break;
					case SDL_CONTROLLER_BUTTON_B: nvc_input(KEY_B, event.cbutton.state); break;
				}
				break;
			case SDL_CONTROLLERAXISMOTION:
			{
				static const u_int16_t dead_zone = 8192;
				switch (event.caxis.axis)
				{
					case SDL_CONTROLLER_AXIS_RIGHTX:
						if (event.caxis.value > dead_zone)
							nvc_input(KEY_RR, true);
						else if (event.caxis.value < -dead_zone)
							nvc_input(KEY_RL, true);
						else
						{
							nvc_input(KEY_RR, false);
							nvc_input(KEY_RL, false);
						}
						break;
					case SDL_CONTROLLER_AXIS_RIGHTY:
						if (event.caxis.value > dead_zone)
							nvc_input(KEY_RD, true);
						else if (event.caxis.value < -dead_zone)
							nvc_input(KEY_RU, true);
						else
						{
							nvc_input(KEY_RD, false);
							nvc_input(KEY_RU, false);
						}
						break;
				}
				break;
			}
			default:
				break;
		}
	}

	return true;
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
