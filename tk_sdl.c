#if INTERFACE
# include <stdbool.h>
#endif // INTERFACE

#include "tk_sdl.h"

#include <SDL.h>

#if !SDL_VERSION_ATLEAST(2, 0, 7)
# warning Problems with game controller GUIDs on macOS with version 2.0.5
#endif

static bool tk_running = false;
static SDL_Window *sdl_window;
static SDL_Renderer *sdl_renderer;
static SDL_Texture *sdl_textures[2];
static u_int32_t sdl_frame[384 * 224];
static SDL_Window *sdl_debug_window;
static SDL_GameController *sdl_controller;
static SDL_Renderer *sdl_debug_renderer;
static SDL_Texture *sdl_debug_texture;
static u_int32_t sdl_debug_frame[512 * 512];

bool
tk_init(void)
{
	if (SDL_Init(SDL_INIT_VIDEO | SDL_INIT_TIMER | SDL_INIT_GAMECONTROLLER) < 0)
	{
		fprintf(stderr, "SDL: Failed to initialize: %s", SDL_GetError());
		return false;
	}

	if (!(sdl_window = SDL_CreateWindow("VVBoy",
					SDL_WINDOWPOS_CENTERED, SDL_WINDOWPOS_CENTERED,
					384 * 2, 224 * 2,
					0)))
	{
		fprintf(stderr, "SDL: Couldn't create window: %s", SDL_GetError());
		return false;
	}
	if (!(sdl_renderer = SDL_CreateRenderer(sdl_window, -1, SDL_RENDERER_PRESENTVSYNC)))
	{
		fprintf(stderr, "SDL: Couldn't create renderer: %s", SDL_GetError());
		return false;
	}

	for (u_int i = 0; i < 2; ++i)
	{
		if (!(sdl_textures[i] = SDL_CreateTexture(sdl_renderer,
		                                          SDL_PIXELFORMAT_ARGB8888,
		                                          SDL_TEXTUREACCESS_STREAMING,
		                                          384,
		                                          224)))
		{
			fprintf(stderr, "SDL: Could not create texture: %s", SDL_GetError());
			return false;
		}
		SDL_SetTextureBlendMode(sdl_textures[i], SDL_BLENDMODE_ADD);
	}
	SDL_SetTextureColorMod(sdl_textures[0], 0xff, 0, 0);
	SDL_SetTextureColorMod(sdl_textures[1], 0, 0, 0xff);

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
tk_get_ticks(void)
{
	return SDL_GetTicks();
}

static Uint32
tk_frame_tick(Uint32 interval __unused, void *param __unused)
{
	SDL_Event event;
	SDL_UserEvent userevent;

	userevent.type = SDL_USEREVENT;
	userevent.code = 0;
	userevent.data1 = NULL;
	userevent.data2 = NULL;

	event.type = SDL_USEREVENT;
	event.user = userevent;

	SDL_PushEvent(&event);

	return 0;
}

void
tk_frame(void)
{
	static Uint32 last_ticks = 0;
	static float smooth_interval = 20;
	static float smooth_jitter = 0;
	Uint32 now = SDL_GetTicks();
	if (last_ticks)
	{
		Sint32 jitter = 20 - (now - last_ticks);
#define JITTER_LPF (0.1)
		smooth_jitter = smooth_jitter * (1.0 - JITTER_LPF) + (float)jitter * JITTER_LPF;
		smooth_interval = fminf(fmaxf(smooth_interval + smooth_jitter, 10), 25);

		/*
		//static u_int trace = 0;
		if ((++trace % 20) == 0)
			debug_tracef("sdl", "tk_frame_tick() smooth_interval = %g, jitter %d, smooth_jitter %g\n",
					smooth_interval, jitter, smooth_jitter);
					*/
	}
	last_ticks = now;

	SDL_AddTimer(lroundf(smooth_interval), tk_frame_tick, NULL);

	main_frame();
}

void
tk_main(void)
{
	tk_running = true;

	SDL_AddTimer(20, tk_frame_tick, NULL);

	SDL_Event event;
	while (tk_running && SDL_WaitEvent(&event))
		switch (event.type)
		{
			case SDL_USEREVENT:
				tk_frame();
				break;
			case SDL_QUIT:
				tk_running = false;
				break;
			case SDL_KEYDOWN:
			case SDL_KEYUP:
			{
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
				if (event.type == SDL_KEYDOWN)
					switch (event.key.keysym.scancode)
					{
						default: break;
						case SDL_SCANCODE_ESCAPE: debug_enter(); break;
						case SDL_SCANCODE_F1: vip_toggle_worlds(); break;
						case SDL_SCANCODE_F2: vip_use_bright = !vip_use_bright; break;
						case SDL_SCANCODE_F3: vip_toggle_rows(); break;
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

void
tk_quit(void)
{
	tk_running = false;
}

void
tk_blit(const u_int8_t *fb, bool right)
{
	if (!right)
		SDL_RenderClear(sdl_renderer);

	SDL_Texture *texture = sdl_textures[(right) ? 0 : 1];
	for (u_int x = 0; x < 384; ++x)
		for (u_int y = 0; y < 224; ++y)
			sdl_frame[y * 384 + x] = vip_fb_read_argb(fb, x, y);
	SDL_UpdateTexture(texture, NULL, sdl_frame, 384 * sizeof(*sdl_frame));
	SDL_RenderCopy(sdl_renderer, texture, NULL, NULL);

	if (right)
		SDL_RenderPresent(sdl_renderer);
}

void
tk_debug_draw(u_int x, u_int y, u_int32_t argb)
{
	if (!sdl_debug_renderer)
	{
		SDL_CreateWindowAndRenderer(512, 512, 0, &sdl_debug_window, &sdl_debug_renderer);
		sdl_debug_texture = SDL_CreateTexture(sdl_debug_renderer,
				SDL_PIXELFORMAT_ARGB8888,
				SDL_TEXTUREACCESS_STREAMING,
				512, 512);
	}

	sdl_debug_frame[y * 512 + x] = argb;
}

void
tk_debug_flip(void)
{
	SDL_UpdateTexture(sdl_debug_texture, NULL, sdl_debug_frame, 512 * sizeof(*sdl_debug_frame));
	SDL_RenderCopy(sdl_debug_renderer, sdl_debug_texture, NULL, NULL);
	SDL_RenderPresent(sdl_debug_renderer);
}

void
tk_fini(void)
{
	if (sdl_controller)
		SDL_GameControllerClose(sdl_controller);

	for (u_int i = 0; i < 2; ++i)
		SDL_DestroyTexture(sdl_textures[i]);
    SDL_DestroyRenderer(sdl_renderer);
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
