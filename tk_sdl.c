#if INTERFACE
# include <stdbool.h>
#endif // INTERFACE

#include "tk_sdl.h"

#include <SDL.h>

static bool tk_running = false;
static SDL_Window *sdl_window;
static SDL_Renderer *sdl_renderer;
static SDL_Texture *sdl_textures[2];
static u_int32_t sdl_frame[384 * 224];
static SDL_Window *sdl_debug_window;
static SDL_Renderer *sdl_debug_renderer;
static SDL_Texture *sdl_debug_texture;
static u_int32_t sdl_debug_frame[512 * 512];

bool
tk_init(void)
{
	if (SDL_Init(SDL_INIT_VIDEO | SDL_INIT_TIMER) < 0)
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

	return true;
}

u_int32_t
tk_get_ticks(void)
{
	return SDL_GetTicks();
}

static Uint32
tk_frame_tick(Uint32 interval, void *param)
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
				bool state = (event.type == SDL_KEYDOWN);
				switch (event.key.keysym.scancode)
				{
					default: break;
					case SDL_SCANCODE_LSHIFT: nvc_input(KEY_LT, state); break;
					case SDL_SCANCODE_W: nvc_input(KEY_LU, state); break;
					case SDL_SCANCODE_A: nvc_input(KEY_LL, state); break;
					case SDL_SCANCODE_S: nvc_input(KEY_LD, state); break;
					case SDL_SCANCODE_D: nvc_input(KEY_LR, state); break;
					case SDL_SCANCODE_APOSTROPHE: nvc_input(KEY_SEL, state); break;
					case SDL_SCANCODE_RETURN: nvc_input(KEY_STA, state); break;
					case SDL_SCANCODE_RSHIFT: nvc_input(KEY_RT, state); break;
					case SDL_SCANCODE_UP: nvc_input(KEY_RU, state); break;
					case SDL_SCANCODE_LEFT: nvc_input(KEY_RL, state); break;
					case SDL_SCANCODE_DOWN: nvc_input(KEY_RD, state); break;
					case SDL_SCANCODE_RIGHT: nvc_input(KEY_RR, state); break;
					case SDL_SCANCODE_RALT: nvc_input(KEY_A, state); break;
					case SDL_SCANCODE_RGUI: nvc_input(KEY_B, state); break;
				}
				if (event.type == SDL_KEYDOWN)
					switch (event.key.keysym.scancode)
					{
						default: break;
						case SDL_SCANCODE_ESCAPE: debug_intr(); break;
						case SDL_SCANCODE_F1: vip_toggle_world(31); break;
						case SDL_SCANCODE_F2: vip_toggle_world(30); break;
						case SDL_SCANCODE_F3: vip_toggle_world(29); break;
						case SDL_SCANCODE_F4: vip_toggle_world(28); break;
						case SDL_SCANCODE_F5: vip_toggle_world(27); break;
						case SDL_SCANCODE_F6: vip_toggle_world(26); break;
						case SDL_SCANCODE_F7: vip_toggle_world(25); break;
						case SDL_SCANCODE_F8: vip_toggle_world(24); break;
						case SDL_SCANCODE_F9: vip_toggle_world(23); break;
						case SDL_SCANCODE_F10: vip_toggle_world(22); break;
						case SDL_SCANCODE_F11: vip_toggle_world(21); break;
						case SDL_SCANCODE_F12: vip_toggle_world(20); break;
					}
			}
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
		{
			u_int8_t intensity = vip_fb_read(fb, x, y);
			u_int32_t argb;
			if (right)
				argb = 0xff000000 | (intensity << 6);
			else
				argb = 0xff000000 | (intensity << 22);
			sdl_frame[y * 384 + x] = argb;
		}
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
	for (u_int i = 0; i < 2; ++i)
		SDL_DestroyTexture(sdl_textures[i]);
    SDL_DestroyRenderer(sdl_renderer);
    SDL_DestroyWindow(sdl_window);

    SDL_Quit();
}

enum tk_error_state
tk_runtime_error(const char *msg)
{
	SDL_MessageBoxButtonData buttons[] =
	{
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
			}
	};
	SDL_MessageBoxData data =
			{
					.flags = SDL_MESSAGEBOX_WARNING,
					.window = sdl_window,
					.title = "Emulation error",
					.message = msg,
					.numbuttons = sizeof(buttons) / sizeof(buttons[0]),
					.buttons = buttons,
					.colorScheme = NULL
			};
	int buttonid;
	SDL_ShowMessageBox(&data, &buttonid);
	return buttonid;
}
