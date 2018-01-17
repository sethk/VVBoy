#include "tk_sdl.h"

#include <SDL.h>

static SDL_Window *sdl_window;
static SDL_Renderer *sdl_renderer;
static SDL_Texture *sdl_texture;
static u_int32_t sdl_frame[384 * 224];
static SDL_Window *sdl_debug_window;
static SDL_Renderer *sdl_debug_renderer;
static SDL_Texture *sdl_debug_texture;
static u_int32_t sdl_debug_frame[512 * 512];

bool
tk_init(void)
{
	if (SDL_Init(SDL_INIT_VIDEO) < 0)
	{
		fprintf(stderr, "SDL: Failed to initialize: %s", SDL_GetError());
		return false;
	}

	if (SDL_CreateWindowAndRenderer(384 * 2, 224 * 2, 0, &sdl_window, &sdl_renderer) < 0)
	{
		fprintf(stderr, "SDL: Couldn't create window and renderer: %s", SDL_GetError());
		return false;
	}

	if (!(sdl_texture = SDL_CreateTexture(sdl_renderer,
					SDL_PIXELFORMAT_ARGB8888,
					SDL_TEXTUREACCESS_STREAMING,
					384,
					224)))
	{
		fprintf(stderr, "SDL: Could not create texture: %s", SDL_GetError());
		return false;
	}

	return true;
}

void
tk_step(void)
{
	SDL_Event event;
    while (SDL_PollEvent(&event))
		switch (event.type)
		{
			case SDL_QUIT:
				main_exit();
				break;
			case SDL_KEYDOWN:
				switch (event.key.keysym.sym)
				{
					case SDLK_ESCAPE: debug_intr(); break;
					case SDLK_F1: vip_toggle_world(31); break;
					case SDLK_F2: vip_toggle_world(30); break;
					case SDLK_F3: vip_toggle_world(29); break;
					case SDLK_F4: vip_toggle_world(28); break;
					case SDLK_F5: vip_toggle_world(27); break;
					case SDLK_F6: vip_toggle_world(26); break;
					case SDLK_F7: vip_toggle_world(25); break;
					case SDLK_F8: vip_toggle_world(24); break;
					case SDLK_F9: vip_toggle_world(23); break;
					case SDLK_F10: vip_toggle_world(22); break;
					case SDLK_F11: vip_toggle_world(21); break;
					case SDLK_F12: vip_toggle_world(20); break;
				}
		}
}

enum tk_keys
tk_poll(void)
{
	const Uint8 *sdl_keys = SDL_GetKeyboardState(NULL);
	enum tk_keys tk_keys = 0;

	if (sdl_keys[SDL_SCANCODE_LSHIFT])
		tk_keys|= KEY_LT;
	if (sdl_keys[SDL_SCANCODE_RSHIFT])
		tk_keys|= KEY_RT;
	if (sdl_keys[SDL_SCANCODE_RETURN])
		tk_keys|= KEY_STA;

	return tk_keys;
}

void
tk_blit(const u_int8_t *fb, bool right)
{
	for (u_int x = 0; x < 384; ++x)
		for (u_int y = 0; y < 224; ++y)
			sdl_frame[y * 384 + x] = vip_fb_read_argb(fb, x, y);
	SDL_UpdateTexture(sdl_texture, NULL, sdl_frame, 384 * sizeof(*sdl_frame));
	SDL_RenderCopy(sdl_renderer, sdl_texture, NULL, NULL);
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
	SDL_DestroyTexture(sdl_texture);
    SDL_DestroyRenderer(sdl_renderer);
    SDL_DestroyWindow(sdl_window);

    SDL_Quit();
}

