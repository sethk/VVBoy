#include "tk.h"
#include "tk_sdl.h"
#include <SDL.h>

static SDL_Window *sdl_window;
static SDL_Renderer *sdl_renderer;
static SDL_Texture *sdl_texture;
static u_int32_t sdl_frame[384 * 224];

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
	{
		if (event.type == SDL_QUIT)
			main_exit();
    }
}

enum nvc_key
tk_poll(void)
{
	const Uint8 *sdl_keys = SDL_GetKeyboardState(NULL);
	enum nvc_key nvc_keys = 0;

	if (sdl_keys[SDL_SCANCODE_LSHIFT])
		nvc_keys|= KEY_LT;
	if (sdl_keys[SDL_SCANCODE_RSHIFT])
		nvc_keys|= KEY_RT;

	return nvc_keys;
}

void
tk_blit(const u_int8_t *fb, bool right)
{
	for (u_int x = 0; x < 384; ++x)
		for (u_int y = 0; y < 224; ++y)
			sdl_frame[y * 384 + x] = vip_fb_read_argb(fb, x, y, right);
	SDL_UpdateTexture(sdl_texture, NULL, sdl_frame, 384 * sizeof(*sdl_frame));
	SDL_RenderCopy(sdl_renderer, sdl_texture, NULL, NULL);
	SDL_RenderPresent(sdl_renderer);
}

void
tk_fini(void)
{
	SDL_DestroyTexture(sdl_texture);
    SDL_DestroyRenderer(sdl_renderer);
    SDL_DestroyWindow(sdl_window);

    SDL_Quit();
}

