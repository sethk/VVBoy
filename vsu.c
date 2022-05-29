#include "types.h"
#include "vsu.h"
#include <assert.h>

struct vsu_ram
{
	u_int8_t vr_waves[5][32];
	u_int8_t vr_snd5mod[32];
	u_int8_t vr_rfu[64];
};

struct vsu_regs
{
	//_Alignas(4)?
	struct vsu_sound_regs
	{
		struct
		{
			u_int8_t vi_data : 5;
			u_int8_t vi_mode : 1;
			u_int8_t vi_rfu1 : 1;
			u_int8_t vi_start : 1;
		} vsr_int;				// 00
		struct
		{
			u_int8_t vl_rlevel : 4;
			u_int8_t vl_llevel : 4;
		} vsr_lrv;				// 04
		u_int8_t vsr_fql;		// 08
		struct
		{
			u_int8_t vf_fqh : 3;
			u_int8_t vf_rfu1 : 5;
		} vsr_fqh;				// 0C
		struct
		{
			u_int8_t ve_step : 3;
			u_int8_t ve_ud : 1;
			u_int8_t ve_init : 4;
		} vsr_ev0;				// 10
		struct
		{
			u_int8_t ve_on : 1;
			u_int8_t ve_rs : 1;
			u_int8_t ve_rfu1 : 2;
			u_int8_t ve_modswp : 1;
			u_int8_t ve_short : 1;
			u_int8_t ve_ed : 1;
			u_int8_t ve_rfu2 : 1;
		} vsr_ev1;				// 14
		union
		{
			struct
			{
				u_int8_t vr_addr : 4;
				u_int8_t vr_rfu1 : 4;
			} vsr_ram;
		};						// 18
		struct
		{
			u_int8_t vs_shifts : 3;
			u_int8_t vs_ud : 1;
			u_int8_t vs_time : 3;
			u_int8_t vs_clk : 1;
		} vsr_swp;				// 1C
		u_int32_t vs_rfu[2];	// 20
	} vr_sounds[6];
	struct
	{
		u_int8_t vs_stop : 1;
		u_int8_t vs_rfu1 : 7;
	} vr_stop;					// 180
	u_int8_t vr_rfu1[7];
	u_int32_t vr_rfu2[6];
};

bool vsu_sounds_open = false;
bool vsu_buffers_open = false;

static struct vsu_ram vsu_ram;
static struct vsu_regs vsu_regs;

const u_int vsu_buffer_size = 417 * 10;
static int16_t vsu_buffer[vsu_buffer_size][2];
static u_int vsu_buffer_head, vsu_buffer_tail;
static bool vsu_buffer_full;

const u_int32_t vsu_sample_rate = 41700;
static const u_int32_t clock_freq = 5000000;

static u_int8_t vsu_sound_mask = 0b111111;
static struct vsu_state
{
	bool vs_started;
	u_int vs_freq_count;
	u_int vs_wave_index;
#if 0
	u_int vs_int_count;
#endif // 0
	u_int16_t vs_env_value;
	u_int vs_env_count;
} vsu_states[6];
static bool vsu_env_enable = true;

bool
vsu_init(void)
{
	return true;
}

void
vsu_init_debug()
{
	debug_create_symbol_array("SNDWAV", 0x01000000, 5, 0x80, true);
	for (u_int i = 0; i < 6; ++i)
	{
		u_int32_t base = 0x01000400 + (i * 0x40);
		u_int sound = i + 1;
		debug_create_symbolf(base + 0x00, true, "S%uINT", sound);
		debug_create_symbolf(base + 0x04, true, "S%uLRV", sound);
		debug_create_symbolf(base + 0x08, true, "S%uFQL", sound);
		debug_create_symbolf(base + 0x0c, true, "S%uFQH", sound);
		debug_create_symbolf(base + 0x10, true, "S%uEV0", sound);
		debug_create_symbolf(base + 0x14, true, "S%uEV1", sound);
		debug_create_symbolf(base + 0x18, true, "S%uRAM", sound);
	}
	debug_create_symbol("SSTOP", 0x01000580, true);
}

void
vsu_test(void)
{
	debug_printf("Running VSU self-test\n");
	ASSERT_SIZEOF(vsu_ram, 0x100);
	ASSERT_SIZEOF(struct vsu_sound_regs, 0x10);
	ASSERT_SIZEOF(vsu_regs, 0x80);
	mem_test_addr("S1INT", 0x01000400, 1, &(vsu_regs.vr_sounds[0].vsr_int));
	mem_test_addr("S2INT", 0x01000440, 1, &(vsu_regs.vr_sounds[1].vsr_int));
	mem_test_addr("S4FQH", 0x010004cc, 1, &(vsu_regs.vr_sounds[3].vsr_fqh));
	mem_test_addr("SSTOP", 0x01000580, 1, &(vsu_regs.vr_stop));
}

void
vsu_reset(void)
{
	vsu_buffer_tail = 0;
	vsu_buffer_head = 0;
	vsu_buffer_full = false;

	for (u_int sound = 0; sound < 6; ++sound)
	{
		vsu_states[sound].vs_started = false;
		vsu_regs.vr_sounds[sound].vsr_int.vi_start = 0;
	}
}

static void
vsu_sound_start(u_int sound)
{
	const struct vsu_sound_regs *vsr = vsu_regs.vr_sounds + sound;
	struct vsu_state *state = vsu_states + sound;

	if (!state->vs_started)
	{
		debug_tracef("vsu", "Starting SOUND%u", sound);
		state->vs_env_value = vsr->vsr_ev0.ve_init;
	}
	else
		debug_tracef("vsu", "Restarting SOUND%u", sound);

	state->vs_started = true;
	state->vs_freq_count = 0;
	state->vs_wave_index = 0;
#if 0
	state->vs_int_count = 0;
#endif // 0
	state->vs_env_count = 0;
}

static void
vsu_sound_stop(u_int sound)
{
	if (vsu_states[sound].vs_started)
	{
		debug_tracef("vsu", "Stopping SOUND%u", sound);
		vsu_states[sound].vs_started = false;
	}
}

void
vsu_samples_render(int16_t samples[][2], u_int num_samples)
{
	os_bzero(samples, sizeof(samples[0]) * num_samples);

	for (u_int sound = 0; sound < 6; ++sound)
	{
		struct vsu_state *state = vsu_states + sound;

		if (!state->vs_started)
			continue;

		const struct vsu_sound_regs *vsr = vsu_regs.vr_sounds + sound;
		const u_int8_t *vsu_wave = vsu_ram.vr_waves[vsr->vsr_ram.vr_addr];

		// TODO: Noise sound source

		u_int16_t freq_index = vsr->vsr_fql;
		freq_index|= vsr->vsr_fqh.vf_fqh << 8;
		u_int32_t freq_divider = vsu_sample_rate * (2048 - freq_index);

		for (u_int sample_index = 0; sample_index < num_samples; ++sample_index)
		{
			while (state->vs_freq_count > freq_divider)
			{
				state->vs_freq_count-= freq_divider;
				state->vs_wave_index = (state->vs_wave_index + 1) % 32;
			}

			int16_t wave = (vsu_wave[state->vs_wave_index] & 0b111111) - 32;

			state->vs_freq_count+= clock_freq;

			u_int8_t env = (vsu_env_enable) ? state->vs_env_value : 0xf;

			if (state->vs_env_count == vsr->vsr_ev0.ve_step)
			{
				if (vsr->vsr_ev0.ve_ud)
				{
					if (state->vs_env_value == 0xf)
					{
						if (vsr->vsr_ev1.ve_rs)
							state->vs_env_value = 0;
					}
					else
						++state->vs_env_value;
				}
				else
				{
					if (state->vs_env_value == 0)
					{
						if (vsr->vsr_ev1.ve_rs)
							state->vs_env_value = 0xf;
					}
					else
						--state->vs_env_value;
				}
				state->vs_env_count = 0;
			}
			else
				++state->vs_env_count;

			u_int8_t left_level = vsr->vsr_lrv.vl_llevel * env;
			if (left_level)
				left_level = (left_level >> 3) + 1;
			u_int8_t right_level = vsr->vsr_lrv.vl_rlevel * env;
			if (right_level)
				right_level = (right_level >> 3) + 1;

			int16_t left_sample = wave * left_level;
			int16_t right_sample = wave * right_level;

			assert(left_sample >= -1024 && left_sample <= 1023);
			assert((int32_t)left_sample * 0x20 <= INT16_MAX);
			assert((int32_t)left_sample * 0x20 >= INT16_MIN);
			assert(right_sample >= -1024 && right_sample <= 1023);
			assert((int32_t)right_sample * 0x20 <= INT16_MAX);
			assert((int32_t)right_sample * 0x20 >= INT16_MIN);

			if (!(vsu_sound_mask & (1u << sound)))
				continue;

			samples[sample_index][0]+= left_sample * 0x20;
			samples[sample_index][1]+= right_sample * 0x20;
		}
	}
}

void
vsu_step(void)
{
	if ((emu_usec % 10000) == 0)
	{
		u_int num_samples = 417;

		tk_audio_lock(); // TODO -- Use atomic circular buffer or double/triple buffer

		while (num_samples)
		{
			u_int end_pos;
			if (vsu_buffer_tail < vsu_buffer_head)
				end_pos = vsu_buffer_head;
			else if (vsu_buffer_tail > vsu_buffer_head || !vsu_buffer_full)
				end_pos = vsu_buffer_size;
			else
			{
				debug_printf("VSU buffer overrun--disabling audio");
				// TODO: Disable audio or adjust timing
				break;
			}

			u_int chunk_size = min_uint(end_pos - vsu_buffer_tail, num_samples);
			vsu_samples_render(vsu_buffer + vsu_buffer_tail, chunk_size);

			vsu_buffer_tail = (vsu_buffer_tail + chunk_size) % vsu_buffer_size;
			if (vsu_buffer_tail == vsu_buffer_head)
				vsu_buffer_full = true;

			num_samples-= chunk_size;
		}

		tk_audio_unlock();
	}
}

void
vsu_buffer_read(int16_t (*samples)[2], u_int count)
{
	while (count)
	{
		u_int end_pos;
		if (vsu_buffer_head < vsu_buffer_tail)
			end_pos = vsu_buffer_tail;
		else if (vsu_buffer_head > vsu_buffer_tail || vsu_buffer_full)
			end_pos = vsu_buffer_size;
		else
		{
			debug_printf("VSU buffer underrun--disabling audio\n");
			// TODO: Disable audio
			os_bzero(samples, count * sizeof(samples[0]));
			return;
		}

		u_int chunk_size = min_uint(end_pos - vsu_buffer_head, count);
		os_bcopy(vsu_buffer + vsu_buffer_head, samples, chunk_size * sizeof(vsu_buffer[0]));

		if (vsu_buffer_head == vsu_buffer_tail)
			vsu_buffer_full = false;
		vsu_buffer_head = (vsu_buffer_head + chunk_size) % vsu_buffer_size;

		samples+= chunk_size;
		count-= chunk_size;
	}
}

static float
vsu_sample_read(void *data, int index)
{
	u_int offset = (vsu_buffer_tail + index) % vsu_buffer_size;
	return (float)((int16_t *)data)[offset * 2];
}

void
vsu_frame_end(void)
{
	if (vsu_sounds_open)
	{
		igSetNextWindowSize((struct ImVec2){600, 0}, ImGuiCond_Once);
		if (igBegin("Sounds", &vsu_sounds_open, ImGuiWindowFlags_NoResize))
		{
			for (u_int sound = 0; sound < 6; ++sound)
			{
				u_int mask = 1u << sound;
				bool sound_enabled = ((vsu_sound_mask & mask) != 0);
				char id[32];
				os_snprintf(id, sizeof(id), "S%u", sound);
				igSameLine(0, -1);
				if (igCheckbox(id, &sound_enabled))
					vsu_sound_mask^= (1u << sound);
			}
			igSameLine(0, -1);
			igCheckbox("Env.", &vsu_env_enable);

			for (u_int sound = 0; sound < 6; ++sound)
			{
				char id[32];
				struct vsu_sound_regs *vsr = &(vsu_regs.vr_sounds[sound]);
				os_snprintf(id, sizeof(id), "SOUND%u", sound);
				char interval_s[16];
				if (vsr->vsr_int.vi_mode)
				{
					u_int int_index = vsr->vsr_int.vi_data;
					float interval = 1000.0 / (260.4 * (int_index + 1));
					os_snprintf(interval_s, sizeof(interval_s), "Int.: %.2f ms (%u)", interval, int_index);
				}
				else
					os_snprintf(interval_s, sizeof(interval_s), "Continuous");

				u_int16_t freq_index = vsr->vsr_fql;
				freq_index|= vsr->vsr_fqh.vf_fqh << 8;
				float freq = 5000000.0 / (2048 - freq_index);

				if (igTreeNodeExStr(id, ImGuiTreeNodeFlags_DefaultOpen, "%s%s %s, %.2f Hz (%u), R/L level %u/%u",
				                    id,
				                    (vsr->vsr_int.vi_start) ? " (STARTED)" : "(stopped)",
				                    interval_s,
				                    freq, freq_index,
				                    vsr->vsr_lrv.vl_rlevel,
				                    vsr->vsr_lrv.vl_llevel))
				{
					float envs[120];
					u_int8_t env = vsr->vsr_ev0.ve_init;
					u_int step_time = vsr->vsr_ev0.ve_step + 1;
					for (u_int i = 0; i < 120; ++i)
					{
						envs[i] = env;
						if (!step_time)
						{
							if (vsr->vsr_ev0.ve_ud)
							{
								if (env == 0xf)
								{
									if (vsr->vsr_ev1.ve_rs)
										env = 0;
								}
								else
									++env;
							}
							else
							{
								if (env == 0)
								{
									if (vsr->vsr_ev1.ve_rs)
										env = 0xf;
								}
								else
									--env;
							}
							step_time = vsr->vsr_ev0.ve_step;
						}
						else
							--step_time;
					}
					char overlay[32];
					os_snprintf(overlay, sizeof(overlay), "Init %u, Step %u %s, %s",
								vsr->vsr_ev0.ve_init,
								vsr->vsr_ev0.ve_step + 1,
								(vsr->vsr_ev0.ve_ud) ? "Up" : "Dn",
								(vsr->vsr_ev1.ve_rs) ? "R/S" : "No R/S");
					igPlotLines("Env.", envs, 120, 0, overlay, 0, 0xf, (struct ImVec2){240, 64}, sizeof(float));
					igSameLine(0, -1);
					igText("(%s)", (vsr->vsr_ev1.ve_on) ? "ON" : "OFF");

					u_int wave_addr = vsr->vsr_ram.vr_addr % 5;
					float wave[32];
					for (u_int i = 0; i < 32; ++i)
					{
						int8_t sample = (vsu_ram.vr_waves[wave_addr][i] & 0b111111) - 32;
						wave[i] = sample;
					}
					igSameLine(0, -1);
					os_snprintf(overlay, sizeof(overlay), "Waveform RAM %u", wave_addr);
					igPlotLines("Wave.",
					            wave,
					            32, 0,
					            overlay,
					            -32, 31,
					            (struct ImVec2){256, 64},
					            sizeof(float));

					igTreePop();
				}
			}
		}
		igEnd();
	}

	if (vsu_buffers_open)
	{
		if (igBegin("Audio Buffers", &vsu_buffers_open, 0))
		{
			for (u_int channel = 0; channel < 2; ++channel)
				igPlotLines2((channel == 0) ? "Left" : "Right",
				             vsu_sample_read,
				             vsu_buffer, vsu_buffer_size, channel * sizeof(vsu_buffer[0][0]),
				             NULL,
				             INT16_MIN, INT16_MAX,
				             (struct ImVec2){834, 128});
		}
		igEnd();
	}
}

bool
vsu_mem_prepare(struct mem_request *request)
{
	if (request->mr_size != 1)
	{
		static bool ignore_size = false;
		if (!debug_runtime_errorf(&ignore_size, "Invalid VSU access size %u @ 0x%08x\n",
		                          request->mr_size, request->mr_emu))
			return false;
		request->mr_size = 1;
	}

	// TODO: More granularity on perms
	if (request->mr_emu < 0x01000400)
	{
		if (request->mr_emu >= 0x01000300)
		{
			u_int32_t mirror = request->mr_emu & 0x010003ff;
			static bool always_ignore = false;
			if (!debug_runtime_errorf(&always_ignore, "Mirroring VSU RAM at 0x%08x -> 0x%x", request->mr_emu, mirror))
				return false;
			request->mr_emu = mirror;
		}

		request->mr_host = (u_int8_t *) &vsu_ram + ((request->mr_emu >> 2) & 0xff);
	}
	else if (request->mr_emu < 0x01000600)
		request->mr_host = (u_int8_t *)&vsu_regs + ((request->mr_emu >> 2) & 0x7f);
	else
	{
		if (!debug_runtime_errorf(NULL, "VSU bus error at 0x%08x\n", request->mr_emu))
			return false;

		static u_int32_t dummy;
		request->mr_host = &dummy;
	}

	return true;
}

void
vsu_mem_write(const struct mem_request *request, const void *src)
{
	u_int8_t value = *(u_int8_t *)src;
	*(u_int8_t *)request->mr_host = value;
	if ((request->mr_emu & 0b10000111111) == 0b10000000000)
	{
		u_int sound = (request->mr_emu >> 6) & 0b111;
		if (sound == 6)
		{
			// SSTOP
			if (value & 1)
			{
				for (u_int i = 0; i < 6; ++i)
					vsu_sound_stop(i);
			}
		}
		else
		{
			assert(sound < 6);
			// SxINT
			if (value & 0x80)
				vsu_sound_start(sound);
			else
				vsu_sound_stop(sound);
		}
	}
}

void
vsu_fini(void)
{
	// TODO
}
