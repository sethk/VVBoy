#include "types.h"
#include "vsu.h"
#include <assert.h>
#define CIMGUI_DEFINE_ENUMS_AND_STRUCTS
#include <cimgui/cimgui.h>

struct vsu_ram
{
	u_int8_t vr_waves[5][32];
	u_int8_t vr_snd5mod[32];
	u_int8_t vr_rfu[64];
};

#pragma warning(1:4820)
__declspec(align(4)) struct vsu_regs
{
	struct vsu_sound_regs
	{
		struct
		{
			u_int8_t vi_data : 5 __attribute__((packed));
			u_int8_t vi_mode : 1 __attribute__((packed));
			u_int8_t vi_rfu1 : 1 __attribute__((packed));
			u_int8_t vi_start : 1 __attribute__((packed));
		} vsr_int;
		struct
		{
			u_int8_t vl_rlevel : 4 __attribute__((packed));
			u_int8_t vl_llevel : 4 __attribute__((packed));
		} vsr_lrv;
		u_int8_t vsr_fql;
		struct
		{
			u_int8_t vf_fqh : 3 __attribute__((packed));
			u_int8_t vf_rfu1 : 5 __attribute__((packed));
		} vsr_fqh;
		struct
		{
			u_int8_t ve_step : 3 __attribute__((packed));
			u_int8_t ve_ud : 1 __attribute__((packed));
			u_int8_t ve_init : 4 __attribute__((packed));
		} vsr_ev0;
		struct
		{
			u_int8_t ve_on : 1 __attribute__((packed));
			u_int8_t ve_rs : 1 __attribute__((packed));
			u_int8_t ve_rfu1 : 2 __attribute__((packed));
			u_int8_t ve_modswp : 1 __attribute__((packed));
			u_int8_t ve_short : 1 __attribute__((packed));
			u_int8_t ve_ed : 1 __attribute__((packed));
			u_int8_t ve_rfu2 : 1 __attribute__((packed));
		} vsr_ev1;
		struct
		{
			u_int8_t vr_addr : 3 __attribute__((packed));
			u_int8_t vr_rfu1 : 5 __attribute__((packed));
		} vsr_ram;
		struct
		{
			u_int8_t vs_shifts : 3 __attribute__((packed));
			u_int8_t vs_ud : 1 __attribute__((packed));
			u_int8_t vs_time : 3 __attribute__((packed));
			u_int8_t vs_clk : 1 __attribute__((packed));
		} vsr_swp;
		u_int32_t vsr_rfu[2];
	} vr_sounds[6];
	struct
	{
		u_int8_t vs_stop : 1 __attribute__((packed));
		u_int8_t vs_unused : 7 __attribute__((packed));
		u_int8_t vs_rfu1;
		u_int16_t vs_rfu;
	} vr_stop;
	u_int32_t vs_rfu[7];
};

bool vsu_sounds_open = false;
bool vsu_buffers_open = false;
static struct vsu_ram vsu_ram;
static struct vsu_regs vsu_regs;

static int16_t vsu_buffers[834][2];
static u_int vsu_buffer_tail;

static u_int8_t vsu_sound_mask = 0b1;
static struct vsu_state
{
	bool vs_started;
	u_int vs_freq_count;
	u_int vs_wave_index;
	u_int vs_int_count;
	u_int16_t vs_env_value;
	u_int vs_env_count;
} vsu_states[6];

bool
vsu_init(void)
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

	return true;
}

void
vsu_test(void)
{
	debug_printf("Running VSU self-test\n");
	assert_sizeof(vsu_ram, 0x100);
	mem_test_addr("S1INT", 0x01000400, 1, &(vsu_regs.vr_sounds[0].vsr_int));
	mem_test_addr("S2INT", 0x01000440, 1, &(vsu_regs.vr_sounds[1].vsr_int));
	mem_test_addr("S4FQH", 0x010004cc, 1, &(vsu_regs.vr_sounds[3].vsr_fqh));
	mem_test_addr("SSTOP", 0x01000580, 1, &(vsu_regs.vr_stop));
	assert_sizeof(vsu_regs, 0x80);
}

void
vsu_reset(void)
{
	vsu_buffer_tail = 0;

	for (u_int sound = 0; sound < 6; ++sound)
		vsu_states[sound].vs_started = false;
	// TODO
}

void
vsu_step(void)
{
	if ((main_usec % 10000) == 0)
	{
		tk_audio_lock(); // TODO -- Use atomic circular buffer

		for (u_int sample_index = 0; sample_index < 417; ++sample_index)
		{
			int16_t left_sample = 0, right_sample = 0;

			for (u_int sound = 0; sound < 6; ++sound)
			{
				if (!(vsu_sound_mask & (1u << sound)))
					continue;

				struct vsu_state *state = &(vsu_states[sound]);
				if (state->vs_started)
				{
					// TODO: Noise sound source

					const struct vsu_sound_regs *vsr = &(vsu_regs.vr_sounds[sound]);
					const u_int8_t *vsu_wave = vsu_ram.vr_waves[vsr->vsr_ram.vr_addr];
					int16_t sample = (vsu_wave[state->vs_wave_index] & 0b111111) - 32;
					sample*= state->vs_env_value;
					left_sample+= sample * vsr->vsr_lrv.vl_llevel;
					right_sample+= sample * vsr->vsr_lrv.vl_rlevel;
					assert(sample >= -1024 && sample <= 1023);
					assert((int32_t)sample * 0x40 <= INT16_MAX);
					assert((int32_t)sample * 0x40 >= INT16_MIN);

					state->vs_wave_index = (state->vs_wave_index + 1) % 32;
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
				}
			}

			vsu_buffers[vsu_buffer_tail][0] = left_sample * 0x20;
			vsu_buffers[vsu_buffer_tail][1] = right_sample * 0x20;

			if (++vsu_buffer_tail == 834)
				vsu_buffer_tail = 0;
		}

		tk_audio_unlock();
	}
}

void
vsu_read_samples(int16_t *samples, u_int count)
{
	(void)count;
	assert(count == 834);
	os_bcopy(vsu_buffers, samples, sizeof(vsu_buffers));
}

static float
vsu_sample_cvtf32(void *data, int index)
{
	return (float)((int16_t *)data)[index * 2];
}

void
vsu_frame_end(void)
{
	if (vsu_sounds_open)
	{
		igSetNextWindowSize((struct ImVec2){600, 0}, ImGuiCond_Once);
		if (igBegin("Sounds", &vsu_sounds_open, 0))
		{
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
				float freq = 5000000.0 / ((2048 - freq_index) * 32);

				if (igTreeNodeExStr(id, ImGuiTreeNodeFlags_DefaultOpen, "%s%s %s, %.2f Hz (%u), R/L level %u/%u",
				                    id,
				                    (vsr->vsr_int.vi_start) ? " (STARTED)" : "",
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
				             vsu_sample_cvtf32,
				             vsu_buffers, 834, channel * sizeof(vsu_buffers[0][0]),
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

static void
vsu_stop_sound(u_int sound)
{
	if (vsu_states[sound].vs_started)
		debug_tracef("vsu", "Stopping SOUND%u", sound);
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
					vsu_stop_sound(i);
			}
		}
		else
		{
			assert(sound < 6);
			// SxINT
			if (value & 0x80)
			{
				debug_tracef("vsu", "Starting SOUND%u", sound);
				const struct vsu_sound_regs *vsr = &(vsu_regs.vr_sounds[sound]);
				struct vsu_state *state = &(vsu_states[sound]);
				state->vs_started = true;
				state->vs_freq_count = 0;
				state->vs_wave_index = 0;
				state->vs_int_count = 0;
				state->vs_env_value = vsr->vsr_ev0.ve_init;
				state->vs_env_count = 0;
			}
			else
				vsu_stop_sound(sound);
		}
	}
}

void
vsu_fini(void)
{
	// TODO
}
