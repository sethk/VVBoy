#include "types.h"
#include "vsu_thread.h"
#include <assert.h>

#if INTERFACE
	struct vsu_thread_data
	{
		bool vtd_inited;
		struct ringbuf vtd_buffer;
		bool vtd_muted, vtd_output_muted;
	};
#endif // INTERFACE

static const u_int vsu_buffer_size = 417 * 10;
static const u_int vsu_low_watermark = 128;

static struct vsu_thread_data vsu_thread_data = { false };

static const u_int vsu_fade_samples = 150;
static u_int16_t vsu_fade_env[vsu_fade_samples];
static const u_int vsu_fade_bits = 5;
static const float vsu_fade_base = 0.9726f;

bool
vsu_thread_init(void)
{
	static int16_t vsu_samples[vsu_buffer_size][2];
	ringbuf_init(&vsu_thread_data.vtd_buffer, vsu_samples, sizeof(vsu_samples), sizeof(vsu_samples[0]));

	static const u_int16_t amp = (1u << vsu_fade_bits);
	for (u_int fade_index = 0; fade_index < vsu_fade_samples; ++fade_index)
		vsu_fade_env[fade_index] = lround(powf(vsu_fade_base, fade_index) * amp);

	vsu_thread_data.vtd_inited = true;
	return true;
}

void
vsu_thread_reset()
{
	tk_audio_lock();

	vsu_thread_data.vtd_output_muted = true;

	vsu_thread_data.vtd_underflow_count = 0;

	ringbuf_clear(&vsu_thread_data.vtd_buffer);

	tk_audio_unlock();
}

void
vsu_thread_fini(void)
{
	vsu_thread_data.vtd_inited = false;
}

struct vsu_thread_data *
vsu_thread_lock(void)
{
	tk_audio_lock();

	return &vsu_thread_data;
}

void
vsu_thread_unlock(struct vsu_thread_data **vtdp)
{
	assert(*vtdp == &vsu_thread_data);
	*vtdp = NULL;

	tk_audio_unlock();
}

// Main thread event handling:
void
vsu_thread_step()
{
	bool did_underflow = false;

	tk_audio_lock();

	if (vsu_thread_data.vtd_underflow_count)
	{
		vsu_thread_data.vtd_underflow_count = 0;
		did_underflow = true;
	}

	tk_audio_unlock();

	if (did_underflow)
	{
		// TODO: Show UI message
		os_runtime_error(OS_RUNERR_TYPE_WARNING,
				BIT(OS_RUNERR_RESP_OKAY),
				"Audio output error. The audio output could not be buffered in time."
				" Possibly the emulation speed is too slow to generate audio in real-time."
				" Sound has been muted.");
		//vsu_set_muted_by_user(true);
		vsu_set_muted_by_engine(true);
	}
}

void
vsu_thread_set_muted(bool muted)
{
	tk_audio_lock();
	vsu_thread_data.vtd_muted = muted;
	tk_audio_unlock();
}

void
vsu_thread_read(int16_t (*samples)[2], u_int count)
{
	tk_audio_lock();

	u_int to_read;
	if (!vsu_thread_data.vtd_muted)
	{
		if (!vsu_thread_data.vtd_output_muted || ringbuf_get_count(&vsu_thread_data.vtd_buffer) >= vsu_low_watermark)
			to_read = count;
		else
		{
			if (debug_trace_vsu_buf)
				debug_tracef("vsu.buf", "Waiting for buffer to hit low watermark\n");

			to_read = 0;
		}
	}
	else
	{
		if (!vsu_thread_data.vtd_output_muted)
			to_read = vsu_fade_samples;
		else
			to_read = 0;
	}

	u_int did_read = 0;
	if (to_read > 0)
	{
		enum event_subsys dummy_subsys;
		enum vsu_event dummy_event; // Hint for makeheaders

		did_read = ringbuf_read_copy(&vsu_thread_data.vtd_buffer, samples, to_read, NULL);
		events_fire(VSU_EVENT_OUTPUT, did_read, 0);

		if (did_read < to_read)
		{
			if (!vsu_muted)
			{
				++vsu_thread_data.vtd_underflow_count;
				debug_printf("VSU buffer underflow--muting audio\n");
			}
		}

		// If we are state transitioning, fade in/out to avoid clicks
		if (vsu_output_muted != vsu_muted)
		{
			u_int fade_count = min_uint(did_read, vsu_fade_samples);

			if (debug_trace_vsu_buf)
				debug_tracef("vsu.buf", "Output %s, fading %u samples\n", (vsu_muted) ? "muted" : "resumed", fade_count);

			int16_t (*fade_end)[2];
			int fade_index, fade_step;
			if (vsu_muted)
			{
				fade_end = samples + fade_count;
				fade_index = 0;
				fade_step = 1;
			}
			else
			{
				fade_end = samples + did_read;
				fade_index = vsu_fade_samples - 1;
				fade_step = -1;
			}

			u_int denom = 0;
			for (int16_t (*fade_sample)[2] = fade_end - fade_count; fade_sample != fade_end; ++fade_sample)
			{
				assert(fade_index >= 0 && fade_index < (int)vsu_fade_samples);

				(*fade_sample)[0] = ((*fade_sample)[0] * vsu_fade_env[fade_index]) >> vsu_fade_bits;
				(*fade_sample)[1] = ((*fade_sample)[1] * vsu_fade_env[fade_index]) >> vsu_fade_bits;

				denom+= vsu_fade_samples;
				while (denom > fade_count)
				{
					fade_index+= fade_step;
					denom-= fade_count;
				}
			}

			vsu_output_muted = vsu_muted;
		}
	}

	if (did_read < count)
		os_bzero(samples + did_read, (count - did_read) * sizeof(samples[0]));

	tk_audio_unlock();
}
