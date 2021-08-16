#include "types.h"
#include "vsu_thread.h"
#include <assert.h>

#if INTERFACE
	struct vsu_thread_data
	{
		bool vtd_inited;
		struct ringbuf vtd_buffer;
		bool vtd_muted, vtd_output_muted;
		u_int vtd_error_count;
		char vtd_error_str[128 + 1];
	};
#endif // INTERFACE

enum vsu_thread_event
{
	VSU_EVENT_OUTPUT = EVENT_SUBSYS_BITS(EVENT_SUBSYS_VSU) | EVENT_WHICH_BITS(1),
	VSU_EVENT_UNDERFLOW = EVENT_SUBSYS_BITS(EVENT_SUBSYS_VSU) | EVENT_WHICH_BITS(2),
};

enum vsu_buffer_size { VSU_BUFFER_SIZE = 417 * 10 };
static const u_int vsu_low_watermark = 128;

static struct vsu_thread_data vsu_thread_data = { false };

enum vsu_fade_samples { VSU_FADE_SAMPLES = 150 };
static u_int16_t vsu_fade_env[VSU_FADE_SAMPLES];
enum vsu_fade_bits { VSU_FADE_BITS = 5 };
static const float vsu_fade_base = 0.9726f;

bool
vsu_thread_init(void)
{
	events_set_desc(VSU_EVENT_OUTPUT, "Output N=%u");
	events_set_desc(VSU_EVENT_UNDERFLOW, "Underflow N=%u");

	static int16_t vsu_samples[VSU_BUFFER_SIZE][2];
	ringbuf_init(&vsu_thread_data.vtd_buffer, vsu_samples, sizeof(vsu_samples), sizeof(vsu_samples[0]));

	static const u_int16_t amp = (1u << VSU_FADE_BITS);
	for (u_int fade_index = 0; fade_index < COUNT_OF(vsu_fade_env); ++fade_index)
		vsu_fade_env[fade_index] = lround(powf(vsu_fade_base, fade_index) * amp);

	vsu_thread_data.vtd_inited = true;
	return true;
}

void
vsu_thread_reset()
{
	tk_audio_lock();

	vsu_thread_data.vtd_output_muted = true;

	vsu_thread_data.vtd_error_count = 0;

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

void
vsu_thread_errorf(struct vsu_thread_data *vtd, const char *fmt, ...)
{
	vtd->vtd_muted = true;
	va_list ap;
	va_start(ap, fmt);
	if (vtd->vtd_error_count++ == 0)
		os_vsnprintf(vtd->vtd_error_str, sizeof(vtd->vtd_error_str), fmt, ap);
	debug_vprintf(fmt, ap);
	va_end(ap);
}

void
vsu_thread_set_muted(bool muted)
{
	tk_audio_lock();
	vsu_thread_data.vtd_muted = muted;
	tk_audio_unlock();
}

void
vsu_thread_read(struct vsu_thread_data *vtd, int16_t (*samples)[2], u_int count)
{
	u_int to_read;
	if (!vtd->vtd_muted)
	{
		if (!vtd->vtd_output_muted || ringbuf_get_count(&vtd->vtd_buffer) >= vsu_low_watermark)
			to_read = count;
		else
		{
			if (debug_trace_vsu_buf)
				debug_tracef("vsu.buf", "Waiting for buffer to hit low watermark");

			to_read = 0;
		}
	}
	else
	{
		if (!vtd->vtd_output_muted)
			to_read = VSU_FADE_SAMPLES;
		else
			to_read = 0;
	}

	u_int did_read = 0;
	if (to_read > 0)
	{
		enum event_subsys dummy_subsys;
		enum vsu_event dummy_event; // Hint for makeheaders

		did_read = ringbuf_read_copy(&vtd->vtd_buffer, samples, to_read, NULL);
		events_fire(VSU_EVENT_OUTPUT, did_read, 0);

		if (did_read < to_read)
		{
			if (!vtd->vtd_muted)
				vsu_thread_errorf(vtd, "The audio output could not be buffered in time."
					" Possibly the emulation speed is too slow to generate audio in real-time.");
		}

		// If we are state transitioning, fade in/out to avoid clicks
		if (vtd->vtd_output_muted != vtd->vtd_muted)
		{
			u_int fade_count = min_uint(did_read, VSU_FADE_SAMPLES);

			if (debug_trace_vsu_buf)
				debug_tracef("vsu.buf", "Output %s, fading %u samples", (vtd->vtd_muted) ? "muted" : "resumed", fade_count);

			int16_t (*fade_end)[2];
			int fade_index, fade_step;
			if (vtd->vtd_muted)
			{
				fade_end = samples + fade_count;
				fade_index = 0;
				fade_step = 1;
			}
			else
			{
				fade_end = samples + did_read;
				fade_index = VSU_FADE_SAMPLES - 1;
				fade_step = -1;
			}

			u_int denom = 0;
			for (int16_t (*fade_sample)[2] = fade_end - fade_count; fade_sample != fade_end; ++fade_sample)
			{
				assert(fade_index >= 0 && fade_index < VSU_FADE_SAMPLES);

				(*fade_sample)[0] = ((*fade_sample)[0] * vsu_fade_env[fade_index]) >> VSU_FADE_BITS;
				(*fade_sample)[1] = ((*fade_sample)[1] * vsu_fade_env[fade_index]) >> VSU_FADE_BITS;

				denom+= VSU_FADE_SAMPLES;
				while (denom > fade_count)
				{
					fade_index+= fade_step;
					denom-= fade_count;
				}
			}

			vtd->vtd_output_muted = vtd->vtd_muted;
		}
	}

	if (did_read < count)
		os_bzero(samples + did_read, (count - did_read) * sizeof(samples[0]));

	tk_audio_unlock();
}
