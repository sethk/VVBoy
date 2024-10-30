#include "Types.hh"
#include "RingBuf.Gen.hh"
#include "OS.hh"
#include <climits>
#include <cassert>

#if INTERFACE
	struct ringbuf
	{
		void *rb_buffer;
		u_int rb_capacity, rb_head, rb_tail, rb_elem_size;
		bool rb_is_full;
	};
#endif // INTERFACE

void
ringbuf_init(struct ringbuf *rbp, void *buffer, size_t buf_size, size_t elem_size)
{
	assert(buf_size <= UINT_MAX);
	assert(elem_size <= UINT_MAX);
	rbp->rb_buffer = buffer;
	rbp->rb_capacity = buf_size / elem_size;
	rbp->rb_elem_size = elem_size;
	ringbuf_clear(rbp);
}

void
ringbuf_clear(struct ringbuf *rbp)
{
	rbp->rb_head = rbp->rb_tail = 0;
	rbp->rb_is_full = false;
}

u_int
ringbuf_get_avail(const struct ringbuf *rbp)
{
	if (rbp->rb_tail < rbp->rb_head)
		return rbp->rb_head - rbp->rb_tail;
	else if (rbp->rb_tail > rbp->rb_head)
		return (rbp->rb_capacity - rbp->rb_tail) + rbp->rb_head;
	else if (!rbp->rb_is_full)
		return rbp->rb_capacity;
	else
		return 0;
}

u_int
ringbuf_get_count(const struct ringbuf *rbp)
{
	if (rbp->rb_head < rbp->rb_tail)
		return rbp->rb_tail - rbp->rb_head;
	else if (rbp->rb_head > rbp->rb_tail)
		return (rbp->rb_capacity - rbp->rb_head) + rbp->rb_tail;
	else if (rbp->rb_is_full)
		return rbp->rb_capacity;
	else
		return 0;
}

u_int
ringbuf_write_contig(struct ringbuf *rbp, void **bufferp, u_int count, const char *trace_tag)
{
	assert(count <= rbp->rb_capacity);

	u_int chunk_size;
	if (rbp->rb_tail < rbp->rb_head)
		chunk_size = min_uint(rbp->rb_head - rbp->rb_tail, count);
	else if (rbp->rb_tail > rbp->rb_head || !rbp->rb_is_full)
		chunk_size = min_uint(rbp->rb_capacity - rbp->rb_tail, count);
	else
	{
		*bufferp = NULL;
		return 0;
	}

	if (trace_tag)
		debug_tracef(trace_tag, "Writing %u-%u", rbp->rb_tail, rbp->rb_tail + chunk_size);

	*bufferp = (char *)rbp->rb_buffer + rbp->rb_tail * rbp->rb_elem_size;
	rbp->rb_tail = (rbp->rb_tail + chunk_size) % rbp->rb_capacity;
	if (rbp->rb_tail == rbp->rb_head)
	{
		rbp->rb_is_full = true;

		if (trace_tag)
			debug_tracef(trace_tag, "Ring buffer full");
	}

	return chunk_size;
}

bool
ringbuf_write_elem(struct ringbuf *rbp, void *elem, const char *trace_tag)
{
	void *buffer;
	if (!ringbuf_write_contig(rbp, &buffer, 1, trace_tag))
		return false;

	os_bcopy(elem, buffer, rbp->rb_elem_size);
	return true;
}

u_int
ringbuf_read_copy(struct ringbuf *rbp, void *buffer, u_int count, const char *trace_tag)
{
	assert(count < rbp->rb_capacity);

	u_int num_copied = 0;
	while (count)
	{
		u_int chunk_size;
		if (rbp->rb_head < rbp->rb_tail)
			chunk_size = min_uint(rbp->rb_tail - rbp->rb_head, count);
		else if (rbp->rb_head > rbp->rb_tail || rbp->rb_is_full)
			chunk_size = min_uint(rbp->rb_capacity - rbp->rb_head, count);
		else
			break;

		if (trace_tag)
			debug_tracef(trace_tag, "Reading %u-%u", rbp->rb_head, rbp->rb_head + chunk_size);

		u_int byte_size = chunk_size * rbp->rb_elem_size;
		os_bcopy((char *)rbp->rb_buffer + rbp->rb_head * rbp->rb_elem_size, buffer, byte_size);
		buffer = (char *)buffer + byte_size;
		num_copied+= chunk_size;
		count-= chunk_size;

		rbp->rb_head = (rbp->rb_head + chunk_size) % rbp->rb_capacity;
		rbp->rb_is_full = false;
	}
	return num_copied;
}

u_int
ringbuf_elem_offset(const struct ringbuf *rbp, u_int index)
{
	return (rbp->rb_tail + index) % rbp->rb_capacity;
}

void *
ringbuf_elem_peek(const struct ringbuf *rbp, u_int index)
{
	u_int offset = ringbuf_elem_offset(rbp, index);
	return (char *)rbp->rb_buffer + offset * rbp->rb_elem_size;
}

u_int
ringbuf_discard(struct ringbuf *rbp, u_int count)
{
	assert(count < rbp->rb_capacity);

	u_int num_discard = 0;
	while (count)
	{
		u_int chunk_size;
		if (rbp->rb_head < rbp->rb_tail)
			chunk_size = min_uint(rbp->rb_tail - rbp->rb_head, count);
		else if (rbp->rb_head > rbp->rb_tail || rbp->rb_is_full)
			chunk_size = min_uint(rbp->rb_capacity - rbp->rb_head, count);
		else
			break;

		num_discard+= chunk_size;
		rbp->rb_head = (rbp->rb_head + chunk_size) % rbp->rb_capacity;
		rbp->rb_is_full = false;
	}
	return num_discard;
}
