// SPDX-License-Identifier: GPL-2.0
/*
 * Regression test for the RISC-V perf user-stack copy taken in SSE
 * (NMI-like) context.
 *
 * On RISC-V, PMU overflow interrupts can be delivered through the SBI
 * Supervisor Software Events (SSE) mechanism. A perf event that samples the
 * raw user stack (PERF_SAMPLE_STACK_USER, as perf record --call-graph dwarf
 * does) then copies a large chunk of the interrupted task's user stack from
 * that context. If that copy is allowed to take a nested page fault it can
 * corrupt the interrupted task's kernel state and hang or crash the machine
 * under load.
 *
 * This test exercises that exact path:
 *   - It opens a sampling hardware PMU event with PERF_SAMPLE_STACK_USER.
 *   - It samples a child running on a controlled user stack followed by an
 *     inaccessible page, so the copy must truncate at that page boundary.
 *   - It checks that every user-stack sample record is well formed and that
 *     the dumped size never exceeds the requested size (i.e. the copy stops
 *     cleanly rather than faulting on).
 *   - It then drives a multi-threaded unix-socket + deep-recursion workload
 *     under high-frequency per-CPU sampling and requires every active sampler
 *     to make progress without taking the machine down.
 *
 * The test is architecture independent in what it drives; it is placed under
 * the RISC-V SSE selftests because SSE delivery is the RISC-V-specific
 * condition it is meant to protect.
 */
#define _GNU_SOURCE

#include <errno.h>
#include <poll.h>
#include <sched.h>
#include <signal.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

#include <linux/perf_event.h>
#include <pthread.h>
#include <sys/ioctl.h>
#include <sys/mman.h>
#include <sys/socket.h>
#include <sys/syscall.h>
#include <sys/wait.h>

#include "../../kselftest.h"

#ifndef noinline
#define noinline __attribute__((noinline))
#endif

#define STACK_DUMP_SIZE		8192		/* 8 KiB, 8-byte aligned */
#define RB_DATA_PAGES		64		/* power of two */
#define SELF_SAMPLE_FREQ	4000
#define STRESS_SAMPLE_FREQ	5000
#define STRESS_SECONDS		5
#define RECURSE_DEPTH		512
#define TRUNCATION_RUN_MS	250

static long page_size;

static int perf_event_open(struct perf_event_attr *attr, pid_t pid, int cpu,
			   int group_fd, unsigned long flags)
{
	return syscall(__NR_perf_event_open, attr, pid, cpu, group_fd, flags);
}

/* Prevent the compiler from optimizing away a stack buffer. */
static void keep_alive(void *p)
{
	__asm__ __volatile__("" : : "r"(p) : "memory");
}

/*
 * Consume a deep user stack and keep it live, so a raw user-stack sample has
 * many pages to copy. Returns a value derived from the stack so the compiler
 * cannot elide the frames.
 */
static noinline unsigned long burn_stack(int depth, unsigned long *sink)
{
	unsigned long frame[32];
	unsigned int i;

	for (i = 0; i < ARRAY_SIZE(frame); i++)
		frame[i] = (unsigned long)depth * i + *sink;

	if (depth > 0)
		frame[depth & 31] += burn_stack(depth - 1, sink);

	for (i = 0; i < ARRAY_SIZE(frame); i++)
		*sink += frame[i];

	keep_alive(frame);
	return *sink;
}

static struct perf_event_attr sampling_attr(unsigned long freq)
{
	struct perf_event_attr attr = {
		.type		= PERF_TYPE_HARDWARE,
		.size		= sizeof(attr),
		.config		= PERF_COUNT_HW_INSTRUCTIONS,
		.sample_type	= PERF_SAMPLE_STACK_USER,
		.sample_stack_user = STACK_DUMP_SIZE,
		.freq		= 1,
		.sample_freq	= freq,
		.disabled	= 1,
		.exclude_kernel	= 1,
		.exclude_hv	= 1,
	};

	return attr;
}

static bool open_skip_reason(int err, const char **why)
{
	switch (err) {
	case EACCES:
	case EPERM:
		*why = "insufficient privilege for PMU sampling (perf_event_paranoid)";
		return true;
	case ENOENT:
	case ENODEV:
	case EOPNOTSUPP:
		*why = "hardware PMU sampling event not available";
		return true;
	default:
		return false;
	}
}

static bool pmu_sse_route_testable(const char **why)
{
	char *line = NULL;
	size_t line_size = 0;
	FILE *interrupts;
	bool testable = true;

	interrupts = fopen("/proc/interrupts", "re");
	if (!interrupts) {
		*why = "cannot inspect the active PMU delivery route";
		return false;
	}

	/* The SBI PMU driver registers this name only for ordinary IRQ delivery. */
	while (getline(&line, &line_size, interrupts) >= 0) {
		if (strstr(line, "riscv-pmu")) {
			*why = "ordinary RISC-V PMU IRQ delivery is active";
			testable = false;
			break;
		}
	}

	free(line);
	fclose(interrupts);
	return testable;
}

static bool ring_copy_from(void *dst, const void *rb, size_t rb_bytes,
			   uint64_t pos, size_t size)
{
	size_t offset = pos % rb_bytes;
	size_t first;

	if (size > rb_bytes)
		return false;

	first = size < rb_bytes - offset ? size : rb_bytes - offset;
	memcpy(dst, (const char *)rb + offset, first);
	if (first != size)
		memcpy((char *)dst + first, rb, size - first);

	return true;
}

static int truncation_child(void *arg)
{
	int ready_fd = (intptr_t)arg;
	char ready = 1;

	if (write(ready_fd, &ready, sizeof(ready)) != 1)
		return 1;

	for (;;)
		__asm__ __volatile__("" : : : "memory");
}

static pid_t start_truncation_child(void **stack_mapping)
{
	struct pollfd pfd = { .events = POLLIN };
	size_t mapping_size = 2 * page_size;
	char ready;
	void *stack;
	pid_t pid;
	int pipefd[2];
	int saved_errno;

	stack = mmap(NULL, mapping_size, PROT_NONE,
		     MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
	if (stack == MAP_FAILED)
		return -1;
	if (mprotect(stack, page_size, PROT_READ | PROT_WRITE))
		goto err_unmap;
	if (pipe(pipefd))
		goto err_unmap;

	/* clone() starts the child below the inaccessible second page. */
	pid = clone(truncation_child, (char *)stack + page_size, SIGCHLD,
		    (void *)(intptr_t)pipefd[1]);
	if (pid < 0)
		goto err_pipe;

	close(pipefd[1]);
	pfd.fd = pipefd[0];
	if (poll(&pfd, 1, 1000) != 1 ||
	    read(pipefd[0], &ready, sizeof(ready)) != sizeof(ready)) {
		saved_errno = ETIMEDOUT;
		kill(pid, SIGKILL);
		waitpid(pid, NULL, 0);
		close(pipefd[0]);
		errno = saved_errno;
		goto err_unmap;
	}
	close(pipefd[0]);

	*stack_mapping = stack;
	return pid;

err_pipe:
	saved_errno = errno;
	close(pipefd[0]);
	close(pipefd[1]);
	errno = saved_errno;
err_unmap:
	saved_errno = errno;
	munmap(stack, mapping_size);
	errno = saved_errno;
	return -1;
}

static void stop_truncation_child(pid_t pid, void *stack_mapping)
{
	kill(pid, SIGKILL);
	while (waitpid(pid, NULL, 0) < 0 && errno == EINTR)
		;
	munmap(stack_mapping, 2 * page_size);
}

/*
 * Subtest 1: sample a child whose stack is followed by an inaccessible page.
 * Every record must be well formed and at least one stack copy must truncate
 * at the controlled page boundary rather than fault or overrun.
 */
static void test_ustack_records_wellformed(void)
{
	struct perf_event_attr attr = sampling_attr(SELF_SAMPLE_FREQ);
	size_t rb_bytes = (size_t)RB_DATA_PAGES * page_size;
	struct perf_event_mmap_page *meta;
	unsigned long samples = 0, truncated = 0;
	void *child_stack;
	const char *why;
	void *rb;
	pid_t child;
	int fd;

	child = start_truncation_child(&child_stack);
	if (child < 0) {
		ksft_test_result_fail("ustack records: create guarded stack child: %s\n",
				      strerror(errno));
		return;
	}

	fd = perf_event_open(&attr, child, -1, -1, PERF_FLAG_FD_CLOEXEC);
	if (fd < 0) {
		if (open_skip_reason(errno, &why))
			ksft_test_result_skip("ustack records: %s\n", why);
		else
			ksft_test_result_fail("ustack records: perf_event_open: %s\n",
					      strerror(errno));
		goto out_child;
	}

	meta = mmap(NULL, page_size + rb_bytes, PROT_READ | PROT_WRITE,
		    MAP_SHARED, fd, 0);
	if (meta == MAP_FAILED) {
		ksft_test_result_fail("ustack records: mmap ring buffer: %s\n",
				      strerror(errno));
		close(fd);
		goto out_child;
	}
	rb = (char *)meta + page_size;

	ioctl(fd, PERF_EVENT_IOC_RESET, 0);
	ioctl(fd, PERF_EVENT_IOC_ENABLE, 0);
	usleep(TRUNCATION_RUN_MS * 1000);
	ioctl(fd, PERF_EVENT_IOC_DISABLE, 0);

	/* Drain the ring buffer and validate every SAMPLE record. */
	{
		uint64_t head = __atomic_load_n(&meta->data_head, __ATOMIC_ACQUIRE);
		uint64_t tail = meta->data_tail;
		bool ok = true;

		if (head < tail || head - tail > rb_bytes)
			ok = false;

		while (ok && tail < head) {
			struct perf_event_header hdr;
			uint64_t available = head - tail;

			if (available < sizeof(hdr) ||
			    !ring_copy_from(&hdr, rb, rb_bytes, tail, sizeof(hdr)) ||
			    hdr.size < sizeof(hdr) || hdr.size > available ||
			    hdr.size > rb_bytes) {
				ok = false;
				break;
			}

			if (hdr.type == PERF_RECORD_SAMPLE) {
				uint64_t dump_size, dyn_size;
				size_t cursor = sizeof(hdr);

				if (sizeof(dump_size) > hdr.size - cursor ||
				    !ring_copy_from(&dump_size, rb, rb_bytes,
						    tail + cursor, sizeof(dump_size)) ||
				    dump_size > STACK_DUMP_SIZE) {
					ok = false;
					break;
				}
				cursor += sizeof(dump_size);
				samples++;
				if (dump_size) {
					/* data blob then trailing dynamic size */
					if (dump_size > hdr.size - cursor) {
						ok = false;
						break;
					}
					cursor += dump_size;
					if (sizeof(dyn_size) > hdr.size - cursor ||
					    !ring_copy_from(&dyn_size, rb, rb_bytes,
							    tail + cursor,
							    sizeof(dyn_size))) {
						ok = false;
						break;
					}
					if (dyn_size > dump_size) {
						ok = false;
						break;
					}
					if (dyn_size < dump_size)
						truncated++;
				}
			}
			tail += hdr.size;
		}
		__atomic_store_n(&meta->data_tail, head, __ATOMIC_RELEASE);

		if (!ok)
			ksft_test_result_fail("ustack records: malformed sample record\n");
		else if (samples == 0)
			ksft_test_result_skip("ustack records: no samples collected\n");
		else if (truncated == 0)
			ksft_test_result_fail("ustack records: no guarded-stack truncation\n");
		else
			ksft_test_result_pass("ustack records: %lu samples, %lu truncated\n",
					      samples, truncated);
	}

	munmap(meta, page_size + rb_bytes);
	close(fd);
out_child:
	stop_truncation_child(child, child_stack);
}

/* ---- Subtest 2: multi-threaded per-CPU sampling stress ---- */

struct stress_thread {
	pthread_t tid;
	int cpu;
	int *stop;
	int fd;
	void *rb;
	size_t rb_bytes;
};

static void *stress_worker(void *arg)
{
	struct stress_thread *st = arg;
	unsigned long sink = 1;
	int sv[2];
	char buf[64];

	if (socketpair(AF_UNIX, SOCK_STREAM, 0, sv) == 0) {
		while (!__atomic_load_n(st->stop, __ATOMIC_RELAXED)) {
			/* unix-socket ping-pong: takes the socket locks the
			 * original bug corrupted, while sampling nests.
			 */
			if (write(sv[0], buf, sizeof(buf)) > 0)
				(void)read(sv[1], buf, sizeof(buf));
			burn_stack(RECURSE_DEPTH, &sink);
			/* Periodically consume the ring buffer so sampling
			 * keeps delivering rather than filling up and stopping.
			 */
			if (st->rb) {
				struct perf_event_mmap_page *m = st->rb;
				uint64_t h = __atomic_load_n(&m->data_head,
							     __ATOMIC_ACQUIRE);
				__atomic_store_n(&m->data_tail, h,
						 __ATOMIC_RELEASE);
			}
		}
		close(sv[0]);
		close(sv[1]);
	}

	return (void *)sink;
}

static void test_sse_stress_no_crash(void)
{
	struct perf_event_attr attr = sampling_attr(STRESS_SAMPLE_FREQ);
	size_t rb_bytes = (size_t)RB_DATA_PAGES * page_size;
	struct stress_thread *threads;
	cpu_set_t available;
	long progressed = 0;
	int stop = 0;
	const char *why = NULL;
	long started = 0;
	long nproc;
	long slot;
	int cpu;

	if (sched_getaffinity(0, sizeof(available), &available)) {
		ksft_test_result_fail("sse stress: sched_getaffinity: %s\n",
				      strerror(errno));
		return;
	}
	nproc = CPU_COUNT(&available);
	if (nproc < 1) {
		ksft_test_result_skip("sse stress: no available CPUs\n");
		return;
	}

	threads = calloc(nproc, sizeof(*threads));
	if (!threads) {
		ksft_test_result_fail("sse stress: out of memory\n");
		return;
	}

	slot = 0;
	for (cpu = 0; cpu < CPU_SETSIZE; cpu++) {
		struct stress_thread *st;
		pthread_attr_t thread_attr;
		cpu_set_t set;
		void *map;
		int ret;

		if (!CPU_ISSET(cpu, &available))
			continue;
		st = &threads[slot++];

		st->fd = -1;
		st->cpu = cpu;
		st->stop = &stop;
		st->rb_bytes = rb_bytes;
		st->fd = perf_event_open(&attr, -1, cpu, -1,
					 PERF_FLAG_FD_CLOEXEC);
		if (st->fd < 0) {
			if (!started && open_skip_reason(errno, &why))
				break;
			continue;
		}

		map = mmap(NULL, page_size + rb_bytes, PROT_READ | PROT_WRITE,
			   MAP_SHARED, st->fd, 0);
		if (map == MAP_FAILED) {
			close(st->fd);
			st->fd = -1;
			continue;
		}
		st->rb = map;

		CPU_ZERO(&set);
		CPU_SET(cpu, &set);
		pthread_attr_init(&thread_attr);
		ret = pthread_attr_setaffinity_np(&thread_attr, sizeof(set), &set);
		if (!ret)
			ret = pthread_create(&st->tid, &thread_attr,
					     stress_worker, st);
		pthread_attr_destroy(&thread_attr);

		if (ret) {
			munmap(st->rb, page_size + rb_bytes);
			close(st->fd);
			st->rb = NULL;
			st->fd = -1;
			continue;
		}

		ioctl(st->fd, PERF_EVENT_IOC_RESET, 0);
		ioctl(st->fd, PERF_EVENT_IOC_ENABLE, 0);
		started++;
	}

	if (started == 0) {
		free(threads);
		if (why)
			ksft_test_result_skip("sse stress: %s\n", why);
		else
			ksft_test_result_skip("sse stress: could not start any sampler\n");
		return;
	}

	sleep(STRESS_SECONDS);
	__atomic_store_n(&stop, 1, __ATOMIC_RELAXED);

	for (slot = 0; slot < nproc; slot++) {
		struct stress_thread *st = &threads[slot];
		struct perf_event_mmap_page *meta;

		if (st->fd < 0)
			continue;
		pthread_join(st->tid, NULL);
		ioctl(st->fd, PERF_EVENT_IOC_DISABLE, 0);
		meta = st->rb;
		if (__atomic_load_n(&meta->data_head, __ATOMIC_ACQUIRE))
			progressed++;
		munmap(st->rb, page_size + rb_bytes);
		close(st->fd);
	}

	free(threads);
	if (progressed != started)
		ksft_test_result_fail("sse stress: %ld/%ld samplers made progress\n",
				      progressed, started);
	else
		ksft_test_result_pass("sse stress: %ld samplers x %ds made progress\n",
				      started, STRESS_SECONDS);
}

int main(void)
{
	const char *why;

	page_size = sysconf(_SC_PAGESIZE);

	ksft_print_header();
	ksft_set_plan(2);
	if (!pmu_sse_route_testable(&why)) {
		ksft_test_result_skip("ustack records: %s\n", why);
		ksft_test_result_skip("sse stress: %s\n", why);
		ksft_finished();
	}

	test_ustack_records_wellformed();
	test_sse_stress_no_crash();

	ksft_finished();
}
