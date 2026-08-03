// SPDX-License-Identifier: GPL-2.0-only
/*
 * Copyright (C) 2026 Qualcomm Technologies, Inc.
 *
 * Author: Himanshu Chauhan <himanshu.chauhan@oss.qualcomm.com>
 */

#define _GNU_SOURCE
#include <linux/perf_event.h>    /* Definition of PERF_* constants */
#include <linux/hw_breakpoint.h> /* Definition of HW_* constants */
#include <sys/syscall.h>         /* Definition of SYS_* constants */
#include <asm/ptrace.h>
#include <unistd.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/ioctl.h>
#include <time.h>
#include <fcntl.h>
#include <signal.h>
#include <sys/mman.h>
#include <sys/ptrace.h>
#include <sys/wait.h>
#include <string.h>
#include <semaphore.h>
#include <errno.h>
#include <stdint.h>
#include <stddef.h>
#include <linux/elf.h>

#ifndef noinline
#define noinline __attribute__((noinline))
#endif

#include "kselftest.h"

static int test_func_sink;

/*
 * Keep a real instruction address for HW execute breakpoints: prevent inlining
 * and force a visible side effect so the function can't be optimized away.
 */
static noinline void test_func(void)
{
	test_func_sink++;
	__asm__ __volatile__("" : : "g" (test_func_sink));
}

/*
 * BREAKPOINT TEST USING PTRACE
 */
static int do_wp_child(void *addr, size_t size)
{
	if (ptrace(PTRACE_TRACEME, 0, NULL, NULL) != 0) {
		ksft_print_msg(
			       "ptrace(PTRACE_TRACEME) failed: %s\n",
			       strerror(errno));
		_exit(1);
	}

	if (raise(SIGSTOP) != 0) {
		ksft_print_msg(
			       "raise(SIGSTOP) failed: %s\n", strerror(errno));
		_exit(1);
	}

	sleep(1);
	switch (size) {
	case 1:
		*(uint8_t *)addr = 47;
		break;
	case 2:
		*(uint16_t *)addr = 47;
		break;
	case 4:
		*(uint32_t *)addr = 47;
		break;
	case 8:
		*(uint64_t *)addr = 47;
		break;
	default:
		ksft_print_msg("Unknown watchpoint access size %u\n", size);
		break;
	}

	_exit(0);
}

static int do_bp_child(void (*bp_func)(void))
{
	if (ptrace(PTRACE_TRACEME, 0, NULL, NULL) != 0) {
		ksft_print_msg(
			       "ptrace(PTRACE_TRACEME) failed: %s\n",
			       strerror(errno));
		_exit(1);
	}

	if (raise(SIGSTOP) != 0) {
		ksft_print_msg(
			       "raise(SIGSTOP) failed: %s\n", strerror(errno));
		_exit(1);
	}

	bp_func();
}

unsigned long var;

static bool set_watchpoint(pid_t pid, int size)
{
	uint8_t *addr = (uint8_t *)&var;
	unsigned int control = 0;
	struct user_hwdebug_state dreg_state;
	struct iovec iov;

	/* Write watchpoint */
	control = (HW_BREAKPOINT_W << 14) & ((0x7 << 14));
	control |= (HW_BREAKPOINT_LEN_8 << 4) & ((0x1f << 4));
	memset(&dreg_state, 0, sizeof(dreg_state));
	dreg_state.dbg_regs[0].addr = (uintptr_t)(addr);
	dreg_state.dbg_regs[0].control = control;
	iov.iov_base = &dreg_state;
	iov.iov_len = offsetof(struct user_hwdebug_state, dbg_regs) +
				sizeof(dreg_state.dbg_regs[0]);

	if (ptrace(PTRACE_SETREGSET, pid, NT_RISCV_HW_WATCH, &iov) == 0) {
		memset(&iov, 0, sizeof(iov));
		memset(&dreg_state, 0, sizeof(dreg_state));

		iov.iov_base = &dreg_state;
		iov.iov_len = offsetof(struct user_hwdebug_state, dbg_regs) +
			sizeof(dreg_state.dbg_regs[0]);

		if (ptrace(PTRACE_GETREGSET, pid, NT_RISCV_HW_WATCH, &iov) == 0) {
			ksft_print_msg(
				       "ptrace(PTRACE_GETREGSET): Number of watchpoints: %u\n", dreg_state.info);
			ksft_print_msg(
				       "ptrace(PTRACE_GETREGSet): addr: 0x%lx control: 0x%x\n", dreg_state.dbg_regs[0].addr, dreg_state.dbg_regs[0].control);
		} else {
			ksft_print_msg(
				       "ptrace(PTRACE_GETREGSET): Failed\n");
			return false;
		}

		return true;
	}

	if (errno == EIO)
		ksft_print_msg(
			       "ptrace(PTRACE_SETREGSET, NT_RISCV_HW_WATCH) not supported on this hardware: %s\n",
			       strerror(errno));
	else
		ksft_print_msg(
			       "ptrace(PTRACE_SETREGSET, NT_RISCV_HW_WATCH) failed: %s\n",
			       strerror(errno));
	return false;
}

static bool set_breakpoint(pid_t pid, void (*bp_func)(void))
{
	struct user_hwdebug_state dreg_state;
	struct iovec iov;
	unsigned int control = 0;

	control = (HW_BREAKPOINT_X << 14) & ((0x7 << 14));
	control |= (HW_BREAKPOINT_LEN_8 << 4) & ((0x1f << 4));
	memset(&dreg_state, 0, sizeof(dreg_state));
	dreg_state.dbg_regs[0].addr = (uintptr_t)bp_func;
	dreg_state.dbg_regs[0].control = control;
	iov.iov_base = &dreg_state;
	iov.iov_len = offsetof(struct user_hwdebug_state, dbg_regs) + sizeof(dreg_state.dbg_regs[0]);

	if (ptrace(PTRACE_SETREGSET, pid, NT_RISCV_HW_BREAK, &iov) == 0)
		return true;

	if (errno == EIO)
		ksft_print_msg(
			       "ptrace(PTRACE_SETREGSET, NT_RISCV_HW_BREAK) not supported on this hardware: %s\n", strerror(errno));
	else
		ksft_print_msg(
			       "ptrace(PTRACE_SETREGSET, NT_RISCV_HW_BREAK) failed: %s\n", strerror(errno));

	return false;
}

static int run_ptrace_wp_test(void)
{
	pid_t pid = fork();
	pid_t wpid;
	siginfo_t siginfo;
	int status;

	if (pid == 0)
		do_wp_child(&var, 8);

	wpid = waitpid(pid, &status, __WALL);
	if (wpid != pid) {
		ksft_print_msg(
			"waitpid() failed: %s\n", strerror(errno));
		return false;
	}
	if (!WIFSTOPPED(status)) {
		ksft_print_msg(
			"child did not stop: %s\n", strerror(errno));
		return false;
	}
	if (WSTOPSIG(status) != SIGSTOP) {
		ksft_print_msg("child did not stop with SIGSTOP\n");
		return false;
	}

	if (!set_watchpoint(pid, 8))
		return false;

	if (ptrace(PTRACE_CONT, pid, NULL, NULL) < 0) {
		ksft_print_msg(
			"ptrace(PTRACE_CONT) failed: %s\n",
			strerror(errno));
		return false;
	}

	alarm(3);
	wpid = waitpid(pid, &status, __WALL);
	if (wpid != pid) {
		ksft_print_msg(
			"waitpid() failed: %s\n", strerror(errno));
		return false;
	}
	alarm(0);
	if (WIFEXITED(status)) {
		ksft_print_msg("child exited prematurely\n");
		return false;
	}
	if (!WIFSTOPPED(status)) {
		ksft_print_msg("child did not stop\n");
		return false;
	}
	if (WSTOPSIG(status) != SIGTRAP) {
		ksft_print_msg("child did not stop with SIGTRAP\n");
		return false;
	}
	if (ptrace(PTRACE_GETSIGINFO, pid, NULL, &siginfo) != 0) {
		ksft_print_msg(
			"ptrace(PTRACE_GETSIGINFO): %s\n",
			strerror(errno));
		return false;
	}
	if (siginfo.si_code != TRAP_HWBKPT) {
		ksft_print_msg(
			"Unexpected si_code %d\n", siginfo.si_code);
		return false;
	}

	kill(pid, SIGKILL);
	wpid = waitpid(pid, &status, 0);
	if (wpid != pid) {
		ksft_print_msg(
			"waitpid() failed: %s\n", strerror(errno));
		return false;
	}

	ksft_print_msg("[ptrace]: Watchpoint test passed!\n");

	return true;
}

static int run_ptrace_bp_test(void)
{
	pid_t pid = fork();
	pid_t wpid;
	siginfo_t siginfo;
	int status;

	if (pid == 0)
		do_bp_child(test_func);

	wpid = waitpid(pid, &status, __WALL);
	if (wpid != pid) {
		ksft_print_msg(
			"waitpid() failed: %s\n", strerror(errno));
		return false;
	}
	if (!WIFSTOPPED(status)) {
		ksft_print_msg(
			"child did not stop: %s\n", strerror(errno));
		return false;
	}
	if (WSTOPSIG(status) != SIGSTOP) {
		ksft_print_msg("child did not stop with SIGSTOP\n");
		return false;
	}

	if (!set_breakpoint(pid, test_func))
		return false;

	if (ptrace(PTRACE_CONT, pid, NULL, NULL) < 0) {
		ksft_print_msg(
			"ptrace(PTRACE_CONT) failed: %s\n",
			strerror(errno));
		return false;
	}

	alarm(3);
	wpid = waitpid(pid, &status, __WALL);
	if (wpid != pid) {
		ksft_print_msg(
			"waitpid() failed: %s\n", strerror(errno));
		return false;
	}
	alarm(0);
	if (WIFEXITED(status)) {
		ksft_print_msg("child exited prematurely\n");
		return false;
	}
	if (!WIFSTOPPED(status)) {
		ksft_print_msg("child did not stop\n");
		return false;
	}
	if (WSTOPSIG(status) != SIGTRAP) {
		ksft_print_msg("child did not stop with SIGTRAP\n");
		return false;
	}
	if (ptrace(PTRACE_GETSIGINFO, pid, NULL, &siginfo) != 0) {
		ksft_print_msg(
			"ptrace(PTRACE_GETSIGINFO): %s\n",
			strerror(errno));
		return false;
	}
	if (siginfo.si_code != TRAP_HWBKPT) {
		ksft_print_msg(
			"Unexpected si_code %d\n", siginfo.si_code);
		return false;
	}

	kill(pid, SIGKILL);
	wpid = waitpid(pid, &status, 0);
	if (wpid != pid) {
		ksft_print_msg(
			"waitpid() failed: %s\n", strerror(errno));
		return false;
	}

	ksft_print_msg("[ptrace]: Breakpoint test passed!\n");

	return true;
}

/*
 * BREAKPOINT TEST USING PTRACE_SETHBPREGS / PTRACE_GETHBPREGS
 */
static bool set_hbpregs_watchpoint(pid_t pid)
{
	struct __riscv_hwdebug_state state;

	memset(&state, 0, sizeof(state));
	state.addr = (unsigned long)&var;
	state.len  = HW_BREAKPOINT_LEN_8;
	state.type = HW_BREAKPOINT_W;
	state.ctrl = 0; /* enabled */

	if (ptrace(PTRACE_SETHBPREGS, pid, 0, &state) != 0) {
		ksft_print_msg(
			"ptrace(PTRACE_SETHBPREGS) failed: %s\n",
			strerror(errno));
		return false;
	}

	/* Read back and verify */
	memset(&state, 0, sizeof(state));
	if (ptrace(PTRACE_GETHBPREGS, pid, 0, &state) != 0) {
		ksft_print_msg(
			"ptrace(PTRACE_GETHBPREGS) failed: %s\n",
			strerror(errno));
		return false;
	}

	ksft_print_msg(
		"[hbpregs] watchpoint readback: addr=0x%lx type=%lu len=%lu ctrl=%lu\n",
		state.addr, state.type, state.len, state.ctrl);

	return true;
}

static bool set_hbpregs_breakpoint(pid_t pid, void (*bp_func)(void))
{
	struct __riscv_hwdebug_state state;

	memset(&state, 0, sizeof(state));
	state.addr = (unsigned long)bp_func;
	state.len  = HW_BREAKPOINT_LEN_4;
	state.type = HW_BREAKPOINT_X;
	state.ctrl = 0; /* enabled */

	if (ptrace(PTRACE_SETHBPREGS, pid, 0, &state) != 0) {
		ksft_print_msg(
			"ptrace(PTRACE_SETHBPREGS) failed: %s\n",
			strerror(errno));
		return false;
	}

	/* Read back and verify */
	memset(&state, 0, sizeof(state));
	if (ptrace(PTRACE_GETHBPREGS, pid, 0, &state) != 0) {
		ksft_print_msg(
			"ptrace(PTRACE_GETHBPREGS) failed: %s\n",
			strerror(errno));
		return false;
	}

	ksft_print_msg(
		"[hbpregs] breakpoint readback: addr=0x%lx type=%lu len=%lu ctrl=%lu\n",
		state.addr, state.type, state.len, state.ctrl);

	return true;
}

static int run_hbpregs_wp_test(void)
{
	pid_t pid = fork();
	pid_t wpid;
	siginfo_t siginfo;
	int status;

	if (pid == 0)
		do_wp_child(&var, 8);

	wpid = waitpid(pid, &status, __WALL);
	if (wpid != pid) {
		ksft_print_msg("waitpid() failed: %s\n", strerror(errno));
		return false;
	}
	if (!WIFSTOPPED(status)) {
		ksft_print_msg("child did not stop: %s\n", strerror(errno));
		return false;
	}
	if (WSTOPSIG(status) != SIGSTOP) {
		ksft_print_msg("child did not stop with SIGSTOP\n");
		return false;
	}

	if (!set_hbpregs_watchpoint(pid))
		return false;

	if (ptrace(PTRACE_CONT, pid, NULL, NULL) < 0) {
		ksft_print_msg("ptrace(PTRACE_CONT) failed: %s\n",
			strerror(errno));
		return false;
	}

	alarm(3);
	wpid = waitpid(pid, &status, __WALL);
	if (wpid != pid) {
		ksft_print_msg("waitpid() failed: %s\n", strerror(errno));
		return false;
	}
	alarm(0);
	if (WIFEXITED(status)) {
		ksft_print_msg("child exited prematurely\n");
		return false;
	}
	if (!WIFSTOPPED(status)) {
		ksft_print_msg("child did not stop\n");
		return false;
	}
	if (WSTOPSIG(status) != SIGTRAP) {
		ksft_print_msg("child did not stop with SIGTRAP\n");
		return false;
	}
	if (ptrace(PTRACE_GETSIGINFO, pid, NULL, &siginfo) != 0) {
		ksft_print_msg("ptrace(PTRACE_GETSIGINFO): %s\n",
			strerror(errno));
		return false;
	}
	if (siginfo.si_code != TRAP_HWBKPT) {
		ksft_print_msg("Unexpected si_code %d\n", siginfo.si_code);
		return false;
	}

	kill(pid, SIGKILL);
	wpid = waitpid(pid, &status, 0);
	if (wpid != pid) {
		ksft_print_msg("waitpid() failed: %s\n", strerror(errno));
		return false;
	}

	ksft_print_msg("[hbpregs]: Watchpoint test passed!\n");
	return true;
}

static int run_hbpregs_bp_test(void)
{
	pid_t pid = fork();
	pid_t wpid;
	siginfo_t siginfo;
	int status;

	if (pid == 0)
		do_bp_child(test_func);

	wpid = waitpid(pid, &status, __WALL);
	if (wpid != pid) {
		ksft_print_msg("waitpid() failed: %s\n", strerror(errno));
		return false;
	}
	if (!WIFSTOPPED(status)) {
		ksft_print_msg("child did not stop: %s\n", strerror(errno));
		return false;
	}
	if (WSTOPSIG(status) != SIGSTOP) {
		ksft_print_msg("child did not stop with SIGSTOP\n");
		return false;
	}

	if (!set_hbpregs_breakpoint(pid, test_func))
		return false;

	if (ptrace(PTRACE_CONT, pid, NULL, NULL) < 0) {
		ksft_print_msg("ptrace(PTRACE_CONT) failed: %s\n",
			strerror(errno));
		return false;
	}

	alarm(3);
	wpid = waitpid(pid, &status, __WALL);
	if (wpid != pid) {
		ksft_print_msg("waitpid() failed: %s\n", strerror(errno));
		return false;
	}
	alarm(0);
	if (WIFEXITED(status)) {
		ksft_print_msg("child exited prematurely\n");
		return false;
	}
	if (!WIFSTOPPED(status)) {
		ksft_print_msg("child did not stop\n");
		return false;
	}
	if (WSTOPSIG(status) != SIGTRAP) {
		ksft_print_msg("child did not stop with SIGTRAP\n");
		return false;
	}
	if (ptrace(PTRACE_GETSIGINFO, pid, NULL, &siginfo) != 0) {
		ksft_print_msg("ptrace(PTRACE_GETSIGINFO): %s\n",
			strerror(errno));
		return false;
	}
	if (siginfo.si_code != TRAP_HWBKPT) {
		ksft_print_msg("Unexpected si_code %d\n", siginfo.si_code);
		return false;
	}

	kill(pid, SIGKILL);
	wpid = waitpid(pid, &status, 0);
	if (wpid != pid) {
		ksft_print_msg("waitpid() failed: %s\n", strerror(errno));
		return false;
	}

	ksft_print_msg("[hbpregs]: Breakpoint test passed!\n");
	return true;
}

static void run_hbpregs_tests(void)
{
	run_hbpregs_bp_test();
	run_hbpregs_wp_test();
}

/*
 * BREAKPOINT TEST USING PTRACE_SETHBPREGS / PTRACE_GETHBPREGS - END
 */
static void run_ptrace_tests(void)
{
	run_ptrace_bp_test();
	run_ptrace_wp_test();
}

/*
 * BREAKPOINT TEST USING PTRACE - END
 */

/*
 * BREAKPOINT TEST USING perf events
 */
static int gfd;
sem_t ib_mtx, wp_mtx;
static int bp_triggered, wp_triggered;
static const int wait_timeout_sec = 5;

int setup_bp(bool is_x, void *addr, int sig)
{
	struct perf_event_attr pe;
	int fd;

	memset(&pe, 0, sizeof(struct perf_event_attr));
	pe.type = PERF_TYPE_BREAKPOINT;
	pe.size = sizeof(struct perf_event_attr);

	pe.config = 0;
	pe.bp_type = is_x ? HW_BREAKPOINT_X : HW_BREAKPOINT_W;
	pe.bp_addr = (unsigned long)addr;
	pe.bp_len = sizeof(long);

	pe.sample_period = 1;
	pe.sample_type = PERF_SAMPLE_IP;
	pe.wakeup_events = 1;

	pe.disabled = 1;
	pe.exclude_kernel = 1;
	pe.exclude_hv = 1;

	fd = syscall(SYS_perf_event_open, &pe, 0, -1, -1, 0);
	if (fd < 0) {
		ksft_print_msg("Failed to open event: %llx\n", pe.config);
		return -1;
	}

	fcntl(fd, F_SETFL, O_RDWR | O_NONBLOCK | O_ASYNC);
	fcntl(fd, F_SETSIG, sig);
	fcntl(fd, F_SETOWN, getpid());

	ioctl(fd, PERF_EVENT_IOC_RESET, 0);

	return fd;
}

static void sig_handler_bp(int signum, siginfo_t *oh, void *uc)
{
	int ret;

	bp_triggered++;

	ioctl(gfd, PERF_EVENT_IOC_DISABLE, 0);
	ret = sem_post(&ib_mtx);
	if (ret) {
		ksft_print_msg("Failed to report BP success\n");
		return;
	}
}

static void sig_handler_wp(int signum, siginfo_t *oh, void *uc)
{
	int ret;

	ioctl(gfd, PERF_EVENT_IOC_DISABLE, 0);
	wp_triggered++;

	ret = sem_post(&wp_mtx);

	if (ret) {
		ksft_print_msg("Failed to report WP success\n");
		return;
	}
}

static int trigger_bp(void)
{
	struct sigaction sa;

	memset(&sa, 0, sizeof(struct sigaction));
	sa.sa_sigaction = (void *)sig_handler_bp;
	sa.sa_flags = SA_SIGINFO;

	if (sigaction(SIGIO, &sa, NULL) < 0) {
		ksft_print_msg("Failed to setup signal handler\n");
		return -1;
	}

	gfd = setup_bp(1, test_func, SIGIO);

	if (gfd < 0) {
		ksft_print_msg("Failed to setup breakpoint.\n");
		return -1;
	}

	ioctl(gfd, PERF_EVENT_IOC_ENABLE, 0);

	test_func();

	ioctl(gfd, PERF_EVENT_IOC_DISABLE, 0);

	close(gfd);

	return 0;
}

static int trigger_wp(void)
{
	struct sigaction sa;
	unsigned long test_data;

	memset(&sa, 0, sizeof(struct sigaction));
	sa.sa_sigaction = (void *)sig_handler_wp;
	sa.sa_flags = SA_SIGINFO;

	if (sigaction(SIGUSR1, &sa, NULL) < 0) {
		ksft_print_msg("Failed to setup signal handler\n");
		return -1;
	}

	gfd = setup_bp(0, &test_data, SIGUSR1);

	if (gfd < 0) {
		ksft_print_msg("Failed to setup watchpoint\n");
		return -1;
	}

	ioctl(gfd, PERF_EVENT_IOC_ENABLE, 0);
	test_data = 0xdeadbeef;
	ioctl(gfd, PERF_EVENT_IOC_DISABLE, 0);

	return 0;
}

static int wait_event(sem_t *sem, const char *name)
{
	struct timespec ts;

	if (clock_gettime(CLOCK_REALTIME, &ts)) {
		printf("%s: Failed to get current time\n", name);
		return -1;
	}

	/*
	 * Deadlock fix: avoid blocking forever on sem_wait() if the breakpoint/
	 * watchpoint signal never arrives. Use a bounded wait and fail the test
	 * on timeout instead.
	 */
	ts.tv_sec += wait_timeout_sec;
	if (!sem_timedwait(sem, &ts))
		return 0;

	if (errno == ETIMEDOUT)
		printf("%s: Timed out waiting for event\n", name);
	else
		printf("%s: sem_timedwait() failed with %d\n", name, errno);

	return -1;
}

int main(int argc, char *argv[])
{
	sem_init(&ib_mtx, 0, 0);
	if (trigger_bp() < 0)
		return -1;
	if (wait_event(&ib_mtx, "Breakpoint") < 0)
		return -1;

	if (bp_triggered)
		ksft_print_msg("[perf_event]: Breakpoint test passed!\n");

	sem_init(&wp_mtx, 0, 0);
	if (trigger_wp() < 0)
		return -1;
	if (wait_event(&wp_mtx, "Watchpoint") < 0)
		return -1;

	if (wp_triggered)
		ksft_print_msg("[perf_event]: Watchpoint test passed!\n");

	run_ptrace_tests();
	run_hbpregs_tests();

	return 0;
}
