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
#include <ucontext.h>

#include "kselftest.h"

static int test_func_sink;
static const int wait_timeout_sec = 5;

static unsigned int hwdebug_control(unsigned int type, unsigned long len)
{
	return HWDEBUG_MK_TYPE(type) | HWDEBUG_MK_SIZE(len);
}

static void cleanup_child(pid_t pid)
{
	int status;

	if (pid <= 0)
		return;

	/* Every error path funnels here so a stopped tracee is never leaked. */
	kill(pid, SIGKILL);
	while (waitpid(pid, &status, __WALL) < 0 && errno == EINTR)
		;
}

static pid_t waitpid_timeout(pid_t pid, int *status)
{
	struct timespec delay = {
		.tv_sec = 0,
		.tv_nsec = 10 * 1000 * 1000,
	};
	int tries = wait_timeout_sec * 100;
	pid_t wpid;

	/* Avoid alarm(): SIGALRM's default action would skip tracee cleanup. */
	while (tries--) {
		wpid = waitpid(pid, status, __WALL | WNOHANG);
		if (wpid < 0 && errno == EINTR)
			continue;
		if (wpid != 0)
			return wpid;
		nanosleep(&delay, NULL);
	}

	errno = ETIMEDOUT;
	return -1;
}

static bool wait_for_child_stop(pid_t pid, int expected_sig, const char *name)
{
	pid_t wpid;
	int status;

	wpid = waitpid_timeout(pid, &status);
	if (wpid != pid) {
		ksft_print_msg("%s: waitpid() failed: %s\n", name,
			       strerror(errno));
		return false;
	}
	if (!WIFSTOPPED(status)) {
		ksft_print_msg("%s: child did not stop\n", name);
		return false;
	}
	if (WSTOPSIG(status) != expected_sig) {
		ksft_print_msg("%s: child stopped with signal %d, expected %d\n",
			       name, WSTOPSIG(status), expected_sig);
		return false;
	}

	return true;
}

static bool continue_and_wait_for_trap(pid_t pid, const char *name)
{
	siginfo_t siginfo;

	if (ptrace(PTRACE_CONT, pid, NULL, NULL) < 0) {
		ksft_print_msg("%s: ptrace(PTRACE_CONT) failed: %s\n",
			       name, strerror(errno));
		return false;
	}

	if (!wait_for_child_stop(pid, SIGTRAP, name))
		return false;

	if (ptrace(PTRACE_GETSIGINFO, pid, NULL, &siginfo) != 0) {
		ksft_print_msg("%s: ptrace(PTRACE_GETSIGINFO): %s\n",
			       name, strerror(errno));
		return false;
	}
	if (siginfo.si_code != TRAP_HWBKPT) {
		ksft_print_msg("%s: unexpected si_code %d\n", name,
			       siginfo.si_code);
		return false;
	}

	return true;
}

/*
 * Keep a real instruction address for HW execute breakpoints: prevent inlining
 * and force a visible side effect so the function can't be optimized away.
 */
static __attribute_noinline__ void test_func(void)
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
		ksft_print_msg("ptrace(PTRACE_TRACEME) failed: %s\n",
			       strerror(errno));
		_exit(1);
	}

	if (raise(SIGSTOP) != 0) {
		ksft_print_msg("raise(SIGSTOP) failed: %s\n", strerror(errno));
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
		ksft_print_msg("Unknown watchpoint access size %zu\n", size);
		break;
	}

	_exit(0);
}

static int do_bp_child(void (*bp_func)(void))
{
	if (ptrace(PTRACE_TRACEME, 0, NULL, NULL) != 0) {
		ksft_print_msg("ptrace(PTRACE_TRACEME) failed: %s\n",
			       strerror(errno));
		_exit(1);
	}

	if (raise(SIGSTOP) != 0) {
		ksft_print_msg("raise(SIGSTOP) failed: %s\n", strerror(errno));
		_exit(1);
	}

	bp_func();
	_exit(0);
}

unsigned long var;

static bool set_watchpoint(pid_t pid, int size)
{
	uint8_t *addr = (uint8_t *)&var;
	unsigned int control = 0;
	struct user_hwdebug_state dreg_state;
	struct iovec iov;

	/* Write watchpoint */
	switch (size) {
	case HW_BREAKPOINT_LEN_1:
	case HW_BREAKPOINT_LEN_2:
	case HW_BREAKPOINT_LEN_4:
	case HW_BREAKPOINT_LEN_8:
		break;
	default:
		ksft_print_msg("Unsupported watchpoint size %d\n", size);
		return false;
	}

	control = hwdebug_control(HW_BREAKPOINT_W, size);
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
			ksft_print_msg("ptrace(PTRACE_GETREGSET): Number of watchpoints: %u\n",
				       dreg_state.info);
			ksft_print_msg("ptrace(PTRACE_GETREGSET): addr: 0x%lx control: 0x%x\n",
				       dreg_state.dbg_regs[0].addr,
				       dreg_state.dbg_regs[0].control);
			if (!dreg_state.info ||
			    dreg_state.dbg_regs[0].addr != (uintptr_t)addr ||
			    HWDEBUG_TYPE(dreg_state.dbg_regs[0].control) != HW_BREAKPOINT_W ||
			    HWDEBUG_SIZE(dreg_state.dbg_regs[0].control) != size) {
				ksft_print_msg("Bad wp readback: info=%u addr=0x%lx ctrl=0x%x\n",
					       dreg_state.info,
					       dreg_state.dbg_regs[0].addr,
					       dreg_state.dbg_regs[0].control);
				return false;
			}
		} else {
			ksft_print_msg("ptrace(PTRACE_GETREGSET): Failed\n");
			return false;
		}

		return true;
	}

	if (errno == EIO)
		ksft_print_msg("ptrace(PTRACE_SETREGSET, NT_RISCV_HW_WATCH) not supported: %s\n",
			       strerror(errno));
	else
		ksft_print_msg("ptrace(PTRACE_SETREGSET, NT_RISCV_HW_WATCH) failed: %s\n",
			       strerror(errno));
	return false;
}

static bool set_breakpoint(pid_t pid, void (*bp_func)(void))
{
	struct user_hwdebug_state dreg_state;
	struct iovec iov;
	unsigned int control = 0;

	control = hwdebug_control(HW_BREAKPOINT_X, HW_BREAKPOINT_LEN_4);
	memset(&dreg_state, 0, sizeof(dreg_state));
	dreg_state.dbg_regs[0].addr = (uintptr_t)bp_func;
	dreg_state.dbg_regs[0].control = control;
	iov.iov_base = &dreg_state;
	iov.iov_len = offsetof(struct user_hwdebug_state, dbg_regs) +
		      sizeof(dreg_state.dbg_regs[0]);

	if (ptrace(PTRACE_SETREGSET, pid, NT_RISCV_HW_BREAK, &iov) == 0)
		return true;

	if (errno == EIO)
		ksft_print_msg("ptrace(PTRACE_SETREGSET, NT_RISCV_HW_BREAK) not supported: %s\n",
			       strerror(errno));
	else
		ksft_print_msg("ptrace(PTRACE_SETREGSET, NT_RISCV_HW_BREAK) failed: %s\n",
			       strerror(errno));

	return false;
}

static bool run_ptrace_wp_test(void)
{
	pid_t pid = fork();
	bool ret = false;

	if (pid < 0) {
		ksft_print_msg("fork() failed: %s\n", strerror(errno));
		return false;
	}

	if (pid == 0)
		do_wp_child(&var, 8);

	if (!wait_for_child_stop(pid, SIGSTOP, "ptrace watchpoint"))
		goto out;

	if (!set_watchpoint(pid, 8))
		goto out;

	if (!continue_and_wait_for_trap(pid, "ptrace watchpoint"))
		goto out;

	ksft_print_msg("[ptrace]: Watchpoint test passed!\n");
	ret = true;

out:
	cleanup_child(pid);
	return ret;
}

static bool run_ptrace_bp_test(void)
{
	pid_t pid = fork();
	bool ret = false;

	if (pid < 0) {
		ksft_print_msg("fork() failed: %s\n", strerror(errno));
		return false;
	}

	if (pid == 0)
		do_bp_child(test_func);

	if (!wait_for_child_stop(pid, SIGSTOP, "ptrace breakpoint"))
		goto out;

	if (!set_breakpoint(pid, test_func))
		goto out;

	if (!continue_and_wait_for_trap(pid, "ptrace breakpoint"))
		goto out;

	ksft_print_msg("[ptrace]: Breakpoint test passed!\n");
	ret = true;

out:
	cleanup_child(pid);
	return ret;
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
		ksft_print_msg("ptrace(PTRACE_SETHBPREGS) failed: %s\n",
			       strerror(errno));
		return false;
	}

	/* Read back and verify */
	memset(&state, 0, sizeof(state));
	if (ptrace(PTRACE_GETHBPREGS, pid, 0, &state) != 0) {
		ksft_print_msg("ptrace(PTRACE_GETHBPREGS) failed: %s\n",
			       strerror(errno));
		return false;
	}

	ksft_print_msg("[hbpregs] watchpoint readback: addr=0x%lx type=%lu len=%lu ctrl=%lu\n",
		       state.addr, state.type, state.len, state.ctrl);
	if (state.addr != (unsigned long)&var ||
	    state.type != HW_BREAKPOINT_W ||
	    state.len != HW_BREAKPOINT_LEN_8 ||
	    state.ctrl != 0) {
		ksft_print_msg("[hbpregs] unexpected watchpoint readback\n");
		return false;
	}

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
		ksft_print_msg("ptrace(PTRACE_SETHBPREGS) failed: %s\n",
			       strerror(errno));
		return false;
	}

	/* Read back and verify */
	memset(&state, 0, sizeof(state));
	if (ptrace(PTRACE_GETHBPREGS, pid, 0, &state) != 0) {
		ksft_print_msg("ptrace(PTRACE_GETHBPREGS) failed: %s\n",
			       strerror(errno));
		return false;
	}

	ksft_print_msg("[hbpregs] breakpoint readback: addr=0x%lx type=%lu len=%lu ctrl=%lu\n",
		       state.addr, state.type, state.len, state.ctrl);
	if (state.addr != (unsigned long)bp_func ||
	    state.type != HW_BREAKPOINT_X ||
	    state.len != HW_BREAKPOINT_LEN_4 ||
	    state.ctrl != 0) {
		ksft_print_msg("[hbpregs] unexpected breakpoint readback\n");
		return false;
	}

	return true;
}

static bool run_hbpregs_wp_test(void)
{
	pid_t pid = fork();
	bool ret = false;

	if (pid < 0) {
		ksft_print_msg("fork() failed: %s\n", strerror(errno));
		return false;
	}

	if (pid == 0)
		do_wp_child(&var, 8);

	if (!wait_for_child_stop(pid, SIGSTOP, "hbpregs watchpoint"))
		goto out;

	if (!set_hbpregs_watchpoint(pid))
		goto out;

	if (!continue_and_wait_for_trap(pid, "hbpregs watchpoint"))
		goto out;

	ksft_print_msg("[hbpregs]: Watchpoint test passed!\n");
	ret = true;

out:
	cleanup_child(pid);
	return ret;
}

static bool run_hbpregs_bp_test(void)
{
	pid_t pid = fork();
	bool ret = false;

	if (pid < 0) {
		ksft_print_msg("fork() failed: %s\n", strerror(errno));
		return false;
	}

	if (pid == 0)
		do_bp_child(test_func);

	if (!wait_for_child_stop(pid, SIGSTOP, "hbpregs breakpoint"))
		goto out;

	if (!set_hbpregs_breakpoint(pid, test_func))
		goto out;

	if (!continue_and_wait_for_trap(pid, "hbpregs breakpoint"))
		goto out;

	ksft_print_msg("[hbpregs]: Breakpoint test passed!\n");
	ret = true;

out:
	cleanup_child(pid);
	return ret;
}

static bool run_hbpregs_tests(void)
{
	bool ret = true;

	ret &= run_hbpregs_bp_test();
	ret &= run_hbpregs_wp_test();

	return ret;
}

/*
 * BREAKPOINT TEST USING PTRACE_SETHBPREGS / PTRACE_GETHBPREGS - END
 */
static bool run_ptrace_tests(void)
{
	bool ret = true;

	ret &= run_ptrace_bp_test();
	ret &= run_ptrace_wp_test();

	return ret;
}

/*
 * BREAKPOINT TEST USING PTRACE - END
 */

/*
 * BREAKPOINT TEST USING perf events
 */
static int gfd;
sem_t ib_mtx, wp_mtx, icount_branch_mtx;
static sig_atomic_t bp_triggered, wp_triggered;
static sig_atomic_t icount_branch_triggered;
static int icount_branch_result;
static unsigned long icount_branch_pc;

static int wait_event(sem_t *sem, const char *name);

int setup_bp_len(bool is_x, void *addr, int sig, unsigned long len)
{
	struct perf_event_attr pe;
	int fd;

	memset(&pe, 0, sizeof(struct perf_event_attr));
	pe.type = PERF_TYPE_BREAKPOINT;
	pe.size = sizeof(struct perf_event_attr);

	pe.config = 0;
	pe.bp_type = is_x ? HW_BREAKPOINT_X : HW_BREAKPOINT_W;
	pe.bp_addr = (unsigned long)addr;
	pe.bp_len = len;

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

int setup_bp(bool is_x, void *addr, int sig)
{
	return setup_bp_len(is_x, addr, sig, sizeof(long));
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

static void *icount_branch_insn_addr(void)
{
	void *addr;

	asm("la %0, icount_branch_insn" : "=r"(addr));
	return addr;
}

static void *icount_branch_fallthrough_addr(void)
{
	void *addr;

	asm("la %0, icount_branch_fallthrough" : "=r"(addr));
	return addr;
}

static void *icount_branch_target_addr(void)
{
	void *addr;

	asm("la %0, icount_branch_target" : "=r"(addr));
	return addr;
}

static __attribute_noinline__ void run_icount_taken_branch(void)
{
	asm volatile(".option push\n"
		".option norvc\n"
		".globl icount_branch_insn\n"
		".globl icount_branch_fallthrough\n"
		".globl icount_branch_target\n"
		"li t0, 1\n"
		"li t1, 1\n"
		".balign 4\n"
		"icount_branch_insn:\n"
		"beq t0, t1, icount_branch_target\n"
		"icount_branch_fallthrough:\n"
		"la t2, icount_branch_result\n"
		"li t3, 2\n"
		"sw t3, 0(t2)\n"
		"j icount_branch_done\n"
		".balign 4\n"
		"icount_branch_target:\n"
		"la t2, icount_branch_result\n"
		"li t3, 1\n"
		"sw t3, 0(t2)\n"
		"icount_branch_done:\n"
		".option pop\n"
		:
		:
		: "t0", "t1", "t2", "t3", "memory");
}

static void sig_handler_icount_branch(int signum, siginfo_t *oh, void *uc)
{
	ucontext_t *ctx = uc;
	int ret;

	icount_branch_triggered++;
	icount_branch_pc = ctx->uc_mcontext.__gregs[REG_PC];

	ioctl(gfd, PERF_EVENT_IOC_DISABLE, 0);
	ret = sem_post(&icount_branch_mtx);
	if (ret) {
		ksft_print_msg("Failed to report icount branch success\n");
		return;
	}
}

static int trigger_icount_branch(void)
{
	struct sigaction sa;
	void *insn_addr;
	void *fallthrough_addr;
	void *target_addr;
	uint64_t count;
	ssize_t nread;

	memset(&sa, 0, sizeof(struct sigaction));
	sa.sa_sigaction = sig_handler_icount_branch;
	sa.sa_flags = SA_SIGINFO;

	if (sigaction(SIGIO, &sa, NULL) < 0) {
		ksft_print_msg("Failed to setup icount branch signal handler\n");
		return -1;
	}

	icount_branch_triggered = 0;
	icount_branch_result = 0;
	icount_branch_pc = 0;

	insn_addr = icount_branch_insn_addr();
	fallthrough_addr = icount_branch_fallthrough_addr();
	target_addr = icount_branch_target_addr();

	gfd = setup_bp_len(1, insn_addr, SIGIO, HW_BREAKPOINT_LEN_4);
	if (gfd < 0) {
		ksft_print_msg("Failed to setup icount branch breakpoint.\n");
		return -1;
	}

	ioctl(gfd, PERF_EVENT_IOC_ENABLE, 0);
	run_icount_taken_branch();

	if (wait_event(&icount_branch_mtx, "Icount branch") < 0) {
		ioctl(gfd, PERF_EVENT_IOC_DISABLE, 0);
		close(gfd);
		return -1;
	}

	nread = read(gfd, &count, sizeof(count));
	ioctl(gfd, PERF_EVENT_IOC_DISABLE, 0);
	close(gfd);

	if (nread != sizeof(count)) {
		ksft_print_msg("Failed to read icount branch count: %s\n",
			       strerror(errno));
		return -1;
	}

	ksft_print_msg("icount branch: insn=%p fall=%p target=%p pc=0x%lx count=%llu res=%d\n",
		       insn_addr, fallthrough_addr, target_addr, icount_branch_pc,
		       (unsigned long long)count, icount_branch_result);

	if (icount_branch_triggered != 1) {
		ksft_print_msg("Unexpected icount branch signal count %d\n",
			       icount_branch_triggered);
		return -1;
	}

	if (count != 1) {
		ksft_print_msg("Unexpected icount branch event count %llu\n",
			       (unsigned long long)count);
		return -1;
	}

	if (icount_branch_result != 1) {
		ksft_print_msg("Icount branch did not take the branch\n");
		return -1;
	}

	if (icount_branch_pc != (unsigned long)target_addr) {
		ksft_print_msg("Icount branch PC 0x%lx does not match target %p\n",
			       icount_branch_pc, target_addr);
		return -1;
	}

	ksft_print_msg("[perf_event]: Icount taken branch PC test passed!\n");

	return 0;
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

	close(gfd);

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

	sem_init(&icount_branch_mtx, 0, 0);
	if (trigger_icount_branch() < 0)
		return -1;

	if (!run_ptrace_tests())
		return -1;
	if (!run_hbpregs_tests())
		return -1;

	return 0;
}
