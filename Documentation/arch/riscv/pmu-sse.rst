.. SPDX-License-Identifier: GPL-2.0

========================================
RISC-V PMU overflow delivery through SSE
========================================

When ``CONFIG_RISCV_PMU_SBI_SSE`` is enabled and firmware provides the local
PMU overflow event, the RISC-V SBI PMU driver uses Supervisor Software Events
(SSE) to deliver counter overflows.

Delivery selection
==================

The delivery mechanism is selected once while the PMU device is probed.  The
driver first tries to register and enable the local PMU overflow SSE event.  It
tries the ordinary PMU interrupt only when the SSE extension or the local PMU
event is explicitly unsupported.  It does not change the delivery mechanism
after the PMU has been registered.

Other SSE setup errors do not prove that firmware released the overflow route,
so the driver does not enable the ordinary PMU interrupt.  The PMU remains
available for counting but not sampling.  A retained event handle does not
mean that SSE delivery is active: the PMU enable and disable callbacks are
installed only after setup succeeds.  Retained state prevents IRQ fallback
and remains subject to SSE cleanup.

Interrupted context
===================

SSE enters Linux through a supervisor handler context constructed by firmware.
The entry contract preserves the interrupted GPRs except ``a6`` and ``a7``,
which Linux reads from the interrupted-register event attributes.  Linux then
reconstructs the interrupted ``pt_regs`` and publishes it while dispatching the
event.

Perf uses that context for register samples and callchains.  Kernel stack
walking verifies that the interrupted frame belongs to the current task stack
before dereferencing it.  For sensitive entry paths and IRQ stacks, Linux
records the interrupted PC without walking a stack whose bounds cannot be
proved.  User callchains use the existing no-fault user unwinder.  A DWARF
raw user-stack copy uses ``__copy_from_user_inatomic()`` with page-fault
handling disabled.  A non-resident source page may still cause a synchronous
exception, which the exception-table fixup handles without entering normal
page-fault handling or enabling interrupts.  Perf truncates the dump by the
number of bytes not copied.  SSE entry preserves the task's stack metadata
and early trap-entry scratch slots across nested exceptions.

The SSE copy checks the user address range and requires the active page-table
root to match ``current->mm``.  This check does not detect stale TLB entries
in the address-space switch window; samples from that window can still be
misattributed.

CPU power management
====================

The PMU and SSE CPU power-management callbacks are ordered according to the
selected delivery mechanism.  With SSE delivery, SSE events are masked before
the lower-priority PMU callback disables the local PMU event and stops the
counters on entry.  On exit, the hart is unmasked while the local PMU event is
still disabled.  The PMU callback then restores the counters and enables the
event, so an unmask failure leaves the counters stopped.  The ordinary
interrupt path retains the existing PMU ordering.
