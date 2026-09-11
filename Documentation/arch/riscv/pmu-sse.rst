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
available for counting but not sampling.  If setup retained an SSE event, the
PMU keeps quiescing that event around perf scheduling changes without rearming
it.  This preserves callback ownership without creating two possible delivery
mechanisms for the same hardware overflow.

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
raw user-stack copy from an SSE handler must not take a page fault, so it
walks the current task's page tables with fast-only GUP, copies each resident
page through its kernel mapping, and stops at the first non-resident page,
preserving perf's truncated-user-stack semantics.

CPU power management
====================

The PMU and SSE CPU power-management callbacks are ordered according to the
selected delivery mechanism.  With SSE delivery, SSE events are masked before
the lower-priority PMU callback disables the local PMU event and stops the
counters on entry.  On exit, the hart is unmasked while the local PMU event is
still disabled.  The PMU callback then restores the counters and enables the
event, so an unmask failure leaves the counters stopped.  The ordinary
interrupt path retains the existing PMU ordering.
