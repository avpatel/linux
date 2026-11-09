============================
The Common Mailbox Framework
============================

:Author: Jassi Brar <jaswinder.singh@linaro.org>

This document aims to help developers write client and controller
drivers for the API. But before we start, let us note that the
client (especially) and controller drivers are likely going to be
very platform specific because the remote firmware is likely to be
proprietary and implement non-standard protocol. So even if two
platforms employ, say, PL320 controller, the client drivers can't
be shared across them. Even the PL320 driver might need to accommodate
some platform specific quirks. So the API is meant mainly to avoid
similar copies of code written for each platform. Having said that,
nothing prevents the remote f/w to also be Linux based and use the
same api there. However none of that helps us locally because we only
ever deal at client's protocol level.

Some of the choices made during implementation are the result of this
peculiarity of this "common" framework.

The framework supports three transmit models:

* non-blocking queued: ``mbox_send_message()`` returns a queue token and
  completion is reported later through ``tx_done``;
* blocking queued: ``tx_block`` is set and the caller waits on the
  channel completion;
* direct synchronous: the controller completes the transfer in the
  caller's context and the client receives the per-call result directly.

The first two models share the per-channel queue and TX-done state
machine.  The direct model is opt-in per channel and bypasses that state
machine entirely.


Controller Driver (See include/linux/mailbox_controller.h)
==========================================================

Allocate mbox_controller and the array of mbox_chan.
Populate mbox_chan_ops.  ``send_data`` is mandatory for queued channels;
``flush``, ``startup``, ``shutdown``, ``last_tx_done``, and ``peek_data``
are optional depending on the controller's capabilities and the selected
TX-done method.
The controller driver might know a message has been consumed
by the remote by getting an IRQ or polling some hardware flag
or it can never know (the client knows by way of the protocol).
The method in order of preference is IRQ -> Poll -> None, which
the controller driver should set via 'txdone_irq' or 'txdone_poll'
or neither.

Queued transmit
---------------

``send_data()`` is called by ``msg_submit()`` with ``chan->lock`` held and
local IRQs disabled.  It must not sleep.  It should return 0 if the message
was accepted, or a negative errno (for example ``-EBUSY``) if it could not
be accepted.  Completion is reported later with ``mbox_chan_txdone()``
(IRQ mode) or by the polling timer calling ``last_tx_done()``.  A client
using the ``knows_txdone`` retrofit calls ``mbox_client_txdone()`` itself.

The queue and TX-done state machine assume a single outstanding request
per channel.  All senders on a queued channel are therefore serialized by
the framework, and ``tx_block`` callers must serialize themselves.

Direct synchronous transmit
---------------------------

Some controllers complete a transfer synchronously in the calling context
and can return the result immediately.  Such a controller may advertise a
direct channel by setting ``struct mbox_chan.sync_caps`` before calling
``mbox_controller_register()``:

.. code-block:: c

    #define MBOX_CHAN_CAP_SYNC_ATOMIC	BIT(0)
    #define MBOX_CHAN_CAP_SYNC_SLEEPABLE	BIT(1)

A channel with either bit set is a *direct channel*.  ``sync_caps`` is
immutable after registration; zero means the channel keeps the existing
queued behavior.  Controllers must therefore initialize it to zero for
queued channels; ``kzalloc()`` and static storage already do so.

The controller implements one or both of these operations:

.. code-block:: c

    int (*send_data_sync)(struct mbox_chan *chan, void *data);
    int (*send_data_sync_sleepable)(struct mbox_chan *chan, void *data);

``send_data_sync()``
    Atomic-safe direct transmit.  It must not sleep, must complete the
    transfer (or return a per-call error) before returning, and must not
    use a later TX-done interrupt, polling timer, or ``mbox_chan_txdone()``.
    It must not call the txdone APIs or any client callback recursively.
    It must not retain ``data`` after returning.

``send_data_sync_sleepable()``
    Sleepable direct transmit.  It has the same per-call, no-retained-buffer
    contract but may use mutexes, completions, sleeping bus access, and other
    sleepable primitives.  It must only be called from sleepable context.

Both operations are called in the client's context with no framework lock
held and with the caller's IRQ and preemption state.  The framework calls
the operation exactly once per client call and returns its result to that
same caller.

A controller that implements a direct operation but does not set the
matching capability bit is valid; the operation is then simply unused.
Registration rejects unknown capability bits, a capability bit without the
matching operation, and a queued channel without ``send_data``.

Concurrency and resource ownership
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

The framework does not serialize direct callers.  Multiple CPUs may call
the direct API on the same channel concurrently.  This is deliberate: a
per-channel framework lock would violate the concurrency contract and would
still not protect controller-wide or per-CPU resources.

The controller owns protection of everything its direct operation touches:

* controller-wide registers and shared FIFOs;
* per-channel state, which may live in ``chan->con_priv``;
* per-CPU scratch memory and other per-CPU state;
* resources shared with non-mailbox users of the same controller helpers.

The controller may take its own lock to serialize, or may return ``-EBUSY``
to a caller it cannot serve concurrently.  It must not assume that the
framework disabled IRQs for it.

If the operation uses per-CPU state, it must also prevent same-CPU IRQ
re-entry.  ``local_irq_save()`` is the portable hardirq-safe choice.
``local_lock_irqsave()`` gives lockdep coverage on non-RT kernels, but on
PREEMPT_RT it maps to a per-CPU sleeping spinlock and must not be used from
hardirq context.  A per-CPU ``raw_spinlock_t`` taken with IRQs disabled is
another option.  A plain ``get_cpu()``/``put_cpu()`` pair only disables
preemption and does not stop an IRQ on the same CPU from re-entering.

Example: atomic-safe controller
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

.. code-block:: c

    struct my_chan {
        void __iomem *tx_reg;
        spinlock_t lock;	/* protects this controller's registers */
        bool busy;
    };

    static int my_send_data_sync(struct mbox_chan *chan, void *data)
    {
        struct my_chan *c = chan->con_priv;
        unsigned long flags;
        u32 status;
        int ret = 0;

        /*
         * The framework does not serialize direct callers and does not
         * disable IRQs.  This controller shares one register block across
         * all CPUs, so it uses its own IRQ-safe lock.
         */
        spin_lock_irqsave(&c->lock, flags);
        if (c->busy) {
            ret = -EBUSY;
            goto out;
        }

        c->busy = true;
        writel(*(u32 *)data, c->tx_reg);
        if (readl_poll_timeout_atomic(c->tx_reg + MY_STATUS, status,
                                      status & MY_DONE, 1, 1000))
            ret = -ETIMEDOUT;
        c->busy = false;
    out:
        spin_unlock_irqrestore(&c->lock, flags);
        return ret;
    }

    static const struct mbox_chan_ops my_ops = {
        .send_data_sync = my_send_data_sync,
        /* .send_data may be NULL if every channel is direct-only. */
    };

    static int my_probe(struct platform_device *pdev)
    {
        ...
        for (i = 0; i < MY_NUM_CHANS; i++)
            mbox->chans[i].sync_caps = MBOX_CHAN_CAP_SYNC_ATOMIC;
        ...
        return devm_mbox_controller_register(dev, &mbox->controller);
    }

Example: per-CPU shared-memory controller
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

A controller that hands a per-CPU buffer to firmware must guard the whole
copy/firmware-call/copy sequence, not just the copy:

.. code-block:: c

    static int my_send_data_sync(struct mbox_chan *chan, void *data)
    {
        struct my_msg *msg = data;
        int ret;

        /*
         * The firmware uses per-CPU scratch memory.  A hardirq on this CPU
         * could otherwise re-enter and clobber it between the copy and the
         * firmware call.
         */
        guard(irqsave)();
        memcpy(this_cpu_ptr(&my_buf)->data, msg->tx, msg->len);
        ret = my_firmware_call(this_cpu_ptr(&my_buf)->phys, msg->len);
        if (!ret)
            memcpy(msg->rx, this_cpu_ptr(&my_buf)->data, msg->rx_len);
        return ret;
    }

Every user of the per-CPU buffer must take the same guard.  Attribute
queries, notification fetches, MSI programming, and non-mailbox users that
share the buffer are all part of the same critical section.  Delivering RX
through ``mbox_chan_received_data()`` while holding that guard can deadlock
if the client sends from ``rx_callback``; release the guard first or use a
separate RX lock.


Client Driver (See include/linux/mailbox_client.h)
==================================================

The client might want to operate in one of three modes:

* non-blocking queued: submit a message and a callback, return immediately;
* blocking queued: wait until the queued transfer completes or times out;
* direct synchronous: call the controller operation and receive its result.

The first two use ``mbox_send_message()`` and the queued state machine.
The third uses ``mbox_send_message_sync()`` or
``mbox_send_message_sync_sleepable()`` and must be used on a direct channel.

Blocking and non-blocking queued modes
--------------------------------------

::

	struct demo_client {
		struct mbox_client cl;
		struct mbox_chan *mbox;
		struct completion c;
		bool async;
		/* ... */
	};

	/*
	* This is the handler for data received from remote. The behaviour is purely
	* dependent upon the protocol. This is just an example.
	*/
	static void message_from_remote(struct mbox_client *cl, void *mssg)
	{
		struct demo_client *dc = container_of(cl, struct demo_client, cl);
		if (dc->async) {
			if (is_an_ack(mssg)) {
				/* An ACK to our last sample sent */
				return; /* Or do something else here */
			} else { /* A new message from remote */
				queue_req(mssg);
			}
		} else {
			/* Remote f/w sends only ACK packets on this channel */
			return;
		}
	}

	static void sample_sent(struct mbox_client *cl, void *mssg, int r)
	{
		struct demo_client *dc = container_of(cl, struct demo_client, cl);
		complete(&dc->c);
	}

	static void client_demo(struct platform_device *pdev)
	{
		struct demo_client *dc_blocking, *dc_async;
		/* The controller already knows async_pkt and blocking_pkt */
		struct async_pkt ap;
		struct blocking_pkt bp;

		dc_blocking = kzalloc_obj(*dc_blocking);
		dc_async = kzalloc_obj(*dc_async);

		/* Populate non-blocking mode client */
		dc_async->cl.dev = &pdev->dev;
		dc_async->cl.rx_callback = message_from_remote;
		dc_async->cl.tx_done = sample_sent;
		dc_async->cl.tx_block = false;
		dc_async->cl.tx_tout = 0; /* doesn't matter here */
		dc_async->cl.knows_txdone = false; /* depending upon protocol */
		dc_async->async = true;
		init_completion(&dc_async->c);

		/* Populate blocking mode client */
		dc_blocking->cl.dev = &pdev->dev;
		dc_blocking->cl.rx_callback = message_from_remote;
		dc_blocking->cl.tx_done = NULL; /* operate in blocking mode */
		dc_blocking->cl.tx_block = true;
		dc_blocking->cl.tx_tout = 500; /* by half a second */
		dc_blocking->cl.knows_txdone = false; /* depending upon protocol */
		dc_blocking->async = false;

		/* ASync mailbox is listed second in 'mboxes' property */
		dc_async->mbox = mbox_request_channel(&dc_async->cl, 1);
		/* Populate data packet */
		/* ap.xxx = 123; etc */
		/* Send async message to remote */
		mbox_send_message(dc_async->mbox, &ap);

		/* Blocking mailbox is listed first in 'mboxes' property */
		dc_blocking->mbox = mbox_request_channel(&dc_blocking->cl, 0);
		/* Populate data packet */
		/* bp.abc = 123; etc */
		/* Send message to remote in blocking mode */
		mbox_send_message(dc_blocking->mbox, &bp);
		/* At this point 'bp' has been sent */

		/* Now wait for async chan to be done */
		wait_for_completion(&dc_async->c);
	}

The documentation uses "blocking queued" rather than "sync" for
``tx_block=true`` so that it is not confused with direct synchronous
transmit.  ``tx_block`` callers must serialize themselves on a channel.

Direct synchronous mode
-----------------------

.. code-block:: c

    int __must_check mbox_send_message_sync(struct mbox_chan *chan,
                                            void *mssg);
    int __must_check mbox_send_message_sync_sleepable(struct mbox_chan *chan,
                                                      void *mssg);

``mbox_send_message_sync()``
    Calls ``send_data_sync()``.  It never sleeps and may be called from any
    context in which the controller operation is safe, including hardirq.
    It does not fall back to a sleepable operation.

``mbox_send_message_sync_sleepable()``
    Calls ``send_data_sync_sleepable()`` when the channel advertises it.
    If only ``MBOX_CHAN_CAP_SYNC_ATOMIC`` is advertised, it calls the
    stronger ``send_data_sync()`` instead.  It calls ``might_sleep()`` and
    may therefore be used only from sleepable context.

Both functions return 0 on success, ``-EINVAL`` for invalid arguments,
``-EOPNOTSUPP`` when the channel does not support the requested direct
mode, or another negative errno from the controller.  Positive values are
not used by the direct API; controllers must return 0 or a negative errno.
The declarations are ``__must_check`` because the per-call result is the
whole point of the API.

The caller must keep the message buffer valid until the call returns.  The
controller must not retain the pointer afterwards.  The caller is also
responsible for serializing the call against ``mbox_free_channel()`` and
driver removal; the framework does not wait for or refcount in-flight direct
calls.  The ``chan->cl`` check in the wrapper is only a best-effort sanity
check.

The capability probe is the call itself: a client may attempt the direct
API and handle ``-EOPNOTSUPP``.  There is no capability query helper in the
minimal API.

Example:

.. code-block:: c

    ret = mbox_send_message_sync(client->chan, msg);
    if (ret)
        /* Handle the per-call error. */

The direct path calls neither ``tx_prepare`` nor ``tx_done``.  The client
prepares its buffer before the call, and the return value is the completion
notification.  ``tx_block``, ``tx_tout``, and ``knows_txdone`` are ignored
on a direct channel because ``mbox_send_message()`` and
``mbox_client_txdone()`` are rejected there.

Interaction with the existing API
=================================

The following table is normative for a direct channel
(``sync_caps != 0``):

.. list-table:: Interaction with the existing API on a direct channel
   :header-rows: 1
   :widths: 30 70

   * - API / callback
     - Behavior on a direct channel
   * - ``mbox_send_message()``
     - Returns ``-EOPNOTSUPP``.  Mixing queued and direct paths would
       reintroduce the single-request state machine.
   * - ``mbox_flush()``
     - Returns ``-EOPNOTSUPP``.  There is no framework transmission to
       flush.
   * - ``tx_prepare``
     - Never called.  The client prepares its own buffer.
   * - ``tx_done``
     - Never called.  The direct return value is the notification.
   * - ``mbox_chan_txdone()``
     - ``WARN_ON_ONCE()`` and no-op.  The controller must return the result
       from the direct operation.
   * - ``mbox_client_txdone()``
     - ``WARN_ON_ONCE()`` and no-op.  Same reason.
   * - ``mbox_chan_tx_slots_available()``
     - Returns 0.  A direct channel has no queue.
   * - ``tx_block`` / ``tx_tout``
     - Ignored.  ``mbox_send_message()`` is rejected.
   * - ``knows_txdone``
     - Ignored.  ``mbox_client_txdone()`` is rejected.
   * - ``startup`` / ``shutdown``
     - Unchanged.  Called on bind/unbind and may sleep.
   * - ``rx_callback`` / ``peek_data`` / ``mbox_chan_received_data()``
     - Unchanged.  Receive delivery is independent of the transmit mode.
   * - ``mbox_free_channel()``
     - Unchanged.  The client must serialize it against in-flight direct
       calls.
   * - debugfs mailbox summary
     - Unchanged; it only reports channel ownership.

Debugging aids provided by the framework are
``lockdep_assert_not_held(&chan->lock)`` in both direct wrappers,
``might_sleep()`` in the sleepable wrapper, txdone misuse warnings, and
registration-time capability validation.  ``CONFIG_DEBUG_ATOMIC_SLEEP`` and
``CONFIG_PROVE_LOCKING`` catch controller bugs that the framework cannot
detect statically.

The KUnit suite in ``drivers/mailbox/mailbox-sync-test.c`` exercises the
capability matrix, registration validation, per-call results, multi-CPU
concurrency, hardirq context, queued compatibility, and free/rebind.
