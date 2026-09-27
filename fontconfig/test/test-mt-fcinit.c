/* Copyright (C) 2026 fontconfig Authors */
/* SPDX-License-Identifier: HPND */
#ifdef HAVE_CONFIG_H
#  include "config.h"
#endif

#include "fcint.h"

#include <fontconfig/fontconfig.h>

#include <pthread.h>
#include <stdatomic.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>

#define NTHR 100

/* Meson treats exit code 77 as "test skipped". */
#define EXIT_SKIP 77

#ifdef ENABLE_TEST_HOOKS

/* Start gate: make all threads reach the first default-config access
 * simultaneously so that concurrent lazy initialization is actually
 * exercised. pthread_barrier_t is unavailable on macOS, so use atomics. */
static atomic_int  ready;
static atomic_bool go;

static void *
run_test_in_thread (void *arg)
{
    (void)arg;

    atomic_fetch_add_explicit (&ready, 1, memory_order_relaxed);
    while (!atomic_load_explicit (&go, memory_order_acquire))
	;

    /* First touch of the default config triggers lazy initialization. */
    FcConfigGetCurrent();

    return NULL;
}

int
main (void)
{
    pthread_t threads[NTHR];
    int       i, j;
    int       baseline, count;

    /* Must not initialize the default config before the concurrent phase,
     * otherwise the threads would find it already built. Reading the counter
     * does not trigger initialization. */
    baseline = fc_atomic_int_add (FcConfigInitCount, 0);

    atomic_init (&ready, 0);
    atomic_init (&go, false);

    for (i = 0; i < NTHR; i++) {
	if (pthread_create (&threads[i], NULL, run_test_in_thread, NULL) != 0) {
	    fprintf (stderr, "Cannot create thread %d\n", i);
	    break;
	}
    }

    /* Open the gate only once every successfully-created thread is ready.
     * Gate on 'i' (threads actually created), not NTHR, so a partial
     * pthread_create failure does not hang here. */
    while (atomic_load_explicit (&ready, memory_order_acquire) < i)
	;
    atomic_store_explicit (&go, true, memory_order_release);

    for (j = 0; j < i; j++)
	pthread_join (threads[j], NULL);

    count = fc_atomic_int_add (FcConfigInitCount, 0) - baseline;
    printf ("Default config built %d time(s) for %d concurrent initializers\n",
            count, i);

    FcFini();

    if (i == 0) {
	fprintf (stderr, "No threads were created\n");
	return EXIT_FAILURE;
    }
    if (count != 1) {
	fprintf (stderr,
	         "FAIL: expected the default config to be built exactly once, "
	         "but it was built %d times (concurrent-init race)\n",
	         count);
	return EXIT_FAILURE;
    }

    return EXIT_SUCCESS;
}

#else /* !ENABLE_TEST_HOOKS */

int
main (void)
{
    fprintf (stderr,
             "test-mt-fcinit requires -Dtest-hooks=true; skipping\n");
    return EXIT_SKIP;
}

#endif
