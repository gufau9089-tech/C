/*
 * fontconfig/test/test-pthread.c
 *
 * Copyright © 2000 Keith Packard
 * Copyright © 2013 Raimund Steger
 *
 * Permission to use, copy, modify, distribute, and sell this software and its
 * documentation for any purpose is hereby granted without fee, provided that
 * the above copyright notice appear in all copies and that both that
 * copyright notice and this permission notice appear in supporting
 * documentation, and that the name of the author(s) not be used in
 * advertising or publicity pertaining to distribution of the software without
 * specific, written prior permission.  The authors make no
 * representations about the suitability of this software for any purpose.  It
 * is provided "as is" without express or implied warranty.
 *
 * THE AUTHOR(S) DISCLAIMS ALL WARRANTIES WITH REGARD TO THIS SOFTWARE,
 * INCLUDING ALL IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS, IN NO
 * EVENT SHALL THE AUTHOR(S) BE LIABLE FOR ANY SPECIAL, INDIRECT OR
 * CONSEQUENTIAL DAMAGES OR ANY DAMAGES WHATSOEVER RESULTING FROM LOSS OF USE,
 * DATA OR PROFITS, WHETHER IN AN ACTION OF CONTRACT, NEGLIGENCE OR OTHER
 * TORTIOUS ACTION, ARISING OUT OF OR IN CONNECTION WITH THE USE OR
 * PERFORMANCE OF THIS SOFTWARE.
 */
#include <fontconfig/fontconfig.h>

#include <pthread.h>
#include <stdatomic.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

#define NTHR  100
#define NTEST 100

struct thr_arg_s {
    int thr_num;
};

/* Start gate: make all threads hit the lazy default-config init
 * simultaneously so the concurrent-init race window is actually exercised.
 * pthread_barrier_t is unavailable on macOS (which this test builds on),
 * so use portable atomics instead. */
static atomic_int  ready;
static atomic_bool go;

static void
test_match (int thr_num, int test_num)
{
    FcPattern *pat;
    FcPattern *match;
    FcResult   result;

    pat = FcNameParse ((const FcChar8 *)"New Century Schoolbook");

    FcConfigSubstitute (0, pat, FcMatchPattern);
    FcConfigSetDefaultSubstitute (0, pat);

    match = FcFontMatch (0, pat, &result);

    FcPatternDestroy (pat);
    FcPatternDestroy (match);
}

static void *
run_test_in_thread (void *arg)
{
    struct thr_arg_s *thr_arg = (struct thr_arg_s *)arg;
    int               thread_num = thr_arg->thr_num;
    int               i = 0;

    /* Announce readiness, then wait for the start gate to open. */
    atomic_fetch_add_explicit (&ready, 1, memory_order_relaxed);
    while (!atomic_load_explicit (&go, memory_order_acquire))
	;

    for (; i < NTEST; i++)
	test_match (thread_num, i);

    printf ("Thread %d: done\n", thread_num);

    return NULL;
}

int
main (int argc, char **argv)
{
    pthread_t        threads[NTHR];
    struct thr_arg_s thr_args[NTHR];
    int              i, j;

    printf ("Creating %d threads\n", NTHR);

    atomic_init (&ready, 0);
    atomic_init (&go, false);

    for (i = 0; i < NTHR; i++) {
	int result;
	thr_args[i].thr_num = i;
	result = pthread_create (&threads[i], NULL, run_test_in_thread,
	                         (void *)&thr_args[i]);
	if (result != 0) {
	    fprintf (stderr, "Cannot create thread %d\n", i);
	    break;
	}
    }

    /* Open the gate once every successfully-created thread is ready.
     * Gate on 'i' (threads actually created), not NTHR, so a partial
     * pthread_create failure does not hang here. */
    while (atomic_load_explicit (&ready, memory_order_acquire) < i)
	;
    atomic_store_explicit (&go, true, memory_order_release);

    for (j = 0; j < i; j++) {
	pthread_join (threads[j], NULL);
	printf ("Joined thread %d\n", j);
    }

    FcFini();

    return 0;
}
