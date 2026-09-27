/* Copyright (C) 2026 fontconfig Authors */
/* SPDX-License-Identifier: HPND */

#ifdef HAVE_CONFIG_H
#  include "config.h"
#endif

#include <pthread.h>
#include <sched.h>
#include <stdatomic.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

#include "fcmutex.h"

#define NUM_READERS 8
#define NUM_WRITERS 2
#define ITERS       1000

static FcRwLock    rw;
static atomic_int  active_readers;
static atomic_int  max_concurrent_readers;
static atomic_bool stop;
static atomic_bool go;
static int         shared_counter;

static void *
reader_thread (void *arg)
{
    (void)arg;
    while (!atomic_load_explicit (&go, memory_order_acquire))
	sched_yield ();
    while (!atomic_load_explicit (&stop, memory_order_relaxed)) {
	FcRwLockReadLock (&rw);
	int cur = atomic_fetch_add_explicit (&active_readers, 1, memory_order_seq_cst) + 1;
	int prev_max = atomic_load_explicit (&max_concurrent_readers, memory_order_relaxed);
	while (cur > prev_max &&
	       !atomic_compare_exchange_weak_explicit (&max_concurrent_readers, &prev_max, cur,
	                                               memory_order_relaxed, memory_order_relaxed))
	    ;
	int val = shared_counter;
	(void)val;
	atomic_fetch_sub_explicit (&active_readers, 1, memory_order_seq_cst);
	FcRwLockUnlockRead (&rw);
	sched_yield ();
    }
    return NULL;
}

static void *
writer_thread (void *arg)
{
    (void)arg;
    while (!atomic_load_explicit (&go, memory_order_acquire))
	sched_yield ();
    for (int i = 0; i < ITERS && !atomic_load_explicit (&stop, memory_order_relaxed); i++) {
	FcRwLockWriteLock (&rw);
	int readers = atomic_load_explicit (&active_readers, memory_order_seq_cst);
	if (readers != 0) {
	    fprintf (stderr, "Error: active_readers = %d during write lock!\n", readers);
	    abort();
	}
	shared_counter++;
	FcRwLockUnlockWrite (&rw);
    }
    return NULL;
}

int
main (void)
{
    pthread_t rth[NUM_READERS];
    pthread_t wth[NUM_WRITERS];
    int       i;

    FcRwLockInit (&rw);

    /* Basic test */
    FcRwLockReadLock (&rw);
    FcRwLockUnlockRead (&rw);
    FcRwLockWriteLock (&rw);
    FcRwLockUnlockWrite (&rw);

    atomic_init (&active_readers, 0);
    atomic_init (&max_concurrent_readers, 0);
    atomic_init (&stop, 0);
    atomic_init (&go, 0);
    shared_counter = 0;

    for (i = 0; i < NUM_READERS; i++) {
	if (pthread_create (&rth[i], NULL, reader_thread, NULL) != 0)
	    return 1;
    }
    for (i = 0; i < NUM_WRITERS; i++) {
	if (pthread_create (&wth[i], NULL, writer_thread, NULL) != 0)
	    return 1;
    }

    atomic_store_explicit (&go, 1, memory_order_release);

    for (i = 0; i < NUM_WRITERS; i++)
	pthread_join (wth[i], NULL);
    atomic_store_explicit (&stop, 1, memory_order_relaxed);
    for (i = 0; i < NUM_READERS; i++)
	pthread_join (rth[i], NULL);

    FcRwLockFinish (&rw);

    printf ("PASS: test-rwlock, max concurrent readers = %d\n",
            atomic_load_explicit (&max_concurrent_readers, memory_order_relaxed));
    return 0;
}
