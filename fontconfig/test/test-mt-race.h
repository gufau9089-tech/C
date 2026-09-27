/* Copyright (C) 2026 fontconfig Authors */
/* SPDX-License-Identifier: HPND */

#ifndef TEST_MT_RACE_H
#define TEST_MT_RACE_H

#ifdef HAVE_CONFIG_H
#  include "config.h"
#endif

#include <fontconfig/fontconfig.h>

#include <pthread.h>
#include <sched.h>
#include <stdatomic.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

#ifndef FONTFILE
#  define FONTFILE "no_family_name.ttf"
#endif

#define NUM_READERS    2
#define NUM_ITERATIONS 100

static atomic_bool race_go;
static atomic_bool race_stop;

typedef void (*fc_race_reader_op_t) (void);
typedef void (*fc_race_writer_op_t) (FcConfig *config);

struct race_reader_arg {
    fc_race_reader_op_t op;
};

struct race_writer_arg {
    fc_race_writer_op_t op;
    FcConfig           *config;
};

static void *
race_reader (void *arg)
{
    struct race_reader_arg *rarg = (struct race_reader_arg *)arg;

    while (!atomic_load_explicit (&race_go, memory_order_acquire)) {
	sched_yield ();
    }
    while (!atomic_load_explicit (&race_stop, memory_order_relaxed)) {
	rarg->op ();
	sched_yield ();
    }
    return NULL;
}

static void *
race_writer (void *arg)
{
    struct race_writer_arg *warg = (struct race_writer_arg *)arg;

    while (!atomic_load_explicit (&race_go, memory_order_acquire)) {
	sched_yield ();
    }
    for (int i = 0; i < NUM_ITERATIONS && !atomic_load_explicit (&race_stop, memory_order_relaxed); i++) {
	warg->op (warg->config);
    }
    atomic_store_explicit (&race_stop, 1, memory_order_relaxed);
    return NULL;
}

static void
default_writer_op (FcConfig *config)
{
    FcConfigAppFontAddFile (config, (const FcChar8 *)FONTFILE);
}

static inline int
run_font_race_test_full (fc_race_reader_op_t reader_op, fc_race_writer_op_t writer_op)
{
    pthread_t		   readers[NUM_READERS];
    pthread_t		   w;
    FcConfig		  *config;
    FcFontSet		  *app_set;
    struct race_reader_arg rarg;
    struct race_writer_arg warg;
    int			   i;

    config = FcConfigCreate ();
    if (!config) {
	fprintf (stderr, "FcConfigCreate failed\n");
	return 1;
    }
    if (!FcConfigParseAndLoadFromMemory (config, (const FcChar8 *)"<fontconfig></fontconfig>", FcTrue)) {
	fprintf (stderr, "FcConfigParseAndLoadFromMemory failed\n");
	return 1;
    }
    if (!FcConfigSetCurrent (config)) {
	fprintf (stderr, "FcConfigSetCurrent failed\n");
	return 1;
    }
    FcConfigDestroy (config);
    config = FcConfigGetCurrent ();

    if (!FcConfigAppFontAddFile (config, (const FcChar8 *)FONTFILE)) {
	fprintf (stderr, "FcConfigAppFontAddFile failed for %s\n", FONTFILE);
	return 1;
    }

    app_set = FcConfigGetFonts (config, FcSetApplication);
    if (!app_set || app_set->nfont < 1) {
	fprintf (stderr, "Application font set is empty\n");
	return 1;
    }

    atomic_init (&race_go, 0);
    atomic_init (&race_stop, 0);

    rarg.op = reader_op;
    warg.op = writer_op;
    warg.config = config;

    for (i = 0; i < NUM_READERS; i++) {
	if (pthread_create (&readers[i], NULL, race_reader, &rarg) != 0) {
	    fprintf (stderr, "Failed to create reader thread %d\n", i);
	    return 1;
	}
    }
    if (pthread_create (&w, NULL, race_writer, &warg) != 0) {
	fprintf (stderr, "Failed to create writer thread\n");
	return 1;
    }

    atomic_store_explicit (&race_go, 1, memory_order_release);

    pthread_join (w, NULL);
    atomic_store_explicit (&race_stop, 1, memory_order_relaxed);
    for (i = 0; i < NUM_READERS; i++) {
	pthread_join (readers[i], NULL);
    }

    FcFini ();
    return 0;
}

static inline int
run_font_race_test (fc_race_reader_op_t reader_op)
{
    return run_font_race_test_full (reader_op, default_writer_op);
}

#endif /* TEST_MT_RACE_H */
