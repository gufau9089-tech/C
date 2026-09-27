/* Copyright (C) 2026 fontconfig Authors */
/* SPDX-License-Identifier: HPND */
/* Build-only throughput/scaling benchmark for cache-backed pattern access.
 * Not installed, not a pass/fail test -- an A/B measurement tool.
 *
 * Hammers FcPatternGet / FcFontSort over cache-resident (const) patterns,
 * single- and multi-threaded, to measure the cost and thread-scaling of the
 * cache hot path.  Useful to catch hot-path serialization regressions.
 *
 * Usage: bench-cache <get|sort> <threads> <iters> [fontdir]
 *   fontdir  a directory of fonts to build a cache from (e.g. the meson
 *            "testfonts" target).  Using a fixed font set makes results
 *            reproducible and comparable across runs/versions.  If omitted,
 *            falls back to the system font set (not hermetic).
 */
#ifdef HAVE_CONFIG_H
#  include <config.h>
#endif
#include <errno.h>
#include <fontconfig/fontconfig.h>
#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <time.h>
#include <unistd.h>

#ifdef _WIN32
#  include <direct.h>
#  define mkdir(path, mode) _mkdir (path)
#endif

#ifdef HAVE_MKDTEMP
#  define fc_mkdtemp mkdtemp
#else
static char *
fc_mkdtemp (char *template)
{
    if (!mktemp (template) || mkdir (template, 0700))
	return NULL;

    return template;
}
#endif

static FcFontSet  *g_fs;
static FcConfig   *g_config;
static int         g_iters;
static const char *g_mode;

static long long
now_ns (void)
{
    struct timespec ts;
    clock_gettime (CLOCK_MONOTONIC, &ts);
    return (long long)ts.tv_sec * 1000000000LL + ts.tv_nsec;
}

static unsigned long
run_get (void)
{
    unsigned long ops = 0;
    int           it, i;

    for (it = 0; it < g_iters; it++) {
	for (i = 0; i < g_fs->nfont; i++) {
	    FcPattern *f = g_fs->fonts[i];
	    FcChar8   *s;
	    int        n;

	    FcPatternGetString (f, FC_FILE, 0, &s);
	    FcPatternGetString (f, FC_FAMILY, 0, &s);
	    FcPatternGetInteger (f, FC_INDEX, 0, &n);
	    ops += 3;
	}
    }
    return ops;
}

static unsigned long
run_sort (void)
{
    unsigned long ops = 0;
    int           it;

    for (it = 0; it < g_iters; it++) {
	FcPattern *pat = FcNameParse ((const FcChar8 *)"sans-serif");
	FcResult   res;
	FcFontSet *sorted;

	FcConfigSubstitute (g_config, pat, FcMatchPattern);
	FcDefaultSubstitute (pat);
	sorted = FcFontSort (g_config, pat, FcTrue, NULL, &res);
	if (sorted)
	    FcFontSetSortDestroy (sorted);
	FcPatternDestroy (pat);
	ops += 1;
    }
    return ops;
}

static void *
worker (void *arg)
{
    unsigned long *out = arg;
    *out = (strcmp (g_mode, "sort") == 0) ? run_sort() : run_get();
    return NULL;
}

/* Build a config + cache over *fontdir* and return its font set. */
static FcFontSet *
setup_from_fontdir (const char *fontdir)
{
    static char tmpl[] = "/tmp/fcbench-XXXXXX";
    char       *cachedir = fc_mkdtemp (tmpl);
    char        conf[1024];
    const char *doc =
	"<fontconfig>\n  <dir>%s</dir>\n  <cachedir>%s</cachedir>\n</fontconfig>\n";

    if (!cachedir) {
	fprintf (stderr, "mkdtemp: %s\n", strerror (errno));
	return NULL;
    }
    g_config = FcConfigCreate();
    snprintf (conf, sizeof (conf), doc, fontdir, cachedir);
    if (!FcConfigParseAndLoadFromMemory (g_config, (const FcChar8 *)conf, FcTrue) ||
        !FcConfigBuildFonts (g_config)) {
	fprintf (stderr, "failed to build fonts from %s\n", fontdir);
	return NULL;
    }
    return FcConfigGetFonts (g_config, FcSetSystem);
}

int
main (int argc, char **argv)
{
    int           nthreads = argc > 2 ? atoi (argv[2]) : 1;
    const char   *fontdir = argc > 4 ? argv[4] : NULL;
    long long     t0, t1;
    unsigned long total = 0;
    double        secs;
    int           t;

    g_mode = argc > 1 ? argv[1] : "get";
    g_iters = argc > 3 ? atoi (argv[3]) : 100;
    if (nthreads < 1)
	nthreads = 1;

    if (!FcInit()) {
	fprintf (stderr, "FcInit failed\n");
	return 1;
    }
    if (fontdir)
	g_fs = setup_from_fontdir (fontdir);
    else {
	g_config = FcConfigGetCurrent();
	g_fs = FcConfigGetFonts (g_config, FcSetSystem);
    }
    if (!g_fs || g_fs->nfont == 0) {
	fprintf (stderr, "no fonts (%s)\n", fontdir ? fontdir : "system");
	return 1;
    }
    fprintf (stderr, "mode=%s threads=%d iters=%d nfont=%d source=%s\n",
             g_mode, nthreads, g_iters, g_fs->nfont, fontdir ? fontdir : "system");

    run_get(); /* warm up: map caches, fault in patterns */

    {
	pthread_t     th[64];
	unsigned long counts[64];

	if (nthreads > 64)
	    nthreads = 64;
	t0 = now_ns();
	for (t = 0; t < nthreads; t++)
	    pthread_create (&th[t], NULL, worker, &counts[t]);
	for (t = 0; t < nthreads; t++) {
	    pthread_join (th[t], NULL);
	    total += counts[t];
	}
	t1 = now_ns();
    }

    secs = (t1 - t0) / 1e9;
    printf ("%s threads=%d ops=%lu time=%.3fs  %.2f Mops/s  %.1f ns/op\n",
            g_mode, nthreads, total, secs,
            total / secs / 1e6, secs * 1e9 / total);
    return 0;
}
