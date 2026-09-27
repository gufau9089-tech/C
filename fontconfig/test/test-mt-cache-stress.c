/* Copyright (C) 2026 fontconfig Authors */
/* SPDX-License-Identifier: HPND */
/*
 * Multithreaded stress test for the cache skip list (FcCacheFindByAddr path).
 * POSIX/pthread only (registered non-Windows in meson.build).
 *
 * Reader threads hammer FcFontSort over cache-resident (const) patterns --
 * every access walks the global cache skip list.  Writer threads concurrently
 * load and unload caches (FcConfigCreate + BuildFonts + Destroy), inserting
 * and removing nodes in that same skip list.
 *
 * With the global mutex this is race-free by construction.  It exists as the
 * correctness net for a future lock-free reader: run under ThreadSanitizer
 * (data races) and AddressSanitizer (use-after-free from reclamation bugs).
 * A lock-free reader without proper node reclamation is expected to trip TSan
 * or ASan here -- that is the test doing its job.
 */
#ifdef HAVE_CONFIG_H
#  include "config.h"
#endif
#include <dirent.h>
#include <errno.h>
#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>
#include <fontconfig/fontconfig.h>

#ifdef HAVE_MKDTEMP
#  define fc_mkdtemp mkdtemp
#else
static char *
fc_mkdtemp (char *t)
{
    if (!mktemp (t) || mkdir (t, 0700))
	return NULL;
    return t;
}
#endif

/* Recursively remove a directory tree (POSIX). */
static void
rmtree (const char *dir)
{
    DIR           *d = opendir (dir);
    struct dirent *e;
    char           path[4096];

    if (!d)
	return;
    while ((e = readdir (d)) != NULL) {
	struct stat st;

	if (!strcmp (e->d_name, ".") || !strcmp (e->d_name, ".."))
	    continue;
	snprintf (path, sizeof (path), "%s/%s", dir, e->d_name);
	if (stat (path, &st) == 0 && S_ISDIR (st.st_mode))
	    rmtree (path);
	else
	    unlink (path);
    }
    closedir (d);
    rmdir (dir);
}

static FcConfig    *g_read_config; /* long-lived; readers use its caches */
static char         g_conf[1024];  /* writer config XML (fontdir/cachedir) */
static int          g_read_iters;
static int          g_write_iters;

static void *
reader (void *arg)
{
    int n = 0;
    (void)arg;
    while (n++ < g_read_iters) {
	FcResult   r;
	FcPattern *pat = FcPatternBuild (NULL, FC_FAMILY, FcTypeString,
	                                 (const FcChar8 *)"sans-serif", NULL);
	FcFontSet *fs;

	if (!pat)
	    continue;
	FcConfigSubstitute (g_read_config, pat, FcMatchPattern);
	FcDefaultSubstitute (pat);
	/* FcFontSort touches every candidate's cached elts -> heavy skip-list
	 * traffic via FcPatternEltStride/FcCacheFindByAddr. */
	fs = FcFontSort (g_read_config, pat, FcTrue, NULL, &r);
	if (fs)
	    FcFontSetSortDestroy (fs);
	FcPatternDestroy (pat);
    }
    return NULL;
}

static void *
writer (void *arg)
{
    int n = 0;
    (void)arg;
    while (n++ < g_write_iters) {
	FcConfig *c = FcConfigCreate();

	if (!c)
	    continue;
	/* Load then drop caches -> skip-list insert then remove, concurrent
	 * with readers walking the list. */
	if (FcConfigParseAndLoadFromMemory (c, (const FcChar8 *)g_conf, FcTrue))
	    FcConfigBuildFonts (c);
	FcConfigDestroy (c);
    }
    return NULL;
}

int
main (int argc, char **argv)
{
    int         nread = argc > 1 ? atoi (argv[1]) : 6;
    int         nwrite = argc > 2 ? atoi (argv[2]) : 2;
    pthread_t   th[64];
    int         i, t = 0, ret = 1;
    char        tmpl[] = "/tmp/fcmtstress-XXXXXX";
    char       *base;
    FcChar8    *fontdir = NULL, *cachedir = NULL;
    const char *doc =
	"<fontconfig>\n  <dir>%s</dir>\n  <cachedir>%s</cachedir>\n</fontconfig>\n";

    g_read_iters = argc > 3 ? atoi (argv[3]) : 400;
    g_write_iters = argc > 4 ? atoi (argv[4]) : 400;
    if (nread + nwrite > 64) { nread = 48; nwrite = 16; }

    if (!FcInit()) {
	fprintf (stderr, "FcInit failed\n");
	return 1;
    }
    g_read_config = FcConfigGetCurrent();

    base = fc_mkdtemp (tmpl);
    if (!base) { fprintf (stderr, "mkdtemp: %s\n", strerror (errno)); goto bail; }
    fontdir = FcStrBuildFilename ((const FcChar8 *)base, (const FcChar8 *)"fonts", NULL);
    cachedir = FcStrBuildFilename ((const FcChar8 *)base, (const FcChar8 *)"cache", NULL);
    mkdir ((const char *)fontdir, 0755);
    mkdir ((const char *)cachedir, 0755);
#ifdef FONTFILE
    {
	FcChar8 *dst = FcStrBuildFilename (fontdir, (const FcChar8 *)"seed.pcf", NULL);
	FILE    *in = fopen (FONTFILE, "rb"), *out = dst ? fopen ((char *)dst, "wb") : NULL;
	char     buf[8192];
	size_t   nr;

	if (in && out)
	    while ((nr = fread (buf, 1, sizeof (buf), in)) > 0)
		if (fwrite (buf, 1, nr, out) != nr)
		    break;
	if (in) fclose (in);
	if (out) fclose (out);
	if (dst) FcStrFree (dst);
    }
#endif
    snprintf (g_conf, sizeof (g_conf), doc, (const char *)fontdir, (const char *)cachedir);

    for (i = 0; i < nwrite; i++)
	if (pthread_create (&th[t], NULL, writer, NULL) == 0) t++;
    for (i = 0; i < nread; i++)
	if (pthread_create (&th[t], NULL, reader, NULL) == 0) t++;
    for (i = 0; i < t; i++)
	pthread_join (th[i], NULL);

    fprintf (stderr, "PASS: %d readers, %d writers, no crash\n", nread, nwrite);
    ret = 0;
bail:
    if (fontdir) FcStrFree (fontdir);
    if (cachedir) FcStrFree (cachedir);
    if (base) rmtree (base);
    FcFini();
    return ret;
}
