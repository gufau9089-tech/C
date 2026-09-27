/* Copyright (C) 2026 fontconfig Authors */
/* SPDX-License-Identifier: HPND */
#ifdef HAVE_CONFIG_H
#  include "config.h"
#endif
#ifdef HAVE_DIRENT_H
#  include <dirent.h>
#endif
#include <errno.h>
#include <fcntl.h>
#include <inttypes.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/types.h>
#ifdef HAVE_UNISTD_H
#  include <unistd.h>
#endif
#include "fcint.h"

#ifdef _WIN32
#  define FC_DIR_SEPARATOR   '\\'
#  define FC_DIR_SEPARATOR_S "\\"
#else
#  define FC_DIR_SEPARATOR   '/'
#  define FC_DIR_SEPARATOR_S "/"
#endif

#ifdef _WIN32
#  include <direct.h>
#  define mkdir(path, mode) _mkdir (path)

int
setenv (const char *name, const char *value, int o)
{
    size_t len = strlen (name) + strlen (value) + 1;
    char  *s = malloc (len + 1);
    int    ret;

    snprintf (s, len, "%s=%s", name, value);
    ret = _putenv (s);
    free (s);
    return ret;
}

void
unsetenv (const char *name)
{
    size_t len = strlen (name) + 1;
    char  *s = malloc (len + 1);

    snprintf (s, len + 1, "%s=", name);
    _putenv (s);
    free (s);
}
#endif

#ifdef HAVE_MKDTEMP
#  define fc_mkdtemp mkdtemp
#else
char *
fc_mkdtemp (char *template)
{
    if (!mktemp (template) || mkdir (template, 0700))
	return NULL;

    return template;
}
#endif

FcBool
unlink_dirs (const char *dir)
{
    DIR           *d = opendir (dir);
    struct dirent *e;
    size_t         len = strlen (dir);
    char          *n = NULL;
    FcBool         ret = FcTrue;
#ifndef HAVE_STRUCT_DIRENT_D_TYPE
    struct stat statb;
#endif

    if (!d)
	return FcFalse;
    while ((e = readdir (d)) != NULL) {
	size_t l;

	if (strcmp (e->d_name, ".") == 0 ||
	    strcmp (e->d_name, "..") == 0)
	    continue;
	l = strlen (e->d_name) + 1;
	if (n)
	    free (n);
	n = malloc (l + len + 1);
	if (!n) {
	    ret = FcFalse;
	    break;
	}
	strcpy (n, dir);
	n[len] = FC_DIR_SEPARATOR;
	strcpy (&n[len + 1], e->d_name);
#ifdef HAVE_STRUCT_DIRENT_D_TYPE
	if (e->d_type == DT_DIR)
#else
	if (stat (n, &statb) == -1) {
	    ret = FcFalse;
	    break;
	}
	if (S_ISDIR (statb.st_mode))
#endif
	{
	    if (!unlink_dirs (n)) {
		ret = FcFalse;
		break;
	    }
	} else {
	    if (unlink (n) == -1) {
		fprintf (stderr, "E: %s\n", n);
		ret = FcFalse;
		break;
	    }
	}
    }
    if (n)
	free (n);
    closedir (d);

    if (rmdir (dir) == -1) {
	fprintf (stderr, "E: %s\n", dir);
	return FcFalse;
    }

    return ret;
}

#ifndef _WIN32
static int
test_cache_checksum (const FcChar8 *fontdir, FcConfig *cfg,
                     int64_t expected_mtime)
{
    FcCache *cache;
    int64_t  cache_mtime;

    cache = FcDirCacheRead (fontdir, FcFalse, cfg);
    if (!cache) {
	fprintf (stderr, "Failed to read cache\n");
	return 0;
    }

    cache_mtime = ((int64_t)cache->checksum_hi << 32) | cache->checksum;

    fprintf (stderr, "  checksum=%" PRIu32 " checksum_hi=%" PRIu32 " reconstructed=%" PRIi64 "\n",
             cache->checksum, cache->checksum_hi, cache_mtime);

    if (cache_mtime != expected_mtime) {
	fprintf (stderr, "mtime mismatch: cache=%" PRIi64 " expected=%" PRIi64 "\n",
	         cache_mtime, expected_mtime);
	FcDirCacheUnload (cache);
	return 0;
    }

    FcDirCacheUnload (cache);
    return 1;
}
#endif

int
main (void)
{
    FcConfig      *cfg = FcConfigCreate();
    char          *basedir = NULL;
    char           template[512];
    FcChar8       *fontdir = NULL, *cachedir = NULL;
    const FcChar8 *doc = (const FcChar8 *)
	"<fontconfig>\n"
	"  <dir>%s</dir>\n"
	"  <cachedir>%s</cachedir>\n"
	"</fontconfig>\n";
    char conf[1024];
    int  retval = 1;

#ifdef _WIN32
    {
	const char *tmpdir = getenv ("TEMP");

	if (!tmpdir)
	    tmpdir = getenv ("TMP");
	if (!tmpdir)
	    tmpdir = ".";
	snprintf (template, sizeof (template),
	          "%s" FC_DIR_SEPARATOR_S "fcy2038-XXXXXX", tmpdir);
    }
#else
    strcpy (template, "/tmp/fcy2038-XXXXXX");
#endif
    basedir = fc_mkdtemp (template);
    if (!basedir) {
	fprintf (stderr, "%s: %s\n", template, strerror (errno));
	goto bail;
    }
    fontdir = FcStrBuildFilename ((const FcChar8 *)basedir, (const FcChar8 *)"fonts", NULL);
    cachedir = FcStrBuildFilename ((const FcChar8 *)basedir, (const FcChar8 *)"cache", NULL);
    mkdir ((const char *)fontdir, 0755);
    mkdir ((const char *)cachedir, 0755);
    snprintf (conf, sizeof (conf), (const char *)doc, fontdir, cachedir);
    if (!FcConfigParseAndLoadFromMemory (cfg, (const FcChar8 *)conf, FcFalse)) {
	fprintf (stderr, "%s: Unable to load a config\n", basedir);
	goto bail;
    }

    unsetenv ("SOURCE_DATE_EPOCH");

#ifndef _WIN32
    /* Test 1: pre-2038 with known mtime */
    {
	struct timespec times[2];
	int64_t         pre2038 = 1700000000LL;

	times[0].tv_sec = pre2038;
	times[0].tv_nsec = 0;
	times[1].tv_sec = pre2038;
	times[1].tv_nsec = 0;
	if (utimensat (AT_FDCWD, (const char *)fontdir, times, 0) == -1) {
	    fprintf (stderr, "utimensat failed: %s\n", strerror (errno));
	    goto bail;
	}
	fprintf (stderr, "Test 1: pre-2038 mtime=%" PRIi64 "\n",
	         pre2038);
	if (!test_cache_checksum (fontdir, cfg, pre2038)) {
	    fprintf (stderr, "FAIL: pre-2038 checksum test\n");
	    goto bail;
	}
	fprintf (stderr, "PASS: pre-2038 checksum test\n");
    }

    /* Test 2: post-2038 with known mtime */
    {
	struct timespec times[2];
	int64_t         post2038 = 2150000000LL;

	times[0].tv_sec = post2038;
	times[0].tv_nsec = 0;
	times[1].tv_sec = post2038;
	times[1].tv_nsec = 0;
	if (utimensat (AT_FDCWD, (const char *)fontdir, times, 0) == -1) {
	    fprintf (stderr, "utimensat failed: %s (skipping post-2038 test)\n",
	             strerror (errno));
	    retval = 0;
	    goto bail;
	}
	fprintf (stderr, "Test 2: post-2038 mtime=%" PRIi64 "\n",
	         post2038);
	if (!test_cache_checksum (fontdir, cfg, post2038)) {
	    fprintf (stderr, "FAIL: post-2038 checksum test\n");
	    goto bail;
	}
	fprintf (stderr, "PASS: post-2038 checksum test\n");
    }
#else
    fprintf (stderr, "Tests skipped (utimensat not available on Windows)\n");
#endif

    retval = 0;
bail:
    if (fontdir)
	FcStrFree (fontdir);
    if (cachedir)
	FcStrFree (cachedir);
    if (basedir)
	unlink_dirs (basedir);
    FcConfigDestroy (cfg);

    return retval;
}
