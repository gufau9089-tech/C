/* Copyright (C) 2026 fontconfig Authors */
/* SPDX-License-Identifier: HPND */

#define _GNU_SOURCE 1

#include <fontconfig/fontconfig.h>

#include <dirent.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

#define FILE1 SRCDIR "/4x6.pcf"
#define DIR1  SRCDIR

/* Best-effort recursive removal of a temporary directory. */
static void
rmrf (const char *path)
{
    DIR           *d = opendir (path);
    struct dirent *e;
    char           child[512];

    if (d) {
	while ((e = readdir (d)) != NULL) {
	    struct stat st;

	    if (strcmp (e->d_name, ".") == 0 || strcmp (e->d_name, "..") == 0)
		continue;
	    snprintf (child, sizeof child, "%s/%s", path, e->d_name);
	    if (stat (child, &st) == 0 && S_ISDIR (st.st_mode))
		rmrf (child);
	    else
		unlink (child);
	}
	closedir (d);
    }
    rmdir (path);
}

static int
list_equals (FcStrList *l, const char **expect, int n)
{
    FcChar8 *s;
    int      i = 0;

    if (!l)
	return 0;
    while ((s = FcStrListNext (l))) {
	if (i >= n || strcmp ((const char *) s, expect[i]) != 0) {
	    fprintf (stderr, "  entry %d: got '%s'\n", i, (const char *) s);
	    FcStrListDone (l);
	    return 0;
	}
	i++;
    }
    FcStrListDone (l);
    return i == n;
}

/* An FcConfig with a private cachedir (returned in @cachedir, which the
 * caller must rmrf()), so directory scans never touch the production cache. */
static FcConfig *
new_config (char *cachedir)
{
    FcConfig *c;
    char      buf[256];

    strcpy (cachedir, "/tmp/fc-appfont-XXXXXX");
    if (!mkdtemp (cachedir)) {
	cachedir[0] = '\0';
	return NULL;
    }
    c = FcConfigCreate ();
    if (!c)
	return NULL;
    snprintf (buf, sizeof buf,
              "<fontconfig><cachedir>%s</cachedir></fontconfig>", cachedir);
    if (!FcConfigParseAndLoadFromMemory (c, (const FcChar8 *) buf, FcTrue)) {
	FcConfigDestroy (c);
	return NULL;
    }
    return c;
}

static int
copy_file (const char *src, const char *dst)
{
    FILE  *in = fopen (src, "rb"), *out;
    char   buf[4096];
    size_t n;
    int    ok = 0;

    if (!in)
	return 0;
    if (!(out = fopen (dst, "wb"))) {
	fclose (in);
	return 0;
    }
    while ((n = fread (buf, 1, sizeof buf, in)) > 0)
	if (fwrite (buf, 1, n, out) != n)
	    goto done;
    ok = 1;
done:
    fclose (in);
    fclose (out);
    return ok;
}

/* fresh config: empty list, not NULL-deref */
static int
test_empty (void)
{
    char      cachedir[64];
    FcConfig *c = new_config (cachedir);
    int       ret = c && list_equals (FcConfigGetAppFonts (c), NULL, 0) ? 0 : 1;

    if (ret)
	fprintf (stderr, "test_empty: expected empty list\n");
    if (c)
	FcConfigDestroy (c);
    if (cachedir[0])
	rmrf (cachedir);
    return ret;
}

/* getter returns what was added, in add order; clear empties it */
static int
test_get_app_fonts (void)
{
    char        cachedir[64];
    FcConfig   *c = new_config (cachedir);
    const char *expect[2] = { FILE1, DIR1 };
    int         ret = 1;

    if (!c)
	goto out;
    if (!FcConfigAppFontAddFile (c, (const FcChar8 *) FILE1) ||
        !FcConfigAppFontAddDir (c, (const FcChar8 *) DIR1)) {
	fprintf (stderr, "test_get_app_fonts: add failed\n");
	goto out;
    }
    if (!list_equals (FcConfigGetAppFonts (c), expect, 2)) {
	fprintf (stderr, "test_get_app_fonts: order/content mismatch\n");
	goto out;
    }
    FcConfigAppFontClear (c);
    if (!list_equals (FcConfigGetAppFonts (c), NULL, 0)) {
	fprintf (stderr, "test_get_app_fonts: not empty after clear\n");
	goto out;
    }
    ret = 0;
out:
    if (c)
	FcConfigDestroy (c);
    if (cachedir[0])
	rmrf (cachedir);
    return ret;
}

/* a file passed to AddDir and a dir passed to AddFile are recorded
 * the same as if the correct entry point were used */
static int
test_cross_validation (void)
{
    char        cachedir[64];
    FcConfig   *c = new_config (cachedir);
    const char *expect[2] = { FILE1, DIR1 };
    int         ret = 1;

    if (!c)
	goto out;
    if (!FcConfigAppFontAddDir (c, (const FcChar8 *) FILE1) ||  /* file -> AddFile */
        !FcConfigAppFontAddFile (c, (const FcChar8 *) DIR1)) {  /* dir  -> AddDir  */
	fprintf (stderr, "test_cross_validation: add failed\n");
	goto out;
    }
    if (!list_equals (FcConfigGetAppFonts (c), expect, 2)) {
	fprintf (stderr, "test_cross_validation: mismatch\n");
	goto out;
    }
    ret = 0;
out:
    if (c)
	FcConfigDestroy (c);
    if (cachedir[0])
	rmrf (cachedir);
    return ret;
}

/* the same path added twice appears once */
static int
test_dedup (void)
{
    char        cachedir[64];
    FcConfig   *c = new_config (cachedir);
    const char *expect[1] = { FILE1 };
    int         ret = 1;

    if (!c)
	goto out;
    if (!FcConfigAppFontAddFile (c, (const FcChar8 *) FILE1) ||
        !FcConfigAppFontAddFile (c, (const FcChar8 *) FILE1)) {
	fprintf (stderr, "test_dedup: add failed\n");
	goto out;
    }
    if (!list_equals (FcConfigGetAppFonts (c), expect, 1)) {
	fprintf (stderr, "test_dedup: expected single entry\n");
	goto out;
    }
    ret = 0;
out:
    if (c)
	FcConfigDestroy (c);
    if (cachedir[0])
	rmrf (cachedir);
    return ret;
}

/* Global reinit: app fonts survive in add order and remain usable;
 * a vanished file is dropped best-effort without failing reinit. */
static int
test_reinit (void)
{
    char        tmpl[] = "/tmp/fc-appfont-reinit-XXXXXX";
    char        conf[320], extra[320];
    const char *before[3];
    const char *after[2] = { FILE1, DIR1 };
    FcFontSet  *fs;
    FILE       *fp;
    FcBool      inited = FcFalse;
    int         ret = 1;

    if (!mkdtemp (tmpl))
	return 1;
    snprintf (conf, sizeof conf, "%s/fonts.conf", tmpl);
    snprintf (extra, sizeof extra, "%s/extra.pcf", tmpl);
    if (!(fp = fopen (conf, "w")))
	goto out;
    fprintf (fp, "<fontconfig><cachedir>%s</cachedir></fontconfig>\n", tmpl);
    fclose (fp);
    setenv ("FONTCONFIG_FILE", conf, 1);

    if (!FcInit ())
	goto out;
    inited = FcTrue;
    if (!copy_file (FILE1, extra))
	goto out;

    /* interleave file, dir, file so a dirs-then-files replay would reorder */
    if (!FcConfigAppFontAddFile (NULL, (const FcChar8 *) FILE1) ||
        !FcConfigAppFontAddDir (NULL, (const FcChar8 *) DIR1) ||
        !FcConfigAppFontAddFile (NULL, (const FcChar8 *) extra)) {
	fprintf (stderr, "test_reinit: add failed\n");
	goto out;
    }
    before[0] = FILE1;
    before[1] = DIR1;
    before[2] = extra;
    if (!list_equals (FcConfigGetAppFonts (NULL), before, 3)) {
	fprintf (stderr, "test_reinit: order wrong before reinit\n");
	goto out;
    }

    /* remove the extra font, then reinitialize */
    unlink (extra);
    if (!FcInitReinitialize ()) {
	fprintf (stderr, "test_reinit: reinit failed\n");
	goto out;
    }

    /* order preserved, vanished file dropped */
    if (!list_equals (FcConfigGetAppFonts (NULL), after, 2)) {
	fprintf (stderr, "test_reinit: order/content wrong after reinit\n");
	goto out;
    }
    /* fonts are actually usable, not just recorded */
    fs = FcConfigGetFonts (FcConfigGetCurrent (), FcSetApplication);
    if (!fs || fs->nfont == 0) {
	fprintf (stderr, "test_reinit: application font set empty\n");
	goto out;
    }
    ret = 0;
out:
    if (inited)
	FcFini ();
    rmrf (tmpl);
    return ret;
}

int
main (void)
{
    if (test_empty ())
	return 1;
    if (test_get_app_fonts ())
	return 1;
    if (test_cross_validation ())
	return 1;
    if (test_dedup ())
	return 1;
    if (test_reinit ()) /* keep last: FcInit/FcFini are global */
	return 1;

    return 0;
}
