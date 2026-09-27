/*
 * fontconfig/test/test-versioned-conf.c
 *
 * Copyright © 2026 fontconfig Authors
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

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static int
check_match_rule (const char *conf)
{
    FcConfig  *cfg = FcConfigCreate ();
    FcPattern *pat;
    double     pixelsize = 0;
    int        applied;

    if (!FcConfigParseAndLoadFromMemory (cfg, (const FcChar8 *)conf, FcTrue)) {
	FcConfigDestroy (cfg);
	return -1;
    }
    pat = FcPatternCreate ();
    FcConfigSubstitute (cfg, pat, FcMatchPattern);
    applied = (FcPatternGetDouble (pat, FC_PIXEL_SIZE, 0, &pixelsize) == FcResultMatch &&
               pixelsize == 99.0);
    FcPatternDestroy (pat);
    FcConfigDestroy (cfg);
    return applied ? 1 : 0;
}

static int
check_alias_rule (const char *conf)
{
    FcConfig  *cfg = FcConfigCreate ();
    FcPattern *pat;
    FcChar8   *family = NULL;
    int        applied;

    if (!FcConfigParseAndLoadFromMemory (cfg, (const FcChar8 *)conf, FcTrue)) {
	FcConfigDestroy (cfg);
	return -1;
    }
    pat = FcPatternCreate ();
    FcPatternAddString (pat, FC_FAMILY, (const FcChar8 *)"sans-serif");
    FcConfigSubstitute (cfg, pat, FcMatchPattern);
    applied = (FcPatternGetString (pat, FC_FAMILY, 0, &family) == FcResultMatch &&
               strcmp ((const char *)family, "TestFont") == 0);
    FcPatternDestroy (pat);
    FcConfigDestroy (cfg);
    return applied ? 1 : 0;
}

#define EXPECT(test_num, desc, got, expected)                                       \
    do {                                                                            \
	if ((got) != (expected)) {                                                  \
	    fprintf (stderr, "FAIL %d: %s (got %d, expected %d)\n",                 \
	             (test_num), (desc), (got), (expected));                         \
	    ret = 1;                                                                \
	}                                                                           \
    } while (0)

int
main (void)
{
    char conf[2048];
    char ver[64];
    int  ret = 0;

    snprintf (ver, sizeof (ver), "%d.%d.%d", FC_MAJOR, FC_MINOR, FC_REVISION);

    /* no since attr — rules applied */
    EXPECT (1, "no since attr",
            check_match_rule (
                "<fontconfig>\n"
                "  <match target=\"pattern\">\n"
                "    <edit name=\"pixelsize\" mode=\"assign\"><double>99</double></edit>\n"
                "  </match>\n"
                "</fontconfig>\n"),
            1);

    /* <fontconfig since="0.0.1"> — current >= 0.0.1, rules applied */
    EXPECT (2, "fontconfig since old version",
            check_match_rule (
                "<fontconfig since=\"0.0.1\">\n"
                "  <match target=\"pattern\">\n"
                "    <edit name=\"pixelsize\" mode=\"assign\"><double>99</double></edit>\n"
                "  </match>\n"
                "</fontconfig>\n"),
            1);

    /* <fontconfig since="99.0.0"> — current < 99.0.0, rules skipped */
    EXPECT (3, "fontconfig since future version",
            check_match_rule (
                "<fontconfig since=\"99.0.0\">\n"
                "  <match target=\"pattern\">\n"
                "    <edit name=\"pixelsize\" mode=\"assign\"><double>99</double></edit>\n"
                "  </match>\n"
                "</fontconfig>\n"),
            0);

    /* <fontconfig since="current"> — current >= current, rules applied */
    snprintf (conf, sizeof (conf),
              "<fontconfig since=\"%s\">\n"
              "  <match target=\"pattern\">\n"
              "    <edit name=\"pixelsize\" mode=\"assign\"><double>99</double></edit>\n"
              "  </match>\n"
              "</fontconfig>\n",
              ver);
    EXPECT (4, "fontconfig since current version", check_match_rule (conf), 1);

    /* <match since="0.0.1"> — matching, rule applied */
    EXPECT (5, "match since old version",
            check_match_rule (
                "<fontconfig>\n"
                "  <match target=\"pattern\" since=\"0.0.1\">\n"
                "    <edit name=\"pixelsize\" mode=\"assign\"><double>99</double></edit>\n"
                "  </match>\n"
                "</fontconfig>\n"),
            1);

    /* <match since="99.0.0"> — non-matching, rule skipped */
    EXPECT (6, "match since future version",
            check_match_rule (
                "<fontconfig>\n"
                "  <match target=\"pattern\" since=\"99.0.0\">\n"
                "    <edit name=\"pixelsize\" mode=\"assign\"><double>99</double></edit>\n"
                "  </match>\n"
                "</fontconfig>\n"),
            0);

    /* <match since="current"> — matching, rule applied */
    snprintf (conf, sizeof (conf),
              "<fontconfig>\n"
              "  <match target=\"pattern\" since=\"%s\">\n"
              "    <edit name=\"pixelsize\" mode=\"assign\"><double>99</double></edit>\n"
              "  </match>\n"
              "</fontconfig>\n",
              ver);
    EXPECT (7, "match since current version", check_match_rule (conf), 1);

    /* <alias since="0.0.1"> — matching, alias applied */
    EXPECT (8, "alias since old version",
            check_alias_rule (
                "<fontconfig>\n"
                "  <alias since=\"0.0.1\">\n"
                "    <family>sans-serif</family>\n"
                "    <prefer><family>TestFont</family></prefer>\n"
                "  </alias>\n"
                "</fontconfig>\n"),
            1);

    /* <alias since="99.0.0"> — non-matching, alias skipped */
    EXPECT (9, "alias since future version",
            check_alias_rule (
                "<fontconfig>\n"
                "  <alias since=\"99.0.0\">\n"
                "    <family>sans-serif</family>\n"
                "    <prefer><family>TestFont</family></prefer>\n"
                "  </alias>\n"
                "</fontconfig>\n"),
            0);

    /* <alias since="current"> — matching, alias applied */
    snprintf (conf, sizeof (conf),
              "<fontconfig>\n"
              "  <alias since=\"%s\">\n"
              "    <family>sans-serif</family>\n"
              "    <prefer><family>TestFont</family></prefer>\n"
              "  </alias>\n"
              "</fontconfig>\n",
              ver);
    EXPECT (10, "alias since current version", check_alias_rule (conf), 1);

    /* invalid since format — skipped, no parse error */
    EXPECT (11, "fontconfig since invalid",
            check_match_rule (
                "<fontconfig since=\"invalid\">\n"
                "  <match target=\"pattern\">\n"
                "    <edit name=\"pixelsize\" mode=\"assign\"><double>99</double></edit>\n"
                "  </match>\n"
                "</fontconfig>\n"),
            0);

    EXPECT (12, "match since invalid",
            check_match_rule (
                "<fontconfig>\n"
                "  <match target=\"pattern\" since=\"invalid\">\n"
                "    <edit name=\"pixelsize\" mode=\"assign\"><double>99</double></edit>\n"
                "  </match>\n"
                "</fontconfig>\n"),
            0);

    /* since with only two components — invalid format */
    EXPECT (13, "match since two-component version",
            check_match_rule (
                "<fontconfig>\n"
                "  <match target=\"pattern\" since=\"2.20\">\n"
                "    <edit name=\"pixelsize\" mode=\"assign\"><double>99</double></edit>\n"
                "  </match>\n"
                "</fontconfig>\n"),
            0);

    return ret;
}
