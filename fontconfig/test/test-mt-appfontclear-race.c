/* Copyright (C) 2026 fontconfig Authors */
/* SPDX-License-Identifier: HPND */

#include "test-mt-race.h"

static void
reader_clear_race (void)
{
    FcPattern *pattern = FcPatternCreate ();
    if (!pattern)
	return;
    FcPatternAddString (pattern, FC_LANG, (const FcChar8 *)"xx");
    FcPatternAddBool (pattern, FC_SCALABLE, FcTrue);
    FcConfigSubstitute (NULL, pattern, FcMatchPattern);
    FcDefaultSubstitute (pattern);
    FcResult   result;
    FcFontSet *fs = FcFontSort (NULL, pattern, FcFalse, NULL, &result);
    if (fs)
	FcFontSetDestroy (fs);
    FcPattern *match = FcFontMatch (NULL, pattern, &result);
    if (match)
	FcPatternDestroy (match);
    FcPatternDestroy (pattern);
}

static void
writer_clear (FcConfig *config)
{
    FcConfigAppFontAddFile (config, (const FcChar8 *)FONTFILE);
    FcConfigAppFontClear (config);
}

int
main (int argc, char **argv)
{
    return run_font_race_test_full (reader_clear_race, writer_clear);
}
