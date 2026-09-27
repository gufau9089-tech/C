/* Copyright (C) 2026 fontconfig Authors */
/* SPDX-License-Identifier: HPND */

#include "test-mt-race.h"

static void
reader_match (void)
{
    FcPattern *pattern = FcPatternCreate ();
    if (!pattern)
	return;
    FcPatternAddString (pattern, FC_LANG, (const FcChar8 *)"xx");
    FcPatternAddBool (pattern, FC_SCALABLE, FcTrue);
    FcConfigSubstitute (NULL, pattern, FcMatchPattern);
    FcDefaultSubstitute (pattern);
    FcResult   result;
    FcPattern *match = FcFontMatch (NULL, pattern, &result);
    if (match)
	FcPatternDestroy (match);
    FcPatternDestroy (pattern);
}

int
main (int argc, char **argv)
{
    return run_font_race_test (reader_match);
}
