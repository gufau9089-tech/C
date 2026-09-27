/* Copyright (C) 2026 fontconfig Authors */
/* SPDX-License-Identifier: HPND */

#include "test-mt-race.h"

static void
reader_list (void)
{
    FcPattern *pattern = FcPatternCreate ();
    if (!pattern)
	return;
    FcObjectSet *os = FcObjectSetBuild (FC_FAMILY, FC_STYLE, FC_LANG, (char *)0);
    FcFontSet   *fs = FcFontList (NULL, pattern, os);
    if (fs)
	FcFontSetDestroy (fs);
    if (os)
	FcObjectSetDestroy (os);
    FcPatternDestroy (pattern);
}

int
main (int argc, char **argv)
{
    return run_font_race_test (reader_list);
}
