/*
  This file is part of libmicrohttpd
  Copyright (C) 2026 Christian Grothoff

  This library is free software; you can redistribute it and/or
  modify it under the terms of the GNU Lesser General Public
  License as published by the Free Software Foundation; either
  version 2.1 of the License, or (at your option) any later version.

  This library is distributed in the hope that it will be useful,
  but WITHOUT ANY WARRANTY; without even the implied warranty of
  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
  Lesser General Public License for more details.

  You should have received a copy of the GNU Lesser General Public
  License along with this library.
  If not, see <http://www.gnu.org/licenses/>.
*/

/**
 * @file fuzz/fuzz_str.c
 * @brief Direct in-process fuzzer for the string primitives of mhd_str.c
 * @author Christian Grothoff
 *
 * Every destination buffer is obtained with malloc() at *exactly* the
 * size that the documented contract of the function under test
 * requires -- never a generous stack array.  Under AddressSanitizer the
 * redzone immediately after the allocation turns any one-byte
 * over-write into a hard error, which is precisely the property a
 * fixed-size stack buffer would not give us.
 *
 * In addition to the contract-exact calls, several functions are also
 * called with a deliberately *too small* output buffer: functions that
 * take a buffer size argument must detect this and must not write past
 * the end.
 *
 * Input format:
 *   byte 0    target selector
 *   byte 1    auxiliary parameter (buffer size shrink, split point, ...)
 *   byte 2..  payload
 */

#define FUZZ_HARNESS_NAME "fuzz_str"
#include "fuzz_common.h"

#include "mhd_options.h"
#include "mhd_str.h"

/**
 * Largest digest MHD supports; this is the size of the on-stack buffers
 * that digestauth.c passes to MHD_hex_to_bin().
 */
#define MODEL_MAX_DIGEST 32

/**
 * Model the (pre-2026) digestauth.c call site that fed a client
 * controlled, up to 4 * digest_size characters long 'response' value
 * into MHD_hex_to_bin() together with a digest_size byte buffer.
 *
 * MHD_hex_to_bin() has no output size parameter: it writes len/2 bytes,
 * so a caller with a fixed size buffer *must* bound the input length.
 * This target replays that call site with an exactly sized heap buffer
 * so that ASAN reports the overflow.  It is OFF by default (it models a
 * caller, not the library) -- enable it with MHD_FUZZ_MODEL_DIGEST_SINK=1
 * to reproduce the primitive behind the digest 'response' overflow.
 */
static int model_digest_sink;
static int model_digest_sink_read;

enum str_target
{
  TGT_HEX_TO_BIN = 0,
  TGT_BIN_TO_HEX,
  TGT_BIN_TO_HEX_Z,
  TGT_PCT_STRICT,
  TGT_PCT_LENIENT,
  TGT_PCT_IN_PLACE_STRICT,
  TGT_PCT_IN_PLACE_LENIENT,
  TGT_UNQUOTE,
  TGT_QUOTE,
  TGT_BASE64,
  TGT_TO_UINT64,
  TGT_TOKENS,
  TGT_EQUAL_CASELESS,
  TGT_DIGEST_HEX_SINK,
  TGT_COUNT
};


/**
 * Allocate exactly @a n bytes.  Zero-sized allocations are turned into
 * a one byte allocation so that the returned pointer stays valid, but
 * the harness never tells the library about that extra byte.
 */
static void *
xalloc (size_t n)
{
  void *p = malloc ((0 == n) ? 1 : n);

  if (NULL == p)
    abort ();
  return p;
}


static char *
dup_z (const uint8_t *d,
       size_t n)
{
  char *p = (char *) xalloc (n + 1);

  memcpy (p, d, n);
  p[n] = '\0';
  return p;
}


int
LLVMFuzzerTestOneInput (const uint8_t *data,
                        size_t size)
{
  enum str_target tgt;
  const uint8_t *p;
  size_t n;
  unsigned int aux;

  if (size < 3)
    return 0;
  tgt = (enum str_target) (data[0] % (unsigned int) TGT_COUNT);
  aux = data[1];
  p = data + 2;
  n = size - 2;
  /* Keep the inputs small: these are unit-level primitives and short
     inputs explore the interesting corner cases far more efficiently. */
  if (n > 512)
    n = 512;

  switch (tgt)
  {
  case TGT_HEX_TO_BIN:
    {
      /* Contract: the output buffer must be len/2 bytes long, or
         len/2 + 1 if len is odd. */
      size_t need = (n / 2) + (n % 2);
      uint8_t *out = (uint8_t *) xalloc (need);
      size_t r = MHD_hex_to_bin ((const char *) p, n, out);

      if (r > need)
        fuzz_report_finding ("MHD_hex_to_bin() reported more bytes written "
                             "than its documented output size");
      free (out);
      break;
    }

  case TGT_BIN_TO_HEX:
    {
      char *out = (char *) xalloc (2 * n);
      size_t r = MHD_bin_to_hex (p, n, out);

      if (r != 2 * n)
        fuzz_report_finding ("MHD_bin_to_hex() did not write 2 * size chars");
      free (out);
      break;
    }

  case TGT_BIN_TO_HEX_Z:
    {
      char *out = (char *) xalloc (2 * n + 1);
      size_t r = MHD_bin_to_hex_z (p, n, out);

      if (r != 2 * n)
        fuzz_report_finding ("MHD_bin_to_hex_z() did not write 2 * size chars");
      if ('\0' != out[r])
        fuzz_report_finding ("MHD_bin_to_hex_z() result is not "
                             "zero-terminated");
      free (out);
      break;
    }

  case TGT_PCT_STRICT:
    {
      /* First with the exact maximum size, then with a buffer that is
         deliberately too small. */
      char *out = (char *) xalloc (n);
      size_t r = MHD_str_pct_decode_strict_n_ ((const char *) p, n, out, n);
      size_t small;

      if (r > n)
        fuzz_report_finding ("MHD_str_pct_decode_strict_n_() overran the "
                             "documented output size");
      free (out);
      small = (0 == n) ? 0 : (n * (aux % 100u)) / 100u;
      out = (char *) xalloc (small);
      (void) MHD_str_pct_decode_strict_n_ ((const char *) p, n, out, small);
      free (out);
      break;
    }

  case TGT_PCT_LENIENT:
    {
      char *out = (char *) xalloc (n);
      bool broken = false;
      size_t r =
        MHD_str_pct_decode_lenient_n_ ((const char *) p, n, out, n, &broken);
      size_t small;

      if (r > n)
        fuzz_report_finding ("MHD_str_pct_decode_lenient_n_() overran the "
                             "documented output size");
      free (out);
      small = (0 == n) ? 0 : (n * (aux % 100u)) / 100u;
      out = (char *) xalloc (small);
      (void) MHD_str_pct_decode_lenient_n_ ((const char *) p, n, out, small,
                                            NULL);
      free (out);
      break;
    }

  case TGT_PCT_IN_PLACE_STRICT:
    {
      char *s = dup_z (p, n);
      size_t r = MHD_str_pct_decode_in_place_strict_ (s);

      if (r > n)
        fuzz_report_finding ("MHD_str_pct_decode_in_place_strict_() grew "
                             "the string");
      free (s);
      break;
    }

  case TGT_PCT_IN_PLACE_LENIENT:
    {
      char *s = dup_z (p, n);
      bool broken = false;
      size_t r = MHD_str_pct_decode_in_place_lenient_ (s, &broken);

      if (r > n)
        fuzz_report_finding ("MHD_str_pct_decode_in_place_lenient_() grew "
                             "the string");
      free (s);
      break;
    }

#ifdef DAUTH_SUPPORT
  case TGT_UNQUOTE:
    {
      /* Unquoting never grows the string. */
      char *out = (char *) xalloc (n);
      size_t r = MHD_str_unquote ((const char *) p, n, out);

      if (r > n)
        fuzz_report_finding ("MHD_str_unquote() wrote more characters than "
                             "the quoted input had");
      free (out);
      break;
    }
#else  /* ! DAUTH_SUPPORT */
  case TGT_UNQUOTE:
    break;
#endif /* ! DAUTH_SUPPORT */

#if defined(DAUTH_SUPPORT) || defined(BAUTH_SUPPORT)
  case TGT_QUOTE:
    {
      /* Quoting can at most double the size. */
      char *out = (char *) xalloc (2 * n);
      size_t r = MHD_str_quote ((const char *) p, n, out, 2 * n);
      size_t small;

      if (r > 2 * n)
        fuzz_report_finding ("MHD_str_quote() wrote more than 2 * len chars");
      free (out);
      small = (0 == n) ? 0 : (n * (aux % 200u)) / 100u;
      out = (char *) xalloc (small);
      (void) MHD_str_quote ((const char *) p, n, out, small);
      free (out);
      break;
    }
#else  /* ! (DAUTH_SUPPORT || BAUTH_SUPPORT) */
  case TGT_QUOTE:
    break;
#endif /* ! (DAUTH_SUPPORT || BAUTH_SUPPORT) */

#ifdef BAUTH_SUPPORT
  case TGT_BASE64:
    {
      size_t need = MHD_base64_max_dec_size_ (n);
      uint8_t *out = (uint8_t *) xalloc (need);
      size_t r = MHD_base64_to_bin_n ((const char *) p, n, out, need);
      size_t small;

      if (r > need)
        fuzz_report_finding ("MHD_base64_to_bin_n() exceeded "
                             "MHD_base64_max_dec_size_()");
      free (out);
      small = (0 == need) ? 0 : (need * (aux % 100u)) / 100u;
      out = (uint8_t *) xalloc (small);
      (void) MHD_base64_to_bin_n ((const char *) p, n, out, small);
      free (out);
      break;
    }
#else  /* ! BAUTH_SUPPORT */
  case TGT_BASE64:
    break;
#endif /* ! BAUTH_SUPPORT */

  case TGT_TO_UINT64:
    {
      char *s = dup_z (p, n);
      uint64_t v1 = 0;
      uint64_t v2 = 0;
      size_t r1 = MHD_str_to_uint64_n_ (s, n, &v1);
      size_t r2 = MHD_strx_to_uint64_n_ (s, n, &v2);

      if (r1 > n)
        fuzz_report_finding ("MHD_str_to_uint64_n_() consumed more than "
                             "maxlen characters");
      if (r2 > n)
        fuzz_report_finding ("MHD_strx_to_uint64_n_() consumed more than "
                             "maxlen characters");
      free (s);
      break;
    }

  case TGT_TOKENS:
    {
      /* The "token" arguments have documented preconditions (no NUL,
         space, tab or comma); a fuzzer that violates them would only
         find its own mistakes, so sanitise them here. */
      char *s = dup_z (p, n);
      size_t split = (0 == n) ? 0 : (aux % n);
      char *tok = dup_z (p + split, n - split);
      size_t tlen;
      ssize_t bs;
      char *out;
      size_t k;

      for (k = 0; k < n - split; k++)
      {
        if ( ('\0' == tok[k]) || (' ' == tok[k]) ||
             ('\t' == tok[k]) || (',' == tok[k]) )
          tok[k] = 'x';
      }
      tlen = strlen (tok);
      if (0 == tlen)
      {
        free (tok);
        tok = dup_z ((const uint8_t *) "chunked", 7);
        tlen = 7;
      }
      (void) MHD_str_has_token_caseless_ (s, tok, tlen);

      /* Documented worst case growth of the output is 50%. */
      bs = (ssize_t) (n + n / 2 + 1);
      out = (char *) xalloc ((size_t) bs);
      (void) MHD_str_remove_token_caseless_ (s, n, tok, tlen, out, &bs);
      if (bs > (ssize_t) (n + n / 2 + 1))
        fuzz_report_finding ("MHD_str_remove_token_caseless_() reported a "
                             "result larger than the documented 50% growth");
      if (0 <= bs)
      {
        /* The output of the previous call is normalised, which is the
           documented precondition of the in-place variant. */
        char *norm = dup_z ((const uint8_t *) out, (size_t) bs);
        size_t nlen = (size_t) bs;

        (void) MHD_str_remove_tokens_caseless_ (norm, &nlen, tok, tlen);
        if (nlen > (size_t) bs)
          fuzz_report_finding ("MHD_str_remove_tokens_caseless_() grew the "
                               "string");
        free (norm);
      }
      free (out);
      free (tok);
      free (s);
      break;
    }

  case TGT_EQUAL_CASELESS:
    {
      size_t split = (0 == n) ? 0 : (aux % n);
      char *a = dup_z (p, split);
      char *b = dup_z (p + split, n - split);

      (void) MHD_str_equal_caseless_bin_n_ (a, b, (split < n - split)
                                            ? split : (n - split));
      (void) MHD_str_equal_caseless_n_ (a, b, n);
      free (a);
      free (b);
      break;
    }

  case TGT_DIGEST_HEX_SINK:
    {
      /* See the comment on model_digest_sink above. */
      size_t len = n;
      uint8_t *out;

      if (! model_digest_sink_read)
      {
        const char *e = getenv ("MHD_FUZZ_MODEL_DIGEST_SINK");

        model_digest_sink_read = 1;
        if (NULL != e)
          model_digest_sink = (0 != atoi (e));
      }
      if (! model_digest_sink)
        break;
      /* digestauth.c only checked 'len <= 4 * digest_size' before the
         fix; replay exactly that bound. */
      if (len > 4 * MODEL_MAX_DIGEST)
        len = 4 * MODEL_MAX_DIGEST;
      out = (uint8_t *) xalloc (MODEL_MAX_DIGEST);
      (void) MHD_hex_to_bin ((const char *) p, len, out);
      free (out);
      break;
    }

  case TGT_COUNT:
  default:
    break;
  }
  return 0;
}


/* ------------------------------------------------------------------ */
/* Generator                                                           */
/* ------------------------------------------------------------------ */

static const char *const gen_str_atoms[] = {
  "%41", "%", "%%", "%zz", "%0", "%00", "%ff", "\\", "\\\"", "\"",
  "0123456789abcdef", "0123456789ABCDEF", "ffffffffffffffffffffffff",
  "gg", "0x", "18446744073709551615", "99999999999999999999",
  "a, b, c", "chunked", "identity", " , ", ",,", "token",
  "QUJD", "QQ==", "Q===", "====", "AAAA", "AA=A",
  "\x00\x01\x7f\x80\xff", "  ", "\t", "\r\n"
};


static size_t
fuzz_generate (struct fuzz_rng *rng,
               uint8_t *buf,
               size_t cap)
{
  size_t len = 0;
  unsigned int natoms;
  unsigned int i;

  if (cap < 8)
    return 0;
  buf[len++] = (uint8_t) fuzz_below (rng, (uint32_t) TGT_COUNT);
  buf[len++] = fuzz_byte (rng);
  natoms = 1 + fuzz_below (rng, 12);
  for (i = 0; i < natoms; i++)
  {
    if (fuzz_chance (rng, 3))
    {
      /* a run of hex digits of a length that is interesting for the
         digest code paths (32, 64, 128 characters) */
      unsigned int k;
      unsigned int run = 1 + fuzz_below (rng, 140);

      for (k = 0; (k < run) && (len < cap); k++)
        buf[len++] = (uint8_t) "0123456789abcdef"[fuzz_below (rng, 16)];
    }
    else if (fuzz_chance (rng, 8))
    {
      if (len < cap)
        buf[len++] = fuzz_byte (rng);
    }
    else
    {
      const char *a =
        gen_str_atoms[fuzz_below (rng,
                                  (uint32_t) (sizeof (gen_str_atoms)
                                              / sizeof (char *)))];
      size_t al = strlen (a);

      if (len + al > cap)
        break;
      memcpy (buf + len, a, al);
      len += al;
    }
  }
  return len;
}


/* ------------------------------------------------------------------ */
/* Seed corpus                                                         */
/* ------------------------------------------------------------------ */

struct str_seed
{
  const char *txt;
  size_t len;
};

#define SSEED(t) { t, sizeof (t) - 1 }

static const struct str_seed str_seeds[] = {
  /* hex -> bin, 128 characters: the length digestauth.c used to allow
     into a 32 byte buffer */
  SSEED ("\x00\x00"
         "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
         "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"),
  SSEED ("\x00\x00" "0123456789abcdef0123456789abcdef"),
  SSEED ("\x00\x00" "abc"),
  SSEED ("\x00\x00" "zz"),
  SSEED ("\x01\x00" "\x01\x02\x03\x04"),
  SSEED ("\x02\x00" "\xff\xfe"),
  SSEED ("\x03\x00" "/a%41%42%zz%"),
  SSEED ("\x04\x40" "/a%41%42%zz%"),
  SSEED ("\x05\x00" "%41%42%%%0"),
  SSEED ("\x06\x00" "%41%42%%%0"),
  SSEED ("\x07\x00" "a\\\"b\\\\c"),
  SSEED ("\x08\x00" "a\"b\\c"),
  SSEED ("\x09\x00" "QUJDRA=="),
  SSEED ("\x09\x00" "QUJDR==="),
  SSEED ("\x0a\x00" "18446744073709551615"),
  SSEED ("\x0a\x00" "ffffffffffffffff"),
  SSEED ("\x0b\x03" "chunked, identity, chunked"),
  SSEED ("\x0c\x04" "CHUNKEDchunked"),
  SSEED ("\x0d\x00"
         "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
         "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef")
};


static size_t
fuzz_seed_count (void)
{
  return sizeof (str_seeds) / sizeof (str_seeds[0]);
}


static const uint8_t *
fuzz_seed_get (size_t idx,
               size_t *len)
{
  *len = str_seeds[idx].len;
  return (const uint8_t *) str_seeds[idx].txt;
}
