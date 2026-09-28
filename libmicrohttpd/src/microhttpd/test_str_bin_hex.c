/*
  This file is part of libmicrohttpd
  Copyright (C) 2022 Karlson2k (Evgeny Grin)

  This test tool is free software; you can redistribute it and/or
  modify it under the terms of the GNU General Public License as
  published by the Free Software Foundation; either version 2, or
  (at your option) any later version.

  This test tool is distributed in the hope that it will be useful,
  but WITHOUT ANY WARRANTY; without even the implied warranty of
  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
  Lesser General Public License for more details.

  You should have received a copy of the GNU Lesser General Public
  License along with this library; if not, write to the Free Software
  Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301  USA
*/

/**
 * @file microhttpd/test_str_bin_hex.c
 * @brief  Unit tests for hex strings <-> binary data processing
 * @author Karlson2k (Evgeny Grin)
 */

#include "mhd_options.h"
#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include "mhd_str.h"
#include "mhd_assert.h"

/* Turn any MHD_PANIC() or failing mhd_assert() reached from this
   test into a marked, classifiable test error (TESTING.md, P5). */
#include "mhd_panic_tripwire.h"

#ifndef MHD_STATICSTR_LEN_
/**
 * Determine length of static string / macro strings at compile time.
 */
#define MHD_STATICSTR_LEN_(macro) (sizeof(macro) / sizeof(char) - 1)
#endif /* ! MHD_STATICSTR_LEN_ */


static char tmp_bufs[4][4 * 1024]; /* should be enough for testing */
static size_t buf_idx = 0;

/* print non-printable chars as char codes */
static char *
n_prnt (const char *str, size_t len)
{
  static char *buf;  /* should be enough for testing */
  static const size_t buf_size = sizeof(tmp_bufs[0]);
  size_t r_pos = 0;
  size_t w_pos = 0;
  if (++buf_idx >= (sizeof(tmp_bufs) / sizeof(tmp_bufs[0])))
    buf_idx = 0;
  buf = tmp_bufs[buf_idx];

  while (len > r_pos && w_pos + 1 < buf_size)
  {
    const unsigned char c = (unsigned char) str[r_pos];
    if ((c == '\\') || (c == '"') )
    {
      if (w_pos + 2 >= buf_size)
        break;
      buf[w_pos++] = '\\';
      buf[w_pos++] = (char) c;
    }
    else if ((c >= 0x20) && (c <= 0x7E) )
      buf[w_pos++] = (char) c;
    else
    {
      if (w_pos + 4 >= buf_size)
        break;
      if (snprintf (buf + w_pos, buf_size - w_pos, "\\x%02hX", (short unsigned
                                                                int) c) != 4)
        break;
      w_pos += 4;
    }
    r_pos++;
  }

  if (len != r_pos)
  {   /* not full string is printed */
      /* enough space for "..." ? */
    if (w_pos + 3 > buf_size)
      w_pos = buf_size - 4;
    buf[w_pos++] = '.';
    buf[w_pos++] = '.';
    buf[w_pos++] = '.';
  }
  buf[w_pos] = 0;
  return buf;
}


#define TEST_BIN_MAX_SIZE (2 * 1024)

/* return zero if succeed, number of failures otherwise */
static unsigned int
expect_decoded_n (const char *const hex, const size_t hex_len,
                  const uint8_t *const bin, const size_t bin_size,
                  const unsigned int line_num)
{
  static const char fill_chr = '#';
  static char buf[TEST_BIN_MAX_SIZE];
  size_t res_size;
  unsigned int ret;

  mhd_assert (NULL != hex);
  mhd_assert (NULL != bin);
  mhd_assert (TEST_BIN_MAX_SIZE > bin_size + 1);
  mhd_assert (TEST_BIN_MAX_SIZE > hex_len + 1);
  mhd_assert (hex_len >= bin_size);
  mhd_assert (1 >= hex_len || hex_len > bin_size);

  ret = 0;

  /* check MHD_hex_to_bin() */
  if (1)
  {
    unsigned int check_res = 0;

    memset (buf, fill_chr, sizeof(buf)); /* Fill buffer with some character */
    res_size = MHD_hex_to_bin (hex, hex_len, buf);
    if (res_size != bin_size)
    {
      check_res = 1;
      fprintf (stderr,
               "'MHD_hex_to_bin ()' FAILED: "
               "Wrong returned value:\n");
    }
    else
    {
      if ((0 != bin_size) &&
          (0 != memcmp (buf, bin, bin_size)))
      {
        check_res = 1;
        fprintf (stderr,
                 "'MHD_hex_to_bin ()' FAILED: "
                 "Wrong output data:\n");
      }
    }
    if (((0 == res_size) && (fill_chr != buf[bin_size]))
        || ((0 != res_size) && (fill_chr != buf[res_size])))
    {
      check_res = 1;
      fprintf (stderr,
               "'MHD_hex_to_bin ()' FAILED: "
               "A char written outside the buffer:\n");
    }
    if (0 != check_res)
    {
      ret++;
      fprintf (stderr,
               "\tRESULT  : MHD_hex_to_bin (\"%s\", %u, "
               "->\"%s\") -> %u\n",
               n_prnt (hex, hex_len), (unsigned) hex_len,
               n_prnt (buf, res_size),
               (unsigned) res_size);
      fprintf (stderr,
               "\tEXPECTED: MHD_hex_to_bin (\"%s\", %u, "
               "->\"%s\") -> %u\n",
               n_prnt (hex, hex_len), (unsigned) hex_len,
               n_prnt ((const char *) bin, bin_size),
               (unsigned) bin_size);
    }
  }

  /* check MHD_bin_to_hex() */
  if (0 == hex_len % 2)
  {
    unsigned int check_res = 0;

    memset (buf, fill_chr, sizeof(buf)); /* Fill buffer with some character */
    res_size = MHD_bin_to_hex_z (bin, bin_size, buf);

    if (res_size != hex_len)
    {
      check_res = 1;
      fprintf (stderr,
               "'MHD_bin_to_hex ()' FAILED: "
               "Wrong returned value:\n");
    }
    else
    {
      if ((0 != hex_len) &&
          (! MHD_str_equal_caseless_bin_n_ (buf, hex, hex_len)))
      {
        check_res = 1;
        fprintf (stderr,
                 "'MHD_bin_to_hex ()' FAILED: "
                 "Wrong output string:\n");
      }
    }
    if (fill_chr != buf[res_size + 1])
    {
      check_res = 1;
      fprintf (stderr,
               "'MHD_bin_to_hex ()' FAILED: "
               "A char written outside the buffer:\n");
    }
    if (0 != buf[res_size])
    {
      check_res = 1;
      fprintf (stderr,
               "'MHD_bin_to_hex ()' FAILED: "
               "The result is not zero-terminated:\n");
    }
    if (0 != check_res)
    {
      ret++;
      fprintf (stderr,
               "\tRESULT  : MHD_bin_to_hex (\"%s\", %u, "
               "->\"%s\") -> %u\n",
               n_prnt ((const char *) bin, bin_size), (unsigned) bin_size,
               n_prnt (buf, res_size),
               (unsigned) res_size);
      fprintf (stderr,
               "\tEXPECTED: MHD_bin_to_hex (\"%s\", %u, "
               "->(lower case)\"%s\") -> %u\n",
               n_prnt ((const char *) bin, bin_size), (unsigned) bin_size,
               n_prnt (hex, hex_len),
               (unsigned) bin_size);
    }
  }

  if (0 != ret)
  {
    fprintf (stderr,
             "The check is at line: %u\n\n", line_num);
  }
  return ret;
}


#define expect_decoded_arr(h,a) \
        expect_decoded_n(h,MHD_STATICSTR_LEN_(h),\
                         a,(sizeof(a)/sizeof(a[0])), \
                         __LINE__)

static unsigned int
check_decode_bin (void)
{
  unsigned int r = 0; /**< The number of errors */

  if (1)
  {
    static const uint8_t bin[256] =
    {0x0, 0x1, 0x2, 0x3, 0x4, 0x5, 0x6, 0x7, 0x8, 0x9, 0xa, 0xb, 0xc, 0xd, 0xe,
     0xf, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a,
     0x1b, 0x1c, 0x1d, 0x1e, 0x1f, 0x20, 0x21, 0x22, 0x23, 0x24, 0x25, 0x26,
     0x27, 0x28, 0x29, 0x2a, 0x2b, 0x2c, 0x2d, 0x2e, 0x2f, 0x30, 0x31, 0x32,
     0x33, 0x34, 0x35, 0x36, 0x37, 0x38, 0x39, 0x3a, 0x3b, 0x3c, 0x3d, 0x3e,
     0x3f, 0x40, 0x41, 0x42, 0x43, 0x44, 0x45, 0x46, 0x47, 0x48, 0x49, 0x4a,
     0x4b, 0x4c, 0x4d, 0x4e, 0x4f, 0x50, 0x51, 0x52, 0x53, 0x54, 0x55, 0x56,
     0x57, 0x58, 0x59, 0x5a, 0x5b, 0x5c, 0x5d, 0x5e, 0x5f, 0x60, 0x61, 0x62,
     0x63, 0x64, 0x65, 0x66, 0x67, 0x68, 0x69, 0x6a, 0x6b, 0x6c, 0x6d, 0x6e,
     0x6f, 0x70, 0x71, 0x72, 0x73, 0x74, 0x75, 0x76, 0x77, 0x78, 0x79, 0x7a,
     0x7b, 0x7c, 0x7d, 0x7e, 0x7f, 0x80, 0x81, 0x82, 0x83, 0x84, 0x85, 0x86,
     0x87, 0x88, 0x89, 0x8a, 0x8b, 0x8c, 0x8d, 0x8e, 0x8f, 0x90, 0x91, 0x92,
     0x93, 0x94, 0x95, 0x96, 0x97, 0x98, 0x99, 0x9a, 0x9b, 0x9c, 0x9d, 0x9e,
     0x9f, 0xa0, 0xa1, 0xa2, 0xa3, 0xa4, 0xa5, 0xa6, 0xa7, 0xa8, 0xa9, 0xaa,
     0xab, 0xac, 0xad, 0xae, 0xaf, 0xb0, 0xb1, 0xb2, 0xb3, 0xb4, 0xb5, 0xb6,
     0xb7, 0xb8, 0xb9, 0xba, 0xbb, 0xbc, 0xbd, 0xbe, 0xbf, 0xc0, 0xc1, 0xc2,
     0xc3, 0xc4, 0xc5, 0xc6, 0xc7, 0xc8, 0xc9, 0xca, 0xcb, 0xcc, 0xcd, 0xce,
     0xcf, 0xd0, 0xd1, 0xd2, 0xd3, 0xd4, 0xd5, 0xd6, 0xd7, 0xd8, 0xd9, 0xda,
     0xdb, 0xdc, 0xdd, 0xde, 0xdf, 0xe0, 0xe1, 0xe2, 0xe3, 0xe4, 0xe5, 0xe6,
     0xe7, 0xe8, 0xe9, 0xea, 0xeb, 0xec, 0xed, 0xee, 0xef, 0xf0, 0xf1, 0xf2,
     0xf3, 0xf4, 0xf5, 0xf6, 0xf7, 0xf8, 0xf9, 0xfa, 0xfb, 0xfc, 0xfd, 0xfe,
     0xff };
    /* The lower case */
    r += expect_decoded_arr ("000102030405060708090a0b0c0d0e" \
                             "0f101112131415161718191a1b1c1d" \
                             "1e1f202122232425262728292a2b2c" \
                             "2d2e2f303132333435363738393a3b" \
                             "3c3d3e3f404142434445464748494a" \
                             "4b4c4d4e4f50515253545556575859" \
                             "5a5b5c5d5e5f606162636465666768" \
                             "696a6b6c6d6e6f7071727374757677" \
                             "78797a7b7c7d7e7f80818283848586" \
                             "8788898a8b8c8d8e8f909192939495" \
                             "969798999a9b9c9d9e9fa0a1a2a3a4" \
                             "a5a6a7a8a9aaabacadaeafb0b1b2b3" \
                             "b4b5b6b7b8b9babbbcbdbebfc0c1c2" \
                             "c3c4c5c6c7c8c9cacbcccdcecfd0d1" \
                             "d2d3d4d5d6d7d8d9dadbdcdddedfe0" \
                             "e1e2e3e4e5e6e7e8e9eaebecedeeef" \
                             "f0f1f2f3f4f5f6f7f8f9fafbfcfdfe" \
                             "ff", bin);
  }

  if (1)
  {
    static const uint8_t bin[256] =
    {0x0, 0x1, 0x2, 0x3, 0x4, 0x5, 0x6, 0x7, 0x8, 0x9, 0xa, 0xb, 0xc, 0xd, 0xe,
     0xf, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a,
     0x1b, 0x1c, 0x1d, 0x1e, 0x1f, 0x20, 0x21, 0x22, 0x23, 0x24, 0x25, 0x26,
     0x27, 0x28, 0x29, 0x2a, 0x2b, 0x2c, 0x2d, 0x2e, 0x2f, 0x30, 0x31, 0x32,
     0x33, 0x34, 0x35, 0x36, 0x37, 0x38, 0x39, 0x3a, 0x3b, 0x3c, 0x3d, 0x3e,
     0x3f, 0x40, 0x41, 0x42, 0x43, 0x44, 0x45, 0x46, 0x47, 0x48, 0x49, 0x4a,
     0x4b, 0x4c, 0x4d, 0x4e, 0x4f, 0x50, 0x51, 0x52, 0x53, 0x54, 0x55, 0x56,
     0x57, 0x58, 0x59, 0x5a, 0x5b, 0x5c, 0x5d, 0x5e, 0x5f, 0x60, 0x61, 0x62,
     0x63, 0x64, 0x65, 0x66, 0x67, 0x68, 0x69, 0x6a, 0x6b, 0x6c, 0x6d, 0x6e,
     0x6f, 0x70, 0x71, 0x72, 0x73, 0x74, 0x75, 0x76, 0x77, 0x78, 0x79, 0x7a,
     0x7b, 0x7c, 0x7d, 0x7e, 0x7f, 0x80, 0x81, 0x82, 0x83, 0x84, 0x85, 0x86,
     0x87, 0x88, 0x89, 0x8a, 0x8b, 0x8c, 0x8d, 0x8e, 0x8f, 0x90, 0x91, 0x92,
     0x93, 0x94, 0x95, 0x96, 0x97, 0x98, 0x99, 0x9a, 0x9b, 0x9c, 0x9d, 0x9e,
     0x9f, 0xa0, 0xa1, 0xa2, 0xa3, 0xa4, 0xa5, 0xa6, 0xa7, 0xa8, 0xa9, 0xaa,
     0xab, 0xac, 0xad, 0xae, 0xaf, 0xb0, 0xb1, 0xb2, 0xb3, 0xb4, 0xb5, 0xb6,
     0xb7, 0xb8, 0xb9, 0xba, 0xbb, 0xbc, 0xbd, 0xbe, 0xbf, 0xc0, 0xc1, 0xc2,
     0xc3, 0xc4, 0xc5, 0xc6, 0xc7, 0xc8, 0xc9, 0xca, 0xcb, 0xcc, 0xcd, 0xce,
     0xcf, 0xd0, 0xd1, 0xd2, 0xd3, 0xd4, 0xd5, 0xd6, 0xd7, 0xd8, 0xd9, 0xda,
     0xdb, 0xdc, 0xdd, 0xde, 0xdf, 0xe0, 0xe1, 0xe2, 0xe3, 0xe4, 0xe5, 0xe6,
     0xe7, 0xe8, 0xe9, 0xea, 0xeb, 0xec, 0xed, 0xee, 0xef, 0xf0, 0xf1, 0xf2,
     0xf3, 0xf4, 0xf5, 0xf6, 0xf7, 0xf8, 0xf9, 0xfa, 0xfb, 0xfc, 0xfd, 0xfe,
     0xff };
    /* The upper case */
    r += expect_decoded_arr ("000102030405060708090A0B0C0D0E" \
                             "0F101112131415161718191A1B1C1D" \
                             "1E1F202122232425262728292A2B2C" \
                             "2D2E2F303132333435363738393A3B" \
                             "3C3D3E3F404142434445464748494A" \
                             "4B4C4D4E4F50515253545556575859" \
                             "5A5B5C5D5E5F606162636465666768" \
                             "696A6B6C6D6E6F7071727374757677" \
                             "78797A7B7C7D7E7F80818283848586" \
                             "8788898A8B8C8D8E8F909192939495" \
                             "969798999A9B9C9D9E9FA0A1A2A3A4" \
                             "A5A6A7A8A9AAABACADAEAFB0B1B2B3" \
                             "B4B5B6B7B8B9BABBBCBDBEBFC0C1C2" \
                             "C3C4C5C6C7C8C9CACBCCCDCECFD0D1" \
                             "D2D3D4D5D6D7D8D9DADBDCDDDEDFE0" \
                             "E1E2E3E4E5E6E7E8E9EAEBECEDEEEF" \
                             "F0F1F2F3F4F5F6F7F8F9FAFBFCFDFE" \
                             "FF", bin);
  }
  if (1)
  {
    static const uint8_t bin[3] =
    {0x1, 0x2, 0x3};
    r += expect_decoded_arr ("010203", bin);
  }
  if (1)
  {
    static const uint8_t bin[3] =
    {0x1, 0x2, 0x3};
    r += expect_decoded_arr ("10203", bin);
  }
  if (1)
  {
    static const uint8_t bin[1] =
    {0x1};
    r += expect_decoded_arr ("01", bin);
  }
  if (1)
  {
    static const uint8_t bin[1] =
    {0x1};
    r += expect_decoded_arr ("1", bin);
  }

  return r;
}


/* return zero if succeed, number of failures otherwise */
static unsigned int
expect_failed_n (const char *const hex, const size_t hex_len,
                 const unsigned int line_num)
{
  static const char fill_chr = '#';
  static char buf[TEST_BIN_MAX_SIZE];
  size_t res_size;
  unsigned int ret;

  mhd_assert (NULL != hex);
  mhd_assert (TEST_BIN_MAX_SIZE > hex_len + 1);

  ret = 0;

  /* check MHD_hex_to_bin() */
  if (1)
  {
    unsigned int check_res = 0;

    memset (buf, fill_chr, sizeof(buf)); /* Fill buffer with some character */
    res_size = MHD_hex_to_bin (hex, hex_len, buf);
    if (res_size != 0)
    {
      check_res = 1;
      fprintf (stderr,
               "'MHD_hex_to_bin ()' FAILED: "
               "Wrong returned value:\n");
    }
    if (0 != check_res)
    {
      ret++;
      fprintf (stderr,
               "\tRESULT  : MHD_hex_to_bin (\"%s\", %u, "
               "->\"%s\") -> %u\n",
               n_prnt (hex, hex_len), (unsigned) hex_len,
               n_prnt (buf, res_size),
               (unsigned) res_size);
      fprintf (stderr,
               "\tEXPECTED: MHD_hex_to_bin (\"%s\", %u, "
               "->(not defined)) -> 0\n",
               n_prnt (hex, hex_len), (unsigned) hex_len);
    }
  }

  if (0 != ret)
  {
    fprintf (stderr,
             "The check is at line: %u\n\n", line_num);
  }
  return ret;
}


#define expect_failed(h) \
        expect_failed_n(h,MHD_STATICSTR_LEN_(h), \
                         __LINE__)


static unsigned int
check_broken_str (void)
{
  unsigned int r = 0; /**< The number of errors */

  r += expect_failed ("abcx");
  r += expect_failed ("X");
  r += expect_failed ("!");
  r += expect_failed ("01z");
  r += expect_failed ("0z");
  r += expect_failed ("00z");
  r += expect_failed ("000Y");

  return r;
}


/**
 * The maximum length of the hexadecimal input used by the exact-sized
 * output buffer checks.
 */
#define TEST_EXACT_MAX_HEX_LEN 320

/**
 * The number of the guard bytes placed right after the output buffer.
 */
#define TEST_GUARD_SIZE 8

/**
 * The value used to fill the guard bytes.
 */
#define TEST_GUARD_CHR 0x5A

/**
 * Check that MHD_hex_to_bin() writes no more than the documented number of
 * the output bytes, which is ((@a hex_len + 1) / 2).
 *
 * Every caller of MHD_hex_to_bin() must size the output buffer by that
 * formula.  A caller that sizes the buffer by the expected size of the
 * decoded value instead (like the digest authentication 'response' check
 * used to do) can be overflown by simply sending a longer hexadecimal
 * string, therefore this contract is checked here with buffers that have
 * no slack at all:
 * - an exactly-sized heap allocation, so that a run-time memory checker
 *   (ASAN, valgrind) traps any out-of-bounds write immediately, and
 * - an allocation with a known guard pattern right after the output area,
 *   so that the overflow is detected even without any such tool.
 *
 * @param hex the input string with hexadecimal digits
 * @param hex_len the length of @a hex
 * @param must_succeed non-zero if the decoding is expected to succeed
 * @param line_num the line number to report in case of failure
 * @return zero if succeed, number of failures otherwise
 */
static unsigned int
expect_exact_dest_n (const char *const hex,
                     const size_t hex_len,
                     const int must_succeed,
                     const unsigned int line_num)
{
  const size_t max_out_size = (hex_len + 1) / 2;
  const size_t expected_size = must_succeed ? max_out_size : 0;
  uint8_t *buf;
  size_t res_size;
  size_t i;
  unsigned int ret;

  ret = 0;

  /* (1) The exactly-sized output buffer. */
  buf = (uint8_t *) malloc (0 != max_out_size ? max_out_size : 1);
  if (NULL == buf)
  {
    fprintf (stderr, "malloc() failed. Line: %u\n", line_num);
    return 1;
  }
  res_size = MHD_hex_to_bin (hex, hex_len, buf);
  free (buf);
  if (res_size != expected_size)
  {
    ret++;
    fprintf (stderr,
             "'MHD_hex_to_bin ()' FAILED: "
             "Wrong returned value with the exactly-sized buffer:\n");
    fprintf (stderr,
             "\tRESULT  : MHD_hex_to_bin (\"%s\", %u, ...) -> %u\n",
             n_prnt (hex, hex_len), (unsigned) hex_len,
             (unsigned) res_size);
    fprintf (stderr,
             "\tEXPECTED: MHD_hex_to_bin (\"%s\", %u, ...) -> %u\n",
             n_prnt (hex, hex_len), (unsigned) hex_len,
             (unsigned) expected_size);
  }

  /* (2) The output buffer followed by the guard bytes. */
  buf = (uint8_t *) malloc (max_out_size + TEST_GUARD_SIZE);
  if (NULL == buf)
  {
    fprintf (stderr, "malloc() failed. Line: %u\n", line_num);
    return ret + 1;
  }
  memset (buf, TEST_GUARD_CHR, max_out_size + TEST_GUARD_SIZE);
  res_size = MHD_hex_to_bin (hex, hex_len, buf);
  if (res_size > max_out_size)
  {
    ret++;
    fprintf (stderr,
             "'MHD_hex_to_bin ()' FAILED: "
             "Returned value is larger than the documented maximum "
             "output size: %u > %u\n",
             (unsigned) res_size, (unsigned) max_out_size);
  }
  for (i = 0; i < TEST_GUARD_SIZE; ++i)
  {
    if (TEST_GUARD_CHR != buf[max_out_size + i])
    {
      ret++;
      fprintf (stderr,
               "'MHD_hex_to_bin ()' FAILED: "
               "The guard byte number %u (of %u) after the output buffer "
               "has been overwritten:\n",
               (unsigned) i, (unsigned) TEST_GUARD_SIZE);
      fprintf (stderr,
               "\tINPUT   : MHD_hex_to_bin (\"%s\", %u, ...), "
               "the maximum output size is %u\n",
               n_prnt (hex, hex_len), (unsigned) hex_len,
               (unsigned) max_out_size);
      break;
    }
  }
  free (buf);

  if (0 != ret)
  {
    fprintf (stderr,
             "The check is at line: %u\n\n", line_num);
  }
  return ret;
}


#define expect_exact_dest(h,ms) \
        expect_exact_dest_n (h, MHD_STATICSTR_LEN_ (h), ms, __LINE__)


/**
 * Check the output size contract of MHD_hex_to_bin() for every input length
 * up to #TEST_EXACT_MAX_HEX_LEN, for valid and for broken input.
 *
 * @return zero if succeed, number of failures otherwise
 */
static unsigned int
check_exact_dest_buffer (void)
{
  static const char hex_digits[] = "0123456789abcdefABCDEF";
  static char hex[TEST_EXACT_MAX_HEX_LEN + 1];
  unsigned int r = 0; /**< The number of errors */
  size_t len;

  for (len = 0; len < sizeof(hex) - 1; ++len)
    hex[len] = hex_digits[len % (sizeof(hex_digits) - 1)];
  hex[sizeof(hex) - 1] = 0;

  /* Valid input of every length, including the odd lengths for which
     an extra leading zero is assumed and therefore one more byte is
     written than (hex_len / 2). */
  for (len = 0; len <= TEST_EXACT_MAX_HEX_LEN; ++len)
    r += expect_exact_dest_n (hex, len, 1, __LINE__);

  /* Broken input: a non-hexadecimal character at every possible position.
     The decoding fails, but the bytes decoded before the broken character
     have already been written and must still fit into the output buffer. */
  for (len = 1; len <= 64; ++len)
  {
    size_t pos;

    for (pos = 0; pos < len; ++pos)
    {
      const char saved = hex[pos];

      hex[pos] = 'z';
      r += expect_exact_dest_n (hex, len, 0, __LINE__);
      hex[pos] = saved;
    }
  }

  /* The lengths that matter for the HTTP Digest authentication code:
     twice the digest size is the largest input any caller may accept. */
  r += expect_exact_dest ("00112233445566778899aabbccddeeff", 1); /* MD5 */
  r += expect_exact_dest ("00112233445566778899aabbccddeeff"
                          "00112233445566778899aabbccddeeff", 1); /* SHA-256 */
  /* Twice as long as the largest supported digest: a caller that sizes the
     output buffer by the digest size only would be overflown here. */
  r += expect_exact_dest ("00112233445566778899aabbccddeeff"
                          "00112233445566778899aabbccddeeff"
                          "00112233445566778899aabbccddeeff"
                          "00112233445566778899aabbccddeeff", 1);

  return r;
}


int
main (int argc, char *argv[])
{
  unsigned int errcount = 0;
  (void) argc; (void) argv; /* Unused. Silent compiler warning. */
  errcount += check_decode_bin ();
  errcount += check_broken_str ();
  errcount += check_exact_dest_buffer ();
  if (0 == errcount)
    printf ("All tests have been passed without errors.\n");
  return errcount == 0 ? 0 : 1;
}
