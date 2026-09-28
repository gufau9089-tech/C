/* sntrup761-encap.c

   Copyright (C) 2023 Simon Josefsson
   Copyright (C) 2026 Niels Möller

   This file is part of GNU Nettle.

   GNU Nettle is free software: you can redistribute it and/or
   modify it under the terms of either:

   * the GNU Lesser General Public License as published by the Free
   Software Foundation; either version 3 of the License, or (at your
   option) any later version.

   or

   * the GNU General Public License as published by the Free
   Software Foundation; either version 2 of the License, or (at your
   option) any later version.

   or both in parallel, as here.

   GNU Nettle is distributed in the hope that it will be useful,
   but WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
   General Public License for more details.

   You should have received copies of the GNU General Public License and
   the GNU Lesser General Public License along with this program.  If
   not, see http://www.gnu.org/licenses/.
*/

/*
 * Derived from public domain source, written by (in alphabetical order):
 * - Daniel J. Bernstein
 * - Chitchanok Chuengsatiansup
 * - Tanja Lange
 * - Christine van Vredendaal
 */

#if HAVE_CONFIG_H
#include "config.h"
#endif

#include "sntrup.h"
#include "sntrup-internal.h"

static void
Rq_decode (sntrup761_Rq_t r, const uint8_t *s)
{
  uint16_t R[SNTRUP761_P];
  int i;

  _sntrup_decode (SNTRUP761_ENCODING_STEPS,_sntrup761_encoding_Rq, R,
		  s + SNTRUP761_PUBLIC_KEY_SIZE);
  for (i = 0; i < SNTRUP761_P; i++)
    r[i] = ((int16_t) R[i]) - SNTRUP761_Q12;
}

static uint16_t
div_3 (uint16_t x)
{
  uint16_t q, r;
  /* Magic constant is ceil (2^16 / 3). */
  q = ((uint32_t) 21846 * x) >> 16;
  r = x - 3 * q;
  return q - (r >> 15);
}

/* Short-circuit rounding followed by exact division by 3. Rounding
   means computing

     u = x + (q-1)/2 + 1 (note (q-1)/2 = 0 (mod 3))
     a = floor (u/3)
     r = u - 3*a - 1
     x' = x - r

   For encoding this rounded value, we compute

     (x' + (q-1)/2)3,

   but this is the same as the quotient a, so let us just compute
   that.
*/
static void
Round_and_encode (uint8_t *s, const sntrup761_Rq_t r)
{
  uint16_t R[SNTRUP761_P];
  int i;

  for (i = 0; i < SNTRUP761_P; i++)
    R[i] = div_3 (r[i] + SNTRUP761_Q12 + 1);
  _sntrup_encode (_sntrup761_encoding_rounded, s, R);
}

/* cache is Hash4(pk) */
void
_sntrup761_encap_internal (const uint8_t *pk, const uint8_t *cache,
			   uint8_t *r_enc, uint8_t *c,
			   const sntrup761_R3_t r)
{
  sntrup761_Rq_t t;
  _sntrup761_small_encode (r_enc, r);
  Rq_decode (t, pk);
  _sntrup761_Rq_mult_small (t, t, r);
  Round_and_encode (c, t);
  _sntrup_hash_confirm (c + SNTRUP761_ROUNDED_SIZE, r_enc, cache);
}

void
sntrup761_encap (const uint8_t *pk, uint8_t *k, uint8_t *c,
		 void *random_ctx, nettle_random_func * random)
{
  sntrup761_R3_t r;
  uint8_t r_enc[SNTRUP761_R3_SIZE];
  uint8_t cache[SNTRUP_HASH_SIZE];

  _sntrup_hash_prefix (cache, 4, SNTRUP761_PUBLIC_KEY_SIZE, pk);
  _sntrup761_short_random (r, random_ctx, random);
  _sntrup761_encap_internal (pk, cache, r_enc, c, r);
  _sntrup_hash_session (k, 1, r_enc, c);
}
