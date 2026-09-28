/* sntrup761-test.c

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

#include "testutils.h"

#include "sntrup.h"
#include "sntrup-internal.h"

#include "drbg-ctr.h"
#include "macros.h"

static void
random_undefined (struct drbg_ctr_aes256_ctx *ctx, size_t size, uint8_t *dst)
{
  drbg_ctr_aes256_random (ctx, size, dst);
  mark_bytes_undefined (size, dst);
}

static void
test_sntrup (struct drbg_ctr_aes256_ctx *rngctx,
	     const struct tstring *xpk, const struct tstring *xsk,
	     const struct tstring *xct, const struct tstring *xk)
{
  uint8_t pk[SNTRUP761_PUBLIC_KEY_SIZE];
  uint8_t sk[SNTRUP761_PRIVATE_KEY_SIZE];
  uint8_t ct[SNTRUP761_CIPHER_SIZE];
  uint8_t k1[SNTRUP_SESSION_KEY_SIZE];
  uint8_t k2[SNTRUP_SESSION_KEY_SIZE];

  ASSERT (xpk->length == SNTRUP761_PUBLIC_KEY_SIZE);
  ASSERT (xsk->length == SNTRUP761_PRIVATE_KEY_SIZE);
  ASSERT (xct->length == SNTRUP761_CIPHER_SIZE);
  ASSERT (xk->length == SNTRUP_SESSION_KEY_SIZE);

  sntrup761_generate_keypair (pk, sk, rngctx,
			      (nettle_random_func *) drbg_ctr_aes256_random);

  if (!MEMEQ (SNTRUP761_PUBLIC_KEY_SIZE, pk, xpk->data)
      || !MEMEQ (SNTRUP761_PRIVATE_KEY_SIZE, sk, xsk->data))
    {
      printf ("\nnstrup761_keypair:\npk = ");
      print_hex (sizeof pk, pk);
      printf ("\nsk = ");
      print_hex (sizeof sk, sk);
      abort ();
    }

  sntrup761_encap (pk, k1, ct, rngctx, (nettle_random_func *) random_undefined);
  mark_bytes_defined (sizeof (ct), ct);
  mark_bytes_defined (sizeof (k1), k1);
  if (!MEMEQ (SNTRUP761_CIPHER_SIZE, ct, xct->data)
      || !MEMEQ (SNTRUP_SESSION_KEY_SIZE, k1, xk->data))
    {
      printf ("\nnstrup761_enc:\nct = ");
      print_hex (sizeof ct, ct);
      printf ("\nk1 = ");
      print_hex (sizeof k1, k1);
      abort ();
    }
  mark_bytes_undefined (sizeof (sk), sk);
  sntrup761_decap (sk, k2, ct);
  mark_bytes_defined (sizeof (k2), k2);

  if (!MEMEQ (SNTRUP_SESSION_KEY_SIZE, k2, xk->data))
    {
      printf ("\nnstrup761_dec:\nk2 = ");
      print_hex (sizeof k2, k2);
      abort ();
    }

  if (!MEMEQ (SNTRUP_SESSION_KEY_SIZE, k1, k2))
    {
      printf ("\nsntrup761 k1 != k2\n");
      abort ();
    }
}

static void
test_randomized (void)
{
  struct drbg_ctr_aes256_ctx rng_ctx;
  uint8_t drbg_seed[DRBG_CTR_AES256_SEED_SIZE];
  unsigned count;
  unsigned end_count = test_side_channel ? 3 : 100;
  uint64_t seed = test_get_seed ();
  WRITE_UINT64 (drbg_seed, seed);
  memset (drbg_seed + 8, 0, DRBG_CTR_AES256_SEED_SIZE - 8);
  drbg_ctr_aes256_init (&rng_ctx, drbg_seed);

  for (count = 0; count < end_count; count++)
    {
      uint8_t pk[SNTRUP761_PUBLIC_KEY_SIZE];
      uint8_t sk[SNTRUP761_PRIVATE_KEY_SIZE];
      uint8_t ct[SNTRUP761_CIPHER_SIZE];
      uint8_t k1[SNTRUP_SESSION_KEY_SIZE];
      uint8_t k2[SNTRUP_SESSION_KEY_SIZE];
      unsigned bit;
      size_t i;
      sntrup761_generate_keypair (pk, sk, &rng_ctx,
				  (nettle_random_func *) drbg_ctr_aes256_random);
      sntrup761_encap (pk, k1, ct, &rng_ctx,
		       (nettle_random_func *) drbg_ctr_aes256_random);
      sntrup761_decap (sk, k2, ct);

      if (!MEMEQ (SNTRUP_SESSION_KEY_SIZE, k1, k2))
	{
	  printf ("sntrup761 failed, test %u\n", count);
	  abort ();
	}
      /* Decanonicalize secret key, replacing all 00 coeffs by 11. */
      for (i = 0; i < 2 * SNTRUP761_R3_SIZE; i++)
	{
	  uint8_t mask;
	  for (mask = 0xc0; mask > 0; mask >>= 2)
	    if ((sk[i] & mask) == 0)
	      sk[i] |= mask;
	}
      sntrup761_decap (sk, k2, ct);

      if (!MEMEQ (SNTRUP_SESSION_KEY_SIZE, k1, k2))
	{
	  printf ("sntrup761 with non-canonical secret key failed, test %u\n", count);
	  abort ();
	}
      bit = count % (SNTRUP761_CIPHER_SIZE * 8);
      ct[bit/8] ^= 1 << (bit % 8);
      sntrup761_decap (sk, k2, ct);
      if (MEMEQ (SNTRUP_SESSION_KEY_SIZE, k1, k2))
	{
	  printf ("sntrup761 failed with modified ciphertext, test %u\n", count);
	  abort ();
	}
    }
}

void
test_main (void)
{
  struct drbg_ctr_aes256_ctx rng;
#if WITH_EXTRA_ASSERTS
  if (test_side_channel)
    SKIP();
#endif

  /* https://ntruprime.cr.yp.to/nist/ntruprime-20201007/KAT/kem/sntrup761/kat_kem.rsp.html */

  drbg_ctr_aes256_init (&rng,
			H ("061550234D158C5EC95595FE04EF7A25767F2E24CC2BC479"
			   "D09D86DC9ABCFDE7056A8C266F9EF97ED08541DBD2E1FFA1"));
  test_sntrup (&rng,
	       read_hex_file ("sntrup761-tc0.pk", SNTRUP761_PUBLIC_KEY_SIZE),
	       read_hex_file ("sntrup761-tc0.sk", SNTRUP761_PRIVATE_KEY_SIZE),
	       read_hex_file ("sntrup761-tc0.ct", SNTRUP761_CIPHER_SIZE),
	       SHEX ("344CA5E25F6DA5EA95E4A695B1C5446ECA9859334532E4A9"
		     "537669F012C743A2"));

  drbg_ctr_aes256_init (&rng,
			H ("D81C4D8D734FCBFBEADE3D3F8A039FAA2A2C9957E835AD55"
			   "B22E75BF57BB556AC81ADDE6AEEB4A5A875C3BFCADFA958F"));
  test_sntrup (&rng,
	       read_hex_file ("sntrup761-tc1.pk", SNTRUP761_PUBLIC_KEY_SIZE),
	       read_hex_file ("sntrup761-tc1.sk", SNTRUP761_PRIVATE_KEY_SIZE),
	       read_hex_file ("sntrup761-tc1.ct", SNTRUP761_CIPHER_SIZE),
	       SHEX ("16C15126F734E51268BA916CE3B39A72E171AE79B8C2B6A6"
		     "8B34AB0DC5621B7E"));

  test_randomized ();
}
