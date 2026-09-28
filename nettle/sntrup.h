/* sntrup.h

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

#ifndef NETTLE_SNTRUP_H
#define NETTLE_SNTRUP_H

#include "nettle-types.h"

#ifdef __cplusplus
extern "C"
{
#endif

/* Name mangling */
#define sntrup761_generate_keypair nettle_sntrup761_generate_keypair
#define sntrup761_encap nettle_sntrup761_encap
#define sntrup761_decap nettle_sntrup761_decap

#define SNTRUP761_PRIVATE_KEY_SIZE 1763
#define SNTRUP761_PUBLIC_KEY_SIZE 1158
#define SNTRUP761_CIPHER_SIZE 1039
#define SNTRUP_SESSION_KEY_SIZE 32

void
sntrup761_generate_keypair (uint8_t *pk, uint8_t *sk, void *random_ctx,
			    nettle_random_func *random);

void
sntrup761_encap (const uint8_t *pk, uint8_t *k, uint8_t *c,
		 void *random_ctx, nettle_random_func *random);

void
sntrup761_decap (const uint8_t *sk, uint8_t *k, const uint8_t *c);

#ifdef __cplusplus
}
#endif

#endif /* NETTLE_SNTRUP_H */
