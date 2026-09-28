/* LibTomCrypt, modular cryptographic library -- Tom St Denis */
/* SPDX-License-Identifier: Unlicense */
/* test the ciphers and hashes using their built-in self-tests */

#include <tomcrypt_test.h>

/* cloning a hash_state via memcpy must yield a working/independent copy */
static int s_hash_state_clone_test(const struct ltc_hash_descriptor *desc, const char *name)
{
   hash_state md, clone1, *clone2;
   unsigned char data[200], out[MAXBLOCKSIZE], expect1[MAXBLOCKSIZE], expect2[MAXBLOCKSIZE];
   unsigned long i, hashsize = desc->hashsize;

   for (i = 0; i < sizeof(data); i++) data[i] = (unsigned char)i;

   /* reference digests: expect1 = H(data[0..149]), expect2 = H(data[0..99] || data[150..199]) */
   DO(desc->init(&md));
   DO(desc->process(&md, data, 100));
   DO(desc->process(&md, data + 100, 50));
   DO(desc->done(&md, expect1));
   DO(desc->init(&md));
   DO(desc->process(&md, data, 100));
   DO(desc->process(&md, data + 150, 50));
   DO(desc->done(&md, expect2));

   /* clone the state after the common prefix, then let the original and the clone diverge */
   DO(desc->init(&md));
   DO(desc->process(&md, data, 100));
   XMEMCPY(&clone1, &md, sizeof(hash_state));
   DO(desc->process(&md, data + 100, 50));
   DO(desc->done(&md, out));
   COMPARE_TESTVECTOR(out, hashsize, expect1, hashsize, name, 0);
   DO(desc->process(&clone1, data + 150, 50));
   DO(desc->done(&clone1, out));
   COMPARE_TESTVECTOR(out, hashsize, expect2, hashsize, name, 1);

   /* clone into heap memory and wipe the original before using the clone */
   DO(desc->init(&md));
   DO(desc->process(&md, data, 100));
   clone2 = XMALLOC(sizeof(hash_state));
   if (clone2 == NULL) return CRYPT_MEM;
   XMEMCPY(clone2, &md, sizeof(hash_state));
   zeromem(&md, sizeof(hash_state));
   DO(desc->process(clone2, data + 150, 50));
   DO(desc->done(clone2, out));
   XFREE(clone2);
   COMPARE_TESTVECTOR(out, hashsize, expect2, hashsize, name, 2);

   return CRYPT_OK;
}

int cipher_hash_test(void)
{
   int           x;

   /* test block ciphers */
   for (x = 0; x < TAB_SIZE && cipher_descriptor[x].name != NULL; x++) {
      DOX(cipher_descriptor[x].test(), cipher_descriptor[x].name);
   }

   /* explicit AES-NI test */
#if defined(LTC_AES_NI)
   if (aesni_is_supported()) {
      DO(aesni_test());
   }
   DO(rijndael_test());
#endif
#if defined(LTC_RIJNDAEL)
#ifndef ENCRYPT_ONLY
   DO(aes_test());
#else
   DO(aes_enc_test());
#endif
#endif

   /* test stream ciphers */
#ifdef LTC_CHACHA
   DO(chacha_test());
#endif
#ifdef LTC_XCHACHA20
   DO(xchacha20_test());
#endif
#ifdef LTC_SALSA20
   DO(salsa20_test());
#endif
#ifdef LTC_XSALSA20
   DO(xsalsa20_test());
#endif
#ifdef LTC_SOSEMANUK
   DO(sosemanuk_test());
#endif
#ifdef LTC_RABBIT
   DO(rabbit_test());
#endif
#ifdef LTC_RC4_STREAM
   DO(rc4_stream_test());
#endif
#ifdef LTC_SOBER128_STREAM
   DO(sober128_stream_test());
#endif

   /* test hashes */
   for (x = 0; x < TAB_SIZE && hash_descriptor[x].name != NULL; x++) {
      DOX(hash_descriptor[x].test(), hash_descriptor[x].name);
      /* test that state can be cloned via memcpy */
      DOX(s_hash_state_clone_test(&hash_descriptor[x], hash_descriptor[x].name), hash_descriptor[x].name);
   }

   /* explicit SHA-NI + portable implementations tests */
   if (shani_is_supported()) {
#if defined(LTC_SHA256) && defined(LTC_SHA256_X86)
      DO(sha256_x86_test());
      DO(s_hash_state_clone_test(&sha256_x86_desc, "sha256-x86-clone"));
#endif
#if defined(LTC_SHA224) && defined(LTC_SHA224_X86)
      DO(sha224_x86_test());
      DO(s_hash_state_clone_test(&sha224_x86_desc, "sha224-x86-clone"));
#endif
#if defined(LTC_SHA1) && defined(LTC_SHA1_X86)
      DO(sha1_x86_test());
      DO(s_hash_state_clone_test(&sha1_x86_desc, "sha1-x86-clone"));
#endif
   }
   if (sha512ni_is_supported()) {
#if defined(LTC_SHA512) && defined(LTC_SHA512_X86)
      DO(sha512_x86_test());
      DO(s_hash_state_clone_test(&sha512_x86_desc, "sha512-x86-clone"));
#endif
#if defined(LTC_SHA384) && defined(LTC_SHA384_X86)
      DO(sha384_x86_test());
      DO(s_hash_state_clone_test(&sha384_x86_desc, "sha384-x86-clone"));
#endif
#if defined(LTC_SHA512_224) && defined(LTC_SHA512_224_X86)
      DO(sha512_224_x86_test());
      DO(s_hash_state_clone_test(&sha512_224_x86_desc, "sha512-224-x86-clone"));
#endif
#if defined(LTC_SHA512_256) && defined(LTC_SHA512_256_X86)
      DO(sha512_256_x86_test());
      DO(s_hash_state_clone_test(&sha512_256_x86_desc, "sha512-256-x86-clone"));
#endif
   }
#if defined(LTC_SHA256)
   DO(sha256_c_test());
   DO(s_hash_state_clone_test(&sha256_portable_desc, "sha256-c-clone"));
#endif
#if defined(LTC_SHA224)
   DO(sha224_c_test());
   DO(s_hash_state_clone_test(&sha224_portable_desc, "sha224-c-clone"));
#endif
#if defined(LTC_SHA1)
   DO(sha1_c_test());
   DO(s_hash_state_clone_test(&sha1_portable_desc, "sha1-c-clone"));
#endif
#if defined(LTC_SHA512)
   DO(sha512_c_test());
   DO(s_hash_state_clone_test(&sha512_portable_desc, "sha512-c-clone"));
#endif
#if defined(LTC_SHA384)
   DO(sha384_c_test());
   DO(s_hash_state_clone_test(&sha384_portable_desc, "sha384-c-clone"));
#endif
#if defined(LTC_SHA512_224)
   DO(sha512_224_c_test());
   DO(s_hash_state_clone_test(&sha512_224_portable_desc, "sha512-224-c-clone"));
#endif
#if defined(LTC_SHA512_256)
   DO(sha512_256_c_test());
   DO(s_hash_state_clone_test(&sha512_256_portable_desc, "sha512-256-c-clone"));
#endif
#ifdef LTC_SHA3
   /* SHAKE128 + SHAKE256 tests are a bit special */
   DOX(sha3_shake_test(), "sha3_shake");
#endif
#ifdef LTC_TURBO_SHAKE
   DO(turbo_shake_test());
#endif
#ifdef LTC_KANGAROO_TWELVE
   DO(kangaroo_twelve_test());
#endif

   return 0;
}
