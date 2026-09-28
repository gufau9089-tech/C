/* LibTomCrypt, modular cryptographic library -- Tom St Denis */
/* SPDX-License-Identifier: Unlicense */
/* print all PEM related infos */
#include "tomcrypt_private.h"

#if defined(LTC_PEM_SSH)
static const struct {
   const char *is, *should;
} cipher_name_map[] = {
   { "", "none" },
   { "aes", "AES" },
   { "aria", "ARIA" },
   { "blowfish", "Blowfish" },
   { "c20p1305", "ChaCha20Poly1305" },
   { "camellia", "Camellia" },
   { "cast5", "CAST5" },
   { "chacha20", "ChaCha20" },
   { "3des", "3DES (EDE)" },
   { "des", "DES" },
   { "desx", "DES-X" },
   { "idea", "IDEA" },
   { "rc5", "RC5" },
   { "rc2", "RC2" },
   { "seed", "SEED" },
   { "serpent", "Serpent" },
   { "twofish", "Twofish" },
};

static const char *s_map_cipher(const char *name)
{
   unsigned long n;
   for (n = 0; n < LTC_ARRAY_SIZE(cipher_name_map); ++n) {
      if (strcmp(name, cipher_name_map[n].is) == 0)
         return cipher_name_map[n].should;
   }
   fprintf(stderr, "Error: Can't map %s\n", name);
   exit(1);
}

static const struct {
   enum cipher_mode mode;
   const char *name;
} cipher_mode_map[] = {
   { cm_none,   "none",   },
   { cm_cbc,    "CBC",    },
   { cm_cfb,    "CFB",    },
   { cm_cfb1,   "CFB1",   },
   { cm_cfb8,   "CFB8",   },
   { cm_ctr,    "CTR",    },
   { cm_ofb,    "OFB",    },
   { cm_stream, "STREAM", },
   { cm_gcm,    "GCM",    },
};

static const char *s_map_mode(enum cipher_mode mode)
{
   size_t n;
   mode &= cm_modes | cm_1bit | cm_8bit;
   for (n = 0; n < LTC_ARRAY_SIZE(cipher_mode_map); ++n) {
      if (cipher_mode_map[n].mode == mode)
         return cipher_mode_map[n].name;
   }
   fprintf(stderr, "Error: Can't map cipher_mode %d\n", mode);
   exit(1);
}

static int print_pem_ciphers(void)
{
   unsigned long n;
   printf("\nPEM ciphers:\n\n");
   for (n = 0; n < pem_dek_infos_num; ++n) {
      char nbuf[32] = {0};
      size_t nlen = strlen(pem_dek_infos[n].name);
      memcpy(nbuf, pem_dek_infos[n].name, nlen);
      nbuf[nlen-1] = '}';
      printf("\\hline \\texttt{%-18s & %-15s & %-25ld & %-6s \\\\\n",
                               nbuf, s_map_cipher(pem_dek_infos[n].algo),
                                              pem_dek_infos[n].keylen * 8,
                                                       s_map_mode(pem_dek_infos[n].mode));
   }
   return 0;
}

static int print_ssh_ciphers(void)
{
   unsigned long n;
   printf("\nSSH ciphers:\n\n");
   for (n = 0; n < ssh_ciphers_num; ++n) {
      char nbuf[32] = {0};
      size_t nlen = strlen(ssh_ciphers[n].name);
      memcpy(nbuf, ssh_ciphers[n].name, nlen);
      nbuf[nlen] = '}';
      printf("\\hline \\texttt{%-30s & %-16s & %-24ld & %-6s \\\\\n",
                               nbuf, s_map_cipher(ssh_ciphers[n].algo),
                                              ssh_ciphers[n].keylen * 8,
                                                       s_map_mode(ssh_ciphers[n].mode));
   }
   return 0;
}

static int s_to_lower(const char *in, char *out, unsigned long *outlen)
{
   unsigned long n;
   for (n = 0; n < *outlen && in[n]; ++n) {
      out[n] = tolower(in[n]);
   }
   if (n == *outlen)
      return CRYPT_BUFFER_OVERFLOW;
   out[n] = '\0';
   *outlen = n;
   return CRYPT_OK;
}

static int print_ecc_curves(void)
{
   unsigned long n;
   printf("\nECC curves:\n\n");
   for (n = 0; ltc_ecc_curves[n].OID != NULL; ++n) {
      const char * const *names;
      char lower[32] = {0}, buf[64] = {0};
      unsigned long m, bufl = 0, lowerl;
      int err = ecc_get_curve_names(ltc_ecc_curves[n].OID, &names);
      if (err != CRYPT_OK) {
         printf("\\error: OID %s not found (%s)\n", ltc_ecc_curves[n].OID, error_to_string(err));
         return EXIT_FAILURE;
      }
      for (m = 1; names[m]; ++m) {
         const char *name = names[m];
         if (memcmp(name, "P-", 2) == 0 || memcmp(name, "ECC-", 4) == 0) {
            /* Use the original name */
         } else {
            lowerl = sizeof(lower);
            if ((err = s_to_lower(name, lower, &lowerl)) != CRYPT_OK) {
               printf("\\error: %s could not be converted to lowercase (%s)\n", name, error_to_string(err));
               return EXIT_FAILURE;
            }
            name = lower;
         }
         if (m == 1) {
            err = snprintf(buf + bufl, sizeof(buf) - bufl, "%s", name);
         } else {
            err = snprintf(buf + bufl, sizeof(buf) - bufl, ", %s", name);
         }
         if (err == -1 || (unsigned)err > sizeof(buf) - bufl) {
            printf("\\error: snprintf returned %d at %s\n", err, name);
            return EXIT_FAILURE;
         }
         bufl += err;
      }
      lower[0] = '{';
      lowerl = sizeof(lower) - 2;
      if ((err = s_to_lower(names[0], &lower[1], &lowerl)) != CRYPT_OK) {
         printf("\\error: %s could not be converted to lowercase (%s)\n", names[0], error_to_string(err));
         return EXIT_FAILURE;
      }
      lower[lowerl + 1] = '}';
      lower[lowerl + 2] = '\0';
      printf("\\hline \\texttt%-17s & %-36s & %-21s \\\\\n", lower, buf, ltc_ecc_curves[n].OID);
   }
   return 0;
}

static int s_to_upper(const char *in, char *out, unsigned long *outlen)
{
   unsigned long n;
   for (n = 0; n < *outlen && in[n]; ++n) {
      out[n] = toupper(in[n]);
   }
   if (n == *outlen)
      return CRYPT_BUFFER_OVERFLOW;
   out[n] = '\0';
   *outlen = n;
   return CRYPT_OK;
}

static int s_to_desc(const char *in, char *out, unsigned long outlen, int has_desc)
{
   unsigned long n, m;
   if (outlen < 6) goto err_exit;
   XMEMCPY(out, "\\code{", 6);
   m = 6;
   for (n = 0; m < outlen - 1 && in[n]; ++n, ++m) {
      if (in[n] == '-' || in[n] == '_') {
         out[m++] = '\\';
         out[m] = '_';
      } else
         out[m] = tolower(in[n]);
   }
   if (outlen <= m) goto err_exit;
   if (!has_desc) {
      XMEMCPY(&out[m], "\\_desc", 6);
      m += 6;
   }
   out[m++] = '}';
   out[m] = '\0';
   return CRYPT_OK;
err_exit:
   fprintf(stderr, "Error: Can't print descriptor %s\n", in);
   exit(1);
}

struct desc {
   void *orig;
   char desc[64];
};

static int hash_sorter(const void *a, const void *b)
{
   const struct ltc_hash_descriptor *A, *B;
   A = ((const struct desc*)a)->orig;
   B = ((const struct desc*)b)->orig;
   if (A->hashsize < B->hashsize) return 1;
   if (A->hashsize > B->hashsize) return -1;
   if (A->ID < B->ID) return -1;
   if (A->ID > B->ID) return 1;
   return 0;
}

static void print_hash_line(const char *name, const struct ltc_hash_descriptor *p)
{
   char nbuf[32];
   unsigned long nlen = sizeof(nbuf);
   s_to_upper(p->name, nbuf, &nlen);
   printf("\\hline %-17s & %-32s & %lu & %2d \\\\\n", nbuf, name, p->hashsize, p->ID);
}

static int print_hash_descriptors(void)
{
   const struct {
      const char *name;
      const struct ltc_hash_descriptor * desc;
   } special_hash_descriptors[] = {
#define HASH_DESC(name) { #name, &name }
                                     HASH_DESC(sha256_portable_desc),
#ifdef LTC_SHA256_X86
                                     HASH_DESC(sha256_x86_desc),
#endif
                                     HASH_DESC(sha224_portable_desc),
#ifdef LTC_SHA224_X86
                                     HASH_DESC(sha224_x86_desc),
#endif
                                     HASH_DESC(sha1_portable_desc),
#ifdef LTC_SHA1_X86
                                     HASH_DESC(sha1_x86_desc),
#endif
                                     HASH_DESC(sha512_portable_desc),
#ifdef LTC_SHA512_X86
                                     HASH_DESC(sha512_x86_desc),
#endif
                                     HASH_DESC(sha384_portable_desc),
#ifdef LTC_SHA384_X86
                                     HASH_DESC(sha384_x86_desc),
#endif
                                     HASH_DESC(sha512_224_portable_desc),
#ifdef LTC_SHA512_224_X86
                                     HASH_DESC(sha512_224_x86_desc),
#endif
                                     HASH_DESC(sha512_256_portable_desc),
#ifdef LTC_SHA512_256_X86
                                     HASH_DESC(sha512_256_x86_desc),
#endif
   };
   struct desc descs[TAB_SIZE + 1] = {0};
   int ids[TAB_SIZE + 1] = {0};
   unsigned long n;

   printf("\nhash descriptors:\n\n");
   register_all_hashes();

   for (n = 0; hash_descriptor[n].name != NULL && n < TAB_SIZE; ++n) {
      if (hash_descriptor[n].ID > TAB_SIZE) {
         printf("Hash descriptor '%s' has invalid ID %d\n", hash_descriptor[n].name, hash_descriptor[n].ID);
         return EXIT_FAILURE;
      }
      if (ids[hash_descriptor[n].ID] != 0) {
         printf("Hash descriptor '%s' has duplicate ID %d\n", hash_descriptor[n].name, hash_descriptor[n].ID);
         return EXIT_FAILURE;
      }
      ids[hash_descriptor[n].ID] = 1;
      descs[n].orig = &hash_descriptor[n];
      s_to_desc(hash_descriptor[n].name, descs[n].desc, sizeof(descs[n].desc), 0);
   }
   qsort(descs, n, sizeof(struct desc), &hash_sorter);
   for (n = 0; hash_descriptor[n].name != NULL && n < TAB_SIZE; ++n) {
      print_hash_line(descs[n].desc, descs[n].orig);
   }

   printf("\nspecial hash descriptors:\n\n");
   for (n = 0; n < LTC_ARRAY_SIZE(special_hash_descriptors); ++n) {
      char nbuf[64];
      unsigned long nlen = sizeof(nbuf);
      s_to_desc(special_hash_descriptors[n].name, nbuf, nlen, 1);
      print_hash_line(nbuf, special_hash_descriptors[n].desc);
   }
   return 0;
}

static void LTC_NORETURN die(int status)
{
   FILE* o = status == EXIT_SUCCESS ? stdout : stderr;
   fprintf(o,
         "Usage: latex-tables [<-h|-l|type>]\n\n"
         "Generate LaTeX tables from some library internal data.\n\n"
         "\ttype\tThe type of table to print.\n"
         "\t-l\tList all built-in types that can be printed.\n"
         "\t-h\tThe help you're looking at.\n"
   );
   exit(status);
}

int main(int argc, char **argv)
{
   const struct {
      const char *name;
      int (*printer)(void);
   } printers[] = {
   #define PRINTER(name) { #name, print_ ## name }
                   PRINTER(hash_descriptors),
                   PRINTER(pem_ciphers),
                   PRINTER(ssh_ciphers),
                   PRINTER(ecc_curves),
   #undef PRINTER
   };
   int err;
   unsigned long n;
   if (argc > 1) {
      if (strstr(argv[1], "-h"))
         die(0);
      if (strstr(argv[1], "-l")) {
         for (n = 0; n < LTC_ARRAY_SIZE(printers); ++n) {
            printf("%s\n", printers[n].name);
         }
         return 0;
      }
   }
   printf("libtomcrypt latex tables\n");

   for (n = 0; n < LTC_ARRAY_SIZE(printers); ++n) {
      if (argc > 1 && strstr(printers[n].name, argv[1]) == NULL)
         continue;
      if ((err = printers[n].printer()) != 0)
         return err;
   }

   return 0;
}
#else
int main(void) { return EXIT_FAILURE; }
#endif
