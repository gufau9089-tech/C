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
 * @file fuzz/fuzz_postprocessor.c
 * @brief Fuzzer for MHD_post_process()
 * @author Christian Grothoff
 *
 * MHD_create_post_processor() only ever looks at the "Content-Type"
 * header of the connection it is given, so this harness fabricates the
 * minimal connection object instead of pushing a whole request through
 * a socket.  That keeps the harness fast and lets the fuzzer control
 * three dimensions that matter for the post processor and that a real
 * request would not expose directly:
 *
 *  - the raw Content-Type (encoding and multipart boundary),
 *  - the post processor buffer size,
 *  - how the POST data is split across MHD_post_process() calls.
 *
 * Input format:
 *   byte 0    content type selector
 *   byte 1    post processor buffer size selector
 *   byte 2    chunking pattern selector
 *   byte 3    length of the boundary taken from the payload
 *   byte 4..  the POST data
 */

#define FUZZ_HARNESS_NAME "fuzz_postprocessor"
#include "fuzz_common.h"

/* internal.h pulls in MHD_config.h and <microhttpd.h> in the right
   order; including <microhttpd.h> first would redefine _MHD_EXTERN. */
#include "internal.h"

static const size_t pp_buf_sizes[] = {
  256, 257, 300, 512, 1024, 2048, 4096, 65536
};

static const size_t chunk_patterns[] = {
  1, 2, 3, 5, 7, 13, 32, 64, 1024, 0 /* 0 == everything at once */
};

static struct MHD_Daemon *shared_daemon;

/** Statistics, printed at exit with --verbose. */
static unsigned long stat_pp_created;
static unsigned long stat_pp_failed;
static unsigned long stat_values;


static enum MHD_Result
dummy_ahc (void *cls,
           struct MHD_Connection *connection,
           const char *url,
           const char *method,
           const char *version,
           const char *upload_data,
           size_t *upload_data_size,
           void **req_cls)
{
  (void) cls; (void) connection; (void) url; (void) method; (void) version;
  (void) upload_data; (void) upload_data_size; (void) req_cls;
  return MHD_NO;
}


static void
stop_shared_daemon (void)
{
  if (NULL != shared_daemon)
  {
    MHD_stop_daemon (shared_daemon);
    shared_daemon = NULL;
  }
}


static void
print_stats (void)
{
  if (! fuzz_verbose)
    return;
  fprintf (stderr,
           "%s: post processors created=%lu rejected=%lu, "
           "values reported=%lu\n",
           FUZZ_HARNESS_NAME,
           stat_pp_created, stat_pp_failed, stat_values);
}


static struct MHD_Daemon *
get_shared_daemon (void)
{
  if (NULL == shared_daemon)
  {
    shared_daemon =
      MHD_start_daemon (MHD_USE_NO_LISTEN_SOCKET
                        | (fuzz_verbose ? MHD_USE_ERROR_LOG : 0u),
                        0, NULL, NULL, &dummy_ahc, NULL,
                        MHD_OPTION_END);
    if (NULL != shared_daemon)
    {
      (void) atexit (&stop_shared_daemon);
      (void) atexit (&print_stats);
    }
  }
  return shared_daemon;
}


struct pp_ctx
{
  const char *data;
  size_t data_len;
  uint64_t max_off;
};


static enum MHD_Result
post_iter (void *cls,
           enum MHD_ValueKind kind,
           const char *key,
           const char *filename,
           const char *content_type,
           const char *transfer_encoding,
           const char *data,
           uint64_t off,
           size_t size)
{
  struct pp_ctx *ctx = (struct pp_ctx *) cls;
  volatile size_t sink = 0;

  (void) kind;
  stat_values++;
  /* Touch every string the post processor claims to have produced;
     ASAN turns any dangling or out-of-bounds pointer into an error. */
  if (NULL != key)
    sink += strlen (key);
  if (NULL != filename)
    sink += strlen (filename);
  if (NULL != content_type)
    sink += strlen (content_type);
  if (NULL != transfer_encoding)
    sink += strlen (transfer_encoding);
  if ( (NULL != data) && (0 != size) )
  {
    size_t i;

    for (i = 0; i < size; i++)
      sink += (size_t) (unsigned char) data[i];
  }
  else if (NULL == data)
  {
    if (0 != size)
      fuzz_report_finding ("MHD_PostDataIterator called with NULL data but "
                           "non-zero size");
  }
  /* A single value is delivered in order and can never be longer than
     the POST data that was fed in. */
  if (off + size > ctx->data_len + 1)
    fuzz_report_finding ("MHD_PostDataIterator reported more value data "
                         "than the POST data contained");
  if (off > ctx->max_off + ctx->data_len)
    fuzz_report_finding ("MHD_PostDataIterator offset jumped implausibly");
  ctx->max_off = off;
  (void) sink;
  return MHD_YES;
}


int
LLVMFuzzerTestOneInput (const uint8_t *data,
                        size_t size)
{
  struct MHD_Connection c;
  struct MHD_HTTP_Req_Header h;
  struct MHD_PostProcessor *pp;
  struct pp_ctx ctx;
  char *ctype;
  char *body;
  size_t body_len;
  size_t buf_size;
  size_t chunk;
  size_t off;
  size_t blen;
  unsigned int sel;

  if (size < 5)
    return 0;
  if (NULL == get_shared_daemon ())
    return 0;

  sel = data[0];
  buf_size = pp_buf_sizes[data[1] % (sizeof (pp_buf_sizes)
                                     / sizeof (pp_buf_sizes[0]))];
  chunk = chunk_patterns[data[2] % (sizeof (chunk_patterns)
                                    / sizeof (chunk_patterns[0]))];
  blen = data[3];

  body_len = size - 4;
  if (body_len > 8192)
    body_len = 8192;
  if (blen > body_len)
    blen = body_len;

  /* Exactly sized copies so that ASAN catches reads past the end. */
  body = (char *) malloc (body_len + 1);
  if (NULL == body)
    return 0;
  memcpy (body, data + 4, body_len);
  body[body_len] = '\0';

  ctype = (char *) malloc (blen + 64);
  if (NULL == ctype)
  {
    free (body);
    return 0;
  }
  switch (sel % 6)
  {
  case 0:
    memcpy (ctype, MHD_HTTP_POST_ENCODING_FORM_URLENCODED,
            sizeof (MHD_HTTP_POST_ENCODING_FORM_URLENCODED));
    break;
  case 1:
  case 2:
    {
      /* multipart with a boundary taken from the payload */
      size_t o = 0;
      size_t i;

      memcpy (ctype, MHD_HTTP_POST_ENCODING_MULTIPART_FORMDATA,
              sizeof (MHD_HTTP_POST_ENCODING_MULTIPART_FORMDATA) - 1);
      o = sizeof (MHD_HTTP_POST_ENCODING_MULTIPART_FORMDATA) - 1;
      memcpy (ctype + o, "; boundary=", 11);
      o += 11;
      for (i = 0; i < blen; i++)
      {
        char ch = body[i];

        /* A NUL would truncate the header value; map it away. */
        ctype[o++] = ('\0' == ch) ? 'x' : ch;
      }
      ctype[o] = '\0';
      break;
    }
  case 3:
    (void) snprintf (ctype, blen + 64,
                     "multipart/form-data; boundary=\"%.*s\"",
                     (int) ((blen > 40) ? 40 : blen), body);
    break;
  case 4:
    memcpy (ctype, MHD_HTTP_POST_ENCODING_MULTIPART_FORMDATA,
            sizeof (MHD_HTTP_POST_ENCODING_MULTIPART_FORMDATA));
    break;
  default:
    memcpy (ctype, "text/plain", sizeof ("text/plain"));
    break;
  }

  memset (&c, 0, sizeof (c));
  memset (&h, 0, sizeof (h));
  h.header = MHD_HTTP_HEADER_CONTENT_TYPE;
  h.header_size = MHD_STATICSTR_LEN_ (MHD_HTTP_HEADER_CONTENT_TYPE);
  h.value = ctype;
  h.value_size = strlen (ctype);
  h.kind = MHD_HEADER_KIND;
  c.daemon = shared_daemon;
  c.rq.headers_received = &h;
  c.rq.headers_received_tail = &h;
  c.state = MHD_CONNECTION_HEADERS_PROCESSED;

  ctx.data = body;
  ctx.data_len = body_len;
  ctx.max_off = 0;

  pp = MHD_create_post_processor (&c, buf_size, &post_iter, &ctx);
  if (NULL == pp)
  {
    stat_pp_failed++;
    free (ctype);
    free (body);
    return 0;
  }
  stat_pp_created++;

  off = 0;
  while (off < body_len)
  {
    size_t n = (0 == chunk) ? (body_len - off) : chunk;

    if (n > body_len - off)
      n = body_len - off;
    (void) MHD_post_process (pp, body + off, n);
    off += n;
  }
  /* Final, zero-length call: what MHD itself does at the end of the
     upload. */
  (void) MHD_post_process (pp, body + body_len, 0);
  (void) MHD_destroy_post_processor (pp);

  free (ctype);
  free (body);
  return 0;
}


/* ------------------------------------------------------------------ */
/* Generator                                                           */
/* ------------------------------------------------------------------ */

static const char *const gen_disp[] = {
  "Content-Disposition: form-data; name=\"a\"",
  "Content-Disposition: form-data; name=\"a\"; filename=\"f.txt\"",
  "Content-Disposition: form-data; name=a",
  "Content-Disposition: form-data",
  "Content-Disposition: attachment; name=\"a\"",
  "Content-Disposition: form-data; name=\"\"",
  "Content-Disposition: form-data; name=\"a",
  "Content-Type: text/plain",
  "Content-Transfer-Encoding: binary",
  "X-Other: value"
};

static const char *const gen_kv[] = {
  "a=1", "b=%41", "c", "d=", "=e", "&", "&&", "a=%", "a=%4", "a=%zz",
  "verylongkeyname=verylongvaluewithlotsofcharacters", "a+b=c+d",
  "%41%42=%43%44"
};


static size_t
fuzz_generate (struct fuzz_rng *rng,
               uint8_t *buf,
               size_t cap)
{
  size_t len = 0;
  int multipart;
  const char *boundary;
  unsigned int nparts;
  unsigned int i;
  static const char *const boundaries[] = {
    "--abc", "XY", "boundary", "-", "aa", "0123456789012345678901234567890",
    "a\"b"
  };

#define ADD(s) \
  do { \
    const char *s_ = (s); \
    size_t l_ = strlen (s_); \
    if (len + l_ >= cap) \
    return len; \
    memcpy (buf + len, s_, l_); \
    len += l_; \
  } while (0)

  if (cap < 64)
    return 0;
  multipart = ! fuzz_chance (rng, 3);
  boundary = boundaries[fuzz_below (rng,
                                    (uint32_t) (sizeof (boundaries)
                                                / sizeof (char *)))];
  buf[len++] = (uint8_t) (multipart ? (1 + fuzz_below (rng, 2)) : 0);
  buf[len++] = fuzz_byte (rng);
  buf[len++] = fuzz_byte (rng);
  buf[len++] = (uint8_t) strlen (boundary);
  if (multipart)
  {
    /* The first strlen(boundary) bytes of the body double as the
       boundary in the Content-Type header (see the input format). */
    ADD (boundary);
    nparts = 1 + fuzz_below (rng, 4);
    for (i = 0; i < nparts; i++)
    {
      unsigned int nhdr = fuzz_below (rng, 3);
      unsigned int k;

      ADD ("\r\n--");
      ADD (boundary);
      ADD ("\r\n");
      for (k = 0; k <= nhdr; k++)
      {
        ADD (gen_disp[fuzz_below (rng,
                                  (uint32_t) (sizeof (gen_disp)
                                              / sizeof (char *)))]);
        ADD ("\r\n");
      }
      ADD ("\r\n");
      {
        unsigned int n = fuzz_below (rng, 40);

        for (k = 0; (k < n) && (len < cap); k++)
          buf[len++] = (uint8_t) ('A' + fuzz_below (rng, 26));
      }
    }
    ADD ("\r\n--");
    ADD (boundary);
    ADD (fuzz_chance (rng, 4) ? "\r\n" : "--\r\n");
  }
  else
  {
    unsigned int n = 1 + fuzz_below (rng, 10);

    for (i = 0; i < n; i++)
    {
      if (0 != i)
        ADD ("&");
      ADD (gen_kv[fuzz_below (rng,
                              (uint32_t) (sizeof (gen_kv) / sizeof (char *)))]);
    }
  }
#undef ADD
  return len;
}


/* ------------------------------------------------------------------ */
/* Seed corpus                                                         */
/* ------------------------------------------------------------------ */

struct pp_seed
{
  const char *txt;
  size_t len;
};

#define PSEED(t) { t, sizeof (t) - 1 }

static const struct pp_seed pp_seeds[] = {
  PSEED ("\x00\x00\x00\x00" "a=1&b=%41&c"),
  PSEED ("\x00\x00\x04\x00" "a=1&b=%41&c"),
  PSEED ("\x00\x00\x00\x00" "a=%"),
  PSEED ("\x00\x00\x00\x00" "&&&&"),
  PSEED ("\x01\x00\x00\x05" "--abc\r\n----abc\r\n"
         "Content-Disposition: form-data; name=\"k\"\r\n\r\nvalue\r\n"
         "----abc--\r\n"),
  PSEED ("\x01\x00\x01\x05" "--abc\r\n----abc\r\n"
         "Content-Disposition: form-data; name=\"k\"; filename=\"f\"\r\n"
         "Content-Type: text/plain\r\n\r\nvalue\r\n----abc--\r\n"),
  PSEED ("\x01\x07\x02\x02" "XY\r\n--XY\r\n\r\nnoheaders\r\n--XY--\r\n"),
  PSEED ("\x01\x00\x00\x01" "-\r\n---\r\n\r\nx\r\n-----\r\n"),
  PSEED ("\x04\x00\x00\x00" "no boundary at all"),
  PSEED ("\x05\x00\x00\x00" "text/plain body"),
  PSEED ("\x03\x00\x00\x03" "a\"b\r\n--a\"b\r\n\r\nv\r\n--a\"b--\r\n")
};


static size_t
fuzz_seed_count (void)
{
  return sizeof (pp_seeds) / sizeof (pp_seeds[0]);
}


static const uint8_t *
fuzz_seed_get (size_t idx,
               size_t *len)
{
  *len = pp_seeds[idx].len;
  return (const uint8_t *) pp_seeds[idx].txt;
}
