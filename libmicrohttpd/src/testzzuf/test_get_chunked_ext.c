/*
     This file is part of libmicrohttpd
     Copyright (C) 2026 Christian Grothoff

     libmicrohttpd is free software; you can redistribute it and/or modify
     it under the terms of the GNU General Public License as published
     by the Free Software Foundation; either version 2, or (at your
     option) any later version.

     libmicrohttpd is distributed in the hope that it will be useful, but
     WITHOUT ANY WARRANTY; without even the implied warranty of
     MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
     General Public License for more details.

     You should have received a copy of the GNU General Public License
     along with libmicrohttpd; see the file COPYING.  If not, write to the
     Free Software Foundation, Inc., 51 Franklin Street, Fifth Floor,
     Boston, MA 02110-1301, USA.
*/

/**
 * @file testzzuf/test_get_chunked_ext.c
 * @brief  Fuzzing testcase for chunked transfers with chunk extensions
 * @author Christian Grothoff
 *
 * This single source builds two programs:
 * - test_get_chunked_ext: the request is a GET with a chunked body and
 *   MHD answers with a chunked reply that carries a footer, so that both
 *   the request-side chunk parser and the reply-side chunk writer are
 *   exercised;
 * - test_put_chunked_ext: the request is a PUT with a chunked body and
 *   MHD answers from a static buffer.
 *
 * libcurl cannot generate chunk extensions, so the requests are written
 * by the raw socket client of mhd_zzuf_common.c.  The client still talks
 * to the very same port (and therefore through the very same zzuf/socat
 * corruption layer) as the libcurl based tests of this directory.
 *
 * In addition to the fuzzed traffic, the test runs a small deterministic
 * self-check of the chunk-extension parser.  The self-check talks to MHD
 * *directly*, bypassing socat, and is therefore not fuzzed at all; it can
 * only be run in the socat mode (which is the mode that is mandatory when
 * MHD is built with sanitizers).  The self-check verifies that a chunked
 * body with chunk extensions is decoded byte-exactly; a parser that fails
 * to consume the CRLF that terminates a chunk-extension line cannot pass
 * it.
 */

#include "platform.h"
#include <curl/curl.h>
#include <microhttpd.h>
#include <stdlib.h>
#include <string.h>

#include "mhd_zzuf_common.h"

#define TEST_MAGIC_MARKER 0xFEE1C0DE

#define EMPTY_PAGE "Empty page."

/**
 * The port offset used if the port cannot be auto-detected.
 */
#define TEST_PORT_OFFSET 145

/**
 * The port offset of the (unfuzzed) self-check daemon.
 */
#define TEST_SELFCHECK_PORT_OFFSET 160

/**
 * The maximum size of a request body accepted by this test.
 */
#define MAX_BODY_SIZE 256


/**
 * Non-zero for the "put" flavour of this test.
 */
static int use_put;

/**
 * Non-zero if MHD should answer with a chunked reply.
 */
static int use_chunked_reply;


/**
 * One chunked request body with (possibly hostile) chunk extensions.
 */
struct chunk_case
{
  /**
   * The name of the case; also used as the last path segment of the URI.
   */
  const char *name;

  /**
   * The chunked body, exactly as it goes on the wire.
   */
  const char *wire;

  /**
   * The body that MHD is expected to decode, or NULL if the request is
   * not required to be accepted at all (deliberately malformed input).
   */
  const char *expected;
};


static const struct chunk_case chunk_cases[] = {
  { "simple",
    "5;name=value\r\nHELLO\r\n0\r\n\r\n",
    "HELLO" },
  { "flag",
    "5;flag\r\nHELLO\r\n0\r\n\r\n",
    "HELLO" },
  { "quoted",
    "5;n=\"a;b=c\"\r\nHELLO\r\n0\r\n\r\n",
    "HELLO" },
  { "multi",
    "3;a=b;c=d;e\r\nabc\r\n2;x\r\nde\r\n0\r\n\r\n",
    "abcde" },
  { "lastext",
    "5;a=b\r\nHELLO\r\n0;final=1\r\n\r\n",
    "HELLO" },
  { "trailers",
    "5;a=b\r\nHELLO\r\n0\r\nX-Trailer: yes\r\nX-Other: 1\r\n\r\n",
    "HELLO" },
  { "extonly",
    "5;a\r\nHELLO\r\n0;b\r\n\r\n",
    "HELLO" },
  /* The following cases are deliberately malformed: MHD is free to reject
     them, it just must not misbehave. */
  { "wsbefore",
    "5 ;n=v\r\nHELLO\r\n0\r\n\r\n",
    NULL },
  { "wsaround",
    "5; n = v \r\nHELLO\r\n0\r\n\r\n",
    NULL },
  { "barelf",
    "5;a=b\nHELLO\r\n0\r\n\r\n",
    NULL },
  { "extcr",
    "5;a=b\rHELLO\r\n0\r\n\r\n",
    NULL },
  { "noext",
    "5;\r\nHELLO\r\n0\r\n\r\n",
    NULL }
};

#define NUM_CHUNK_CASES \
        (sizeof(chunk_cases) / sizeof(chunk_cases[0]))

/**
 * The number of leading entries of #chunk_cases that are well-formed and
 * therefore usable for the deterministic self-check.
 */
#define NUM_VALID_CHUNK_CASES 7

/**
 * A chunk-size line with a very long extension, built at run time.
 */
static char *long_ext_body;


/**
 * The closure of the access handler callback.
 */
struct ahc_param
{
  /**
   * Must have #TEST_MAGIC_MARKER value.
   */
  unsigned int magic;

  /**
   * Non-zero if any error has been encountered.
   */
  unsigned int err_flag;

  /**
   * Non-zero while the deterministic self-check is running.
   */
  int self_check;

  /**
   * The body that is expected during the self-check, may be NULL.
   */
  const char *expect_body;

  /**
   * Set to non-zero by the handler when the expected body has been seen.
   */
  int body_matched;
};


/**
 * The per-request state.
 */
struct req_state
{
  /**
   * The number of bytes stored in @e body.
   */
  size_t body_len;

  /**
   * Set to non-zero if more data has been received than fits into @e body.
   */
  int overflow;

  /**
   * The received body.
   */
  char body[MAX_BODY_SIZE];
};


/**
 * The closure of the content reader callback.
 */
struct content_cb_param
{
  /**
   * The response the callback belongs to, needed to add the footer.
   */
  struct MHD_Response *response;
};


/**
 * MHD content reader callback for the chunked reply.
 *
 * @param cls the closure
 * @param pos the position in the reply body
 * @param[out] buf the buffer to fill
 * @param max the size of @a buf
 * @return the number of bytes written, or the end-of-stream marker
 */
static ssize_t
content_cb (void *cls, uint64_t pos, char *buf, size_t max)
{
  struct content_cb_param *ccp = (struct content_cb_param *) cls;

  if (pos >= 512)
  {
    if (MHD_YES != MHD_add_response_footer (ccp->response,
                                            "Footer", "working"))
    {
      fprintf (stderr, "MHD_add_response_footer() failed "
               "at line %d.\n", (int) __LINE__);
      fflush (stderr);
      abort ();
    }
    return MHD_CONTENT_READER_END_OF_STREAM;
  }
  if (max > 128)
    max = 128;
  memset (buf, 'A' + (char) (unsigned int) (pos / 128), max);
  return (ssize_t) max;
}


/**
 * Free the closure of the content reader callback.
 *
 * @param ptr the closure to free
 */
static void
content_cb_free (void *ptr)
{
  free (ptr);
}


/**
 * Iterator over the request footers (trailers).
 *
 * @param cls the closure
 * @param kind the kind of the value
 * @param key the key
 * @param value the value
 * @return #MHD_YES to continue the iteration
 */
static enum MHD_Result
footer_iterator (void *cls,
                 enum MHD_ValueKind kind,
                 const char *key,
                 const char *value)
{
  unsigned int *sum = (unsigned int *) cls;

  (void) kind; /* Unused. Mute compiler warning. */
  if (NULL != key)
    *sum += (unsigned int) strlen (key);
  if (NULL != value)
    *sum += (unsigned int) strlen (value);
  return MHD_YES;
}


static enum MHD_Result
ahc_chunked_ext (void *cls,
                 struct MHD_Connection *connection,
                 const char *url,
                 const char *method,
                 const char *version,
                 const char *upload_data,
                 size_t *upload_data_size,
                 void **req_cls)
{
  struct ahc_param *param = (struct ahc_param *) cls;
  struct req_state *rs;
  struct MHD_Response *response;
  enum MHD_Result ret;
  unsigned int footer_sum = 0;

  (void) url; (void) method; (void) version;

  if ((NULL == param) || (TEST_MAGIC_MARKER != param->magic))
  {
    fprintf (stderr, "The 'cls' parameter is invalid "
             "at line %d.\n", (int) __LINE__);
    fflush (stderr);
    abort ();
  }
  if (NULL == *req_cls)
  {
    rs = malloc (sizeof(struct req_state));
    if (NULL == rs)
      return MHD_NO; /* External error */
    rs->body_len = 0;
    rs->overflow = 0;
    *req_cls = rs;
    return MHD_YES;
  }
  rs = (struct req_state *) *req_cls;

  if ((NULL != upload_data_size) && (0 != *upload_data_size))
  {
    size_t to_copy = *upload_data_size;

    if (to_copy > sizeof(rs->body) - rs->body_len)
    {
      to_copy = sizeof(rs->body) - rs->body_len;
      rs->overflow = 1;
    }
    if ((0 != to_copy) && (NULL != upload_data))
    {
      memcpy (rs->body + rs->body_len, upload_data, to_copy);
      rs->body_len += to_copy;
    }
    *upload_data_size = 0; /* All data have been processed */
    return MHD_YES;
  }

  /* The request is complete. */
  (void) MHD_get_connection_values (connection, MHD_FOOTER_KIND,
                                    &footer_iterator, &footer_sum);
  if (param->self_check && (NULL != param->expect_body))
  {
    const size_t elen = strlen (param->expect_body);

    if ((! rs->overflow) &&
        (elen == rs->body_len) &&
        (0 == memcmp (rs->body, param->expect_body, elen)))
      param->body_matched = 1;
    else
    {
      fprintf (stderr,
               "Self-check: the decoded request body does not match the "
               "expected body. Expected %u bytes ('%s'), got %u bytes. "
               "At line %d.\n",
               (unsigned int) elen, param->expect_body,
               (unsigned int) rs->body_len, (int) __LINE__);
      param->err_flag = 1;
    }
  }
  free (rs);
  *req_cls = NULL;

  if (use_chunked_reply)
  {
    struct content_cb_param *ccp;

    ccp = malloc (sizeof(struct content_cb_param));
    if (NULL == ccp)
      return MHD_NO; /* External error */
    ccp->response = NULL;
    response = MHD_create_response_from_callback (MHD_SIZE_UNKNOWN, 1024,
                                                  &content_cb, ccp,
                                                  &content_cb_free);
    if (NULL == response)
      free (ccp);
    else
      ccp->response = response;
  }
  else
    response =
      MHD_create_response_from_buffer_static (MHD_STATICSTR_LEN_ (EMPTY_PAGE),
                                              EMPTY_PAGE);
  if (NULL == response)
  {
    fprintf (stderr, "Failed to create the response "
             "at line %d.\n", (int) __LINE__);
    return MHD_NO; /* External error, do not raise the error flag */
  }
  ret = MHD_YES;
  if (zzuf_use_close || ! zzuf_oneone)
    ret = MHD_add_response_header (response,
                                   MHD_HTTP_HEADER_CONNECTION,
                                   "close");
  if (MHD_YES == ret)
    ret = MHD_queue_response (connection, MHD_HTTP_OK, response);
  MHD_destroy_response (response);
  return ret;
}


static void
req_completed (void *cls,
               struct MHD_Connection *connection,
               void **req_cls,
               enum MHD_RequestTerminationCode toe)
{
  (void) cls; (void) connection; (void) toe;

  if (NULL == *req_cls)
    return;
  free (*req_cls);
  *req_cls = NULL;
}


/**
 * Build the request head for a given case.
 *
 * @param name the case name (used in the URI)
 * @param close_conn if non-zero, "Connection: close" is added, so that MHD
 *                   closes the connection right after the reply instead of
 *                   waiting for the connection timeout
 * @param[out] buf the buffer to fill
 * @param buf_size the size of @a buf
 */
static void
build_head (const char *name, int close_conn, char *buf, size_t buf_size)
{
  int len;

  len = snprintf (buf, buf_size,
                  "%s /chunked_ext/%s HTTP/1.1\r\n"
                  "Host: " ZZUF_MHD_LISTEN_IP "\r\n"
                  "Transfer-Encoding: chunked\r\n"
                  "%s"
                  "\r\n",
                  use_put ? "PUT" : "GET",
                  name,
                  close_conn ? "Connection: close\r\n" : "");
  if ((0 > len) || (buf_size <= (size_t) len))
  {
    fprintf (stderr, "snprintf() failed at line %d.\n", (int) __LINE__);
    fflush (stderr);
    abort ();
  }
}


static unsigned int
client_run (struct MHD_Daemon *d_extern,
            uint16_t port,
            void *cls)
{
  struct ahc_param *param = (struct ahc_param *) cls;
  unsigned int i;
  unsigned int loops;

  loops = zzuf_loop_count ();
  for (i = 0; i < loops; ++i)
  {
    const struct chunk_case *cc = chunk_cases + (i % NUM_CHUNK_CASES);
    struct zzuf_raw_part parts[4];
    char head[256];
    size_t num_parts;
    const char *wire;
    size_t wire_len;
    size_t split;

    fprintf (stderr, ".");
    build_head (cc->name, 0, head, sizeof(head));
    if ((NULL != long_ext_body) && (0 == i % 5))
      wire = long_ext_body; /* Occasionally use the over-long extension */
    else
      wire = cc->wire;
    wire_len = strlen (wire);
    /* Split the body so that the chunk-size (and chunk-extension) lines
       are torn apart between two TCP segments. */
    split = wire_len / 2;
    parts[0].data = head;
    parts[0].size = strlen (head);
    parts[1].data = wire;
    parts[1].size = split;
    parts[2].data = wire + split;
    parts[2].size = wire_len - split;
    /* Always append a pipelined follow-up request: if the chunk-extension
       line is not consumed correctly, the request boundary is lost and this
       second request is interpreted as chunk data (or the other way round).
       Its "Connection: close" also makes MHD close the connection right
       after the reply instead of waiting for the connection timeout. */
    parts[3].data = "GET /chunked_ext/after HTTP/1.1\r\n"
                    "Host: " ZZUF_MHD_LISTEN_IP "\r\n"
                    "Connection: close\r\n\r\n";
    parts[3].size = strlen (parts[3].data);
    num_parts = 4;
    if (ZZUF_RAW_SETUP_FAILED ==
        zzuf_raw_exchange (d_extern, port, parts, num_parts,
                           (unsigned int) ZZUF_CLIENT_TIMEOUT))
    {
      fprintf (stderr, "The raw client could not be set up "
               "at line %d.\n", (int) __LINE__);
      return 99; /* Not an MHD error */
    }
    fflush (stderr);
  }

  if (0 != param->err_flag)
  {
    fprintf (stderr, "One or more errors have been detected by the access "
             "handler callback function. At line %d.\n", (int) __LINE__);
    return 1;
  }
  return 0;
}


/**
 * Run the deterministic (unfuzzed) self-check of the chunk-extension
 * parser.  Only possible in the socat mode, where MHD's own port is not
 * touched by zzuf.
 *
 * @return zero on success, non-zero on failure
 */
static unsigned int
run_self_check (void)
{
  struct MHD_Daemon *d;
  struct MHD_Daemon *d_extern;
  struct ahc_param param;
  uint16_t port;
  unsigned int flags;
  unsigned int i;
  unsigned int ret = 0;

  param.magic = (unsigned int) TEST_MAGIC_MARKER;
  param.err_flag = 0;
  param.self_check = 1;
  param.expect_body = NULL;
  param.body_matched = 0;

  if (MHD_NO != MHD_is_feature_supported (MHD_FEATURE_AUTODETECT_BIND_PORT))
    port = 0;
  else
    port = (uint16_t) (ZZUF_BASE_PORT + TEST_SELFCHECK_PORT_OFFSET);
  if (MHD_YES == MHD_is_feature_supported (MHD_FEATURE_THREADS))
    flags = MHD_USE_SELECT_INTERNALLY;
  else
    flags = MHD_USE_NO_THREAD_SAFETY;
  d = zzuf_start_daemon (flags, &port, zzuf_opt_profile (0), 0,
                         &ahc_chunked_ext, &param,
                         &req_completed, &param, NULL);
  if (NULL == d)
    return 99; /* Not an MHD error */
  d_extern = (0 == (MHD_USE_INTERNAL_POLLING_THREAD & flags)) ? d : NULL;

  printf ("Running the deterministic (unfuzzed) chunk-extension "
          "self-check...\n");
  fflush (stdout);
  for (i = 0; i < NUM_VALID_CHUNK_CASES; ++i)
  {
    const struct chunk_case *cc = chunk_cases + i;
    struct zzuf_raw_part parts[3];
    char head[256];
    char resp[512];
    size_t resp_len = 0;
    size_t wire_len;
    size_t split;

    build_head (cc->name, 1, head, sizeof(head));
    wire_len = strlen (cc->wire);
    split = wire_len / 2;
    parts[0].data = head;
    parts[0].size = strlen (head);
    parts[1].data = cc->wire;
    parts[1].size = split;
    parts[2].data = cc->wire + split;
    parts[2].size = wire_len - split;

    param.expect_body = cc->expected;
    param.body_matched = 0;
    if (ZZUF_RAW_SETUP_FAILED ==
        zzuf_raw_exchange2 (d_extern, port, 1, parts, 3,
                            (unsigned int) ZZUF_CLIENT_TIMEOUT,
                            resp, sizeof(resp), &resp_len))
    {
      fprintf (stderr, "The raw client could not be set up "
               "at line %d.\n", (int) __LINE__);
      MHD_stop_daemon (d);
      return 99; /* Not an MHD error */
    }
    if (! param.body_matched)
    {
      fprintf (stderr,
               "Self-check FAILED for the chunk-extension case '%s': "
               "MHD did not decode the body as expected. "
               "At line %d.\n", cc->name, (int) __LINE__);
      ret = 1;
    }
    else if ((12 > resp_len) || (0 != memcmp (resp, "HTTP/1.1 200", 12)))
    {
      fprintf (stderr,
               "Self-check FAILED for the chunk-extension case '%s': "
               "MHD did not reply with '200'. "
               "At line %d.\n", cc->name, (int) __LINE__);
      ret = 1;
    }
  }
  MHD_stop_daemon (d);
  if (0 != param.err_flag)
    ret = 1;
  if (0 == ret)
    printf ("The chunk-extension self-check succeeded.\n");
  fflush (stdout);
  return ret;
}


/**
 * Build the chunked body with a very long chunk extension.
 *
 * With a connection memory pool of 256 or 512 bytes the chunk-size line
 * does not fit into the read buffer, so MHD emits the 413 reply from
 * handle_req_chunk_size_line_no_space().  Before commit e04eb218 it then
 * re-entered the error path and discarded that reply, so this is also the
 * regression test for it.
 *
 * @return non-zero on success, zero on failure
 */
static int
init_long_ext_body (void)
{
  static const char head[] = "5;longext=";
  static const char tail[] = "\r\nHELLO\r\n0\r\n\r\n";
  const size_t ext_len = 600;
  char *buf;

  buf = malloc (sizeof(head) + ext_len + sizeof(tail));
  if (NULL == buf)
    return 0;
  memcpy (buf, head, MHD_STATICSTR_LEN_ (head));
  memset (buf + MHD_STATICSTR_LEN_ (head), 'E', ext_len);
  memcpy (buf + MHD_STATICSTR_LEN_ (head) + ext_len, tail, sizeof(tail));
  long_ext_body = buf;
  return ! 0;
}


int
main (int argc, char *const *argv)
{
  struct ahc_param param;
  struct zzuf_run_params rp;
  unsigned int res;
  int use_magic_exit_codes;

  zzuf_parse_common_args (argc, argv);
  use_put = zzuf_name_has ("_put");
  use_chunked_reply = zzuf_name_has ("_get");
  if (1 != ((use_put ? 1 : 0) + (use_chunked_reply ? 1 : 0)))
  {
    fprintf (stderr, "Wrong test name '%s': no or multiple indications "
             "for the test type.\n", (NULL != argv[0]) ? argv[0] : "(NULL)");
    return 99;
  }
  use_magic_exit_codes = zzuf_run_with_socat || zzuf_dry_run;

  res = zzuf_check_runnable ();
  if (0 != res)
    return use_magic_exit_codes ? (int) res : 0;

  long_ext_body = NULL;
  if (! init_long_ext_body ())
  {
    fprintf (stderr, "malloc() failed at line %d.\n", (int) __LINE__);
    return use_magic_exit_codes ? 99 : 0;
  }

  /* The self-check needs an unfuzzed channel to MHD, which only exists
     when zzuf fuzzes socat instead of this process. */
  if (zzuf_run_with_socat && ! zzuf_dry_run)
  {
    res = run_self_check ();
    if (99 == res)
    {
      free (long_ext_body);
      return 99;
    }
    if (0 != res)
    {
      free (long_ext_body);
      return 1;
    }
  }

  param.magic = (unsigned int) TEST_MAGIC_MARKER;
  param.err_flag = 0;
  param.self_check = 0;
  param.expect_body = NULL;
  param.body_matched = 0;

  memset (&rp, 0, sizeof(rp));
  rp.port = zzuf_pick_port (TEST_PORT_OFFSET);
  rp.ahc = &ahc_chunked_ext;
  rp.ahc_cls = &param;
  rp.rcc = &req_completed;
  rp.rcc_cls = &param;
  rp.mem_limit_override = 0;
  rp.sweep_profiles = 1;
  rp.profile_start = 0;
  rp.client = &client_run;
  rp.client_cls = &param;

  res = zzuf_run_polling_modes (&rp);
  free (long_ext_body);
  long_ext_body = NULL;

  if (99 == res)
    return use_magic_exit_codes ? 99 : 0;
  if (77 == res)
    return use_magic_exit_codes ? 77 : 0;
  return (0 == res) ? 0 : 1; /* 0 == pass */
}
