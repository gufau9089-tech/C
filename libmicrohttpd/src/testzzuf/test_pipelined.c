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
 * @file testzzuf/test_pipelined.c
 * @brief  Fuzzing testcase for pipelined requests
 * @author Christian Grothoff
 *
 * Several complete requests are written with a single send() call, so that
 * MHD has to find the request boundaries inside one read buffer.  Corrupting
 * such a stream (or combining it with a connection memory pool that is too
 * small to hold all pipelined requests at once) is the most direct way to
 * produce a request boundary de-synchronisation.
 *
 * libcurl does not pipeline any more (HTTP/1.1 pipelining support was
 * removed in libcurl 7.62), therefore the raw socket client is used.  The
 * traffic still goes to the same port and through the same zzuf/socat
 * corruption layer as the libcurl based tests of this directory.
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
#define TEST_PORT_OFFSET 150

/**
 * The maximum size of a single pipelined batch.
 */
#define MAX_BATCH_SIZE 4096

#define HOST_HDR "Host: " ZZUF_MHD_LISTEN_IP "\r\n"


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
   * The number of requests seen so far.
   */
  unsigned int num_requests;
};


/**
 * The request templates that are concatenated into one pipelined batch.
 * The last request of every batch is added by build_batch().
 */
static const char *const req_templates[] = {
  "GET /pipe/a HTTP/1.1\r\n" HOST_HDR "\r\n",
  "GET /pipe/b?x=1&y HTTP/1.1\r\n" HOST_HDR "X-Pad: 0123456789\r\n\r\n",
  "HEAD /pipe/c HTTP/1.1\r\n" HOST_HDR "\r\n",
  "POST /pipe/d HTTP/1.1\r\n" HOST_HDR
  "Content-Length: 5\r\n\r\nHELLO",
  "PUT /pipe/e HTTP/1.1\r\n" HOST_HDR
  "Transfer-Encoding: chunked\r\n\r\n5\r\nHELLO\r\n0\r\n\r\n",
  /* An empty line before the request line: allowed to be skipped by MHD */
  "\r\nGET /pipe/f HTTP/1.1\r\n" HOST_HDR "\r\n",
  /* A request with a body that is *not* announced: the following bytes
     must not be swallowed as a body */
  "GET /pipe/g HTTP/1.1\r\n" HOST_HDR "\r\n"
};

#define NUM_REQ_TEMPLATES \
        (sizeof(req_templates) / sizeof(req_templates[0]))


static enum MHD_Result
ahc_pipelined (void *cls,
               struct MHD_Connection *connection,
               const char *url,
               const char *method,
               const char *version,
               const char *upload_data,
               size_t *upload_data_size,
               void **req_cls)
{
  static int marker;
  struct ahc_param *param = (struct ahc_param *) cls;
  struct MHD_Response *response;
  enum MHD_Result ret;

  (void) url; (void) method; (void) version; (void) upload_data;

  if ((NULL == param) || (TEST_MAGIC_MARKER != param->magic))
  {
    fprintf (stderr, "The 'cls' parameter is invalid "
             "at line %d.\n", (int) __LINE__);
    fflush (stderr);
    abort ();
  }
  if ((NULL == url) || (NULL == method) || (NULL == version))
  {
    fprintf (stderr, "One of the mandatory string parameters is NULL "
             "at line %d.\n", (int) __LINE__);
    param->err_flag = 1;
    return MHD_NO;
  }
  if (NULL == *req_cls)
  {
    *req_cls = &marker;
    return MHD_YES;
  }
  if ((NULL != upload_data_size) && (0 != *upload_data_size))
  {
    *upload_data_size = 0; /* Discard the body */
    return MHD_YES;
  }
  param->num_requests++;

  response =
    MHD_create_response_from_buffer_static (MHD_STATICSTR_LEN_ (EMPTY_PAGE),
                                            EMPTY_PAGE);
  if (NULL == response)
  {
    fprintf (stderr, "MHD_create_response_from_buffer_static() failed "
             "at line %d.\n", (int) __LINE__);
    return MHD_NO; /* External error, do not raise the error flag */
  }
  ret = MHD_YES;
  if (zzuf_use_close)
    ret = MHD_add_response_header (response,
                                   MHD_HTTP_HEADER_CONNECTION,
                                   "close");
  if (MHD_YES == ret)
    ret = MHD_queue_response (connection, MHD_HTTP_OK, response);
  MHD_destroy_response (response);
  return ret;
}


/**
 * Build one pipelined batch of requests.
 *
 * @param iteration the number of the current iteration
 * @param[out] buf the buffer to fill
 * @param buf_size the size of @a buf
 * @return the number of bytes written to @a buf
 */
static size_t
build_batch (unsigned int iteration, char *buf, size_t buf_size)
{
  static const char last_req[] =
    "GET /pipe/last HTTP/1.1\r\n" HOST_HDR "Connection: close\r\n\r\n";
  size_t pos = 0;
  unsigned int i;
  unsigned int num;

  num = 2 + (iteration % 4); /* 2 to 5 requests per batch */
  for (i = 0; i < num; ++i)
  {
    const char *req =
      req_templates[(iteration + i) % NUM_REQ_TEMPLATES];
    const size_t len = strlen (req);

    if (pos + len + sizeof(last_req) > buf_size)
      break;
    memcpy (buf + pos, req, len);
    pos += len;
  }
  if (pos + MHD_STATICSTR_LEN_ (last_req) <= buf_size)
  {
    memcpy (buf + pos, last_req, MHD_STATICSTR_LEN_ (last_req));
    pos += MHD_STATICSTR_LEN_ (last_req);
  }
  return pos;
}


static unsigned int
client_run (struct MHD_Daemon *d_extern,
            uint16_t port,
            void *cls)
{
  struct ahc_param *param = (struct ahc_param *) cls;
  unsigned int i;
  unsigned int loops;
  char batch[MAX_BATCH_SIZE];

  loops = zzuf_loop_count ();
  for (i = 0; i < loops; ++i)
  {
    struct zzuf_raw_part parts[2];
    size_t batch_len;
    size_t num_parts;

    fprintf (stderr, ".");
    batch_len = build_batch (i, batch, sizeof(batch));
    parts[0].data = batch;
    parts[0].size = batch_len;
    num_parts = 1;
    if (0 != i % 2)
    {
      /* Every other iteration: split the batch in the middle of a request,
         so that MHD has to keep a partial request in the read buffer while
         the previous ones are still being answered. */
      parts[0].size = batch_len / 2;
      parts[1].data = batch + parts[0].size;
      parts[1].size = batch_len - parts[0].size;
      num_parts = 2;
    }
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


int
main (int argc, char *const *argv)
{
  struct ahc_param param;
  struct zzuf_run_params rp;
  unsigned int res;
  int use_magic_exit_codes;

  zzuf_parse_common_args (argc, argv);
  use_magic_exit_codes = zzuf_run_with_socat || zzuf_dry_run;

  res = zzuf_check_runnable ();
  if (0 != res)
    return use_magic_exit_codes ? (int) res : 0;

  param.magic = (unsigned int) TEST_MAGIC_MARKER;
  param.err_flag = 0;
  param.num_requests = 0;

  memset (&rp, 0, sizeof(rp));
  rp.port = zzuf_pick_port (TEST_PORT_OFFSET);
  rp.ahc = &ahc_pipelined;
  rp.ahc_cls = &param;
  rp.rcc = NULL;
  rp.rcc_cls = NULL;
  rp.mem_limit_override = 0;
  rp.sweep_profiles = 1;
  rp.profile_start = 0;
  rp.client = &client_run;
  rp.client_cls = &param;

  res = zzuf_run_polling_modes (&rp);

  if (99 == res)
    return use_magic_exit_codes ? 99 : 0;
  if (77 == res)
    return use_magic_exit_codes ? 77 : 0;
  return (0 == res) ? 0 : 1; /* 0 == pass */
}
