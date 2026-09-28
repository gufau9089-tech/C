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
 * @file testzzuf/test_get_args.c
 * @brief  Fuzzing testcase for GET requests with hostile query strings
 * @author Christian Grothoff
 *
 * The point of this test is the combination of
 * - query strings that contain arguments *without* the '=' character,
 *   empty names, empty values, trailing '&', percent-encoded names and
 *   a very long tail argument, and
 * - a very small connection memory pool (below MHD_BUF_INC_SIZE == 1500).
 *
 * Only with a pool that small does MHD try to re-use the tail of the
 * request header buffer ("shift back", see get_req_headers() in
 * connection.c), and the position of the end of the *last parsed element*
 * is used for the pointer arithmetic there.  For an argument without '='
 * that element has no value at all, so the "end of the value" is not a
 * valid pointer.
 *
 * libcurl always sends at least a "Host:" header, so with libcurl alone
 * the last parsed element is always a header and never a query argument.
 * Therefore this test additionally uses the raw socket client to send
 * header-less HTTP/1.0 requests, for which the last parsed element really
 * is the trailing query argument.
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
#define TEST_PORT_OFFSET 140

/**
 * The length of the "very long" trailing argument.
 * Deliberately larger than the largest memory pool of the option matrix,
 * so that MHD has to reject some of the requests as "too large" as well.
 */
#define LONG_ARG_LEN 700


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
   * The checksum over all seen arguments, only used to make sure that
   * the compiler cannot optimise the memory accesses away.
   */
  unsigned int arg_sum;
};


/**
 * The query strings used by the libcurl-driven part of the test.
 * Every one of them ends with an element that has no '=' character.
 */
static const char *const query_strings[] = {
  "/test_uri?a=1&b&c=&d",
  "/test_uri?x&y=&z=%20%41&trail",
  "/test_uri?%61%62=%63&noeq",
  "/test_uri?one=1&&two=2&",
  "/test_uri?=novalue&=&x",
  "/test_uri?a=1;b=2&c",
  "/test_uri?%zz=%2&broken%",
  "/test_uri?dup=1&dup=2&dup"
};

/**
 * The raw (header-less) requests.  Filled in by init_raw_requests().
 */
static char *raw_requests[6];


/**
 * Build the raw requests used by this test.
 *
 * @return non-zero on success, zero on failure
 */
static int
init_raw_requests (void)
{
  static const char *const tails[] = {
    /* Last element of the request has no '=': the interesting case. */
    "/test_uri?a=1&b HTTP/1.0\r\n\r\n",
    "/test_uri?trailing_argument_without_equals_sign HTTP/1.0\r\n\r\n",
    "/test_uri?a=1&b=2& HTTP/1.0\r\n\r\n",
    "/test_uri?= HTTP/1.0\r\n\r\n"
  };
  size_t i;
  char *buf;

  for (i = 0; i < sizeof(tails) / sizeof(tails[0]); ++i)
  {
    const size_t len = strlen ("GET ") + strlen (tails[i]);
    buf = malloc (len + 1);
    if (NULL == buf)
      return 0;
    memcpy (buf, "GET ", strlen ("GET "));
    memcpy (buf + strlen ("GET "), tails[i], strlen (tails[i]) + 1);
    raw_requests[i] = buf;
  }
  /* A header-less request with a very long trailing argument without '=' */
  buf = malloc (LONG_ARG_LEN + 64);
  if (NULL == buf)
    return 0;
  memcpy (buf, "GET /t?k=v&", strlen ("GET /t?k=v&"));
  memset (buf + strlen ("GET /t?k=v&"), 'L', LONG_ARG_LEN);
  memcpy (buf + strlen ("GET /t?k=v&") + LONG_ARG_LEN,
          " HTTP/1.0\r\n\r\n",
          strlen (" HTTP/1.0\r\n\r\n") + 1);
  raw_requests[4] = buf;
  /* The same, but with a single (minimal) header line, so that the last
     parsed element is a header and the "normal" branch is taken with the
     very same (small) memory pool. */
  buf = malloc (LONG_ARG_LEN + 96);
  if (NULL == buf)
    return 0;
  memcpy (buf, "GET /t?k=v&", strlen ("GET /t?k=v&"));
  memset (buf + strlen ("GET /t?k=v&"), 'L', LONG_ARG_LEN);
  memcpy (buf + strlen ("GET /t?k=v&") + LONG_ARG_LEN,
          " HTTP/1.1\r\nHost: a\r\n\r\n",
          strlen (" HTTP/1.1\r\nHost: a\r\n\r\n") + 1);
  raw_requests[5] = buf;
  return ! 0;
}


/**
 * Free the raw requests.
 */
static void
free_raw_requests (void)
{
  size_t i;

  for (i = 0; i < sizeof(raw_requests) / sizeof(raw_requests[0]); ++i)
  {
    if (NULL != raw_requests[i])
      free (raw_requests[i]);
    raw_requests[i] = NULL;
  }
}


/**
 * Touch every byte of every key and value so that the sanitizers (or
 * the operating system) notice pointers into unmapped memory.
 *
 * @param cls the closure
 * @param kind the kind of the value
 * @param key the key, never NULL
 * @param key_size the size of @a key
 * @param value the value, may be NULL for arguments without '='
 * @param value_size the size of @a value
 * @return #MHD_YES to continue the iteration
 */
static enum MHD_Result
arg_iterator (void *cls,
              enum MHD_ValueKind kind,
              const char *key,
              size_t key_size,
              const char *value,
              size_t value_size)
{
  struct ahc_param *param = (struct ahc_param *) cls;
  size_t i;

  (void) kind; /* Unused. Mute compiler warning. */
  if (TEST_MAGIC_MARKER != param->magic)
  {
    fprintf (stderr, "The 'param->magic' has wrong value "
             "at line %d.\n", (int) __LINE__);
    fflush (stderr);
    abort ();
  }
  if ((NULL == key) && (0 != key_size))
  {
    fprintf (stderr, "The 'key' is NULL while 'key_size' is not zero "
             "at line %d.\n", (int) __LINE__);
    param->err_flag = 1;
    return MHD_YES;
  }
  if ((NULL == value) && (0 != value_size))
  {
    fprintf (stderr, "The 'value' is NULL while 'value_size' is not zero "
             "at line %d.\n", (int) __LINE__);
    param->err_flag = 1;
    return MHD_YES;
  }
  for (i = 0; i < key_size; ++i)
    param->arg_sum += (unsigned int) (unsigned char) key[i];
  for (i = 0; i < value_size; ++i)
    param->arg_sum += (unsigned int) (unsigned char) value[i];
  /* Also touch the zero-termination that MHD guarantees. */
  if (NULL != key)
    param->arg_sum += (unsigned int) (unsigned char) key[key_size];
  if (NULL != value)
    param->arg_sum += (unsigned int) (unsigned char) value[value_size];
  return MHD_YES;
}


static enum MHD_Result
ahc_args (void *cls,
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
  const char *val;

  (void) url; (void) method; (void) version; (void) upload_data;

  if ((NULL == param) || (TEST_MAGIC_MARKER != param->magic))
  {
    fprintf (stderr, "The 'cls' parameter is invalid "
             "at line %d.\n", (int) __LINE__);
    fflush (stderr);
    abort ();
  }
  if (NULL == *req_cls)
  {
    *req_cls = &marker;
    return MHD_YES;
  }
  if ((NULL != upload_data_size) && (0 != *upload_data_size))
  {
    *upload_data_size = 0; /* Discard any body */
    return MHD_YES;
  }

  /* Walk over all arguments; this is what dereferences the (possibly
     broken) pointers stored while the request line was parsed. */
  (void) MHD_get_connection_values_n (connection,
                                      MHD_GET_ARGUMENT_KIND,
                                      &arg_iterator,
                                      param);
  /* Also walk over the headers, so that a corrupted header list is
     detected as well. */
  (void) MHD_get_connection_values_n (connection,
                                      MHD_HEADER_KIND,
                                      &arg_iterator,
                                      param);
  /* Lookups of both present and absent keys, including a key that is
     known to be present without a value. */
  val = MHD_lookup_connection_value (connection, MHD_GET_ARGUMENT_KIND, "b");
  if (NULL != val)
    param->arg_sum += (unsigned int) strlen (val);
  val = MHD_lookup_connection_value (connection, MHD_GET_ARGUMENT_KIND, "a");
  if (NULL != val)
    param->arg_sum += (unsigned int) strlen (val);
  val = MHD_lookup_connection_value (connection, MHD_GET_ARGUMENT_KIND,
                                     "no_such_argument");
  if (NULL != val)
    param->arg_sum += (unsigned int) strlen (val);

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
  if (zzuf_use_close || ! zzuf_oneone)
    ret = MHD_add_response_header (response,
                                   MHD_HTTP_HEADER_CONNECTION,
                                   "close");
  if (MHD_YES == ret)
    ret = MHD_queue_response (connection, MHD_HTTP_OK, response);
  MHD_destroy_response (response);
  return ret;
}


static unsigned int
client_run (struct MHD_Daemon *d_extern,
            uint16_t port,
            void *cls)
{
  struct ahc_param *param = (struct ahc_param *) cls;
  struct zzuf_curl_driver drv;
  struct zzuf_curl_sink sink;
  unsigned int i;
  unsigned int loops;

  loops = zzuf_loop_count ();
  if (! zzuf_curl_driver_init (&drv, d_extern))
    return 99; /* Not an MHD error */

  for (i = 0; i < loops; ++i)
  {
    CURL *c;
    const unsigned int num_q =
      (unsigned int) (sizeof(query_strings) / sizeof(query_strings[0]));
    const unsigned int num_r =
      (unsigned int) (sizeof(raw_requests) / sizeof(raw_requests[0]));

    fprintf (stderr, ".");
    c = zzuf_curl_setup (port, query_strings[i % num_q], &sink);
    if (NULL == c)
    {
      zzuf_curl_driver_deinit (&drv);
      return 99; /* Not an MHD error */
    }
    zzuf_curl_driver_perform (&drv, c);
    curl_easy_cleanup (c);

    /* The raw, header-less requests: only these can make a query
       argument the last parsed element of the request header. */
    if (ZZUF_RAW_SETUP_FAILED ==
        zzuf_raw_request (d_extern, port, raw_requests[i % num_r]))
    {
      fprintf (stderr, "The raw client could not be set up "
               "at line %d.\n", (int) __LINE__);
      zzuf_curl_driver_deinit (&drv);
      return 99; /* Not an MHD error */
    }
    fflush (stderr);
  }
  zzuf_curl_driver_deinit (&drv);

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

  if (CURLE_OK != curl_global_init (CURL_GLOBAL_WIN32))
  {
    fprintf (stderr, "curl_global_init() failed at line %d.\n",
             (int) __LINE__);
    return use_magic_exit_codes ? 99 : 0;
  }
  memset (raw_requests, 0, sizeof(raw_requests));
  if (! init_raw_requests ())
  {
    fprintf (stderr, "malloc() failed at line %d.\n", (int) __LINE__);
    free_raw_requests ();
    curl_global_cleanup ();
    return use_magic_exit_codes ? 99 : 0;
  }

  param.magic = (unsigned int) TEST_MAGIC_MARKER;
  param.err_flag = 0;
  param.arg_sum = 0;

  memset (&rp, 0, sizeof(rp));
  rp.port = zzuf_pick_port (TEST_PORT_OFFSET);
  rp.ahc = &ahc_args;
  rp.ahc_cls = &param;
  rp.rcc = NULL;
  rp.rcc_cls = NULL;
  rp.mem_limit_override = 0; /* Use the small pools of the option matrix */
  rp.sweep_profiles = 1;
  rp.profile_start = 1;      /* Skip the "plain" (large pool) profile */
  rp.client = &client_run;
  rp.client_cls = &param;

  res = zzuf_run_polling_modes (&rp);

  free_raw_requests ();
  curl_global_cleanup ();

  if (99 == res)
    return use_magic_exit_codes ? 99 : 0;
  if (77 == res)
    return use_magic_exit_codes ? 77 : 0;
  return (0 == res) ? 0 : 1; /* 0 == pass */
}
