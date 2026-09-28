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
 * @file testzzuf/test_basic_auth.c
 * @brief  Fuzzing testcase for Basic Authentication
 * @author Christian Grothoff
 *
 * Before this test existed, no fuzzing test of this directory ever sent an
 * "Authorization:" header, so neither the Base64 decoder nor the username /
 * password splitting of MHD were reachable by the fuzzer at all.
 *
 * libcurl performs a normal Basic Authentication handshake (so that zzuf's
 * bit flips land inside a real "Authorization: Basic" header) and the raw
 * socket client adds hand-crafted headers with Base64 payloads that are
 * truncated, over-long, contain characters outside the Base64 alphabet,
 * decode to data with binary zeros or lack the ':' separator entirely.
 */

#include "platform.h"
#include <curl/curl.h>
#include <microhttpd.h>
#include <stdlib.h>
#include <string.h>

#include "mhd_zzuf_common.h"

#define TEST_MAGIC_MARKER 0xFEE1C0DE

#define DENIED_PAGE "Access denied."
#define GRANTED_PAGE "Access granted."

/**
 * The port offset used if the port cannot be auto-detected.
 */
#define TEST_PORT_OFFSET 165

#define TEST_REALM "TestRealm"
#define TEST_USERNAME "testuser"
#define TEST_PASSWORD "testpass"

#define TEST_URI "/bauth"

#define HOST_HDR "Host: " ZZUF_MHD_LISTEN_IP "\r\n"

/**
 * The size of the buffer used to build the raw requests.
 */
#define RAW_BUF_SIZE 8192


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
   * The checksum over the decoded credentials, only used so that the
   * compiler cannot optimise the memory accesses away.
   */
  unsigned int cred_sum;
};


static enum MHD_Result
ahc_basic (void *cls,
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
  struct MHD_BasicAuthInfo *creds;
  struct MHD_Response *response;
  enum MHD_Result ret;
  int authenticated = 0;

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
    *upload_data_size = 0; /* Discard the body */
    return MHD_YES;
  }

  /* This is the call that decodes the (fuzzed or hand-crafted) client's
     "Authorization: Basic" header. */
  creds = MHD_basic_auth_get_username_password3 (connection);
  if (NULL != creds)
  {
    size_t i;

    if (NULL == creds->username)
    {
      fprintf (stderr, "The 'username' member is NULL "
               "at line %d.\n", (int) __LINE__);
      param->err_flag = 1;
    }
    else
    {
      /* Touch every byte, including the zero-termination that MHD
         guarantees. */
      for (i = 0; i <= creds->username_len; ++i)
        param->cred_sum += (unsigned int) (unsigned char) creds->username[i];
    }
    if (NULL == creds->password)
    {
      if (0 != creds->password_len)
      {
        fprintf (stderr, "The 'password' is NULL while 'password_len' is "
                 "not zero at line %d.\n", (int) __LINE__);
        param->err_flag = 1;
      }
    }
    else
    {
      for (i = 0; i <= creds->password_len; ++i)
        param->cred_sum += (unsigned int) (unsigned char) creds->password[i];
    }
    if ((NULL != creds->username) &&
        (MHD_STATICSTR_LEN_ (TEST_USERNAME) == creds->username_len) &&
        (0 == memcmp (creds->username, TEST_USERNAME,
                      MHD_STATICSTR_LEN_ (TEST_USERNAME))) &&
        (NULL != creds->password) &&
        (MHD_STATICSTR_LEN_ (TEST_PASSWORD) == creds->password_len) &&
        (0 == memcmp (creds->password, TEST_PASSWORD,
                      MHD_STATICSTR_LEN_ (TEST_PASSWORD))))
      authenticated = 1;
    MHD_free (creds);
  }

  if (authenticated)
  {
    response =
      MHD_create_response_from_buffer_static (MHD_STATICSTR_LEN_ (
                                                GRANTED_PAGE),
                                              GRANTED_PAGE);
    if (NULL == response)
      return MHD_NO; /* External error */
    if (zzuf_use_close || ! zzuf_oneone)
      (void) MHD_add_response_header (response,
                                      MHD_HTTP_HEADER_CONNECTION, "close");
    ret = MHD_queue_response (connection, MHD_HTTP_OK, response);
    MHD_destroy_response (response);
    return ret;
  }

  response =
    MHD_create_response_from_buffer_static (MHD_STATICSTR_LEN_ (DENIED_PAGE),
                                            DENIED_PAGE);
  if (NULL == response)
    return MHD_NO; /* External error */
  if (zzuf_use_close || ! zzuf_oneone)
    (void) MHD_add_response_header (response,
                                    MHD_HTTP_HEADER_CONNECTION, "close");
  ret = MHD_queue_basic_auth_required_response3 (connection, TEST_REALM,
                                                 MHD_NO, response);
  MHD_destroy_response (response);
  return ret;
}


/**
 * Build one hostile "Authorization: Basic" request.
 *
 * @param variant the number of the variant to build
 * @param[out] buf the buffer for the request
 * @param buf_size the size of @a buf
 * @return the length of the request, or zero on failure
 */
static size_t
build_hostile_request (unsigned int variant,
                       char *buf,
                       size_t buf_size)
{
  static const char b64_alphabet[] =
    "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
  char big[4096];
  const char *value;
  size_t i;
  int len;

  switch (variant % 10)
  {
  case 0:
    /* A truncated Base64 payload (not a multiple of four). */
    value = "dGVzdHVzZXI";
    break;
  case 1:
    /* Characters outside the Base64 alphabet. */
    value = "!!!!\?\?\?\?===="; /* '?' escaped to avoid a trigraph */
    break;
  case 2:
    /* Valid Base64 that decodes to a string without ':' separator. */
    value = "dGVzdHVzZXI=";
    break;
  case 3:
    /* Valid Base64 that decodes to "\0:\0" (binary zeros). */
    value = "ADoA";
    break;
  case 4:
    /* Valid Base64 that decodes to ":" only (empty username). */
    value = "Og==";
    break;
  case 5:
    /* Padding in the middle of the payload. */
    value = "dGVz=dXNlcjpwYXNz";
    break;
  case 6:
    /* An empty value. */
    value = "";
    break;
  case 7:
    /* A very long, but valid, Base64 payload. */
    for (i = 0; i + 1 < sizeof(big); ++i)
      big[i] = b64_alphabet[i % 64];
    big[sizeof(big) - 1] = 0;
    value = big;
    break;
  case 8:
    /* Whitespace inside the payload. */
    value = "dGVz dXNl cjpw YXNz";
    break;
  case 9:
  default:
    /* An unknown scheme, and a second "Authorization" header. */
    len = snprintf (buf, buf_size,
                    "GET " TEST_URI " HTTP/1.1\r\n" HOST_HDR
                    "Authorization: Bearer dGVzdHVzZXI6dGVzdHBhc3M=\r\n"
                    "Authorization: Basic\r\n"
                    "Connection: close\r\n\r\n");
    if ((0 > len) || (buf_size <= (size_t) len))
      return 0;
    return (size_t) len;
  }
  len = snprintf (buf, buf_size,
                  "GET " TEST_URI " HTTP/1.1\r\n" HOST_HDR
                  "Authorization: Basic %s\r\n"
                  "Connection: close\r\n\r\n",
                  value);
  if ((0 > len) || (buf_size <= (size_t) len))
    return 0;
  return (size_t) len;
}


static unsigned int
client_run (struct MHD_Daemon *d_extern,
            uint16_t port,
            void *cls)
{
  struct ahc_param *param = (struct ahc_param *) cls;
  struct zzuf_curl_driver drv;
  struct zzuf_curl_sink sink;
  char *req;
  unsigned int i;
  unsigned int loops;

  loops = zzuf_loop_count ();
  if (! zzuf_curl_driver_init (&drv, d_extern))
    return 99; /* Not an MHD error */
  req = malloc (RAW_BUF_SIZE);
  if (NULL == req)
  {
    zzuf_curl_driver_deinit (&drv);
    return 99; /* Not an MHD error */
  }

  for (i = 0; i < loops; ++i)
  {
    CURL *c;
    struct zzuf_raw_part part;
    size_t req_len;

    fprintf (stderr, ".");
    /* 1. A well-formed Basic Authentication handshake by libcurl, going
       through the fuzzing layer. */
    c = zzuf_curl_setup (port, TEST_URI, &sink);
    if (NULL == c)
    {
      free (req);
      zzuf_curl_driver_deinit (&drv);
      return 99; /* Not an MHD error */
    }
    if ((CURLE_OK != curl_easy_setopt (c, CURLOPT_HTTPAUTH,
                                       (long) CURLAUTH_BASIC)) ||
        (CURLE_OK != curl_easy_setopt (c, CURLOPT_USERPWD,
                                       TEST_USERNAME ":" TEST_PASSWORD)))
    {
      curl_easy_cleanup (c);
      free (req);
      zzuf_curl_driver_deinit (&drv);
      return 99; /* Not an MHD error */
    }
    zzuf_curl_driver_perform (&drv, c);
    curl_easy_cleanup (c);

    /* 2. The hand-crafted hostile headers. */
    req_len = build_hostile_request (i, req, RAW_BUF_SIZE);
    if (0 != req_len)
    {
      part.data = req;
      part.size = req_len;
      /* Once through the fuzzing layer ... */
      if (ZZUF_RAW_SETUP_FAILED ==
          zzuf_raw_exchange (d_extern, port, &part, 1,
                             (unsigned int) ZZUF_CLIENT_TIMEOUT))
      {
        free (req);
        zzuf_curl_driver_deinit (&drv);
        return 99; /* Not an MHD error */
      }
      /* ... and once verbatim. */
      if (ZZUF_RAW_SETUP_FAILED ==
          zzuf_raw_exchange2 (d_extern, port, 1, &part, 1,
                              (unsigned int) ZZUF_CLIENT_TIMEOUT,
                              NULL, 0, NULL))
      {
        free (req);
        zzuf_curl_driver_deinit (&drv);
        return 99; /* Not an MHD error */
      }
    }
    fflush (stderr);
  }
  free (req);
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

  if (MHD_NO == MHD_is_feature_supported (MHD_FEATURE_BASIC_AUTH))
  {
    fprintf (stderr, "Basic Authentication is not supported by this "
             "MHD build.\n");
    return use_magic_exit_codes ? 77 : 0;
  }
  res = zzuf_check_runnable ();
  if (0 != res)
    return use_magic_exit_codes ? (int) res : 0;

  if (CURLE_OK != curl_global_init (CURL_GLOBAL_WIN32))
  {
    fprintf (stderr, "curl_global_init() failed at line %d.\n",
             (int) __LINE__);
    return use_magic_exit_codes ? 99 : 0;
  }

  param.magic = (unsigned int) TEST_MAGIC_MARKER;
  param.err_flag = 0;
  param.cred_sum = 0;

  memset (&rp, 0, sizeof(rp));
  rp.port = zzuf_pick_port (TEST_PORT_OFFSET);
  rp.ahc = &ahc_basic;
  rp.ahc_cls = &param;
  rp.rcc = NULL;
  rp.rcc_cls = NULL;
  /* The hostile headers are large, use a memory limit that can hold them. */
  rp.mem_limit_override = 8192;
  rp.sweep_profiles = 1;
  rp.profile_start = 0;
  rp.client = &client_run;
  rp.client_cls = &param;
  rp.extra_opts = NULL;

  res = zzuf_run_polling_modes (&rp);
  curl_global_cleanup ();

  if (99 == res)
    return use_magic_exit_codes ? 99 : 0;
  if (77 == res)
    return use_magic_exit_codes ? 77 : 0;
  return (0 == res) ? 0 : 1; /* 0 == pass */
}
