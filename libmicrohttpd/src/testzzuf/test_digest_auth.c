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
 * @file testzzuf/test_digest_auth.c
 * @brief  Fuzzing testcase for Digest Authentication
 * @author Christian Grothoff
 *
 * The Digest Authentication parser of MHD used to be completely outside of
 * the reach of the fuzzing tests of this directory: no test ever produced
 * an "Authorization: Digest" header.
 *
 * This test closes that gap from two sides:
 * - libcurl performs a complete, well-formed digest handshake (two round
 *   trips), so zzuf's bit flips land inside real "WWW-Authenticate:" and
 *   "Authorization:" headers;
 * - the raw socket client sends hand-crafted "Authorization: Digest"
 *   headers that are *syntactically* well-formed but semantically hostile
 *   (unknown "algorithm" token, over-long "response", over-long userhash,
 *   over-long username, missing parameters, ...).  Random bit flipping
 *   essentially never produces such an input; these headers have to be
 *   written on purpose.
 *
 * The hostile headers that need a server generated nonce (everything that
 * is checked *after* the nonce validation) are built from the nonce that
 * MHD hands out in its own 401 reply, which the raw client parses.
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
#define TEST_PORT_OFFSET 155

#define TEST_REALM "TestRealm"
#define TEST_OPAQUE "0123456789abcdef"
#define TEST_USERNAME "testuser"
#define TEST_PASSWORD "testpass"

/**
 * The path that makes MHD issue an MD5 challenge (used by libcurl).
 */
#define URI_MD5 "/dauth/md5"

/**
 * The path that makes MHD issue a SHA-256 challenge.  A SHA-256 nonce is
 * needed to reach the code that decodes the client's "response" parameter
 * with a SHA-256 sized digest.
 */
#define URI_SHA256 "/dauth/sha256"

#define HOST_HDR "Host: " ZZUF_MHD_LISTEN_IP "\r\n"

/**
 * The size of the buffer used to build the raw requests.
 */
#define RAW_BUF_SIZE 2048

/**
 * The random data for the nonce generation.
 */
static const char digest_rnd_data[32] =
{ 'z','z','u','f','_','d','i','g','e','s','t','_','a','u','t','h',
  '_','r','a','n','d','o','m','_','s','e','e','d','_','0','0','1' };


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
   * The number of successful authentications.
   */
  unsigned int num_ok;
};


static enum MHD_Result
ahc_digest (void *cls,
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
  enum MHD_DigestAuthResult check_res;
  enum MHD_DigestAuthMultiAlgo3 challenge_algo;

  (void) method; (void) version; (void) upload_data;

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

  /* This is the call that parses the (fuzzed or hand-crafted) client's
     "Authorization: Digest" header. */
  check_res = MHD_digest_auth_check3 (connection,
                                      TEST_REALM,
                                      TEST_USERNAME,
                                      TEST_PASSWORD,
                                      0 /* daemon default timeout */,
                                      0 /* daemon default max nc */,
                                      MHD_DIGEST_AUTH_MULT_QOP_ANY_NON_INT,
                                      MHD_DIGEST_AUTH_MULT_ALGO3_ANY_NON_SESSION);
  if (MHD_DAUTH_OK == check_res)
  {
    param->num_ok++;
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

  /* Not authenticated (or the header was broken): send a challenge. */
  if ((NULL != url) && (0 == strcmp (url, URI_SHA256)))
    challenge_algo = MHD_DIGEST_AUTH_MULT_ALGO3_SHA256;
  else
    challenge_algo = MHD_DIGEST_AUTH_MULT_ALGO3_MD5;
  response =
    MHD_create_response_from_buffer_static (MHD_STATICSTR_LEN_ (DENIED_PAGE),
                                            DENIED_PAGE);
  if (NULL == response)
    return MHD_NO; /* External error */
  if (zzuf_use_close || ! zzuf_oneone)
    (void) MHD_add_response_header (response,
                                    MHD_HTTP_HEADER_CONNECTION, "close");
  ret = MHD_queue_auth_required_response3 (connection,
                                           TEST_REALM,
                                           TEST_OPAQUE,
                                           NULL,
                                           response,
                                           (MHD_DAUTH_NONCE_STALE ==
                                            check_res) ? MHD_YES : MHD_NO,
                                           MHD_DIGEST_AUTH_MULT_QOP_AUTH,
                                           challenge_algo,
                                           MHD_YES /* userhash support */,
                                           MHD_NO);
  MHD_destroy_response (response);
  return ret;
}


/**
 * Extract the value of the "nonce" parameter from a reply.
 *
 * @param reply the reply, not necessarily zero-terminated
 * @param reply_len the number of valid bytes in @a reply
 * @param[out] nonce the buffer for the nonce
 * @param nonce_size the size of @a nonce
 * @return non-zero if a nonce has been extracted, zero otherwise
 */
static int
extract_nonce (const char *reply,
               size_t reply_len,
               char *nonce,
               size_t nonce_size)
{
  static const char marker[] = "nonce=\"";
  size_t i;

  if (reply_len < MHD_STATICSTR_LEN_ (marker) + 1)
    return 0;
  for (i = 0; i <= reply_len - MHD_STATICSTR_LEN_ (marker) - 1; ++i)
  {
    size_t k;

    if (0 != memcmp (reply + i, marker, MHD_STATICSTR_LEN_ (marker)))
      continue;
    i += MHD_STATICSTR_LEN_ (marker);
    for (k = 0; (i + k < reply_len) && (k + 1 < nonce_size); ++k)
    {
      if ('"' == reply[i + k])
      {
        nonce[k] = 0;
        return (0 != k) ? ! 0 : 0;
      }
      if (('\r' == reply[i + k]) || ('\n' == reply[i + k]))
        return 0;
      nonce[k] = reply[i + k];
    }
    return 0;
  }
  return 0;
}


/**
 * Fill @a buf with @a len hexadecimal digits and zero-terminate it.
 *
 * @param[out] buf the buffer to fill
 * @param len the number of digits to write
 */
static void
fill_hex (char *buf, size_t len)
{
  static const char hex[] = "0123456789abcdef";
  size_t i;

  for (i = 0; i < len; ++i)
    buf[i] = hex[i % 16];
  buf[len] = 0;
}


/**
 * Build one hostile "Authorization: Digest" request.
 *
 * @param variant the number of the variant to build
 * @param nonce the server generated nonce, may be an empty string
 * @param[out] buf the buffer for the request
 * @param buf_size the size of @a buf
 * @return the length of the request, or zero on failure
 */
static size_t
build_hostile_request (unsigned int variant,
                       const char *nonce,
                       char *buf,
                       size_t buf_size)
{
  char big1[512];
  char big2[512];
  int len;

  switch (variant % 10)
  {
  case 0:
    /* An "algorithm" token that MHD does not know.  Before the fix of
       2026-07-27 this made MHD_digest_auth_check3() run into
       MHD_PANIC("Wrong 'malgo3' value, API violation") and abort().
       No valid nonce is needed: the algorithm is checked first. */
    len = snprintf (buf, buf_size,
                    "GET " URI_MD5 " HTTP/1.1\r\n" HOST_HDR
                    "Authorization: Digest username=\"" TEST_USERNAME "\", "
                    "realm=\"" TEST_REALM "\", nonce=\"%s\", uri=\"" URI_MD5
                    "\", algorithm=BOGUS-ALGO, qop=auth, nc=00000001, "
                    "cnonce=\"0a0b0c0d\", response=\""
                    "0123456789abcdef0123456789abcdef\"\r\n"
                    "Connection: close\r\n\r\n",
                    nonce);
    break;
  case 1:
    /* An empty (quoted) "algorithm" value. */
    len = snprintf (buf, buf_size,
                    "GET " URI_MD5 " HTTP/1.1\r\n" HOST_HDR
                    "Authorization: Digest username=\"" TEST_USERNAME "\", "
                    "realm=\"" TEST_REALM "\", nonce=\"%s\", uri=\"" URI_MD5
                    "\", algorithm=\"\", qop=auth, nc=00000001, "
                    "cnonce=\"0a0b0c0d\", response=\""
                    "0123456789abcdef0123456789abcdef\"\r\n"
                    "Connection: close\r\n\r\n",
                    nonce);
    break;
  case 2:
    /* A "-sess" algorithm, which MHD does not support. */
    len = snprintf (buf, buf_size,
                    "GET " URI_MD5 " HTTP/1.1\r\n" HOST_HDR
                    "Authorization: Digest username=\"" TEST_USERNAME "\", "
                    "realm=\"" TEST_REALM "\", nonce=\"%s\", uri=\"" URI_MD5
                    "\", algorithm=MD5-sess, qop=auth, nc=00000001, "
                    "cnonce=\"0a0b0c0d\", response=\""
                    "0123456789abcdef0123456789abcdef\"\r\n"
                    "Connection: close\r\n\r\n",
                    nonce);
    break;
  case 3:
    /* An over-long "response" together with a SHA-256 nonce.  Before the
       fix of 2026-07-27 the hex decoder wrote 64 bytes into a 32 byte
       stack buffer.  This needs a *valid* server nonce, otherwise the
       nonce check rejects the request before the "response" is decoded. */
    fill_hex (big1, 128);
    len = snprintf (buf, buf_size,
                    "GET " URI_SHA256 " HTTP/1.1\r\n" HOST_HDR
                    "Authorization: Digest username=\"" TEST_USERNAME "\", "
                    "realm=\"" TEST_REALM "\", nonce=\"%s\", uri=\""
                    URI_SHA256 "\", algorithm=SHA-256, qop=auth, "
                    "nc=00000001, cnonce=\"0a0b0c0d\", response=\"%s\"\r\n"
                    "Connection: close\r\n\r\n",
                    nonce, big1);
    break;
  case 4:
    /* The same, unquoted. */
    fill_hex (big1, 128);
    len = snprintf (buf, buf_size,
                    "GET " URI_SHA256 " HTTP/1.1\r\n" HOST_HDR
                    "Authorization: Digest username=\"" TEST_USERNAME "\", "
                    "realm=\"" TEST_REALM "\", nonce=%s, uri=\""
                    URI_SHA256 "\", algorithm=SHA-256, qop=auth, "
                    "nc=00000001, cnonce=\"0a0b0c0d\", response=%s\r\n"
                    "Connection: close\r\n\r\n",
                    nonce, big1);
    break;
  case 5:
    /* An over-long hex encoded userhash. */
    fill_hex (big1, 256);
    fill_hex (big2, 64);
    len = snprintf (buf, buf_size,
                    "GET " URI_SHA256 " HTTP/1.1\r\n" HOST_HDR
                    "Authorization: Digest username=\"%s\", userhash=true, "
                    "realm=\"" TEST_REALM "\", nonce=\"%s\", uri=\""
                    URI_SHA256 "\", algorithm=SHA-256, qop=auth, "
                    "nc=00000001, cnonce=\"0a0b0c0d\", response=\"%s\"\r\n"
                    "Connection: close\r\n\r\n",
                    big1, nonce, big2);
    break;
  case 6:
    /* A very long username. */
    fill_hex (big1, 500);
    len = snprintf (buf, buf_size,
                    "GET " URI_MD5 " HTTP/1.1\r\n" HOST_HDR
                    "Authorization: Digest username=\"%s\", "
                    "realm=\"" TEST_REALM "\", nonce=\"%s\", uri=\"" URI_MD5
                    "\", algorithm=MD5, qop=auth, nc=00000001, "
                    "cnonce=\"0a0b0c0d\", response=\""
                    "0123456789abcdef0123456789abcdef\"\r\n"
                    "Connection: close\r\n\r\n",
                    big1, nonce);
    break;
  case 7:
    /* No "response" parameter at all, plus the extended notation for the
       username. */
    len = snprintf (buf, buf_size,
                    "GET " URI_MD5 " HTTP/1.1\r\n" HOST_HDR
                    "Authorization: Digest username*=UTF-8''%%41%%42, "
                    "realm=\"" TEST_REALM "\", nonce=\"%s\", uri=\"" URI_MD5
                    "\", algorithm=MD5, qop=auth, nc=00000001, "
                    "cnonce=\"0a0b0c0d\"\r\n"
                    "Connection: close\r\n\r\n",
                    nonce);
    break;
  case 8:
    /* Garbage in "nc" and an unterminated quoted string. */
    len = snprintf (buf, buf_size,
                    "GET " URI_MD5 " HTTP/1.1\r\n" HOST_HDR
                    "Authorization: Digest username=\"" TEST_USERNAME "\", "
                    "realm=\"" TEST_REALM "\", nonce=\"%s\", uri=\"" URI_MD5
                    "\", algorithm=MD5, qop=auth, nc=zzzzzzzz, "
                    "cnonce=\"0a0b0c0d, response=\""
                    "0123456789abcdef0123456789abcdef\"\r\n"
                    "Connection: close\r\n\r\n",
                    nonce);
    break;
  case 9:
  default:
    /* A "Digest" scheme without any parameter, and a second, empty
       "Authorization" header. */
    len = snprintf (buf, buf_size,
                    "GET " URI_MD5 " HTTP/1.1\r\n" HOST_HDR
                    "Authorization: Digest\r\n"
                    "Authorization: \r\n"
                    "Connection: close\r\n\r\n");
    break;
  }
  if ((0 > len) || (buf_size <= (size_t) len))
    return 0;
  return (size_t) len;
}


/**
 * Ask MHD for a challenge and extract the nonce from the reply.
 *
 * @param d_extern the daemon to drive, or NULL
 * @param port the port MHD is listening on
 * @param uri the URI to request
 * @param[out] nonce the buffer for the nonce
 * @param nonce_size the size of @a nonce
 */
static void
fetch_nonce (struct MHD_Daemon *d_extern,
             uint16_t port,
             const char *uri,
             char *nonce,
             size_t nonce_size)
{
  struct zzuf_raw_part part;
  char req[256];
  char reply[2048];
  size_t reply_len = 0;
  int len;

  nonce[0] = 0;
  len = snprintf (req, sizeof(req),
                  "GET %s HTTP/1.1\r\n" HOST_HDR "Connection: close\r\n\r\n",
                  uri);
  if ((0 > len) || (sizeof(req) <= (size_t) len))
    return;
  part.data = req;
  part.size = (size_t) len;
  /* Bypass socat (when it is used): a nonce that has been mangled by zzuf
     is useless for building a request that must survive the nonce check. */
  if (ZZUF_RAW_OK !=
      zzuf_raw_exchange2 (d_extern, port, 1, &part, 1,
                          (unsigned int) ZZUF_CLIENT_TIMEOUT,
                          reply, sizeof(reply), &reply_len))
    return;
  (void) extract_nonce (reply, reply_len, nonce, nonce_size);
}


static unsigned int
client_run (struct MHD_Daemon *d_extern,
            uint16_t port,
            void *cls)
{
  struct ahc_param *param = (struct ahc_param *) cls;
  struct zzuf_curl_driver drv;
  struct zzuf_curl_sink sink;
  char nonce_md5[256];
  char nonce_sha256[256];
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
  nonce_md5[0] = 0;
  nonce_sha256[0] = 0;

  for (i = 0; i < loops; ++i)
  {
    CURL *c;
    struct zzuf_raw_part part;
    size_t req_len;
    const char *nonce;

    fprintf (stderr, ".");
    /* 1. A complete, well-formed digest handshake performed by libcurl.
       The traffic goes through the fuzzing layer. */
    c = zzuf_curl_setup (port, URI_MD5, &sink);
    if (NULL == c)
    {
      free (req);
      zzuf_curl_driver_deinit (&drv);
      return 99; /* Not an MHD error */
    }
    if ((CURLE_OK != curl_easy_setopt (c, CURLOPT_HTTPAUTH,
                                       (long) CURLAUTH_DIGEST)) ||
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

    /* 2. Refresh the nonces from time to time: MHD only accepts a given
       nonce/nc combination once. */
    if (0 == i % 2)
    {
      fetch_nonce (d_extern, port, URI_MD5, nonce_md5, sizeof(nonce_md5));
      fetch_nonce (d_extern, port, URI_SHA256,
                   nonce_sha256, sizeof(nonce_sha256));
    }

    /* 3. The hand-crafted hostile headers. */
    nonce = ((3 == i % 10) || (4 == i % 10) || (5 == i % 10)) ?
            nonce_sha256 : nonce_md5;
    req_len = build_hostile_request (i, nonce, req, RAW_BUF_SIZE);
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
      /* ... and once verbatim, so that the hostile header is guaranteed
         to reach the parser unmodified at least once. */
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
  struct MHD_OptionItem extra_opts[3];
  unsigned int res;
  int use_magic_exit_codes;

  zzuf_parse_common_args (argc, argv);
  use_magic_exit_codes = zzuf_run_with_socat || zzuf_dry_run;

  if (MHD_NO == MHD_is_feature_supported (MHD_FEATURE_DIGEST_AUTH))
  {
    fprintf (stderr, "Digest Authentication is not supported by this "
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
  param.num_ok = 0;

  extra_opts[0].option = MHD_OPTION_DIGEST_AUTH_RANDOM;
  extra_opts[0].value = (intptr_t) sizeof(digest_rnd_data);
  extra_opts[0].ptr_value = (void *) (intptr_t) digest_rnd_data;
  extra_opts[1].option = MHD_OPTION_NONCE_NC_SIZE;
  extra_opts[1].value = (intptr_t) 300;
  extra_opts[1].ptr_value = NULL;
  extra_opts[2].option = MHD_OPTION_END;
  extra_opts[2].value = 0;
  extra_opts[2].ptr_value = NULL;

  memset (&rp, 0, sizeof(rp));
  rp.port = zzuf_pick_port (TEST_PORT_OFFSET);
  rp.ahc = &ahc_digest;
  rp.ahc_cls = &param;
  rp.rcc = NULL;
  rp.rcc_cls = NULL;
  /* The digest headers are large, use a memory limit that can hold them. */
  rp.mem_limit_override = 4096;
  rp.sweep_profiles = 1;
  rp.profile_start = 0;
  rp.client = &client_run;
  rp.client_cls = &param;
  rp.extra_opts = extra_opts;

  res = zzuf_run_polling_modes (&rp);
  curl_global_cleanup ();

  if (99 == res)
    return use_magic_exit_codes ? 99 : 0;
  if (77 == res)
    return use_magic_exit_codes ? 77 : 0;
  return (0 == res) ? 0 : 1; /* 0 == pass */
}
