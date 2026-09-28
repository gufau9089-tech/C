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
 * @file test_dauth_malformed.c
 * @brief  Testcase for malformed Digest "Authorization:" request headers
 * @author Christian Grothoff
 *
 * The malformed headers used by this test cannot be produced with libcurl,
 * therefore all the requests are sent over a raw socket.
 *
 * The test is a regression test for two remotely triggerable defects:
 *
 * - An unrecognised "algorithm=" token is parsed to
 *   #MHD_DIGEST_AUTH_ALGO3_INVALID, the numeric value of which is zero.  The
 *   "is the client's algorithm allowed by the application" bit-mask test is
 *   passed trivially by a zero value, so an invalid algorithm used to reach
 *   digest_init_one_time(), which aborts the process with MHD_PANIC().
 *
 * - The "response=" value was hex-decoded into a #MAX_DIGEST bytes long
 *   buffer on the stack, while the only length check allowed four times as
 *   many characters as the digest size, resulting in an out-of-bounds stack
 *   write of up to #MAX_DIGEST bytes.  Reaching the decoder requires an
 *   otherwise complete and valid Digest handshake, hence the two-step
 *   exchange performed by this test.
 *
 * A number of adjacent malformed, empty, over-long and duplicated parameters
 * is checked as well.  Every sub-case must leave the daemons alive and must
 * be answered with a regular HTTP error reply.
 *
 * Two daemons are used: one that issues SHA-256 challenges and one that
 * issues the challenges with the default "any non-session" algorithm.  This
 * keeps the length of the nonces recorded by a single daemon uniform, which
 * is what a real-world application does as well.
 *
 * The test honours the daemon option matrix of mhd_opt_matrix.h: when one of
 * the MHD_TEST_* environment variables selects a profile, its connection
 * memory limit, client discipline level, threading mode and polling backend
 * are applied to both daemons.  Without those variables nothing changes.  A
 * Digest handshake needs room for a 76 character nonce plus the realm, the
 * username and the response, so a profile asking for less than
 * #MIN_POOL_FOR_TEST bytes is raised to that value and the adjustment is
 * reported.
 */

#include "MHD_config.h"
#include "platform.h"
#include <microhttpd.h>
#include <stdlib.h>
#include <string.h>
#include <stdarg.h>
#include <stdint.h>
#include <errno.h>

#ifdef HAVE_STRINGS_H
#include <strings.h>
#endif /* HAVE_STRINGS_H */

#ifndef WINDOWS
#include <unistd.h>
#include <sys/socket.h>
#endif

#include "mhd_sockets.h" /* only macros used */
#include "mhd_opt_matrix.h"
/* Turn any MHD_PANIC() or failing mhd_assert() reached from this
   test into a marked, classifiable test error (TESTING.md, P5). */
#include "mhd_panic_tripwire.h"

/**
 * The smallest connection memory pool this test can work with: a complete
 * Digest "Authorization:" header plus the "WWW-Authenticate:" challenge of
 * the reply do not fit into a smaller pool.
 */
#define MIN_POOL_FOR_TEST 4096

#ifndef MHD_STATICSTR_LEN_
/**
 * Determine length of static string / macro strings at compile time.
 */
#define MHD_STATICSTR_LEN_(macro) (sizeof(macro) / sizeof(char) - 1)
#endif /* ! MHD_STATICSTR_LEN_ */

#if defined(DAUTH_SUPPORT) && defined(MHD_SHA256_SUPPORT)

/**
 * The realm used by the test daemons.
 */
#define TEST_REALM "TestRealm"

/**
 * The username known to the test daemons.
 */
#define TEST_USERNAME "testuser"

/**
 * The password known to the test daemons.
 */
#define TEST_PASSWORD "testpass"

/**
 * The URL used by all the requests.
 */
#define TEST_URL "/auth"

/**
 * The size of the buffer used to build a request.
 */
#define REQ_BUF_SIZE 32768

/**
 * The size of the buffer used to receive a reply.
 */
#define RPLY_BUF_SIZE 8192

/**
 * The length of the over-long parameter values.
 */
#define LONG_PARAM_LEN 4000

/**
 * Socket send/receive timeout in seconds.
 */
#define SOCK_TIMEOUT_SEC 5

/**
 * The number of the "nonce"/"nc" pairs recorded by a daemon.
 */
#define NONCE_NC_SIZE 100


/**
 * The port of the daemon issuing SHA-256 challenges.
 */
static uint16_t port_sha256;

/**
 * The port of the daemon issuing "any non-session" (MD5) challenges.
 */
static uint16_t port_any;

/**
 * The port used by the sub-case being executed.
 */
static uint16_t test_port;

/**
 * The number of the sub-case being executed.
 */
static unsigned int case_num;

/**
 * The number of the failed sub-cases.
 */
static unsigned int failures;

/**
 * The 'nc' value for the next request, incremented for every request so that
 * a "nonce"/"nc" combination is never re-used.
 */
static unsigned int nc_counter;

/**
 * Run only the sub-cases with a name containing this string, NULL for all.
 */
static const char *case_filter;

/**
 * Set to non-zero by the daemon if a malformed request was authenticated.
 */
static volatile int wrongly_authenticated;

/**
 * The profile selected by the environment, NULL if the built-in daemon
 * configuration is used (which is the case for a stock "make check").
 */
static const struct MHD_OptMatrixProfile *test_prof;

/**
 * The (possibly adjusted) copy of the profile @a test_prof points to.
 */
static struct MHD_OptMatrixProfile test_prof_copy;


_MHD_NORETURN static void
hard_error (const char *msg)
{
  fprintf (stderr,
           "Hard error: %s\n",
           msg);
  fflush (stderr);
  exit (99);
}


/**
 * Fill @a buf with @a len hexadecimal digits and zero-terminate it.
 *
 * @param[out] buf the buffer to fill, must be at least @a len + 1 bytes long
 * @param len the number of the hexadecimal digits to generate
 * @return the @a buf pointer
 */
static char *
fill_hex (char *buf,
          size_t len)
{
  static const char hex_chars[] = "0123456789abcdef";
  size_t i;

  for (i = 0; i < len; ++i)
    buf[i] = hex_chars[i % (MHD_STATICSTR_LEN_ (hex_chars))];
  buf[len] = 0;
  return buf;
}


/**
 * Fill @a buf with @a len copies of @a chr and zero-terminate it.
 *
 * @param[out] buf the buffer to fill, must be at least @a len + 1 bytes long
 * @param chr the character to repeat
 * @param len the number of the characters to generate
 * @return the @a buf pointer
 */
static char *
fill_chr (char *buf,
          char chr,
          size_t len)
{
  memset (buf, chr, len);
  buf[len] = 0;
  return buf;
}


/* * * * * * * * * * * *  The daemon side  * * * * * * * * * * * */

static enum MHD_Result
ahc_check (void *cls,
           struct MHD_Connection *connection,
           const char *url,
           const char *method,
           const char *version,
           const char *upload_data,
           size_t *upload_data_size,
           void **req_cls)
{
  static int marker;
  const enum MHD_DigestAuthMultiAlgo3 *const challenge_algo = cls;
  struct MHD_Response *response;
  enum MHD_DigestAuthResult check_res;
  enum MHD_Result ret;
  (void) url; (void) method; (void) version; (void) upload_data;
  (void) upload_data_size;

  if (&marker != *req_cls)
  { /* The first call for the request */
    *req_cls = &marker;
    return MHD_YES;
  }

  check_res =
    MHD_digest_auth_check3 (connection,
                            TEST_REALM,
                            TEST_USERNAME,
                            TEST_PASSWORD,
                            300,
                            0,
                            MHD_DIGEST_AUTH_MULT_QOP_ANY_NON_INT,
                            MHD_DIGEST_AUTH_MULT_ALGO3_ANY_NON_SESSION);
  if (MHD_DAUTH_OK == check_res)
  { /* None of the sub-cases must be authenticated */
    static const char page[] = "Authenticated";

    wrongly_authenticated = 1;
    response =
      MHD_create_response_from_buffer (MHD_STATICSTR_LEN_ (page),
                                       (void *) page,
                                       MHD_RESPMEM_PERSISTENT);
    if (NULL == response)
      return MHD_NO;
    ret = MHD_queue_response (connection,
                              MHD_HTTP_OK,
                              response);
    MHD_destroy_response (response);
    return ret;
  }

  if (1)
  {
    static const char page[] = "Access denied";

    response =
      MHD_create_response_from_buffer (MHD_STATICSTR_LEN_ (page),
                                       (void *) page,
                                       MHD_RESPMEM_PERSISTENT);
    if (NULL == response)
      return MHD_NO;
    ret =
      MHD_queue_auth_required_response3 (connection,
                                         TEST_REALM,
                                         "test-opaque",
                                         NULL,
                                         response,
                                         (MHD_DAUTH_NONCE_STALE == check_res) ?
                                         MHD_YES : MHD_NO,
                                         MHD_DIGEST_AUTH_MULT_QOP_ANY_NON_INT,
                                         *challenge_algo,
                                         MHD_YES,
                                         MHD_NO);
    MHD_destroy_response (response);
  }
  return ret;
}


/* * * * * * * * * * * *  The raw client side  * * * * * * * * * * * */

/**
 * Send @a req to the daemon at #test_port and receive the complete reply.
 *
 * @param req the request to send, zero-terminated
 * @param[out] rply the buffer for the reply
 * @param rply_size the size of the @a rply buffer
 * @return the number of the received bytes,
 *         -1 if no reply has been received
 */
static ssize_t
exchange (const char *req,
          char *rply,
          size_t rply_size)
{
  MHD_socket sckt;
  struct sockaddr_in sa;
  struct timeval tmo;
  size_t req_len;
  size_t sent;
  size_t received;

  sckt = socket (AF_INET, SOCK_STREAM, IPPROTO_TCP);
  if (MHD_INVALID_SOCKET == sckt)
    hard_error ("socket() failed");

  tmo.tv_sec = SOCK_TIMEOUT_SEC;
  tmo.tv_usec = 0;
  if ( (0 != setsockopt (sckt, SOL_SOCKET, SO_RCVTIMEO,
                         (const void *) &tmo, sizeof (tmo))) ||
       (0 != setsockopt (sckt, SOL_SOCKET, SO_SNDTIMEO,
                         (const void *) &tmo, sizeof (tmo))) )
    hard_error ("setsockopt() failed");

  memset (&sa, 0, sizeof (sa));
  sa.sin_family = AF_INET;
  sa.sin_port = htons (test_port);
  sa.sin_addr.s_addr = htonl (INADDR_LOOPBACK);
  if (0 != connect (sckt, (const struct sockaddr *) &sa, sizeof (sa)))
  {
    MHD_socket_close_chk_ (sckt);
    return -1;
  }

  req_len = strlen (req);
  sent = 0;
  while (sent < req_len)
  {
    ssize_t res;

    res = send (sckt, req + sent, req_len - sent, 0);
    if (0 >= res)
      break;
    sent += (size_t) res;
  }
  if (sent != req_len)
  {
    MHD_socket_close_chk_ (sckt);
    return -1;
  }

  received = 0;
  while (received + 1 < rply_size)
  {
    ssize_t res;

    res = recv (sckt, rply + received, rply_size - received - 1, 0);
    if (0 >= res)
      break;
    received += (size_t) res;
  }
  rply[received] = 0;
  MHD_socket_close_chk_ (sckt);
  if (0 == received)
    return -1;
  return (ssize_t) received;
}


/**
 * Extract the HTTP status code from a raw reply.
 *
 * @param rply the reply, zero-terminated
 * @return the status code, zero if the reply is not a valid HTTP reply
 */
static unsigned int
get_status (const char *rply)
{
  unsigned int status;

  if (MHD_STATICSTR_LEN_ ("HTTP/1.1 000") > strlen (rply))
    return 0;
  if (0 != memcmp (rply, "HTTP/1.", MHD_STATICSTR_LEN_ ("HTTP/1.")))
    return 0;
  status = 0;
  if (1 != sscanf (rply + MHD_STATICSTR_LEN_ ("HTTP/1.1 "), "%3u", &status))
    return 0;
  return status;
}


/**
 * Request a challenge from the daemon at #test_port and extract the "nonce"
 * value from it.
 *
 * @param[out] nonce the buffer for the "nonce" value
 * @param nonce_size the size of the @a nonce buffer
 * @return non-zero on success, zero on failure
 */
static int
get_nonce (char *nonce,
           size_t nonce_size)
{
  static const char nonce_tk[] = "nonce=\"";
  static const char req[] =
    "GET " TEST_URL " HTTP/1.1\r\n"
    "Host: 127.0.0.1\r\n"
    "Connection: close\r\n"
    "\r\n";
  char rply[RPLY_BUF_SIZE];
  const char *start;
  const char *end;
  size_t len;

  if (0 >= exchange (req, rply, sizeof (rply)))
    return 0;
  if (MHD_HTTP_UNAUTHORIZED != get_status (rply))
    return 0;
  start = strstr (rply, nonce_tk);
  if (NULL == start)
    return 0;
  start += MHD_STATICSTR_LEN_ (nonce_tk);
  end = strchr (start, '"');
  if (NULL == end)
    return 0;
  len = (size_t) (end - start);
  if (len + 1 > nonce_size)
    return 0;
  memcpy (nonce, start, len);
  nonce[len] = 0;
  return 0 != len;
}


/**
 * Obtain a "nonce" or fail the whole test.
 *
 * @param[out] nonce the buffer for the "nonce" value
 * @param nonce_size the size of the @a nonce buffer
 */
static void
need_nonce (char *nonce,
            size_t nonce_size)
{
  if (! get_nonce (nonce, nonce_size))
    hard_error ("cannot obtain a 'nonce' from the daemon");
}


/**
 * Run a single sub-case: send a request with the given "Authorization:"
 * header value and check that the daemon replies with a regular HTTP error.
 *
 * @param name the name of the sub-case, used for reporting
 * @param auth_fmt the printf-style format of the "Authorization:" header
 *                 value, NULL to send no "Authorization:" header
 * @param ... the arguments for the @a auth_fmt
 */
static void
run_case (const char *name,
          const char *auth_fmt,
          ...)
{
  static char req[REQ_BUF_SIZE];
  static char auth[REQ_BUF_SIZE - 512];
  char rply[RPLY_BUF_SIZE];
  unsigned int status;

  ++case_num;
  if ( (NULL != case_filter) &&
       (NULL == strstr (name, case_filter)) )
    return;

  /* Report the sub-case before it is executed: if the daemon aborts the
     process, the last reported sub-case is the failing one. */
  fprintf (stderr,
           "[%02u] %s\n",
           case_num,
           name);
  fflush (stderr);

  if (NULL != auth_fmt)
  {
    va_list ap;

    va_start (ap, auth_fmt);
    vsnprintf (auth, sizeof (auth), auth_fmt, ap);
    va_end (ap);
    snprintf (req, sizeof (req),
              "GET " TEST_URL " HTTP/1.1\r\n"
              "Host: 127.0.0.1\r\n"
              "Connection: close\r\n"
              "Authorization: %s\r\n"
              "\r\n",
              auth);
  }
  else
    snprintf (req, sizeof (req),
              "GET " TEST_URL " HTTP/1.1\r\n"
              "Host: 127.0.0.1\r\n"
              "Connection: close\r\n"
              "\r\n");

  if (0 >= exchange (req, rply, sizeof (rply)))
  {
    fprintf (stderr,
             "FAILED sub-case '%s': no reply received.\n",
             name);
    fflush (stderr);
    ++failures;
    return;
  }
  status = get_status (rply);
  /* Any regular HTTP error reply is fine: the point of the test is that the
     daemon neither crashes nor accepts the malformed credentials. */
  if ( (MHD_HTTP_UNAUTHORIZED != status) &&
       (MHD_HTTP_BAD_REQUEST != status) &&
       (MHD_HTTP_REQUEST_HEADER_FIELDS_TOO_LARGE != status) )
  {
    fprintf (stderr,
             "FAILED sub-case '%s': unexpected HTTP status %u.\n",
             name,
             status);
    fflush (stderr);
    ++failures;
    return;
  }
  if (0 != wrongly_authenticated)
  {
    fprintf (stderr,
             "FAILED sub-case '%s': the malformed request was "
             "authenticated.\n",
             name);
    fflush (stderr);
    wrongly_authenticated = 0;
    ++failures;
  }
}


/**
 * Build the common part of an otherwise valid Digest "Authorization:" header.
 *
 * @param[out] buf the buffer to fill
 * @param buf_size the size of the @a buf
 * @param nonce the "nonce" value received from the daemon
 */
static void
make_valid_params (char *buf,
                   size_t buf_size,
                   const char *nonce)
{
  snprintf (buf, buf_size,
            "username=\"" TEST_USERNAME "\", realm=\"" TEST_REALM "\", "
            "nonce=\"%s\", uri=\"" TEST_URL "\", qop=auth, nc=%08x, "
            "cnonce=\"0123456789abcdef\"",
            nonce,
            ++nc_counter);
}


/* * * * * * * * * * * *  The sub-cases  * * * * * * * * * * * */

/**
 * Sub-cases for the missing #MHD_DIGEST_AUTH_ALGO3_INVALID check.
 *
 * An unknown "algorithm=" token is parsed to
 * #MHD_DIGEST_AUTH_ALGO3_INVALID, which has the numeric value of zero and
 * therefore satisfies the "allowed algorithms" bit-mask test.  Without the
 * explicit check for the invalid value the request reaches
 * digest_init_one_time() and aborts the process with MHD_PANIC().
 *
 * The algorithm is checked before anything else, so most of the sub-cases
 * need no other parameter at all.
 */
static void
test_invalid_algorithm (void)
{
  char nonce[256];
  char params[512];
  char resp[128];

  fill_hex (resp, 64);

  test_port = port_any;

  run_case ("bug-c/algo-bogus-alone",
            "Digest algorithm=BOGUS");
  run_case ("bug-c/algo-md5-x",
            "Digest algorithm=MD5-x");
  run_case ("bug-c/algo-sha512",
            "Digest algorithm=SHA-512");
  run_case ("bug-c/algo-sha1",
            "Digest algorithm=SHA1");
  run_case ("bug-c/algo-sha256-typo",
            "Digest algorithm=SHA256");
  run_case ("bug-c/algo-empty-quotes",
            "Digest algorithm=\"\"");
  run_case ("bug-c/algo-empty-token",
            "Digest algorithm=");
  run_case ("bug-c/algo-empty-token-comma",
            "Digest algorithm=, nonce=\"deadbeef\"");
  run_case ("bug-c/algo-quoted-bogus",
            "Digest algorithm=\"BOGUS\"");
  run_case ("bug-c/algo-space",
            "Digest algorithm = BOGUS");
  /* A backslash inside the value marks the parameter as "quoted", which
     selects the second, separate branch of the algorithm token parser. */
  run_case ("bug-c/algo-escaped-bogus",
            "Digest algorithm=\"\\BOGUS\"");
  run_case ("bug-c/algo-escaped-md5-x",
            "Digest algorithm=\"MD5\\-x\"");
  /* The "-sess" variants are valid tokens, but they are rejected by the
     bit-mask test as they are not allowed by the application. */
  run_case ("bug-c/algo-md5-sess",
            "Digest algorithm=MD5-sess");
  run_case ("bug-c/algo-sha256-sess",
            "Digest algorithm=SHA-256-sess");
  run_case ("bug-c/algo-sha512-256-sess",
            "Digest algorithm=SHA-512-256-sess");
  run_case ("bug-c/algo-escaped-md5-sess",
            "Digest algorithm=\"MD5\\-sess\"");
  run_case ("bug-c/algo-escaped-sha512-256",
            "Digest algorithm=\"SHA\\-512-256\"");
  /* The last occurrence of a duplicated parameter is the effective one. */
  run_case ("bug-c/algo-duplicated",
            "Digest algorithm=MD5, algorithm=BOGUS");
  run_case ("bug-c/algo-duplicated-rev",
            "Digest algorithm=BOGUS, algorithm=MD5");

  /* The same, but with all the other parameters present and valid, so that
     nothing else can short-circuit the check. */
  test_port = port_sha256;

  need_nonce (nonce, sizeof (nonce));
  make_valid_params (params, sizeof (params), nonce);
  run_case ("bug-c/algo-bogus-full",
            "Digest %s, algorithm=BOGUS, response=\"%s\"",
            params,
            resp);

  need_nonce (nonce, sizeof (nonce));
  make_valid_params (params, sizeof (params), nonce);
  run_case ("bug-c/algo-empty-full",
            "Digest %s, algorithm=\"\", response=\"%s\"",
            params,
            resp);

  need_nonce (nonce, sizeof (nonce));
  make_valid_params (params, sizeof (params), nonce);
  run_case ("bug-c/algo-escaped-bogus-full",
            "Digest %s, algorithm=\"\\BOGUS\", response=\"%s\"",
            params,
            resp);
}


/**
 * Sub-cases for the out-of-bounds stack write in the "response=" hex decoder.
 *
 * The decoder writes (len + 1) / 2 bytes into a #MAX_DIGEST (32) bytes long
 * stack buffer, while the length sanity check accepts up to digest_size * 4
 * (128) characters.  All the other parameters must be valid to reach the
 * decoder, therefore a fresh "nonce" is obtained for every sub-case.
 */
static void
test_overlong_response (void)
{
  /* 128 and 127 characters produce the maximum overflow of 32 bytes, 66 and
     65 characters produce the minimum overflow of a single byte, 64
     characters fit exactly and must not overflow. */
  static const size_t resp_lengths[] = { 128, 127, 100, 66, 65, 64 };
  char nonce[256];
  char params[512];
  char resp[512];
  char name[128];
  size_t i;

  test_port = port_sha256;

  for (i = 0; i < sizeof (resp_lengths) / sizeof (resp_lengths[0]); ++i)
  {
    const size_t len = resp_lengths[i];

    /* The value without the quotation marks */
    need_nonce (nonce, sizeof (nonce));
    make_valid_params (params, sizeof (params), nonce);
    snprintf (name, sizeof (name),
              "bug-d/sha256-response-%u-bare",
              (unsigned) len);
    run_case (name,
              "Digest %s, algorithm=SHA-256, response=%s",
              params,
              fill_hex (resp, len));

    /* The same value in the quotation marks */
    need_nonce (nonce, sizeof (nonce));
    make_valid_params (params, sizeof (params), nonce);
    snprintf (name, sizeof (name),
              "bug-d/sha256-response-%u-quoted",
              (unsigned) len);
    run_case (name,
              "Digest %s, algorithm=SHA-256, response=\"%s\"",
              params,
              fill_hex (resp, len));
  }

  /* A backslash marks the value as "quoted", so it is unquoted into the
     temporal buffer first and only then decoded. */
  need_nonce (nonce, sizeof (nonce));
  make_valid_params (params, sizeof (params), nonce);
  run_case ("bug-d/sha256-response-127-escaped",
            "Digest %s, algorithm=SHA-256, response=\"\\%s\"",
            params,
            fill_hex (resp, 127));

  /* The SHA-512/256 algorithm uses the same digest size as SHA-256 and the
     same nonce length, so it reaches the decoder as well. */
#ifdef MHD_SHA512_256_SUPPORT
  need_nonce (nonce, sizeof (nonce));
  make_valid_params (params, sizeof (params), nonce);
  run_case ("bug-d/sha512-256-response-128-bare",
            "Digest %s, algorithm=SHA-512-256, response=%s",
            params,
            fill_hex (resp, 128));
#endif /* MHD_SHA512_256_SUPPORT */

  /* The RFC2069 mode: no "qop", no "nc" and no "cnonce". */
  need_nonce (nonce, sizeof (nonce));
  run_case ("bug-d/sha256-response-128-rfc2069",
            "Digest username=\"" TEST_USERNAME "\", realm=\"" TEST_REALM "\", "
            "nonce=\"%s\", uri=\"" TEST_URL "\", algorithm=SHA-256, "
            "response=%s",
            nonce,
            fill_hex (resp, 128));

  /* The value is not a valid hexadecimal string, the decoder must bail out
     before writing anything. */
  need_nonce (nonce, sizeof (nonce));
  make_valid_params (params, sizeof (params), nonce);
  run_case ("bug-d/sha256-response-128-non-hex",
            "Digest %s, algorithm=SHA-256, response=%s",
            params,
            fill_chr (resp, 'z', 128));

  /* Only the last character is not a hexadecimal digit, so the decoder
     writes 63 bytes before it detects the error. */
  need_nonce (nonce, sizeof (nonce));
  make_valid_params (params, sizeof (params), nonce);
  fill_hex (resp, 128);
  resp[127] = 'z';
  run_case ("bug-d/sha256-response-128-tail-non-hex",
            "Digest %s, algorithm=SHA-256, response=%s",
            params,
            resp);

  /* Duplicated parameter: the last (over-long) value is the effective one. */
  need_nonce (nonce, sizeof (nonce));
  make_valid_params (params, sizeof (params), nonce);
  run_case ("bug-d/sha256-response-duplicated",
            "Digest %s, algorithm=SHA-256, response=\"00112233\", response=%s",
            params,
            fill_hex (resp, 128));

#ifdef MHD_MD5_SUPPORT
  /* The MD5 variant: the decoder writes 32 bytes, which overflows the buffer
     only in an MD5-only build, where MAX_DIGEST is 16. */
  test_port = port_any;

  need_nonce (nonce, sizeof (nonce));
  make_valid_params (params, sizeof (params), nonce);
  run_case ("bug-d/md5-response-64-bare",
            "Digest %s, algorithm=MD5, response=%s",
            params,
            fill_hex (resp, 64));

  need_nonce (nonce, sizeof (nonce));
  make_valid_params (params, sizeof (params), nonce);
  run_case ("bug-d/md5-response-63-bare",
            "Digest %s, algorithm=MD5, response=%s",
            params,
            fill_hex (resp, 63));

  need_nonce (nonce, sizeof (nonce));
  make_valid_params (params, sizeof (params), nonce);
  run_case ("bug-d/md5-response-34-quoted",
            "Digest %s, algorithm=MD5, response=\"%s\"",
            params,
            fill_hex (resp, 34));
#endif /* MHD_MD5_SUPPORT */
}


/**
 * Sub-cases for the adjacent malformed, empty, over-long and duplicated
 * parameters.
 */
static void
test_adjacent (void)
{
  static char big[LONG_PARAM_LEN + 1];
  char nonce[256];
  char resp[128];

  fill_hex (resp, 64);

  /* No or unusable "Authorization:" header.  These never reach the
     "nonce" handling, the daemon used does not matter. */
  test_port = port_any;

  run_case ("adj/no-auth-header", NULL);
  run_case ("adj/scheme-only", "Digest");
  run_case ("adj/scheme-and-space", "Digest ");
  run_case ("adj/only-commas", "Digest ,,,,");
  run_case ("adj/basic-scheme", "Basic dGVzdHVzZXI6dGVzdHBhc3M=");
  run_case ("adj/unknown-scheme", "Bogus xyz");
  run_case ("adj/unterminated-quote",
            "Digest username=\"" TEST_USERNAME);
  run_case ("adj/unterminated-quote-escape",
            "Digest username=\"" TEST_USERNAME "\\\"");
  run_case ("adj/no-equal-sign", "Digest username");
  run_case ("adj/leading-equal-sign", "Digest =value");
  run_case ("adj/semicolon-in-value", "Digest username=a;b");
  run_case ("adj/garbage-after-value", "Digest username=\"a\" garbage");
  run_case ("adj/unknown-parameter",
            "Digest bogus=\"x\", username=\"" TEST_USERNAME "\"");

  /* Over-long parameter values */
  run_case ("adj/username-too-long",
            "Digest username=\"%s\", realm=\"" TEST_REALM "\"",
            fill_chr (big, 'u', LONG_PARAM_LEN));
  run_case ("adj/realm-too-long",
            "Digest username=\"" TEST_USERNAME "\", realm=\"%s\"",
            fill_chr (big, 'r', LONG_PARAM_LEN));
  run_case ("adj/uri-too-long",
            "Digest username=\"" TEST_USERNAME "\", realm=\"" TEST_REALM "\", "
            "uri=\"%s\"",
            fill_chr (big, 'p', LONG_PARAM_LEN));
  run_case ("adj/cnonce-too-long",
            "Digest username=\"" TEST_USERNAME "\", realm=\"" TEST_REALM "\", "
            "qop=auth, nc=00000001, cnonce=\"%s\"",
            fill_chr (big, 'c', LONG_PARAM_LEN));
  run_case ("adj/nc-too-long",
            "Digest username=\"" TEST_USERNAME "\", realm=\"" TEST_REALM "\", "
            "qop=auth, nc=%s, cnonce=\"abc\"",
            fill_hex (big, LONG_PARAM_LEN));
  run_case ("adj/opaque-too-long",
            "Digest username=\"" TEST_USERNAME "\", realm=\"" TEST_REALM "\", "
            "opaque=\"%s\"",
            fill_chr (big, 'o', LONG_PARAM_LEN));
  run_case ("adj/nonce-too-long",
            "Digest username=\"" TEST_USERNAME "\", realm=\"" TEST_REALM "\", "
            "nonce=\"%s\"",
            fill_hex (big, LONG_PARAM_LEN));
  run_case ("adj/response-too-long",
            "Digest username=\"" TEST_USERNAME "\", realm=\"" TEST_REALM "\", "
            "response=\"%s\"",
            fill_hex (big, LONG_PARAM_LEN));
  run_case ("adj/username-ext-too-long",
            "Digest username*=UTF-8''%s, realm=\"" TEST_REALM "\"",
            fill_chr (big, 'e', LONG_PARAM_LEN));

  /* The extended ("username*") notation */
  run_case ("adj/username-ext-truncated",
            "Digest username*=U, realm=\"" TEST_REALM "\"");
  run_case ("adj/username-ext-no-lang",
            "Digest username*=UTF-8', realm=\"" TEST_REALM "\"");
  run_case ("adj/username-ext-empty",
            "Digest username*=UTF-8'', realm=\"" TEST_REALM "\"");
  run_case ("adj/username-ext-broken-pct",
            "Digest username*=UTF-8''%%, realm=\"" TEST_REALM "\"");
  run_case ("adj/username-ext-broken-pct2",
            "Digest username*=UTF-8''%%z, realm=\"" TEST_REALM "\"");
  run_case ("adj/username-ext-broken-pct3",
            "Digest username*=UTF-8''%%zz, realm=\"" TEST_REALM "\"");
  run_case ("adj/username-ext-trailing-pct",
            "Digest username*=UTF-8''abc%%, realm=\"" TEST_REALM "\"");
  run_case ("adj/username-ext-bad-charset",
            "Digest username*=ISO-8859-1''abc, realm=\"" TEST_REALM "\"");
  run_case ("adj/username-ext-quoted",
            "Digest username*=\"UTF-8''\\abc\", realm=\"" TEST_REALM "\"");
  run_case ("adj/username-ext-and-plain",
            "Digest username=\"" TEST_USERNAME "\", "
            "username*=UTF-8''" TEST_USERNAME ", realm=\"" TEST_REALM "\"");

  /* The "userhash" handling */
  run_case ("adj/userhash-username-too-short",
            "Digest userhash=true, username=\"abcd\", "
            "realm=\"" TEST_REALM "\"");
  run_case ("adj/userhash-username-empty",
            "Digest userhash=true, username=\"\", "
            "realm=\"" TEST_REALM "\"");
  run_case ("adj/userhash-username-too-long",
            "Digest userhash=true, username=\"%s\", "
            "realm=\"" TEST_REALM "\"",
            fill_hex (big, 200));
  run_case ("adj/userhash-username-ext",
            "Digest userhash=true, username*=UTF-8''abc, "
            "realm=\"" TEST_REALM "\"");
  run_case ("adj/userhash-no-username",
            "Digest userhash=true, realm=\"" TEST_REALM "\"");

  /* The "nc" handling */
  run_case ("adj/nc-zero",
            "Digest username=\"" TEST_USERNAME "\", realm=\"" TEST_REALM "\", "
            "qop=auth, nc=00000000, cnonce=\"abc\"");
  run_case ("adj/nc-non-hex",
            "Digest username=\"" TEST_USERNAME "\", realm=\"" TEST_REALM "\", "
            "qop=auth, nc=zzzzzzzz, cnonce=\"abc\"");
  run_case ("adj/nc-empty",
            "Digest username=\"" TEST_USERNAME "\", realm=\"" TEST_REALM "\", "
            "qop=auth, nc=, cnonce=\"abc\"");
  run_case ("adj/nc-overflow",
            "Digest username=\"" TEST_USERNAME "\", realm=\"" TEST_REALM "\", "
            "qop=auth, nc=ffffffffffffffffffffffff, cnonce=\"abc\"");
  run_case ("adj/qop-auth-no-nc",
            "Digest username=\"" TEST_USERNAME "\", realm=\"" TEST_REALM "\", "
            "qop=auth, cnonce=\"abc\"");
  run_case ("adj/qop-auth-no-cnonce",
            "Digest username=\"" TEST_USERNAME "\", realm=\"" TEST_REALM "\", "
            "qop=auth, nc=00000001");
  run_case ("adj/cnonce-empty",
            "Digest username=\"" TEST_USERNAME "\", realm=\"" TEST_REALM "\", "
            "qop=auth, nc=00000001, cnonce=\"\"");

  /* Malformed "nonce" values.  These are rejected by the length check
     before the "nonce"/"nc" map is consulted. */
  run_case ("adj/nonce-short",
            "Digest username=\"" TEST_USERNAME "\", realm=\"" TEST_REALM "\", "
            "nonce=\"deadbeef\", uri=\"" TEST_URL "\", qop=auth, "
            "nc=00000001, cnonce=\"abc\", response=\"00112233\"");
  run_case ("adj/nonce-empty",
            "Digest username=\"" TEST_USERNAME "\", realm=\"" TEST_REALM "\", "
            "nonce=\"\", uri=\"" TEST_URL "\", qop=auth, "
            "nc=00000001, cnonce=\"abc\", response=\"00112233\"");

  /* Duplicated parameters */
  run_case ("adj/duplicated-username",
            "Digest username=\"a\", username=\"" TEST_USERNAME "\", "
            "realm=\"" TEST_REALM "\"");
  run_case ("adj/duplicated-realm",
            "Digest username=\"" TEST_USERNAME "\", realm=\"x\", "
            "realm=\"" TEST_REALM "\"");
  run_case ("adj/duplicated-userhash",
            "Digest username=\"" TEST_USERNAME "\", realm=\"" TEST_REALM "\", "
            "userhash=false, userhash=true");

  /* The sub-cases below use the SHA-256 algorithm and therefore need the
     daemon that issues the SHA-256 (76 characters long) nonces. */
  test_port = port_sha256;

  run_case ("adj/nonce-not-generated-by-mhd",
            "Digest username=\"" TEST_USERNAME "\", realm=\"" TEST_REALM "\", "
            "nonce=\"%s\", uri=\"" TEST_URL "\", algorithm=SHA-256, "
            "qop=auth, nc=00000001, cnonce=\"abc\", response=\"%s\"",
            fill_hex (big, 76),
            resp);

  need_nonce (nonce, sizeof (nonce));
  run_case ("adj/uri-mismatch",
            "Digest username=\"" TEST_USERNAME "\", realm=\"" TEST_REALM "\", "
            "nonce=\"%s\", uri=\"/other\", algorithm=SHA-256, qop=auth, "
            "nc=%08x, cnonce=\"abc\", response=\"%s\"",
            nonce,
            ++nc_counter,
            resp);

  need_nonce (nonce, sizeof (nonce));
  run_case ("adj/uri-empty",
            "Digest username=\"" TEST_USERNAME "\", realm=\"" TEST_REALM "\", "
            "nonce=\"%s\", uri=\"\", algorithm=SHA-256, qop=auth, "
            "nc=%08x, cnonce=\"abc\", response=\"%s\"",
            nonce,
            ++nc_counter,
            resp);

  need_nonce (nonce, sizeof (nonce));
  run_case ("adj/uri-with-args",
            "Digest username=\"" TEST_USERNAME "\", realm=\"" TEST_REALM "\", "
            "nonce=\"%s\", uri=\"" TEST_URL "?a=b\", algorithm=SHA-256, "
            "qop=auth, nc=%08x, cnonce=\"abc\", response=\"%s\"",
            nonce,
            ++nc_counter,
            resp);

  need_nonce (nonce, sizeof (nonce));
  run_case ("adj/duplicated-nonce",
            "Digest username=\"" TEST_USERNAME "\", realm=\"" TEST_REALM "\", "
            "nonce=\"deadbeef\", nonce=\"%s\", uri=\"" TEST_URL "\", "
            "algorithm=SHA-256, qop=auth, nc=%08x, cnonce=\"abc\", "
            "response=\"%s\"",
            nonce,
            ++nc_counter,
            resp);

  need_nonce (nonce, sizeof (nonce));
  run_case ("adj/qop-auth-int",
            "Digest username=\"" TEST_USERNAME "\", realm=\"" TEST_REALM "\", "
            "nonce=\"%s\", uri=\"" TEST_URL "\", algorithm=SHA-256, "
            "qop=auth-int, nc=%08x, cnonce=\"abc\", response=\"%s\"",
            nonce,
            ++nc_counter,
            resp);

  need_nonce (nonce, sizeof (nonce));
  run_case ("adj/qop-bogus",
            "Digest username=\"" TEST_USERNAME "\", realm=\"" TEST_REALM "\", "
            "nonce=\"%s\", uri=\"" TEST_URL "\", algorithm=SHA-256, "
            "qop=BOGUS, nc=%08x, cnonce=\"abc\", response=\"%s\"",
            nonce,
            ++nc_counter,
            resp);

  need_nonce (nonce, sizeof (nonce));
  run_case ("adj/userhash-64-non-hex",
            "Digest userhash=true, username=\"%s\", realm=\"" TEST_REALM "\", "
            "nonce=\"%s\", uri=\"" TEST_URL "\", algorithm=SHA-256, qop=auth, "
            "nc=%08x, cnonce=\"abc\", response=\"%s\"",
            fill_chr (big, 'z', 64),
            nonce,
            ++nc_counter,
            resp);

  need_nonce (nonce, sizeof (nonce));
  run_case ("adj/userhash-128-hex",
            "Digest userhash=true, username=\"%s\", realm=\"" TEST_REALM "\", "
            "nonce=\"%s\", uri=\"" TEST_URL "\", algorithm=SHA-256, qop=auth, "
            "nc=%08x, cnonce=\"abc\", response=\"%s\"",
            fill_hex (big, 128),
            nonce,
            ++nc_counter,
            resp);

  /* An empty "qop" value ("qop=" or "qop=\"\"") is parsed to
     #MHD_DIGEST_AUTH_QOP_INVALID, whose numeric value is zero, so it used to
     pass the "allowed QOP" bit-mask test in exactly the same way an unknown
     "algorithm" token did before commit bd49ce93, and the empty value then
     reached get_unquoted_param(), which asserts that the value is not empty.
     Fixed in commit 3b898eae; these two sub-cases are its regression test. */
  need_nonce (nonce, sizeof (nonce));
  run_case ("adj/qop-empty",
            "Digest username=\"" TEST_USERNAME "\", realm=\"" TEST_REALM "\", "
            "nonce=\"%s\", uri=\"" TEST_URL "\", algorithm=SHA-256, qop=, "
            "nc=%08x, cnonce=\"abc\", response=\"%s\"",
            nonce,
            ++nc_counter,
            resp);

  need_nonce (nonce, sizeof (nonce));
  run_case ("adj/qop-empty-quotes",
            "Digest username=\"" TEST_USERNAME "\", realm=\"" TEST_REALM "\", "
            "nonce=\"%s\", uri=\"" TEST_URL "\", algorithm=SHA-256, qop=\"\", "
            "nc=%08x, cnonce=\"abc\", response=\"%s\"",
            nonce,
            ++nc_counter,
            resp);
}


/**
 * Start a test daemon.
 *
 * @param challenge_algo the pointer to the algorithm used for the challenges
 * @param[out] pport the pointer to store the port the daemon listens on
 * @return the daemon
 */
static struct MHD_Daemon *
start_test_daemon (const enum MHD_DigestAuthMultiAlgo3 *challenge_algo,
                   uint16_t *pport)
{
  struct MHD_Daemon *daemon;
  const union MHD_DaemonInfo *dinfo;
  struct MHD_OptMatrixProfile prof;
  struct MHD_OptionItem ops[8];
  unsigned int flags;

  if (NULL != test_prof)
    prof = *test_prof;
  else
  {
    memset (&prof, 0, sizeof (prof));
    prof.name = "built-in";
    prof.threading = MHD_OPT_MATRIX_THR_INTERNAL;
    prof.poll_backend = MHD_OPT_MATRIX_POLL_SELECT;
  }
  if (0 == mhd_opt_matrix_fill_options (&prof, ops,
                                        (unsigned int) (sizeof (ops)
                                                        / sizeof (ops[0]))))
    hard_error ("The daemon option array is too small");
  /* The client of this test is a plain blocking socket client, so external
     polling is served with an internal polling thread instead. */
  flags = mhd_opt_matrix_daemon_flags (&prof, MHD_USE_ERROR_LOG, 0);

  daemon = MHD_start_daemon (flags,
                             0,
                             NULL, NULL,
                             &ahc_check, (void *) challenge_algo,
                             MHD_OPTION_ARRAY, ops,
                             MHD_OPTION_CONNECTION_TIMEOUT,
                             (unsigned int) 10,
                             MHD_OPTION_NONCE_NC_SIZE,
                             (unsigned int) NONCE_NC_SIZE,
                             MHD_OPTION_END);
  if (NULL == daemon)
    hard_error ("MHD_start_daemon() failed");
  dinfo = MHD_get_daemon_info (daemon, MHD_DAEMON_INFO_BIND_PORT);
  if ( (NULL == dinfo) || (0 == dinfo->port) )
  {
    MHD_stop_daemon (daemon);
    hard_error ("MHD_get_daemon_info() failed");
  }
  *pport = dinfo->port;
  return daemon;
}


int
main (int argc, char *const *argv)
{
  static const enum MHD_DigestAuthMultiAlgo3 algo_sha256 =
    MHD_DIGEST_AUTH_MULT_ALGO3_SHA256;
  static const enum MHD_DigestAuthMultiAlgo3 algo_any =
    MHD_DIGEST_AUTH_MULT_ALGO3_ANY_NON_SESSION;
  struct MHD_Daemon *daemon_sha256;
  struct MHD_Daemon *daemon_any;
  char nonce[256];

  if (1 < argc)
    case_filter = argv[1];

  mhd_opt_matrix_print_notice ("test_dauth_malformed");
  test_prof = mhd_opt_matrix_from_env ();
  if (NULL != test_prof)
  {
    char desc[256];

    test_prof_copy = *test_prof;
    test_prof = &test_prof_copy;
    if (! mhd_opt_matrix_profile_supported (test_prof))
    {
      printf ("test_dauth_malformed: the selected profile %s is not "
              "supported by this build, the test is skipped.\n",
              mhd_opt_matrix_describe (test_prof, desc, sizeof (desc)));
      return 77;
    }
    if (mhd_opt_matrix_raise_mem_limit (&test_prof_copy, MIN_POOL_FOR_TEST))
      printf ("test_dauth_malformed: the connection memory limit of the "
              "profile was raised to %u, the smallest pool this test can "
              "work with.\n", (unsigned) MIN_POOL_FOR_TEST);
  }

  daemon_sha256 = start_test_daemon (&algo_sha256, &port_sha256);
  daemon_any = start_test_daemon (&algo_any, &port_any);

  test_invalid_algorithm ();
  test_overlong_response ();
  test_adjacent ();

  /* Both daemons must still be alive and functional. */
  test_port = port_sha256;
  if (! get_nonce (nonce, sizeof (nonce)))
  {
    fprintf (stderr,
             "FAILED: the SHA-256 daemon does not respond after the test.\n");
    ++failures;
  }
  test_port = port_any;
  if (! get_nonce (nonce, sizeof (nonce)))
  {
    fprintf (stderr,
             "FAILED: the default daemon does not respond after the test.\n");
    ++failures;
  }

  MHD_stop_daemon (daemon_any);
  MHD_stop_daemon (daemon_sha256);

  if (0 != failures)
  {
    fprintf (stderr,
             "Test FAILED: %u of %u sub-cases failed.\n",
             failures,
             case_num);
    return 1;
  }
  printf ("Test PASSED: %u sub-cases.\n",
          case_num);
  return 0;
}


#else  /* ! DAUTH_SUPPORT || ! MHD_SHA256_SUPPORT */


int
main (void)
{
  fprintf (stderr,
           "Digest Auth or SHA-256 support is not enabled in this MHD build, "
           "the test is skipped.\n");
  return 77;
}


#endif /* ! DAUTH_SUPPORT || ! MHD_SHA256_SUPPORT */
