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
 * @file test_chunked_ext.c
 * @brief Regression test for the handling of the chunk-extension part of
 *        the chunk size line of a chunked request body.
 *
 * When a chunk size line carries a chunk-extension (RFC 9112, Section 7.1.1)
 * the length of that line used to be computed as the position of the CR (or
 * of the bare LF) instead of the position just after the line delimiter.
 * As a result the line delimiter was not consumed and became part of the
 * chunk data, shifting all the following body parsing by two (or one) bytes.
 * That both corrupts the data given to the application and de-synchronises
 * the request/response stream, which can be abused for HTTP request
 * smuggling.
 *
 * Every sub-case sends, in a single write, a chunked request using a
 * chunk-extension immediately followed by a pipelined second request on the
 * same connection.  The test verifies the exact bytes received by the
 * request handler, that exactly one chunked request was processed and that
 * the pipelined request was parsed correctly.
 *
 * The test honours the daemon option matrix of mhd_opt_matrix.h: when one of
 * the MHD_TEST_* environment variables selects a profile, its connection
 * memory limit, threading mode and polling backend are applied to every
 * daemon this test starts.  The *client discipline level* is deliberately
 * NOT taken from the profile: it is the very thing each sub-case varies (a
 * bare LF is accepted as the chunk size line delimiter only at level -3), so
 * the per-sub-case value always wins.  Without those environment variables
 * nothing changes.  As the sub-cases need a pool that can still hold the
 * request and the reply, a profile asking for less than #MIN_POOL_FOR_TEST
 * bytes is raised to that value and the adjustment is reported.
 *
 * @author Christian Grothoff
 */
#include "MHD_config.h"
#include "platform.h"
#include <microhttpd.h>
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <errno.h>

#ifdef HAVE_STRINGS_H
#include <strings.h>
#endif /* HAVE_STRINGS_H */

#ifndef WINDOWS
#include <unistd.h>
#endif /* ! WINDOWS */

#ifdef _WIN32
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN 1
#endif /* !WIN32_LEAN_AND_MEAN */
#include <windows.h>
#endif /* _WIN32 */

#ifdef HAVE_SIGNAL_H
#include <signal.h>
#endif /* HAVE_SIGNAL_H */

#include "mhd_sockets.h" /* only macros used */
#include "mhd_opt_matrix.h"
/* Turn any MHD_PANIC() or failing mhd_assert() reached from this
   test into a marked, classifiable test error (TESTING.md, P5). */
#include "mhd_panic_tripwire.h"

/**
 * The smallest connection memory pool this test can work with: the sub-cases
 * send a chunked request plus a pipelined second request and expect two
 * complete replies, which does not fit into a smaller pool.
 */
#define MIN_POOL_FOR_TEST 1024

#ifndef MHD_STATICSTR_LEN_
/**
 * Determine length of static string / macro strings at compile time.
 */
#define MHD_STATICSTR_LEN_(macro) (sizeof(macro) / sizeof(char) - 1)
#endif /* ! MHD_STATICSTR_LEN_ */

#if MHD_VERSION >= 0x00097701
#define TEST_MK_RESPONSE(len,str) \
  MHD_create_response_from_buffer_static ((len), (str))
#else  /* MHD_VERSION < 0x00097701 */
#define TEST_MK_RESPONSE(len,str) \
  MHD_create_response_from_buffer ((len), (void *) (str), \
                                   MHD_RESPMEM_PERSISTENT)
#endif /* MHD_VERSION < 0x00097701 */

/**
 * The exit code for a failed test.
 */
#define EXIT_FAILED_TEST 1

/**
 * The exit code for a failure of the test framework itself.
 */
#define EXIT_HARD_ERROR 99

/**
 * The maximum time (in seconds) to wait for any single socket operation.
 */
#define TEST_SOCKET_TIMEOUT_SEC 5

/**
 * The time (in milliseconds) to wait between the two parts of a request
 * which is intentionally sent in two writes.
 */
#define TEST_SPLIT_DELAY_MS 50

/**
 * The body of the response sent by the test daemon.
 */
#define RESP_BODY "OK"

/**
 * The URL of the chunked request.
 */
#define URL_FIRST "/first"

/**
 * The URL of the pipelined request.
 */
#define URL_SECOND "/second"

/**
 * The head of the chunked request, the chunked body is appended to it.
 */
#define REQ_FIRST_HEAD \
  "POST " URL_FIRST " HTTP/1.1\r\nHost: h\r\n" \
  "Transfer-Encoding: chunked\r\n\r\n"

/**
 * The complete pipelined request, appended after the chunked body.
 */
#define REQ_SECOND \
  "GET " URL_SECOND " HTTP/1.1\r\nHost: h\r\nConnection: close\r\n\r\n"

/**
 * The number of the requests that could be tracked.
 */
#define MAX_TRACKED_REQS 8

/**
 * The maximum size of the tracked request body.
 */
#define MAX_TRACKED_BODY 256

/**
 * The data tracked for a single request.
 */
struct ReqTrack
{
  /**
   * The URL of the request.
   */
  char url[64];

  /**
   * The body of the request as given to the request handler.
   */
  char body[MAX_TRACKED_BODY];

  /**
   * The number of bytes in @a body.
   */
  size_t body_size;

  /**
   * Non-zero if the body of the request did not fit in @a body.
   */
  int body_overflow;

  /**
   * Non-zero if the request has been fully received.
   */
  int completed;
};

/**
 * The tracked requests.
 * Written by the daemon thread only, read by the main thread only after
 * MHD_stop_daemon() (which joins the daemon thread) has returned.
 */
static struct ReqTrack tracked[MAX_TRACKED_REQS];

/**
 * The number of the used elements in #tracked.
 */
static unsigned int num_tracked;

/**
 * Be verbose.
 */
static int verbose;

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
hard_error (const char *desc,
            int line_num)
{
  fprintf (stderr,
           "HARD ERROR: %s at line %d. Last errno: %d (%s).\n",
           desc,
           line_num,
           (int) errno,
           strerror (errno));
  fflush (stderr);
  exit (EXIT_HARD_ERROR);
}


#define hardErrorExit(desc) hard_error ((desc), __LINE__)


/**
 * Pause the execution for the specified number of milliseconds.
 *
 * @param ms the number of the milliseconds to sleep
 */
static void
test_sleep_ms (unsigned int ms)
{
#if defined(_WIN32) && ! defined(__CYGWIN__)
  Sleep ((DWORD) ms);
#elif defined(HAVE_NANOSLEEP)
  struct timespec slp;
  struct timespec rmn;
  int num_retries = 0;

  slp.tv_sec = (time_t) (ms / 1000);
  slp.tv_nsec = (long) ((ms % 1000) * 1000000);
  while (0 != nanosleep (&slp, &rmn))
  {
    if (EINTR != errno)
      break;
    if (8 < num_retries++)
      break;
    slp = rmn;
  }
#elif defined(HAVE_USLEEP)
  usleep (((unsigned long) ms) * 1000);
#else  /* ! HAVE_NANOSLEEP && ! HAVE_USLEEP */
  (void) ms; /* Mute compiler warning, the test works without the delay */
#endif /* ! HAVE_NANOSLEEP && ! HAVE_USLEEP */
}


/**
 * The handler of the requests, tracks the URL and the exact body bytes.
 */
static enum MHD_Result
ahc_track (void *cls,
           struct MHD_Connection *connection,
           const char *url,
           const char *method,
           const char *version,
           const char *upload_data,
           size_t *upload_data_size,
           void **req_cls)
{
  struct ReqTrack *trk = (struct ReqTrack *) *req_cls;
  struct MHD_Response *resp;
  enum MHD_Result ret;

  (void) cls; (void) method; (void) version;

  if (NULL == trk)
  {
    if (MAX_TRACKED_REQS <= num_tracked)
      return MHD_NO; /* Too many requests, the check in the main thread fails */
    trk = tracked + num_tracked++;
    memset (trk,
            0,
            sizeof (*trk));
    if (sizeof (trk->url) <= strlen (url))
      return MHD_NO;
    memcpy (trk->url,
            url,
            strlen (url) + 1);
    *req_cls = trk;
    return MHD_YES;
  }
  if (0 != *upload_data_size)
  {
    if (sizeof (trk->body) < trk->body_size + *upload_data_size)
      trk->body_overflow = 1;
    else
    {
      memcpy (trk->body + trk->body_size,
              upload_data,
              *upload_data_size);
      trk->body_size += *upload_data_size;
    }
    *upload_data_size = 0;
    return MHD_YES;
  }
  trk->completed = 1;
  resp = TEST_MK_RESPONSE (MHD_STATICSTR_LEN_ (RESP_BODY),
                           RESP_BODY);
  if (NULL == resp)
    return MHD_NO;
  ret = MHD_queue_response (connection,
                            MHD_HTTP_OK,
                            resp);
  MHD_destroy_response (resp);
  return ret;
}


/**
 * Set send and receive timeouts on the socket so that the test cannot
 * block indefinitely.
 *
 * @param sk the socket to set the timeouts on
 * @return non-zero if succeed, zero if failed
 */
static int
set_socket_timeouts (MHD_socket sk)
{
#if defined(MHD_WINSOCK_SOCKETS)
  DWORD tv = (DWORD) (TEST_SOCKET_TIMEOUT_SEC * 1000);
#else  /* ! MHD_WINSOCK_SOCKETS */
  struct timeval tv;

  tv.tv_sec = (time_t) TEST_SOCKET_TIMEOUT_SEC;
  tv.tv_usec = 0;
#endif /* ! MHD_WINSOCK_SOCKETS */
  if (0 != setsockopt (sk,
                       SOL_SOCKET,
                       SO_RCVTIMEO,
                       (const void *) &tv,
                       (socklen_t) sizeof (tv)))
    return 0;
  if (0 != setsockopt (sk,
                       SOL_SOCKET,
                       SO_SNDTIMEO,
                       (const void *) &tv,
                       (socklen_t) sizeof (tv)))
    return 0;
  return ! 0;
}


/**
 * Open a TCP connection to the given port on the loopback interface.
 *
 * @param port the port to connect to
 * @return the connected socket, MHD_INVALID_SOCKET on failure
 */
static MHD_socket
connect_to_port (uint16_t port)
{
  MHD_socket sk;
  struct sockaddr_in sa;

  sk = socket (PF_INET,
               SOCK_STREAM,
               0);
  if (MHD_INVALID_SOCKET == sk)
    return MHD_INVALID_SOCKET;
  if (! set_socket_timeouts (sk))
  {
    (void) MHD_socket_close_ (sk);
    return MHD_INVALID_SOCKET;
  }
  memset (&sa,
          0,
          sizeof (sa));
  sa.sin_family = AF_INET;
  sa.sin_port = htons (port);
  sa.sin_addr.s_addr = htonl (INADDR_LOOPBACK);
  if (0 != connect (sk,
                    (const struct sockaddr *) &sa,
                    (socklen_t) sizeof (sa)))
  {
    (void) MHD_socket_close_ (sk);
    return MHD_INVALID_SOCKET;
  }
  return sk;
}


/**
 * Send all the given data over the socket.
 *
 * @param sk the socket to use
 * @param buf the data to send
 * @param size the size of @a buf
 * @return non-zero if succeed, zero if failed
 */
static int
send_all (MHD_socket sk,
          const char *buf,
          size_t size)
{
  size_t off = 0;

  while (off < size)
  {
    ssize_t res;

    res = MHD_send_ (sk,
                     buf + off,
                     size - off);
    if (0 > res)
    {
      if (MHD_SCKT_ERR_IS_EINTR_ (MHD_socket_get_error_ ()))
        continue;
      return 0;
    }
    if (0 == res)
      return 0;
    off += (size_t) res;
  }
  return ! 0;
}


/**
 * Receive data from the socket until the remote side closes the connection,
 * the buffer is full or the receive timeout expires.
 *
 * @param sk the socket to use
 * @param[out] buf the buffer to fill
 * @param buf_size the size of @a buf, the result is always zero-terminated,
 *                 therefore at most @a buf_size minus one bytes are received
 * @return the number of the received bytes
 */
static size_t
recv_all (MHD_socket sk,
          char *buf,
          size_t buf_size)
{
  size_t off = 0;

  while (off + 1 < buf_size)
  {
    ssize_t res;

    res = MHD_recv_ (sk,
                     buf + off,
                     buf_size - 1 - off);
    if (0 > res)
    {
      if (MHD_SCKT_ERR_IS_EINTR_ (MHD_socket_get_error_ ()))
        continue;
      break; /* Timeout or error */
    }
    if (0 == res)
      break;   /* The remote side closed the connection */
    off += (size_t) res;
  }
  buf[off] = 0;
  return off;
}


/**
 * Count the number of the non-overlapping occurrences of @a needle
 * in @a haystack.
 *
 * @param haystack the zero-terminated string to search in
 * @param needle the zero-terminated string to search for
 * @return the number of the found occurrences
 */
static unsigned int
count_substr (const char *haystack,
              const char *needle)
{
  const size_t needle_len = strlen (needle);
  unsigned int num = 0;
  const char *pos = haystack;

  if (0 == needle_len)
    return 0;
  while (NULL != (pos = strstr (pos, needle)))
  {
    ++num;
    pos += needle_len;
  }
  return num;
}


/**
 * Print the data to the standard error stream, replacing the non-printable
 * characters with their escaped hexadecimal form.
 *
 * @param data the data to print
 * @param size the size of @a data
 */
static void
print_escaped (const char *data,
               size_t size)
{
  size_t i;

  for (i = 0; i < size; ++i)
  {
    const unsigned char chr = (unsigned char) data[i];

    if ((0x20 <= chr) && (0x7e >= chr) && ('\\' != chr))
      fputc ((int) chr,
             stderr);
    else if ('\\' == chr)
      fputs ("\\\\",
             stderr);
    else if ('\r' == chr)
      fputs ("\\r",
             stderr);
    else if ('\n' == chr)
      fputs ("\\n",
             stderr);
    else if ('\t' == chr)
      fputs ("\\t",
             stderr);
    else
      fprintf (stderr,
               "\\x%02X",
               (unsigned int) chr);
  }
}


/**
 * The description of a single sub-case.
 */
struct ChunkCase
{
  /**
   * The human readable name of the sub-case.
   */
  const char *name;

  /**
   * The chunked body of the request, including the terminating chunk and
   * the (empty) trailer section.
   */
  const char *chunked;

  /**
   * The exact bytes that the request handler must receive.
   */
  const char *expected;

  /**
   * The number of the bytes in @a expected.
   */
  size_t expected_size;

  /**
   * If non-zero, the request is sent in two writes and this is the number of
   * the bytes of @a chunked included in the first write.
   */
  size_t split_at;

  /**
   * The value for MHD_OPTION_CLIENT_DISCIPLINE_LVL.
   */
  int discipline;

  /**
   * Non-zero if the sub-case requires the support of the bare LF as the
   * line delimiter of the chunk size line.
   */
  int need_bare_lf;
};

#define CHUNK_CASE(nm,ch,exp,spl,dsc,blf) \
  { (nm), (ch), (exp), MHD_STATICSTR_LEN_ (exp), (spl), (dsc), (blf) }

/**
 * The sub-cases.
 * All of them must be processed identically: the handler must receive
 * exactly the expected bytes, and the pipelined request must be processed
 * as the second (and the last) request on the connection.
 */
static const struct ChunkCase chunkcases[] = {
  CHUNK_CASE ("no chunk-extension (control)",
              "5\r\nHELLO\r\n0\r\n\r\n",
              "HELLO", 0, 0, 0),
  CHUNK_CASE ("chunk-extension with a value",
              "5;ext=val\r\nHELLO\r\n0\r\n\r\n",
              "HELLO", 0, 0, 0),
  CHUNK_CASE ("chunk-extension without a value",
              "5;ext\r\nHELLO\r\n0\r\n\r\n",
              "HELLO", 0, 0, 0),
  CHUNK_CASE ("chunk-extension after a bad whitespace (space)",
              "5 ;ext=val\r\nHELLO\r\n0\r\n\r\n",
              "HELLO", 0, 0, 0),
  CHUNK_CASE ("chunk-extension after a bad whitespace (tab)",
              "5\t;ext\r\nHELLO\r\n0\r\n\r\n",
              "HELLO", 0, 0, 0),
  CHUNK_CASE ("chunk-extension with a quoted-string value",
              "5;ext=\"quoted; value\"\r\nHELLO\r\n0\r\n\r\n",
              "HELLO", 0, 0, 0),
  CHUNK_CASE ("several chunk-extensions",
              "5;e1=v1;e2=\"v 2\";e3\r\nHELLO\r\n0\r\n\r\n",
              "HELLO", 0, 0, 0),
  CHUNK_CASE ("two chunks, both with a chunk-extension",
              "3;a=b\r\nabc\r\n4;c=d\r\ndefg\r\n0\r\n\r\n",
              "abcdefg", 0, 0, 0),
  CHUNK_CASE ("two chunks, only the first with a chunk-extension",
              "3;a=b\r\nabc\r\n4\r\ndefg\r\n0\r\n\r\n",
              "abcdefg", 0, 0, 0),
  CHUNK_CASE ("two chunks, only the second with a chunk-extension",
              "3\r\nabc\r\n4;c=d\r\ndefg\r\n0\r\n\r\n",
              "abcdefg", 0, 0, 0),
  CHUNK_CASE ("chunk-extension on the terminating chunk as well",
              "3;a=b\r\nabc\r\n4;c=d\r\ndefg\r\n0;last=1\r\n\r\n",
              "abcdefg", 0, 0, 0),
  CHUNK_CASE ("chunk data with an embedded CRLF",
              "7;ext=val\r\nAB\r\nCDE\r\n0\r\n\r\n",
              "AB\r\nCDE", 0, 0, 0),
  CHUNK_CASE ("chunk-extension line split between two writes",
              "5;ext=val\r\nHELLO\r\n0\r\n\r\n",
              "HELLO", 4, 0, 0),
  CHUNK_CASE ("chunk-extension line delimiter split between two writes",
              "5;ext=val\r\nHELLO\r\n0\r\n\r\n",
              "HELLO", 10, 0, 0),
  CHUNK_CASE ("chunk-extension with a bare LF line delimiter",
              "5;ext=val\nHELLO\r\n0\r\n\r\n",
              "HELLO", 0, -3, 1),
  CHUNK_CASE ("two chunks with a bare LF line delimiter",
              "3;a=b\nabc\r\n4;c=d\ndefg\r\n0\r\n\r\n",
              "abcdefg", 0, -3, 1)
};

/**
 * The sub-case used to detect whether this build accepts the bare LF as the
 * line delimiter of the chunk size line.  It does not use any
 * chunk-extension, therefore it is not affected by the tested bug.
 */
static const struct ChunkCase bare_lf_probe =
  CHUNK_CASE ("bare LF support probe",
              "5\nHELLO\r\n0\r\n\r\n",
              "HELLO", 0, -3, 0);


/**
 * Run a single sub-case.
 *
 * @param cc the sub-case to run
 * @param quiet if non-zero, do not report the failures
 * @return non-zero if the sub-case succeeded, zero if it failed
 */
static int
run_subcase (const struct ChunkCase *cc,
             int quiet)
{
  struct MHD_Daemon *d;
  const union MHD_DaemonInfo *dinfo;
  uint16_t port;
  MHD_socket sk;
  char req[1024];
  char resp[4096];
  size_t req_size;
  size_t chunked_size;
  size_t resp_size;
  int failed = 0;
  int sent_ok;
  struct MHD_OptMatrixProfile prof;
  struct MHD_OptionItem ops[8];
  unsigned int flags;

  chunked_size = strlen (cc->chunked);
  req_size = MHD_STATICSTR_LEN_ (REQ_FIRST_HEAD) + chunked_size
             + MHD_STATICSTR_LEN_ (REQ_SECOND);
  if (sizeof (req) <= req_size)
    hardErrorExit ("The request does not fit in the buffer");
  memcpy (req,
          REQ_FIRST_HEAD,
          MHD_STATICSTR_LEN_ (REQ_FIRST_HEAD));
  memcpy (req + MHD_STATICSTR_LEN_ (REQ_FIRST_HEAD),
          cc->chunked,
          chunked_size);
  memcpy (req + MHD_STATICSTR_LEN_ (REQ_FIRST_HEAD) + chunked_size,
          REQ_SECOND,
          MHD_STATICSTR_LEN_ (REQ_SECOND) + 1);

  num_tracked = 0;
  memset (tracked,
          0,
          sizeof (tracked));

  /* The profile (if any) supplies the memory limit, the threading mode and
     the polling backend.  The client discipline level always comes from the
     sub-case, see the file comment. */
  if (NULL != test_prof)
    prof = *test_prof;
  else
  {
    memset (&prof, 0, sizeof (prof));
    prof.name = "built-in";
    prof.threading = MHD_OPT_MATRIX_THR_INTERNAL;
    prof.poll_backend = MHD_OPT_MATRIX_POLL_SELECT;
  }
  prof.discipline_lvl = 0;
  prof.use_legacy_strict = 0;
  if (0 == mhd_opt_matrix_fill_options (&prof, ops,
                                        (unsigned int) (sizeof (ops)
                                                        / sizeof (ops[0]))))
    hardErrorExit ("The daemon option array is too small");
  /* The client of this test is a plain blocking socket client, so external
     polling is served with an internal polling thread instead. */
  flags = mhd_opt_matrix_daemon_flags (&prof, MHD_USE_ERROR_LOG, 0);

  d = MHD_start_daemon (flags,
                        0,
                        NULL, NULL,
                        &ahc_track, NULL,
                        MHD_OPTION_ARRAY, ops,
                        MHD_OPTION_CLIENT_DISCIPLINE_LVL, cc->discipline,
                        MHD_OPTION_CONNECTION_TIMEOUT,
                        (unsigned int) TEST_SOCKET_TIMEOUT_SEC,
                        MHD_OPTION_END);
  if (NULL == d)
    hardErrorExit ("Cannot start the test daemon");
  dinfo = MHD_get_daemon_info (d,
                               MHD_DAEMON_INFO_BIND_PORT);
  if ((NULL == dinfo) || (0 == dinfo->port))
  {
    MHD_stop_daemon (d);
    hardErrorExit ("Cannot detect the port used by the test daemon");
  }
  port = (uint16_t) dinfo->port;

  sk = connect_to_port (port);
  if (MHD_INVALID_SOCKET == sk)
  {
    MHD_stop_daemon (d);
    hardErrorExit ("Cannot connect to the test daemon");
  }

  if (0 == cc->split_at)
    sent_ok = send_all (sk,
                        req,
                        req_size);
  else
  {
    const size_t first_part =
      MHD_STATICSTR_LEN_ (REQ_FIRST_HEAD) + cc->split_at;

    if (first_part >= req_size)
      hardErrorExit ("Wrong 'split_at' value in the sub-case");
    sent_ok = send_all (sk,
                        req,
                        first_part);
    if (sent_ok)
    {
      test_sleep_ms (TEST_SPLIT_DELAY_MS);
      sent_ok = send_all (sk,
                          req + first_part,
                          req_size - first_part);
    }
  }
  if (! sent_ok)
  {
    if (! quiet)
      fprintf (stderr,
               "FAILED: sub-case '%s': cannot send the request.\n",
               cc->name);
    (void) MHD_socket_close_ (sk);
    MHD_stop_daemon (d);
    return 0;
  }
  resp_size = recv_all (sk,
                        resp,
                        sizeof (resp));
  (void) MHD_socket_close_ (sk);
  /* MHD_stop_daemon() joins the daemon thread, therefore all the data
     tracked by the request handler is safely visible afterwards. */
  MHD_stop_daemon (d);

  if (2 != num_tracked)
  {
    if (! quiet)
      fprintf (stderr,
               "FAILED: sub-case '%s': the number of the processed requests "
               "is %u, while exactly 2 requests are expected.\n",
               cc->name,
               num_tracked);
    failed = 1;
  }
  if (1 <= num_tracked)
  {
    const struct ReqTrack *const trk = tracked + 0;

    if (0 != strcmp (trk->url,
                     URL_FIRST))
    {
      if (! quiet)
        fprintf (stderr,
                 "FAILED: sub-case '%s': the URL of the first request is "
                 "'%s', while '%s' is expected.\n",
                 cc->name,
                 trk->url,
                 URL_FIRST);
      failed = 1;
    }
    if (0 != trk->body_overflow)
    {
      if (! quiet)
        fprintf (stderr,
                 "FAILED: sub-case '%s': the body of the first request is "
                 "too large.\n",
                 cc->name);
      failed = 1;
    }
    else if ((cc->expected_size != trk->body_size) ||
             (0 != memcmp (cc->expected,
                           trk->body,
                           cc->expected_size)))
    {
      if (! quiet)
      {
        fprintf (stderr,
                 "FAILED: sub-case '%s': the body of the first request is '",
                 cc->name);
        print_escaped (trk->body,
                       trk->body_size);
        fprintf (stderr,
                 "' (%u bytes), while '",
                 (unsigned) trk->body_size);
        print_escaped (cc->expected,
                       cc->expected_size);
        fprintf (stderr,
                 "' (%u bytes) is expected.\n",
                 (unsigned) cc->expected_size);
      }
      failed = 1;
    }
    if (0 == trk->completed)
    {
      if (! quiet)
        fprintf (stderr,
                 "FAILED: sub-case '%s': the first request has not been "
                 "completed.\n",
                 cc->name);
      failed = 1;
    }
  }
  if (2 <= num_tracked)
  {
    const struct ReqTrack *const trk = tracked + 1;

    if (0 != strcmp (trk->url,
                     URL_SECOND))
    {
      if (! quiet)
        fprintf (stderr,
                 "FAILED: sub-case '%s': the URL of the pipelined request is "
                 "'%s', while '%s' is expected. The request stream has been "
                 "de-synchronised.\n",
                 cc->name,
                 trk->url,
                 URL_SECOND);
      failed = 1;
    }
    if ((0 != trk->body_size) || (0 != trk->body_overflow))
    {
      if (! quiet)
        fprintf (stderr,
                 "FAILED: sub-case '%s': the pipelined request has a body of "
                 "%u bytes, while no body is expected.\n",
                 cc->name,
                 (unsigned) trk->body_size);
      failed = 1;
    }
    if (0 == trk->completed)
    {
      if (! quiet)
        fprintf (stderr,
                 "FAILED: sub-case '%s': the pipelined request has not been "
                 "completed.\n",
                 cc->name);
      failed = 1;
    }
  }
  if (2 != count_substr (resp,
                         "HTTP/1.1 "))
  {
    if (! quiet)
      fprintf (stderr,
               "FAILED: sub-case '%s': the number of the replies is %u, "
               "while exactly 2 replies are expected. The reply stream is:\n"
               "%.*s\n",
               cc->name,
               count_substr (resp, "HTTP/1.1 "),
               (int) resp_size,
               resp);
    failed = 1;
  }
  else if (2 != count_substr (resp,
                              "HTTP/1.1 200 "))
  {
    if (! quiet)
      fprintf (stderr,
               "FAILED: sub-case '%s': not all replies have the '200' status "
               "code. The reply stream is:\n%.*s\n",
               cc->name,
               (int) resp_size,
               resp);
    failed = 1;
  }

  if ((0 == failed) && verbose)
    printf ("PASSED: %s\n",
            cc->name);
  return ! failed;
}


int
main (int argc, char *const *argv)
{
  unsigned int num_failed = 0;
  unsigned int num_skipped = 0;
  int bare_lf_supported;
  size_t i;

  verbose = 0;
  for (i = 1; i < (size_t) argc; ++i)
  {
    if ((0 == strcmp (argv[i], "-v")) ||
        (0 == strcmp (argv[i], "--verbose")))
      verbose = 1;
  }

  if (MHD_YES != MHD_is_feature_supported (MHD_FEATURE_AUTOSUPPRESS_SIGPIPE))
  {
#if defined(HAVE_SIGNAL_H) && defined(SIGPIPE)
    if (SIG_ERR == signal (SIGPIPE, SIG_IGN))
      hardErrorExit ("Cannot suppress the SIGPIPE signal");
#else  /* ! HAVE_SIGNAL_H || ! SIGPIPE */
    fprintf (stderr,
             "Cannot suppress the SIGPIPE signal.\n");
#endif /* ! HAVE_SIGNAL_H || ! SIGPIPE */
  }

  mhd_opt_matrix_print_notice ("test_chunked_ext");
  test_prof = mhd_opt_matrix_from_env ();
  if (NULL != test_prof)
  {
    char desc[256];

    test_prof_copy = *test_prof;
    test_prof = &test_prof_copy;
    if (! mhd_opt_matrix_profile_supported (test_prof))
    {
      printf ("test_chunked_ext: the selected profile %s is not supported by "
              "this build, the test is skipped.\n",
              mhd_opt_matrix_describe (test_prof, desc, sizeof (desc)));
      return 77;
    }
    if (mhd_opt_matrix_raise_mem_limit (&test_prof_copy, MIN_POOL_FOR_TEST))
      printf ("test_chunked_ext: the connection memory limit of the profile "
              "was raised to %u, the smallest pool this test can work "
              "with.\n", (unsigned) MIN_POOL_FOR_TEST);
  }

  /* Detect whether the bare LF is accepted as the line delimiter of the
     chunk size line with the lowest client discipline level. */
  bare_lf_supported = run_subcase (&bare_lf_probe,
                                   1);
  if ((! bare_lf_supported) && verbose)
    printf ("The bare LF as the chunk size line delimiter is not supported "
            "by this build, the related sub-cases are skipped.\n");

  for (i = 0; i < sizeof (chunkcases) / sizeof (chunkcases[0]); ++i)
  {
    const struct ChunkCase *const cc = chunkcases + i;

    if ((0 != cc->need_bare_lf) && (! bare_lf_supported))
    {
      ++num_skipped;
      continue;
    }
    /* Report the sub-case before running it, so that the failing sub-case
       can be identified even if the daemon aborts the process. */
    fprintf (stderr,
             "Running sub-case: %s\n",
             cc->name);
    fflush (stderr);
    if (! run_subcase (cc,
                       0))
      ++num_failed;
  }

  if (0 != num_failed)
  {
    fprintf (stderr,
             "FAILED: %u sub-case(s) failed.\n",
             num_failed);
    return EXIT_FAILED_TEST;
  }
  if (verbose)
    printf ("All sub-cases passed (%u sub-case(s) skipped).\n",
            num_skipped);
  return 0;
}
