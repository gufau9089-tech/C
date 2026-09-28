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
 * @file test_rq_shift_back.c
 * @brief Regression test for the read buffer "shift back" underflow that
 *        happened when the last element of the request headers list was
 *        a query argument without the '=' character.
 *
 * The "shift back" optimisation at the end of get_req_headers() re-uses the
 * tail of the parsed request header area for the read buffer.  It computes
 * the end of the last element of the @a headers_received list as
 * "value + value_size".  A query argument given without '=' is stored with
 * a NULL @a value, so the computed end was NULL, the resulting shift size
 * was huge and the read buffer became a wild pointer.
 *
 * The optimisation is performed only when the space in the connection
 * memory pool is small (MHD_BUF_INC_SIZE > read_buffer_size), therefore the
 * daemons are started with a small MHD_OPTION_CONNECTION_MEMORY_LIMIT.
 * The tail of the headers list is a query argument only when the request has
 * no header lines at all, as the query arguments are added while the request
 * line is parsed and the header fields are appended afterwards.
 *
 * The test honours the daemon option matrix of mhd_opt_matrix.h: when one of
 * the MHD_TEST_* environment variables selects a profile, the built-in sweep
 * of connection memory limits is replaced by the memory limit of the profile
 * and the threading/polling mode of the profile is used as well.  Without
 * those variables nothing changes.  As the sub-cases need a pool that can
 * still hold the request, a profile asking for less than
 * #MIN_POOL_FOR_TEST bytes is raised to that value and the adjustment is
 * reported.
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

#ifdef HAVE_SIGNAL_H
#include <signal.h>
#endif /* HAVE_SIGNAL_H */

#include "mhd_sockets.h" /* only macros used */
#include "mhd_opt_matrix.h"
/* Turn any MHD_PANIC() or failing mhd_assert() reached from this
   test into a marked, classifiable test error (TESTING.md, P5). */
#include "mhd_panic_tripwire.h"

#ifndef MHD_STATICSTR_LEN_
/**
 * Determine length of static string / macro strings at compile time.
 */
#define MHD_STATICSTR_LEN_(macro) (sizeof(macro) / sizeof(char) - 1)
#endif /* ! MHD_STATICSTR_LEN_ */

/**
 * The smallest connection memory pool this test can work with: below that
 * MHD cannot even build the reply header and the sub-cases would fail for a
 * reason that has nothing to do with the "shift back" code.
 */
#define MIN_POOL_FOR_TEST 512

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
 * The body of the response sent by the test daemon.
 */
#define RESP_BODY "OK"

/**
 * The expected start of the response.
 */
#define EXPECTED_STATUS "HTTP/1.1 200"

/**
 * Be verbose.
 */
static int verbose;


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
 * The handler of the requests, always replies with a tiny static response.
 */
static enum MHD_Result
ahc_reply (void *cls,
           struct MHD_Connection *connection,
           const char *url,
           const char *method,
           const char *version,
           const char *upload_data,
           size_t *upload_data_size,
           void **req_cls)
{
  static int marker;
  struct MHD_Response *resp;
  enum MHD_Result ret;

  (void) cls; (void) url; (void) method; (void) version;
  (void) upload_data;

  if (NULL == *req_cls)
  {
    *req_cls = &marker;
    return MHD_YES;
  }
  if (0 != *upload_data_size)
  {
    *upload_data_size = 0;
    return MHD_YES;
  }
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
 * Receive data from the socket until @a min_size bytes are received, the
 * remote side closes the connection or the receive timeout expires.
 *
 * @param sk the socket to use
 * @param[out] buf the buffer to fill
 * @param buf_size the size of @a buf, the result is always zero-terminated,
 *                 therefore at most @a buf_size minus one bytes are received
 * @param min_size stop receiving as soon as this number of bytes is collected
 * @return the number of the received bytes
 */
static size_t
recv_reply (MHD_socket sk,
            char *buf,
            size_t buf_size,
            size_t min_size)
{
  size_t off = 0;

  while ((off < min_size) && (off + 1 < buf_size))
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
 * The description of a single sub-case.
 */
struct SubCase
{
  /**
   * The human readable name of the sub-case.
   */
  const char *name;

  /**
   * The raw request (and any trailing data) to be sent in a single write.
   */
  const char *request;
};


/**
 * The sub-cases.
 * The sub-cases with a trailing query argument without '=' and without any
 * header line are the ones triggering the bug.  The requests with some
 * trailing data force a non-zero read buffer offset, which turns the
 * underflow into a memmove() with a wild destination pointer (detected
 * even when the asserts are disabled), therefore these variants are run
 * first.  The control sub-cases are run before them, so that a failure of
 * the test harness itself can be distinguished from the bug.
 */
static const struct SubCase subcases[] = {
  /* Controls, must always succeed. */
  { "no query arguments at all (control)",
    "GET /a HTTP/1.0\r\n\r\n" },
  { "no query arguments at all, with trailing data (control)",
    "GET /a HTTP/1.0\r\n\r\nZZZZZZZZ" },
  { "empty argument value (control)",
    "GET /a?x= HTTP/1.0\r\n\r\n" },
  { "empty argument value, with trailing data (control)",
    "GET /a?x= HTTP/1.0\r\n\r\nZZZZZZZZ" },
  { "non-empty argument value (control)",
    "GET /a?x=1 HTTP/1.0\r\n\r\n" },
  { "non-empty argument value, with trailing data (control)",
    "GET /a?x=1 HTTP/1.0\r\n\r\nZZZZZZZZ" },
  { "argument without '=' plus a header line (control)",
    "GET /a?x HTTP/1.1\r\nHost: h\r\nConnection: close\r\n\r\n" },
  { "arguments without '=' plus a header line (control)",
    "GET /a?x&y HTTP/1.1\r\nHost: h\r\nConnection: close\r\n\r\n" },
  { "argument with trailing '&' plus a header line (control)",
    "GET /a?x& HTTP/1.1\r\nHost: h\r\nConnection: close\r\n\r\n" },
  /* The sub-cases triggering the bug. */
  { "single argument without '=', with trailing data",
    "GET /a?x HTTP/1.0\r\n\r\nZZZZZZZZ" },
  { "single argument without '='",
    "GET /a?x HTTP/1.0\r\n\r\n" },
  { "two arguments, both without '=', with trailing data",
    "GET /a?x&y HTTP/1.0\r\n\r\nZZZZZZZZ" },
  { "two arguments, both without '='",
    "GET /a?x&y HTTP/1.0\r\n\r\n" },
  { "argument with value followed by argument without '=', trailing data",
    "GET /a?x=1&y HTTP/1.0\r\n\r\nZZZZZZZZ" },
  { "argument with value followed by argument without '='",
    "GET /a?x=1&y HTTP/1.0\r\n\r\n" },
  { "single argument with trailing '&', with trailing data",
    "GET /a?x& HTTP/1.0\r\n\r\nZZZZZZZZ" },
  { "single argument with trailing '&'",
    "GET /a?x& HTTP/1.0\r\n\r\n" },
  { "percent-encoded argument name without '=', with trailing data",
    "GET /a?%78%79 HTTP/1.0\r\n\r\nZZZZZZZZ" },
  { "percent-encoded argument name without '='",
    "GET /a?%78%79 HTTP/1.0\r\n\r\n" },
  { "plus-encoded argument name without '=', with trailing data",
    "GET /a?x+y HTTP/1.0\r\n\r\nZZZZZZZZ" },
  { "plus-encoded argument name without '='",
    "GET /a?x+y HTTP/1.0\r\n\r\n" }
};

/**
 * The values for MHD_OPTION_CONNECTION_MEMORY_LIMIT to be tested.
 * All of them must be small enough to keep the read buffer size below
 * MHD_BUF_INC_SIZE (1500), otherwise the "shift back" code is not used
 * at all.
 */
static const size_t mem_limits[] = { 512, 1024 };

/**
 * The profile selected by the environment, NULL if the built-in sweep is
 * used (which is the case for a stock "make check").
 */
static const struct MHD_OptMatrixProfile *test_prof;

/**
 * The (possibly adjusted) copy of the profile @a test_prof points to.
 */
static struct MHD_OptMatrixProfile test_prof_copy;


/**
 * Run a single sub-case against the given port.
 *
 * @param port the port of the test daemon
 * @param sc the sub-case to run
 * @return non-zero if the sub-case succeeded, zero if it failed
 */
static int
run_subcase (uint16_t port,
             const struct SubCase *sc)
{
  MHD_socket sk;
  char buf[1024];
  size_t got;
  int ret = ! 0;

  sk = connect_to_port (port);
  if (MHD_INVALID_SOCKET == sk)
    hardErrorExit ("Cannot connect to the test daemon");

  if (! send_all (sk,
                  sc->request,
                  strlen (sc->request)))
  {
    fprintf (stderr,
             "FAILED: cannot send the request of the sub-case '%s'.\n",
             sc->name);
    (void) MHD_socket_close_ (sk);
    return 0;
  }
  got = recv_reply (sk,
                    buf,
                    sizeof (buf),
                    MHD_STATICSTR_LEN_ (EXPECTED_STATUS));
  if (MHD_STATICSTR_LEN_ (EXPECTED_STATUS) > got)
  {
    fprintf (stderr,
             "FAILED: sub-case '%s': no reply received "
             "(got %u bytes, expected at least %u bytes). "
             "The daemon may have crashed.\n",
             sc->name,
             (unsigned) got,
             (unsigned) MHD_STATICSTR_LEN_ (EXPECTED_STATUS));
    ret = 0;
  }
  else if (0 != memcmp (buf,
                        EXPECTED_STATUS,
                        MHD_STATICSTR_LEN_ (EXPECTED_STATUS)))
  {
    fprintf (stderr,
             "FAILED: sub-case '%s': unexpected reply status. "
             "Expected '%s', got '%.*s'.\n",
             sc->name,
             EXPECTED_STATUS,
             (int) MHD_STATICSTR_LEN_ (EXPECTED_STATUS),
             buf);
    ret = 0;
  }
  else if (verbose)
    printf ("PASSED: %s\n",
            sc->name);

  (void) MHD_socket_close_ (sk);
  return ret;
}


/**
 * Run all sub-cases with the given connection memory limit.
 *
 * @param mem_limit the value for MHD_OPTION_CONNECTION_MEMORY_LIMIT
 * @return the number of the failed sub-cases
 */
static unsigned int
run_with_mem_limit (size_t mem_limit)
{
  struct MHD_Daemon *d;
  const union MHD_DaemonInfo *dinfo;
  uint16_t port;
  unsigned int num_failed = 0;
  size_t i;
  struct MHD_OptMatrixProfile prof;
  struct MHD_OptionItem ops[8];
  unsigned int flags;

  /* The profile (if any) supplies the discipline level, the threading mode
     and the polling backend; the memory limit is the one of the sweep, which
     the caller has already taken from the profile. */
  if (NULL != test_prof)
  {
    prof = *test_prof;
    prof.mem_limit = mem_limit;
  }
  else
  {
    memset (&prof, 0, sizeof (prof));
    prof.name = "built-in";
    prof.mem_limit = mem_limit;
    prof.threading = MHD_OPT_MATRIX_THR_INTERNAL;
    prof.poll_backend = MHD_OPT_MATRIX_POLL_SELECT;
  }
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
                        &ahc_reply, NULL,
                        MHD_OPTION_ARRAY, ops,
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

  for (i = 0; i < sizeof (subcases) / sizeof (subcases[0]); ++i)
  {
    /* Report the sub-case before running it: if the daemon aborts (which is
       the expected failure mode of the un-fixed code) the whole test process
       is terminated and the last reported sub-case is the failing one. */
    fprintf (stderr,
             "Running sub-case with memory limit %u: %s\n",
             (unsigned) mem_limit,
             subcases[i].name);
    fflush (stderr);
    if (! run_subcase (port,
                       subcases + i))
      ++num_failed;
  }
  MHD_stop_daemon (d);
  return num_failed;
}


int
main (int argc, char *const *argv)
{
  unsigned int num_failed = 0;
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

  mhd_opt_matrix_print_notice ("test_rq_shift_back");
  test_prof = mhd_opt_matrix_from_env ();
  if (NULL != test_prof)
  {
    /* A profile pins one configuration: its memory limit replaces the
       built-in sweep so that the driver script can walk the matrix. */
    char desc[256];

    test_prof_copy = *test_prof;
    test_prof = &test_prof_copy;
    if (! mhd_opt_matrix_profile_supported (test_prof))
    {
      printf ("test_rq_shift_back: the selected profile %s is not supported "
              "by this build, the test is skipped.\n",
              mhd_opt_matrix_describe (test_prof, desc, sizeof (desc)));
      return 77;
    }
    if (mhd_opt_matrix_raise_mem_limit (&test_prof_copy, MIN_POOL_FOR_TEST))
      printf ("test_rq_shift_back: the connection memory limit of the "
              "profile was raised to %u, the smallest pool this test can "
              "work with.\n", (unsigned) MIN_POOL_FOR_TEST);
    if (0 == test_prof_copy.mem_limit)
      printf ("test_rq_shift_back: NOTE: the profile uses the default "
              "connection memory pool, so the \"shift back\" code path is "
              "not reached at all by this run.\n");
    num_failed = run_with_mem_limit (test_prof_copy.mem_limit);
  }
  else
  {
    for (i = 0; i < sizeof (mem_limits) / sizeof (mem_limits[0]); ++i)
      num_failed += run_with_mem_limit (mem_limits[i]);
  }

  if (0 != num_failed)
  {
    fprintf (stderr,
             "FAILED: %u sub-case(s) failed.\n",
             num_failed);
    return EXIT_FAILED_TEST;
  }
  if (verbose)
    printf ("All sub-cases passed.\n");
  return 0;
}
