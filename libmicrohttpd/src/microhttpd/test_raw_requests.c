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
 * @file test_raw_requests.c
 * @brief  Data-driven raw HTTP request corpus, replayed at every possible
 *         TCP stream split point and under a sweep of connection memory
 *         limits.
 * @author Christian Grothoff
 *
 * ## Why this test exists
 *
 * The MHD request parser is *incremental*: it is re-entered every time more
 * bytes arrive from the network and has to decide, at each entry, whether it
 * already holds a complete line / chunk header / chunk / body.  Off-by-N
 * errors, misplaced `break; /_* need more data *_/` statements and
 * state-machine desynchronisations live exactly in that logic and they are
 * invisible when the whole request arrives in a single `read()`.
 *
 * This test therefore takes every corpus entry and replays it over a fresh TCP
 * connection once per possible split offset, forcing the server to re-enter
 * the parser at that offset.  The parse result (method, URL, version, upload
 * body, headers, GET arguments, footers, number of complete requests, response
 * status, connection re-use) must be *identical* for every split offset.  Any
 * divergence is a bug, no matter what the declared expectations say.
 *
 * The whole corpus is additionally replayed for a sweep of
 * #MHD_OPTION_CONNECTION_MEMORY_LIMIT values.  Values below #MHD_BUF_INC_SIZE
 * (1500) unlock the read-buffer "shift back" and buffer-grow code paths that
 * are never reached with the default pool size.
 *
 * ## How to add a corpus entry
 *
 * Add exactly one initialiser to the @a corpus[] table below.  Nothing else
 * has to be touched.  The fields are:
 *
 * * `.name`  - short identifier, printed on failure;
 * * `.desc`  - one line saying which behaviour the entry pins down;
 * * `.raw`   - the raw request byte stream (may contain several pipelined
 *              requests);  `.raw_len` may stay 0, then `strlen()` is used;
 * * `.n_req` - how many complete requests MHD *must* parse out of `.raw`
 *              (this is the request-smuggling / desync detector: a stream
 *              that must yield 2 requests may never yield 1 or 3);
 * * `.reqs[]`- the per-request expectations.  `.hdrs`, `.args` and `.foot`
 *              are newline separated `key=value` lists in the order in which
 *              MHD reports them; a NULL value (what a query argument without
 *              '=' produces) is written as `<NULL>`;
 * * `.n_resp`- how many HTTP responses the client must see;
 * * `.status`- expected status code of the *first* response, 0 for "any
 *              well-formed response";
 * * `.alive` - 1 if the connection must stay alive afterwards, 0 if MHD must
 *              close it;
 * * `.deep`  - non-zero to additionally run the (much slower) three-way split
 *              pass over this entry.
 *
 * The escaping used by the observation format has to be applied to the
 * expectation strings as well: every byte outside the printable ASCII range
 * appears as `\\xNN` (so a TAB inside a header value is written as `\\x09`).
 *
 * If the entry does not fit into the connection memory pool of the current
 * sweep step, MHD answers 431/413/414/500 without ever invoking the request
 * handler, or it cannot even build the reply header and closes the connection
 * without an answer, or it serves only the first of several pipelined
 * requests.  All three are legitimate resource limitations; the test detects
 * them and falls back to the relaxed check "every request that MHD did parse
 * matches the expectation for its index, and MHD never parses more requests
 * than the stream contains".  A 400 Bad Request is never accepted as a
 * resource limitation.
 *
 * ## The daemon option matrix
 *
 * The test honours the matrix of mhd_opt_matrix.h: when one of the MHD_TEST_*
 * environment variables selects a profile, the built-in memory limit sweep is
 * replaced by the single memory limit of the profile and the threading mode,
 * the polling backend and the client discipline level of the profile are
 * applied.  Without those variables nothing changes, so a stock "make check"
 * runs exactly the sweep described above.
 *
 * The declared expectations of a corpus entry are only valid for a range of
 * client discipline levels - the levels are precisely the knob that switches
 * the parser leniency the entries pin down.  Every entry whose expectation
 * depends on the level is therefore listed in @a discp_limits[] with the
 * range in which it is meaningful, and is skipped outside of it.  At the
 * default level 0 nothing is ever skipped.
 *
 * ## Command line
 *
 * * `-v`            - report the memory limit sweep and degraded entries;
 * * `-v -v`         - additionally print the MHD error log;
 * * `--entry=NAME`  - restrict the run to a single corpus entry (`NAME` may
 *                     also be given as a bare argument).
 *
 * Exit codes: 0 = pass, 77 = skip, 99 = hard setup error, 1 = test failure.
 */
#include "MHD_config.h"
#include "platform.h"
#include <microhttpd.h>
#include <stdlib.h>
#include <string.h>
#include <stdarg.h>
#include <time.h>
#include <stdint.h>
#include <errno.h>

#ifdef HAVE_STRINGS_H
#include <strings.h>
#endif /* HAVE_STRINGS_H */

#ifdef _WIN32
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN 1
#endif /* !WIN32_LEAN_AND_MEAN */
#include <windows.h>
#endif

#ifndef WINDOWS
#include <unistd.h>
#include <sys/socket.h>
#endif

#ifdef HAVE_LIMITS_H
#include <limits.h>
#endif /* HAVE_LIMITS_H */

#ifdef HAVE_SIGNAL_H
#include <signal.h>
#endif /* HAVE_SIGNAL_H */

#include <stdio.h>

#include "mhd_sockets.h" /* only macros used */
#include "mhd_opt_matrix.h"

#ifndef MHD_STATICSTR_LEN_
/**
 * Determine length of static string / macro strings at compile time.
 */
#define MHD_STATICSTR_LEN_(macro) (sizeof(macro) / sizeof(char) - 1)
#endif /* ! MHD_STATICSTR_LEN_ */

/**
 * Convenience shorthand used all over the corpus table.
 */
#define CRLF "\r\n"

/**
 * Maximum number of pipelined requests a single corpus entry may contain.
 */
#define MAX_REQS 4

/**
 * Size of the textual observation buffers.
 */
#define OBS_SIZE 8192

/**
 * Size of the client receive buffer.
 */
#define RX_SIZE 16384

/**
 * Milliseconds to wait between two parts of a split request so that the
 * server really gets to process the partial input.
 */
#define SPLIT_DELAY_MS 2

/**
 * Hard upper bound (ms) for reading the complete server answer.
 */
#define READ_DEADLINE_MS 400

/**
 * Silence (ms) after the expected number of responses that is accepted as
 * "the server is done and keeps the connection alive".  Only used for the
 * unsplit reference run.
 */
#define READ_GRACE_MS 12

/**
 * Milliseconds to wait for the server side to finish tearing down the
 * connection (and thus for the observations to become stable).
 */
#define CLOSE_WAIT_MS 2000

/**
 * Split offsets 1 .. SPLIT_DENSE_LIMIT are all exercised, beyond that only
 * every SPLIT_STRIDE-th offset is used.
 */
#define SPLIT_DENSE_LIMIT 512

/**
 * Stride for sampling split offsets of long requests.
 */
#define SPLIT_STRIDE 7

/**
 * Maximum number of three-way split combinations per entry and pool size.
 */
#define DEEP_SPLIT_MAX 24

/**
 * Give up after that many reported failures.
 */
#define MAX_FAILURES 10


#if defined(HAVE___FUNC__)
#define externalErrorExit(ignore) \
        _externalErrorExit_func (NULL, __func__, __LINE__)
#define externalErrorExitDesc(errDesc) \
        _externalErrorExit_func (errDesc, __func__, __LINE__)
#elif defined(HAVE___FUNCTION__)
#define externalErrorExit(ignore) \
        _externalErrorExit_func (NULL, __FUNCTION__, __LINE__)
#define externalErrorExitDesc(errDesc) \
        _externalErrorExit_func (errDesc, __FUNCTION__, __LINE__)
#else
#define externalErrorExit(ignore) _externalErrorExit_func (NULL, NULL, __LINE__)
#define externalErrorExitDesc(errDesc) \
        _externalErrorExit_func (errDesc, NULL, __LINE__)
#endif


/* Forward declaration, needed by the error exit helpers. */
static void
print_context (FILE *out);


_MHD_NORETURN static void
_externalErrorExit_func (const char *errDesc, const char *funcName, int lineNum)
{
  if ((NULL != errDesc) && (0 != errDesc[0]))
    fprintf (stderr, "%s", errDesc);
  else
    fprintf (stderr, "System or external library call failed");
  if ((NULL != funcName) && (0 != funcName[0]))
    fprintf (stderr, " in %s", funcName);
  if (0 < lineNum)
    fprintf (stderr, " at line %d", lineNum);

  fprintf (stderr, ".\nLast errno value: %d (%s)\n", (int) errno,
           strerror (errno));
#ifdef MHD_WINSOCK_SOCKETS
  fprintf (stderr, "WSAGetLastError() value: %d\n", (int) WSAGetLastError ());
#endif /* MHD_WINSOCK_SOCKETS */
  print_context (stderr);
  fflush (stderr);
  exit (99);
}


/**
 * Pause execution for specified number of milliseconds.
 * @param ms the number of milliseconds to sleep
 */
static void
_MHD_sleep (uint32_t ms)
{
#if defined(_WIN32)
  Sleep (ms);
#elif defined(HAVE_NANOSLEEP)
  struct timespec slp = {(time_t) (ms / 1000), (long) ((ms % 1000) * 1000000)};
  struct timespec rmn;
  int num_retries = 0;
  while (0 != nanosleep (&slp, &rmn))
  {
    if (EINTR != errno)
      externalErrorExit ();
    if (num_retries++ > 8)
      break;
    slp = rmn;
  }
#elif defined(HAVE_USLEEP)
  uint64_t us = ms * 1000;
  do
  {
    uint64_t this_sleep;
    if (999999 < us)
      this_sleep = 999999;
    else
      this_sleep = us;
    /* Ignore return value as it could be void */
    usleep ((useconds_t) this_sleep);
    us -= this_sleep;
  } while (us > 0);
#else
  externalErrorExitDesc ("No sleep function available on this system");
#endif
}


/**
 * Monotonic-ish millisecond clock.
 */
static uint64_t
now_ms (void)
{
#if defined(HAVE_CLOCK_GETTIME) && defined(CLOCK_MONOTONIC)
  struct timespec ts;

  if (0 == clock_gettime (CLOCK_MONOTONIC, &ts))
    return ((uint64_t) ts.tv_sec) * 1000 + (uint64_t) (ts.tv_nsec / 1000000);
#endif /* HAVE_CLOCK_GETTIME && CLOCK_MONOTONIC */
  return ((uint64_t) time (NULL)) * 1000;
}


/* ------------------------------------------------------------------ */
/* Textual observation buffers                                        */
/* ------------------------------------------------------------------ */

/**
 * A bounded, always NUL-terminated text accumulator.  All observations
 * (expected as well as actual) are rendered into such a buffer and the
 * comparison is a plain strcmp(), which also gives readable diagnostics.
 */
struct obs_buf
{
  char d[OBS_SIZE];
  size_t len;
  int overflow;
};


static void
obs_reset (struct obs_buf *b)
{
  b->len = 0;
  b->overflow = 0;
  b->d[0] = 0;
}


static void
obs_addf (struct obs_buf *b, const char *fmt, ...)
{
  va_list ap;
  int r;
  size_t space;

  if (b->len >= sizeof(b->d) - 1)
  {
    b->overflow = 1;
    return;
  }
  space = sizeof(b->d) - b->len;
  va_start (ap, fmt);
  r = vsnprintf (b->d + b->len, space, fmt, ap);
  va_end (ap);
  if (0 > r)
  {
    b->overflow = 1;
    return;
  }
  if ((size_t) r >= space)
  {
    b->len = sizeof(b->d) - 1;
    b->overflow = 1;
    return;
  }
  b->len += (size_t) r;
}


/**
 * Append @a data with all non-printable bytes escaped as \\xNN.
 */
static void
obs_add_escaped (struct obs_buf *b, const char *data, size_t size)
{
  size_t i;

  for (i = 0; i < size; ++i)
  {
    const unsigned char c = (unsigned char) data[i];

    if ((0x20 <= c) && (0x7e >= c) && ('\\' != c))
      obs_addf (b, "%c", (char) c);
    else if ('\\' == c)
      obs_addf (b, "\\\\");
    else
      obs_addf (b, "\\x%02x", (unsigned int) c);
  }
}


/* ------------------------------------------------------------------ */
/* The corpus                                                         */
/* ------------------------------------------------------------------ */

/**
 * Expectations for a single (possibly pipelined) request inside a stream.
 */
struct exp_req
{
  const char *method;
  const char *url;
  const char *version;
  /**
   * Expected upload body, NULL for "no body at all".
   */
  const char *body;
  /**
   * Length of @a body, 0 means strlen().
   */
  size_t body_len;
  /**
   * Newline separated list of expected #MHD_HEADER_KIND elements.
   */
  const char *hdrs;
  /**
   * Newline separated list of expected #MHD_GET_ARGUMENT_KIND elements.
   */
  const char *args;
  /**
   * Newline separated list of expected #MHD_FOOTER_KIND elements.
   */
  const char *foot;
};


struct corpus_entry
{
  const char *name;
  const char *desc;
  const char *raw;
  size_t raw_len;               /**< 0 -> strlen (raw) */
  unsigned int n_req;           /**< complete requests MHD must parse */
  unsigned int n_resp;          /**< responses the client must see */
  int status;                   /**< first response status, 0 = any */
  int alive;                    /**< 1: keep-alive, 0: MHD must close */
  int deep;                     /**< also run three-way splits */
  struct exp_req reqs[MAX_REQS];
};


#define H_LOCAL "Host: localhost" CRLF
#define E_HOST "Host=localhost"

static const struct corpus_entry corpus[] = {
  /* ---- request line basics -------------------------------------- */
  { "get_11_host",
    "baseline: request line + one header, incremental line assembly",
    "GET / HTTP/1.1" CRLF H_LOCAL CRLF, 0, 1, 1, 200, 1, 1,
    { { "GET", "/", "HTTP/1.1", NULL, 0, E_HOST, "", "" } } },
  { "get_10_nohost",
    "HTTP/1.0 without Host: no header lines at all, must not keep alive",
    "GET / HTTP/1.0" CRLF CRLF, 0, 1, 1, 200, 0, 1,
    { { "GET", "/", "HTTP/1.0", NULL, 0, "", "", "" } } },
  { "head_11",
    "HEAD: reply must carry no body, parser path is the same",
    "HEAD / HTTP/1.1" CRLF H_LOCAL CRLF, 0, 1, 1, 200, 1, 0,
    { { "HEAD", "/", "HTTP/1.1", NULL, 0, E_HOST, "", "" } } },

  /* ---- query string handling ------------------------------------ */
  { "q_bare",
    "single query argument without '=' -> NULL value",
    "GET /?a HTTP/1.1" CRLF H_LOCAL CRLF, 0, 1, 1, 200, 1, 0,
    { { "GET", "/", "HTTP/1.1", NULL, 0, E_HOST, "a=<NULL>", "" } } },
  { "q_two_bare",
    "two arguments, both without '='",
    "GET /?a&b HTTP/1.1" CRLF H_LOCAL CRLF, 0, 1, 1, 200, 1, 0,
    { { "GET", "/", "HTTP/1.1", NULL, 0, E_HOST, "a=<NULL>\nb=<NULL>", "" } } },
  { "q_mixed",
    "'=' in the first argument only",
    "GET /?a=1&b HTTP/1.1" CRLF H_LOCAL CRLF, 0, 1, 1, 200, 1, 0,
    { { "GET", "/", "HTTP/1.1", NULL, 0, E_HOST, "a=1\nb=<NULL>", "" } } },
  { "q_empty_val",
    "'a=' must give an empty (not NULL) value",
    "GET /?a= HTTP/1.1" CRLF H_LOCAL CRLF, 0, 1, 1, 200, 1, 0,
    { { "GET", "/", "HTTP/1.1", NULL, 0, E_HOST, "a=", "" } } },
  { "q_trailing_amp",
    "trailing '&' must not create a second, empty argument",
    "GET /?a& HTTP/1.1" CRLF H_LOCAL CRLF, 0, 1, 1, 200, 1, 0,
    { { "GET", "/", "HTTP/1.1", NULL, 0, E_HOST, "a=<NULL>", "" } } },
  { "q_no_key",
    "'=v' must give an empty key with value 'v'",
    "GET /?=v HTTP/1.1" CRLF H_LOCAL CRLF, 0, 1, 1, 200, 1, 0,
    { { "GET", "/", "HTTP/1.1", NULL, 0, E_HOST, "=v", "" } } },
  { "q_pct",
    "percent decoding of both key and value happens in place",
    "GET /?a%20b=c%26d HTTP/1.1" CRLF H_LOCAL CRLF, 0, 1, 1, 200, 1, 0,
    { { "GET", "/", "HTTP/1.1", NULL, 0, E_HOST, "a b=c&d", "" } } },
  { "q_frag",
    "'#' is not special for a server: it stays part of the argument",
    "GET /?a#frag HTTP/1.1" CRLF H_LOCAL CRLF, 0, 1, 1, 200, 1, 0,
    { { "GET", "/", "HTTP/1.1", NULL, 0, E_HOST, "a#frag=<NULL>", "" } } },
  { "q_plus",
    "'+' is decoded to a space in query arguments",
    "GET /?a+b=c+d HTTP/1.1" CRLF H_LOCAL CRLF, 0, 1, 1, 200, 1, 0,
    { { "GET", "/", "HTTP/1.1", NULL, 0, E_HOST, "a b=c d", "" } } },
  { "q_pct_url",
    "percent decoding of the path part",
    "GET /a%2Fb%20c HTTP/1.1" CRLF H_LOCAL CRLF, 0, 1, 1, 200, 1, 0,
    { { "GET", "/a/b c", "HTTP/1.1", NULL, 0, E_HOST, "", "" } } },
  /* The next two entries have *no* header line at all, so the last parsed
     element is a query argument with a NULL value.  With a connection memory
     limit below MHD_BUF_INC_SIZE this is the precondition of the read buffer
     "shift back" underflow fixed in 29eaa56b. */
  { "q_only_10_nohdr",
    "no headers at all + trailing arg without '=': read-buffer shift back",
    "GET /x?a HTTP/1.0" CRLF CRLF, 0, 1, 1, 200, 0, 1,
    { { "GET", "/x", "HTTP/1.0", NULL, 0, "", "a=<NULL>", "" } } },
  { "q_only_10_nohdr2",
    "same, but two NULL-valued args (tail element is the second one)",
    "GET /y?a&b HTTP/1.0" CRLF CRLF, 0, 1, 1, 200, 0, 1,
    { { "GET", "/y", "HTTP/1.0", NULL, 0, "", "a=<NULL>\nb=<NULL>", "" } } },
  { "q_only_10_nohdr_val",
    "control case: no headers but a trailing arg *with* '='",
    "GET /z?a=1 HTTP/1.0" CRLF CRLF, 0, 1, 1, 200, 0, 0,
    { { "GET", "/z", "HTTP/1.0", NULL, 0, "", "a=1", "" } } },

  /* ---- Content-Length bodies ------------------------------------ */
  { "cl_exact",
    "Content-Length body, delivered incrementally to the handler",
    "POST /p HTTP/1.1" CRLF H_LOCAL "Content-Length: 5" CRLF CRLF "Hello",
    0, 1, 1, 200, 1, 1,
    { { "POST", "/p", "HTTP/1.1", "Hello", 0,
        E_HOST "\nContent-Length=5", "", "" } } },
  { "cl_zero",
    "Content-Length: 0 must not wait for body bytes",
    "POST /p HTTP/1.1" CRLF H_LOCAL "Content-Length: 0" CRLF CRLF,
    0, 1, 1, 200, 1, 0,
    { { "POST", "/p", "HTTP/1.1", "", 0,
        E_HOST "\nContent-Length=0", "", "" } } },
  { "cl_long",
    "longer Content-Length body, forces several read-buffer rounds",
    "POST /p HTTP/1.1" CRLF H_LOCAL "Content-Length: 40" CRLF CRLF
    "0123456789abcdefghijklmnopqrstuvwxyz+-*/",
    0, 1, 1, 200, 1, 0,
    { { "POST", "/p", "HTTP/1.1",
        "0123456789abcdefghijklmnopqrstuvwxyz+-*/", 0,
        E_HOST "\nContent-Length=40", "", "" } } },

  /* ---- chunked bodies ------------------------------------------- */
  { "chunk_plain",
    "plain chunked body without extensions",
    "POST /c HTTP/1.1" CRLF H_LOCAL "Transfer-Encoding: chunked" CRLF CRLF
    "5" CRLF "Hello" CRLF "0" CRLF CRLF,
    0, 1, 1, 200, 1, 1,
    { { "POST", "/c", "HTTP/1.1", "Hello", 0,
        E_HOST "\nTransfer-Encoding=chunked", "", "" } } },
  /* The chunk-extension entries pin down that the CRLF that terminates the
     chunk size line is consumed *together with* the extension.  Failing to do
     so (bug fixed in c13f4c64) shifts the whole chunk body by two bytes and
     desynchronises the stream -> request smuggling. */
  { "chunk_ext_val",
    "chunk extension 'ext=val': CRLF after the extension must be consumed",
    "POST /c HTTP/1.1" CRLF H_LOCAL "Transfer-Encoding: chunked" CRLF CRLF
    "5;ext=val" CRLF "Hello" CRLF "0" CRLF CRLF,
    0, 1, 1, 200, 1, 1,
    { { "POST", "/c", "HTTP/1.1", "Hello", 0,
        E_HOST "\nTransfer-Encoding=chunked", "", "" } } },
  { "chunk_ext_noval",
    "chunk extension without a value",
    "POST /c HTTP/1.1" CRLF H_LOCAL "Transfer-Encoding: chunked" CRLF CRLF
    "5;ext" CRLF "Hello" CRLF "0" CRLF CRLF,
    0, 1, 1, 200, 1, 1,
    { { "POST", "/c", "HTTP/1.1", "Hello", 0,
        E_HOST "\nTransfer-Encoding=chunked", "", "" } } },
  { "chunk_ext_quoted",
    "quoted chunk extension value containing ';'",
    "POST /c HTTP/1.1" CRLF H_LOCAL "Transfer-Encoding: chunked" CRLF CRLF
    "5;ext=\"quoted;value\"" CRLF "Hello" CRLF "0" CRLF CRLF,
    0, 1, 1, 200, 1, 1,
    { { "POST", "/c", "HTTP/1.1", "Hello", 0,
        E_HOST "\nTransfer-Encoding=chunked", "", "" } } },
  { "chunk_ext_bws",
    "'bad whitespace' between chunk size and ';' (lenient mode)",
    "POST /c HTTP/1.1" CRLF H_LOCAL "Transfer-Encoding: chunked" CRLF CRLF
    "5 ;ext=val" CRLF "Hello" CRLF "0" CRLF CRLF,
    0, 1, 1, 200, 1, 1,
    { { "POST", "/c", "HTTP/1.1", "Hello", 0,
        E_HOST "\nTransfer-Encoding=chunked", "", "" } } },
  { "chunk_ext_last",
    "chunk extension on the terminating chunk",
    "POST /c HTTP/1.1" CRLF H_LOCAL "Transfer-Encoding: chunked" CRLF CRLF
    "5;a=b" CRLF "Hello" CRLF "0;z=y" CRLF CRLF,
    0, 1, 1, 200, 1, 1,
    { { "POST", "/c", "HTTP/1.1", "Hello", 0,
        E_HOST "\nTransfer-Encoding=chunked", "", "" } } },
  { "chunk_multi",
    "several chunks are concatenated into one upload body",
    "POST /c HTTP/1.1" CRLF H_LOCAL "Transfer-Encoding: chunked" CRLF CRLF
    "3" CRLF "abc" CRLF "2" CRLF "de" CRLF "1" CRLF "f" CRLF "0" CRLF CRLF,
    0, 1, 1, 200, 1, 1,
    { { "POST", "/c", "HTTP/1.1", "abcdef", 0,
        E_HOST "\nTransfer-Encoding=chunked", "", "" } } },
  { "chunk_lead_zeros",
    "chunk size with leading zeros",
    "POST /c HTTP/1.1" CRLF H_LOCAL "Transfer-Encoding: chunked" CRLF CRLF
    "0005" CRLF "Hello" CRLF "000" CRLF CRLF,
    0, 1, 1, 200, 1, 0,
    { { "POST", "/c", "HTTP/1.1", "Hello", 0,
        E_HOST "\nTransfer-Encoding=chunked", "", "" } } },
  { "chunk_trailers",
    "trailer (footer) fields after the terminating chunk",
    "POST /c HTTP/1.1" CRLF H_LOCAL "Transfer-Encoding: chunked" CRLF CRLF
    "5" CRLF "Hello" CRLF "0" CRLF "X-Trailer: v" CRLF "X-T2: w" CRLF CRLF,
    0, 1, 1, 200, 1, 1,
    { { "POST", "/c", "HTTP/1.1", "Hello", 0,
        E_HOST "\nTransfer-Encoding=chunked", "", "X-Trailer=v\nX-T2=w" } } },
  { "chunk_fold_trailer",
    "obs-fold continuation inside a trailer field",
    "POST /c HTTP/1.1" CRLF H_LOCAL "Transfer-Encoding: chunked" CRLF CRLF
    "5" CRLF "Hello" CRLF "0" CRLF "X-T: a" CRLF " b" CRLF CRLF,
    0, 1, 1, 200, 1, 1,
    { { "POST", "/c", "HTTP/1.1", "Hello", 0,
        E_HOST "\nTransfer-Encoding=chunked", "", "X-T=a   b" } } },
  { "chunk_ext_trailers",
    "chunk extension *and* trailers in the same message",
    "POST /c HTTP/1.1" CRLF H_LOCAL "Transfer-Encoding: chunked" CRLF CRLF
    "5;ext=val" CRLF "Hello" CRLF "0" CRLF "X-Trailer: v" CRLF CRLF,
    0, 1, 1, 200, 1, 1,
    { { "POST", "/c", "HTTP/1.1", "Hello", 0,
        E_HOST "\nTransfer-Encoding=chunked", "", "X-Trailer=v" } } },
  { "chunk_empty",
    "only the terminating chunk: empty upload body",
    "POST /c HTTP/1.1" CRLF H_LOCAL "Transfer-Encoding: chunked" CRLF CRLF
    "0" CRLF CRLF,
    0, 1, 1, 200, 1, 0,
    { { "POST", "/c", "HTTP/1.1", "", 0,
        E_HOST "\nTransfer-Encoding=chunked", "", "" } } },

  /* MHD keeps room for a chunk "header" of MHD_CHUNK_HEADER_REASONABLE_LEN
     (24) bytes in the read buffer; a longer chunk extension forces the
     buffer-grow path in the middle of the chunk size line. */
  { "chunk_ext_long",
    "chunk extension longer than the reserved chunk header space",
    "POST /c HTTP/1.1" CRLF H_LOCAL "Transfer-Encoding: chunked" CRLF CRLF
    "5;ext=aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa" CRLF "Hello" CRLF
    "0" CRLF CRLF,
    0, 1, 1, 200, 1, 1,
    { { "POST", "/c", "HTTP/1.1", "Hello", 0,
        E_HOST "\nTransfer-Encoding=chunked", "", "" } } },
  { "chunk_multi_ext",
    "a chunk extension on every single chunk",
    "POST /c HTTP/1.1" CRLF H_LOCAL "Transfer-Encoding: chunked" CRLF CRLF
    "3;a=1" CRLF "abc" CRLF "2;b=2" CRLF "de" CRLF "1;c" CRLF "f" CRLF
    "0;d=4" CRLF CRLF,
    0, 1, 1, 200, 1, 1,
    { { "POST", "/c", "HTTP/1.1", "abcdef", 0,
        E_HOST "\nTransfer-Encoding=chunked", "", "" } } },

  /* ---- pipelining / desynchronisation --------------------------- */
  { "pipe2",
    "two pipelined requests must yield exactly two parsed requests",
    "GET /1 HTTP/1.1" CRLF H_LOCAL CRLF
    "GET /2 HTTP/1.1" CRLF H_LOCAL CRLF,
    0, 2, 2, 200, 1, 1,
    { { "GET", "/1", "HTTP/1.1", NULL, 0, E_HOST, "", "" },
      { "GET", "/2", "HTTP/1.1", NULL, 0, E_HOST, "", "" } } },
  { "pipe3",
    "three pipelined requests, never two and never four",
    "GET /1 HTTP/1.1" CRLF H_LOCAL CRLF
    "GET /2?x=1 HTTP/1.1" CRLF H_LOCAL CRLF
    "GET /3 HTTP/1.1" CRLF H_LOCAL CRLF,
    0, 3, 3, 200, 1, 0,
    { { "GET", "/1", "HTTP/1.1", NULL, 0, E_HOST, "", "" },
      { "GET", "/2", "HTTP/1.1", NULL, 0, E_HOST, "x=1", "" },
      { "GET", "/3", "HTTP/1.1", NULL, 0, E_HOST, "", "" } } },
  { "pipe_chunk_get",
    "chunked POST followed by a GET: the smuggling detector",
    "POST /c HTTP/1.1" CRLF H_LOCAL "Transfer-Encoding: chunked" CRLF CRLF
    "5" CRLF "Hello" CRLF "0" CRLF CRLF
    "GET /after HTTP/1.1" CRLF H_LOCAL CRLF,
    0, 2, 2, 200, 1, 1,
    { { "POST", "/c", "HTTP/1.1", "Hello", 0,
        E_HOST "\nTransfer-Encoding=chunked", "", "" },
      { "GET", "/after", "HTTP/1.1", NULL, 0, E_HOST, "", "" } } },
  { "pipe_chunkext_get",
    "chunk *extension* + pipelined GET: smuggling detector for c13f4c64",
    "POST /c HTTP/1.1" CRLF H_LOCAL "Transfer-Encoding: chunked" CRLF CRLF
    "5;ext=val" CRLF "Hello" CRLF "0" CRLF CRLF
    "GET /after HTTP/1.1" CRLF H_LOCAL CRLF,
    0, 2, 2, 200, 1, 1,
    { { "POST", "/c", "HTTP/1.1", "Hello", 0,
        E_HOST "\nTransfer-Encoding=chunked", "", "" },
      { "GET", "/after", "HTTP/1.1", NULL, 0, E_HOST, "", "" } } },
  { "pipe_cl_get",
    "Content-Length POST followed by a GET",
    "POST /p HTTP/1.1" CRLF H_LOCAL "Content-Length: 5" CRLF CRLF "Hello"
    "GET /after HTTP/1.1" CRLF H_LOCAL CRLF,
    0, 2, 2, 200, 1, 0,
    { { "POST", "/p", "HTTP/1.1", "Hello", 0,
        E_HOST "\nContent-Length=5", "", "" },
      { "GET", "/after", "HTTP/1.1", NULL, 0, E_HOST, "", "" } } },

  /* ---- header line edge cases ----------------------------------- */
  { "hdr_obs_fold",
    "obs-fold continuation: CR, LF and the fold space each become one space",
    "GET / HTTP/1.1" CRLF H_LOCAL "X-Fold: one" CRLF " two" CRLF CRLF,
    0, 1, 1, 200, 1, 1,
    { { "GET", "/", "HTTP/1.1", NULL, 0,
        E_HOST "\nX-Fold=one   two", "", "" } } },
  /* Note: the CR and the LF of the folded line are each replaced by a space
     and the leading whitespace of the continuation line is kept verbatim, so
     a TAB survives as a TAB. */
  { "hdr_fold_multi",
    "two consecutive obs-fold continuation lines, second one folded with TAB",
    "GET / HTTP/1.1" CRLF H_LOCAL "X-F: one" CRLF " two" CRLF "\ttree" CRLF
    CRLF,
    0, 1, 1, 200, 1, 1,
    { { "GET", "/", "HTTP/1.1", NULL, 0,
        E_HOST "\nX-F=one   two  \\x09tree", "", "" } } },
  { "hdr_empty_val",
    "header with an empty value",
    "GET / HTTP/1.1" CRLF H_LOCAL "X-Empty:" CRLF CRLF,
    0, 1, 1, 200, 1, 0,
    { { "GET", "/", "HTTP/1.1", NULL, 0, E_HOST "\nX-Empty=", "", "" } } },
  { "hdr_dup",
    "duplicated header names are reported twice, in order",
    "GET / HTTP/1.1" CRLF H_LOCAL "X-Dup: 1" CRLF "X-Dup: 2" CRLF CRLF,
    0, 1, 1, 200, 1, 0,
    { { "GET", "/", "HTTP/1.1", NULL, 0,
        E_HOST "\nX-Dup=1\nX-Dup=2", "", "" } } },
  { "hdr_bare_lf",
    "bare LF line terminators (lenient mode) must parse identically",
    "GET / HTTP/1.1\n" H_LOCAL "X-B: v\n\n",
    0, 1, 1, 200, 1, 1,
    { { "GET", "/", "HTTP/1.1", NULL, 0, E_HOST "\nX-B=v", "", "" } } },
  { "hdr_bare_cr",
    "a bare CR inside a header value is rejected with 400 at the default "
    "client discipline level",
    "GET / HTTP/1.1" CRLF H_LOCAL "X-Cr: a\rb" CRLF CRLF,
    0, 0, 1, 400, 0, 1,
    { { NULL, NULL, NULL, NULL, 0, NULL, NULL, NULL } } },
  { "hdr_trail_ws",
    "trailing whitespace in a header value must be stripped",
    "GET / HTTP/1.1" CRLF H_LOCAL "X-Ws: val   " CRLF CRLF,
    0, 1, 1, 200, 1, 0,
    { { "GET", "/", "HTTP/1.1", NULL, 0, E_HOST "\nX-Ws=val", "", "" } } },
  { "hdr_lead_ws",
    "several spaces after the colon are not part of the value",
    "GET / HTTP/1.1" CRLF H_LOCAL "X-Lw:    val" CRLF CRLF,
    0, 1, 1, 200, 1, 0,
    { { "GET", "/", "HTTP/1.1", NULL, 0, E_HOST "\nX-Lw=val", "", "" } } },
  { "hdr_many",
    "many small headers: exercises pool allocation and buffer growth",
    "GET / HTTP/1.1" CRLF H_LOCAL
    "A: 1" CRLF "B: 2" CRLF "C: 3" CRLF "D: 4" CRLF "E: 5" CRLF
    "F: 6" CRLF "G: 7" CRLF "H: 8" CRLF CRLF,
    0, 1, 1, 200, 1, 0,
    { { "GET", "/", "HTTP/1.1", NULL, 0,
        E_HOST "\nA=1\nB=2\nC=3\nD=4\nE=5\nF=6\nG=7\nH=8", "", "" } } },
  /* Bare LF is accepted as a line terminator in the request header but NOT
     inside the chunked framing (process_request_body() requires discipline
     level < -2 for that), so this must be a clean 400 - and it must be a 400
     no matter where the stream is cut. */
  { "hdr_bare_lf_chunk",
    "bare LF inside the chunked framing is rejected with 400",
    "POST /c HTTP/1.1\n" H_LOCAL "Transfer-Encoding: chunked\n\n"
    "5;ext=val\nHello\n0\n\n",
    0, 0, 1, 400, 0, 1,
    { { NULL, NULL, NULL, NULL, 0, NULL, NULL, NULL } } }
};

#define CORPUS_SIZE (sizeof(corpus) / sizeof(corpus[0]))

/**
 * Sweep of #MHD_OPTION_CONNECTION_MEMORY_LIMIT values; 0 means "use the MHD
 * default".  Everything below #MHD_BUF_INC_SIZE (1500) unlocks read-buffer
 * code paths that are otherwise never taken.
 */
static const size_t mem_limits[] = { 256, 512, 1024, 1499, 4096, 0 };

#define MEM_LIMITS_SIZE (sizeof(mem_limits) / sizeof(mem_limits[0]))

/**
 * The range of client discipline levels in which the declared expectation of
 * a corpus entry holds.
 *
 * Every entry that is not listed here is level independent.  The bounds
 * follow the predicates of connection.c directly:
 *
 * * a bare LF is a line terminator only while `MHD_ALLOW_BARE_LF_AS_CRLF_`
 *   (0 >= level) holds, and an obs-fold continuation only while
 *   `allow_folded` (0 >= level) holds, so both are meaningless above 0;
 * * `allow_bws` is (2 > level), so the "bad whitespace" chunk-size line is
 *   meaningless above 1;
 * * a bare CR is turned into a space by `bare_cr_as_sp` (-1 >= level) and
 *   kept by `bare_cr_keep` (-3 >= level), so the entry that expects a 400
 *   only holds from level 0 upwards;
 * * inside the chunked framing `bare_lf_as_crlf` is (-2 > level), so the
 *   entry that expects a 400 for a bare LF there only holds from -2 upwards.
 */
struct entry_discp_limit
{
  const char *name;
  int min_discp;
  int max_discp;
};

static const struct entry_discp_limit discp_limits[] = {
  { "hdr_bare_lf",        -3, 0 },
  { "hdr_obs_fold",       -3, 0 },
  { "hdr_fold_multi",     -3, 0 },
  { "chunk_fold_trailer", -3, 0 },
  { "chunk_ext_bws",      -3, 1 },
  { "hdr_bare_cr",         0, 3 },
  { "hdr_bare_lf_chunk",  -2, 3 }
};

#define DISCP_LIMITS_SIZE \
        (sizeof(discp_limits) / sizeof(discp_limits[0]))

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
 * The client discipline level really in effect, see
 * mhd_opt_matrix_effective_discipline().
 */
static int test_discp;


/**
 * Check whether the declared expectation of @a name holds at the client
 * discipline level currently in effect.
 *
 * @param name the name of the corpus entry
 * @return non-zero if the entry may be run
 */
static int
entry_in_discp_range (const char *name)
{
  size_t i;

  for (i = 0; i < DISCP_LIMITS_SIZE; ++i)
  {
    if (0 == strcmp (name, discp_limits[i].name))
      return ((test_discp >= discp_limits[i].min_discp) &&
              (test_discp <= discp_limits[i].max_discp)) ? 1 : 0;
  }
  return 1;
}


/* ------------------------------------------------------------------ */
/* Global state                                                       */
/* ------------------------------------------------------------------ */

static int verbose;

/** Current corpus entry under test (the test is strictly serialised). */
static const struct corpus_entry *cur_entry;
/** Human readable description of the current split. */
static char cur_split[128];
/** Current connection memory limit. */
static size_t cur_mem_limit;
/** Non-zero while the (slow) three-way split pass is enabled. */
static int deep_enabled;

static uint16_t global_port;

/** Server side observations of the connection currently under test. */
static struct obs_buf srv_obs;
/** Number of completed requests seen by the request handler. */
static volatile unsigned int srv_n_req;
/** Set if the handler noticed something structurally impossible. */
static volatile unsigned int srv_error;

static volatile unsigned int conn_started;
static volatile unsigned int conn_closed;

/** Total number of (entry x split x memory limit) combinations executed. */
static unsigned long combos;
/** Number of combinations that could not fit into the memory pool. */
static unsigned long combos_pool_limited;
/** Number of failures found. */
static unsigned long failures;


static void
print_context (FILE *out)
{
  fprintf (out, "  context: entry='%s' split=%s mem_limit=",
           (NULL != cur_entry) ? cur_entry->name : "(none)",
           cur_split);
  if (0 == cur_mem_limit)
    fprintf (out, "default\n");
  else
    fprintf (out, "%u\n", (unsigned int) cur_mem_limit);
  if (NULL != cur_entry)
    fprintf (out, "  entry purpose: %s\n", cur_entry->desc);
}


#if defined(HAVE_SIGNAL_H) && defined(SIGABRT)
/**
 * Report the corpus entry and split offset when the library aborts (e.g.
 * from an internal assertion), instead of dying anonymously.
 */
static void
abort_handler (int sig)
{
  (void) sig;
  fprintf (stderr,
           "\nFATAL: the library aborted while running a corpus entry.\n");
  print_context (stderr);
  fflush (stderr);
  _exit (1);
}


#endif /* HAVE_SIGNAL_H && SIGABRT */


/**
 * Panic callback: a library panic must be reported as a test failure that
 * names the corpus entry and split offset.
 */
static void
test_panic (void *cls, const char *file, unsigned int line, const char *reason)
{
  (void) cls;
  fprintf (stderr,
           "\nFATAL: MHD panic at %s:%u: %s\n",
           (NULL != file) ? file : "(unknown)",
           line,
           (NULL != reason) ? reason : "(no reason given)");
  print_context (stderr);
  fflush (stderr);
  _exit (1);
}


/* ------------------------------------------------------------------ */
/* Request handler: records the observations                          */
/* ------------------------------------------------------------------ */

struct req_state
{
  int marker;
  unsigned int idx;
  struct obs_buf body;
};


struct iter_ctx
{
  struct obs_buf *out;
  unsigned int num;
};


static enum MHD_Result
value_iterator (void *cls,
                enum MHD_ValueKind kind,
                const char *key,
                size_t key_size,
                const char *value,
                size_t value_size)
{
  struct iter_ctx *const ctx = (struct iter_ctx *) cls;

  (void) kind;
  if (0 != ctx->num)
    obs_addf (ctx->out, "\n");
  ctx->num++;
  if (NULL != key)
    obs_add_escaped (ctx->out, key, key_size);
  else
    obs_addf (ctx->out, "<NULLKEY>");
  obs_addf (ctx->out, "=");
  if (NULL == value)
    obs_addf (ctx->out, "<NULL>");
  else
    obs_add_escaped (ctx->out, value, value_size);
  return MHD_YES;
}


static void
dump_values (struct MHD_Connection *c,
             enum MHD_ValueKind kind,
             const char *label,
             struct obs_buf *out)
{
  struct iter_ctx ctx;

  ctx.out = out;
  ctx.num = 0;
  obs_addf (out, "  %s=[", label);
  MHD_get_connection_values_n (c, kind, &value_iterator, &ctx);
  obs_addf (out, "]\n");
}


static enum MHD_Result
ahc_record (void *cls,
            struct MHD_Connection *connection,
            const char *url,
            const char *method,
            const char *version,
            const char *upload_data,
            size_t *upload_data_size,
            void **req_cls)
{
  /* The reply body is intentionally empty: that makes the reply of a HEAD
     request byte-identical to the reply of a GET request and keeps the
     client side response framing trivial. */
  static const char rp_data[] = "";
  struct req_state *rs;
  struct MHD_Response *response;
  enum MHD_Result ret;

  (void) cls;
  if (NULL == *req_cls)
  {
    rs = (struct req_state *) malloc (sizeof (struct req_state));
    if (NULL == rs)
      externalErrorExitDesc ("malloc() failed");
    rs->marker = 1;
    rs->idx = srv_n_req;
    obs_reset (&rs->body);
    *req_cls = rs;
    return MHD_YES;
  }
  rs = (struct req_state *) *req_cls;
  if (0 != *upload_data_size)
  {
    obs_add_escaped (&rs->body, upload_data, *upload_data_size);
    *upload_data_size = 0;
    return MHD_YES;
  }

  /* The request is complete: record everything we can observe. */
  obs_addf (&srv_obs, "REQ %u\n", rs->idx);
  obs_addf (&srv_obs, "  method=%s\n", (NULL != method) ? method : "(null)");
  obs_addf (&srv_obs, "  url=");
  if (NULL != url)
    obs_add_escaped (&srv_obs, url, strlen (url));
  else
    obs_addf (&srv_obs, "(null)");
  obs_addf (&srv_obs, "\n");
  obs_addf (&srv_obs, "  version=%s\n",
            (NULL != version) ? version : "(null)");
  obs_addf (&srv_obs, "  body=[%s]\n", rs->body.d);
  dump_values (connection, MHD_HEADER_KIND, "hdr", &srv_obs);
  dump_values (connection, MHD_GET_ARGUMENT_KIND, "arg", &srv_obs);
  dump_values (connection, MHD_FOOTER_KIND, "foot", &srv_obs);

  free (rs);
  *req_cls = NULL;
  srv_n_req++;

  response =
    MHD_create_response_from_buffer (MHD_STATICSTR_LEN_ (rp_data),
                                     (void *) rp_data,
                                     MHD_RESPMEM_PERSISTENT);
  if (NULL == response)
  {
    srv_error++;
    return MHD_NO;
  }
  ret = MHD_queue_response (connection, MHD_HTTP_OK, response);
  MHD_destroy_response (response);
  if (MHD_YES != ret)
    srv_error++;
  return ret;
}


/**
 * MHD is started with #MHD_USE_ERROR_LOG so that library complaints are
 * available, but they are only printed with '-v -v' to keep the (very
 * repetitive) output of the sweep readable.
 */
static void
test_log (void *cls, const char *fmt, va_list ap)
{
  (void) cls;
  if (1 < verbose)
  {
    vfprintf (stderr, fmt, ap);
    fflush (stderr);
  }
}


static void
conn_notify (void *cls,
             struct MHD_Connection *c,
             void **socket_context,
             enum MHD_ConnectionNotificationCode toe)
{
  (void) cls; (void) c; (void) socket_context;
  if (MHD_CONNECTION_NOTIFY_STARTED == toe)
    conn_started++;
  else if (MHD_CONNECTION_NOTIFY_CLOSED == toe)
    conn_closed++;
}


static void
req_completed (void *cls,
               struct MHD_Connection *c,
               void **req_cls,
               enum MHD_RequestTerminationCode term_code)
{
  (void) cls; (void) c; (void) term_code;
  if ((NULL != req_cls) && (NULL != *req_cls))
  {
    free (*req_cls);
    *req_cls = NULL;
  }
}


/* ------------------------------------------------------------------ */
/* Raw client                                                         */
/* ------------------------------------------------------------------ */

struct client_result
{
  unsigned int n_resp;
  int first_status;
  int peer_closed;
  int timed_out;
  size_t rx_len;
  char rx[RX_SIZE];
};


/**
 * Case-insensitive comparison of @a size bytes (ASCII only).
 */
static int
mem_equal_ci (const char *a, const char *b, size_t size)
{
  size_t i;

  for (i = 0; i < size; ++i)
  {
    char ca = a[i];
    char cb = b[i];

    if (('A' <= ca) && ('Z' >= ca))
      ca = (char) (ca - 'A' + 'a');
    if (('A' <= cb) && ('Z' >= cb))
      cb = (char) (cb - 'A' + 'a');
    if (ca != cb)
      return 0;
  }
  return 1;
}


/**
 * Count the number of complete HTTP responses in @a buf.
 *
 * @param buf the received bytes
 * @param len the number of bytes in @a buf
 * @param[out] first_status set to the status code of the first response
 * @return the number of *complete* responses found
 */
static unsigned int
count_responses (const char *buf, size_t len, int *first_status)
{
  size_t pos = 0;
  unsigned int num = 0;

  *first_status = 0;
  while (pos < len)
  {
    const char *hdr_end;
    const char *cl;
    size_t hdr_len;
    size_t body_len = 0;
    int status;
    size_t i;

    if (7 > len - pos)
      break;
    if (0 != memcmp (buf + pos, "HTTP/1.", 7))
      break; /* Not a well-formed response */
    hdr_end = NULL;
    for (i = pos; i + 3 < len; ++i)
    {
      if (('\r' == buf[i]) && ('\n' == buf[i + 1]) &&
          ('\r' == buf[i + 2]) && ('\n' == buf[i + 3]))
      {
        hdr_end = buf + i + 4;
        break;
      }
    }
    if (NULL == hdr_end)
      break; /* Incomplete header */
    hdr_len = (size_t) (hdr_end - (buf + pos));
    status = 0;
    if ((pos + 12 <= len) &&
        ('0' <= buf[pos + 9]) && ('9' >= buf[pos + 9]))
      status = (buf[pos + 9] - '0') * 100
               + (buf[pos + 10] - '0') * 10
               + (buf[pos + 11] - '0');
    if (0 == num)
      *first_status = status;
    /* Find "Content-Length:" inside this response header. */
    cl = NULL;
    for (i = pos; i + 15 <= pos + hdr_len; ++i)
    {
      if (mem_equal_ci (buf + i, "content-length:", 15))
      {
        cl = buf + i + 15;
        break;
      }
    }
    if (NULL != cl)
    {
      while ((cl < buf + pos + hdr_len) && (' ' == *cl))
        cl++;
      body_len = 0;
      while ((cl < buf + pos + hdr_len) && ('0' <= *cl) && ('9' >= *cl))
      {
        body_len = body_len * 10 + (size_t) (*cl - '0');
        cl++;
      }
    }
    if (pos + hdr_len + body_len > len)
      break; /* Body incomplete */
    pos += hdr_len + body_len;
    num++;
  }
  return num;
}


static MHD_socket
client_connect (void)
{
  MHD_socket sk;
  struct sockaddr_in sa;
  const MHD_SCKT_OPT_BOOL_ on_val = 1;

  sk = socket (AF_INET, SOCK_STREAM, IPPROTO_TCP);
  if (MHD_INVALID_SOCKET == sk)
    externalErrorExitDesc ("Cannot create the client socket");
#ifdef MHD_socket_nosignal_
  if (! MHD_socket_nosignal_ (sk))
    externalErrorExitDesc ("Cannot suppress SIGPIPE on the client socket");
#endif /* MHD_socket_nosignal_ */
  if (0 != setsockopt (sk, IPPROTO_TCP, TCP_NODELAY,
                       (const void *) &on_val, sizeof (on_val)))
    externalErrorExitDesc ("Cannot set TCP_NODELAY option");

  memset (&sa, 0, sizeof (sa));
  sa.sin_family = AF_INET;
  sa.sin_port = htons (global_port);
  sa.sin_addr.s_addr = htonl (INADDR_LOOPBACK);
  if (0 != connect (sk, (struct sockaddr *) &sa, sizeof (sa)))
    externalErrorExitDesc ("Cannot connect() to the daemon");
  return sk;
}


static int
client_send_all (MHD_socket sk, const char *data, size_t size)
{
  size_t off = 0;

  while (off < size)
  {
    ssize_t s = MHD_send_ (sk, data + off, size - off);

    if (0 > s)
    {
      const int err = MHD_socket_get_error_ ();

      if (MHD_SCKT_ERR_IS_EINTR_ (err) || MHD_SCKT_ERR_IS_EAGAIN_ (err))
        continue;
      return 0; /* Server closed the connection early, that is an observation */
    }
    off += (size_t) s;
  }
  return 1;
}


/**
 * Wait for a socket to become readable.
 *
 * @return 1 readable, 0 timeout, -1 error
 */
static int
wait_readable (MHD_socket sk, unsigned int timeout_ms)
{
  fd_set rs;
  struct timeval tv;
  int r;

  FD_ZERO (&rs);
  FD_SET (sk, &rs);
  tv.tv_sec = (time_t) (timeout_ms / 1000);
  tv.tv_usec = (long) ((timeout_ms % 1000) * 1000);
  r = select ((int) sk + 1, &rs, NULL, NULL, &tv);
  if (0 > r)
  {
    if (EINTR == errno)
      return 0;
    return -1;
  }
  return (0 == r) ? 0 : 1;
}


/**
 * Read the server answer.
 *
 * @param sk the socket to read from
 * @param[out] r the result
 * @param min_resp stop once that many complete responses have been read
 * @param want_close keep reading until the peer closes the connection
 * @param grace_ms extra silence to wait for after @a min_resp responses
 */
static void
client_read (MHD_socket sk,
             struct client_result *r,
             unsigned int min_resp,
             int want_close,
             unsigned int grace_ms)
{
  const uint64_t start = now_ms ();

  memset (r, 0, sizeof (*r));
  while (1)
  {
    const uint64_t el = now_ms () - start;
    unsigned int tmo;
    int wr;
    ssize_t got;

    if (el >= READ_DEADLINE_MS)
    {
      r->timed_out = 1;
      break;
    }
    r->n_resp = count_responses (r->rx, r->rx_len, &r->first_status);
    if ((r->n_resp >= min_resp) && (! want_close))
      tmo = grace_ms;
    else
      tmo = (unsigned int) (READ_DEADLINE_MS - el);
    wr = wait_readable (sk, tmo);
    if (0 > wr)
    {
      r->peer_closed = 1;
      break;
    }
    if (0 == wr)
    {
      if ((r->n_resp >= min_resp) && (! want_close))
        break; /* Done, connection stays alive */
      r->timed_out = 1;
      break;
    }
    if (r->rx_len >= sizeof (r->rx))
      break; /* Way too much data, will be reported as a mismatch */
    got = MHD_recv_ (sk, r->rx + r->rx_len, sizeof (r->rx) - r->rx_len);
    if (0 > got)
    {
      const int err = MHD_socket_get_error_ ();

      if (MHD_SCKT_ERR_IS_EINTR_ (err) || MHD_SCKT_ERR_IS_EAGAIN_ (err))
        continue;
      r->peer_closed = 1; /* Connection reset counts as "closed" */
      break;
    }
    if (0 == got)
    {
      r->peer_closed = 1;
      break;
    }
    r->rx_len += (size_t) got;
  }
  r->n_resp = count_responses (r->rx, r->rx_len, &r->first_status);
}


/**
 * Wait until the daemon has finished tearing down all connections, so that
 * the server side observations are stable.
 *
 * @return 1 on success, 0 on timeout
 */
static int
wait_conns_closed (void)
{
  const uint64_t start = now_ms ();
  unsigned int spin = 0;

  while (conn_closed != conn_started)
  {
    if (1000 > spin)
      spin++;
    else
      _MHD_sleep (1);
    if (now_ms () - start > CLOSE_WAIT_MS)
      return 0;
  }
  return 1;
}


/* ------------------------------------------------------------------ */
/* One replay of one corpus entry                                     */
/* ------------------------------------------------------------------ */

/**
 * Send @a e over a fresh connection, cut into @a n_cuts + 1 pieces at the
 * offsets given in @a cuts, and render all observations into @a out.
 */
static void
run_stream (const struct corpus_entry *e,
            const size_t *cuts,
            unsigned int n_cuts,
            unsigned int min_resp,
            int want_close,
            unsigned int grace_ms,
            struct obs_buf *out)
{
  const size_t len = (0 != e->raw_len) ? e->raw_len : strlen (e->raw);
  struct client_result cr;
  MHD_socket sk;
  size_t off = 0;
  unsigned int i;
  int send_ok = 1;

  obs_reset (&srv_obs);
  srv_n_req = 0;
  srv_error = 0;

  sk = client_connect ();
  for (i = 0; i <= n_cuts; ++i)
  {
    const size_t end = (i < n_cuts) ? cuts[i] : len;

    if (end > off)
    {
      if (! client_send_all (sk, e->raw + off, end - off))
      {
        send_ok = 0;
        break;
      }
      off = end;
    }
    if (i < n_cuts)
      _MHD_sleep (SPLIT_DELAY_MS);
  }
  client_read (sk, &cr, min_resp, want_close, grace_ms);
  (void) MHD_socket_close_ (sk);
  if (! wait_conns_closed ())
  {
    fprintf (stderr, "WARNING: timeout waiting for connection teardown.\n");
    print_context (stderr);
  }

  obs_reset (out);
  obs_addf (out, "%s", srv_obs.d);
  obs_addf (out, "nreq=%u\n", srv_n_req);
  obs_addf (out, "nresp=%u status=%d closed=%d\n",
            cr.n_resp, cr.first_status, cr.peer_closed);
  if (cr.timed_out)
    obs_addf (out, "TIMED_OUT\n");
  /* Note: whether the *client* managed to push out the rest of the request
     before MHD closed the connection is inherently racy, so it must not be
     part of the compared observation; 'closed=' already carries the relevant
     information.  It is only reported in verbose mode. */
  if ((! send_ok) && (1 < verbose))
  {
    printf ("    (send aborted by the server for entry '%s' split %s)\n",
            e->name, cur_split);
    fflush (stdout);
  }
  if (0 != srv_error)
    obs_addf (out, "SERVER_ERROR=%u\n", srv_error);
  if (srv_obs.overflow || out->overflow)
    obs_addf (out, "OBS_OVERFLOW\n");
}


/**
 * Render the declared expectations of @a e into the very same format that
 * run_stream() produces, so that a single strcmp() does the whole check.
 */
static void
build_expected (const struct corpus_entry *e, struct obs_buf *out)
{
  unsigned int i;

  obs_reset (out);
  for (i = 0; i < e->n_req; ++i)
  {
    const struct exp_req *const r = &e->reqs[i];
    size_t bl;

    obs_addf (out, "REQ %u\n", i);
    obs_addf (out, "  method=%s\n", r->method);
    obs_addf (out, "  url=");
    obs_add_escaped (out, r->url, strlen (r->url));
    obs_addf (out, "\n");
    obs_addf (out, "  version=%s\n", r->version);
    obs_addf (out, "  body=[");
    if (NULL != r->body)
    {
      bl = (0 != r->body_len) ? r->body_len : strlen (r->body);
      obs_add_escaped (out, r->body, bl);
    }
    obs_addf (out, "]\n");
    obs_addf (out, "  hdr=[%s]\n", r->hdrs);
    obs_addf (out, "  arg=[%s]\n", r->args);
    obs_addf (out, "  foot=[%s]\n", r->foot);
  }
  obs_addf (out, "nreq=%u\n", e->n_req);
  obs_addf (out, "nresp=%u status=%d closed=%d\n",
            e->n_resp, e->status, e->alive ? 0 : 1);
}


static void
hexdump (FILE *out, const char *data, size_t size)
{
  size_t i;

  for (i = 0; i < size; i += 16)
  {
    size_t j;

    fprintf (out, "    %04x  ", (unsigned int) i);
    for (j = 0; j < 16; ++j)
    {
      if (i + j < size)
        fprintf (out, "%02x ", (unsigned char) data[i + j]);
      else
        fprintf (out, "   ");
    }
    fprintf (out, " |");
    for (j = 0; (j < 16) && (i + j < size); ++j)
    {
      const unsigned char c = (unsigned char) data[i + j];

      fprintf (out, "%c", ((0x20 <= c) && (0x7e >= c)) ? (char) c : '.');
    }
    fprintf (out, "|\n");
  }
}


static void
report_failure (const struct corpus_entry *e,
                const char *what,
                const char *expected,
                const char *actual)
{
  const size_t len = (0 != e->raw_len) ? e->raw_len : strlen (e->raw);

  failures++;
  fprintf (stderr, "\n==== FAILURE: %s ====\n", what);
  fprintf (stderr, "  entry:      %s (%s)\n", e->name, e->desc);
  fprintf (stderr, "  split:      %s\n", cur_split);
  fprintf (stderr, "  mem_limit:  ");
  if (0 == cur_mem_limit)
    fprintf (stderr, "default\n");
  else
    fprintf (stderr, "%u\n", (unsigned int) cur_mem_limit);
  fprintf (stderr, "  --- expected ---\n%s", expected);
  fprintf (stderr, "  --- observed ---\n%s", actual);
  fprintf (stderr, "  --- raw request (%u bytes) ---\n", (unsigned int) len);
  hexdump (stderr, e->raw, len);
  fflush (stderr);
}


/**
 * Length of the leading "REQ ..." section of an observation, i.e. everything
 * that describes the requests that MHD actually parsed.
 */
static size_t
obs_reqs_len (const struct obs_buf *o)
{
  const char *const p = strstr (o->d, "nreq=");

  return (NULL != p) ? (size_t) (p - o->d) : o->len;
}


/**
 * Read an unsigned decimal number that follows @a key in the observation.
 */
static unsigned int
obs_get_uint (const struct obs_buf *o, const char *key)
{
  const char *const p = strstr (o->d, key);

  if (NULL == p)
    return 0;
  return (unsigned int) strtoul (p + strlen (key), NULL, 10);
}


/**
 * Decide whether a deviation from the declared expectations is a legitimate
 * *resource* limitation of an artificially small connection memory pool
 * rather than a parser problem.
 *
 * Only these three signatures are accepted, and only when a non-default
 * #MHD_OPTION_CONNECTION_MEMORY_LIMIT is configured:
 *  - 431/413/414/500 without a single completed request (the request header
 *    does not fit into the pool),
 *  - no reply at all and MHD closed the connection (it could not even build
 *    the reply header),
 *  - fewer requests than the stream contains but a successful reply (a
 *    pipelined stream that was only served partially).
 *
 * In particular a 400 Bad Request is *never* accepted as a resource
 * limitation: a well-formed corpus entry that suddenly becomes malformed is
 * exactly the kind of parser bug this test hunts for.
 */
static int
is_resource_degradation (const struct obs_buf *o,
                         const struct corpus_entry *e)
{
  const unsigned int nreq = obs_get_uint (o, "nreq=");
  const unsigned int nresp = obs_get_uint (o, "nresp=");
  const unsigned int status = obs_get_uint (o, "status=");

  if (0 == cur_mem_limit)
    return 0;
  if (NULL != strstr (o->d, "TIMED_OUT"))
    return 0;
  if ((0 == nreq) &&
      ((431 == status) || (413 == status) ||
       (414 == status) || (500 == status)))
    return 1;
  if ((0 == nresp) && (0 == status))
    return 1;
  if ((nreq < e->n_req) && ((200 == status) || (0 == status)))
    return 1;
  return 0;
}


/**
 * Status codes that a run under memory pressure may legitimately show.
 *
 * 0 means "no reply at all" (MHD could not build the reply header), 200 is
 * the normal answer, the 4xx/5xx codes are the resource errors.  A 400 is
 * deliberately *not* in this set: a well-formed corpus entry that MHD
 * suddenly considers malformed is a parser bug, not a resource problem.
 */
static int
status_acceptable_degraded (const struct obs_buf *o,
                            const struct corpus_entry *e)
{
  const unsigned int status = obs_get_uint (o, "status=");

  if ((unsigned int) e->status == status)
    return 1;
  switch (status)
  {
  case 0:
  case 200:
  case 413:
  case 414:
  case 431:
  case 500:
    return 1;
  default:
    break;
  }
  return 0;
}


/**
 * Relaxed check used when the connection memory pool is too small for the
 * corpus entry.
 *
 * Under memory pressure MHD may legitimately stop early: it may answer
 * 431/413, it may fail to build a reply header, or it may serve only the
 * first of several pipelined requests.  What may *never* happen is that a
 * request which MHD does parse is parsed differently, or that MHD conjures up
 * more requests than the byte stream contains (that would be smuggling).
 *
 * So the requests that were parsed must form an exact prefix of the declared
 * expectations.
 *
 * @return 1 if acceptable, 0 on a real mismatch
 */
static int
check_relaxed (const struct obs_buf *exp, const struct obs_buf *got)
{
  const size_t gl = obs_reqs_len (got);
  const size_t el = obs_reqs_len (exp);

  if (gl > el)
    return 0; /* More requests parsed than the stream contains */
  return 0 == memcmp (exp->d, got->d, gl);
}


/**
 * Build the list of split offsets that will be exercised for a request of
 * @a len bytes.
 *
 * @return the number of offsets stored in @a offs
 */
static unsigned int
build_split_offsets (size_t len, size_t *offs, unsigned int max_offs)
{
  unsigned int n = 0;
  size_t s;

  for (s = 1; (s < len) && (n < max_offs); ++s)
  {
    if ((s <= SPLIT_DENSE_LIMIT) || (0 == (s % SPLIT_STRIDE)))
      offs[n++] = s;
  }
  return n;
}


/* ------------------------------------------------------------------ */
/* Main test driver                                                   */
/* ------------------------------------------------------------------ */

static struct MHD_Daemon *
start_daemon_with_limit (size_t limit)
{
  struct MHD_Daemon *d;
  struct MHD_OptMatrixProfile prof;
  struct MHD_OptionItem ops[8];
  unsigned int flags;

  /* The profile (if any) supplies the discipline level, the threading mode
     and the polling backend; the memory limit is the one of the sweep, which
     the caller has already taken from the profile. */
  if (NULL != test_prof)
    prof = *test_prof;
  else
  {
    memset (&prof, 0, sizeof (prof));
    prof.name = "built-in";
    prof.threading = MHD_OPT_MATRIX_THR_INTERNAL;
    prof.poll_backend = MHD_OPT_MATRIX_POLL_SELECT;
  }
  prof.mem_limit = limit;
  if (0 == mhd_opt_matrix_fill_options (&prof, ops,
                                        (unsigned int) (sizeof (ops)
                                                        / sizeof (ops[0]))))
    externalErrorExitDesc ("The daemon option array is too small");
  /* The client of this test is a plain blocking socket client, so external
     polling is served with an internal polling thread instead. */
  flags = mhd_opt_matrix_daemon_flags (&prof, MHD_USE_ERROR_LOG, 0);
  d = MHD_start_daemon (flags,
                        0, NULL, NULL,
                        &ahc_record, NULL,
                        MHD_OPTION_ARRAY, ops,
                        MHD_OPTION_EXTERNAL_LOGGER, &test_log, NULL,
                        MHD_OPTION_NOTIFY_CONNECTION, &conn_notify, NULL,
                        MHD_OPTION_NOTIFY_COMPLETED, &req_completed, NULL,
                        MHD_OPTION_CONNECTION_TIMEOUT,
                        (unsigned int) 8,
                        MHD_OPTION_END);
  return d;
}


/**
 * Run one corpus entry through the full split sweep at the current memory
 * limit.
 */
static void
run_entry (const struct corpus_entry *e, unsigned long *split_counter)
{
  const size_t len = (0 != e->raw_len) ? e->raw_len : strlen (e->raw);
  struct obs_buf expected;
  struct obs_buf ref;
  struct obs_buf got;
  size_t *offs;
  unsigned int n_offs;
  unsigned int i;
  unsigned int stride;
  int degraded;
  int ref_bad = 0;
  const struct obs_buf *cmp;
  unsigned int ref_resp;
  unsigned int min_resp;
  int want_close;

  cur_entry = e;
  build_expected (e, &expected);

  /* 1) Unsplit reference run. */
  snprintf (cur_split, sizeof (cur_split), "none (unsplit)");
  run_stream (e, NULL, 0, e->n_resp, ! e->alive, READ_GRACE_MS, &ref);
  combos++;
  (*split_counter)++;

  degraded = (0 != strcmp (expected.d, ref.d)) &&
             is_resource_degradation (&ref, e);
  if ((0 != strcmp (expected.d, ref.d)) && (! degraded))
  {
    /* Either the default connection memory pool is in use, or the deviation
       does not look like a resource limitation: in both cases the corpus
       entry must match its declared expectations exactly. */
    report_failure (e, "unsplit run does not match the expectations",
                    expected.d, ref.d);
    /* The reference is useless as a comparison base now; keep checking the
       split runs against the declared expectations so that the report names
       the concrete split offsets that are affected. */
    ref_bad = 1;
  }
  else if (degraded)
  {
    combos_pool_limited++;
    if (! check_relaxed (&expected, &ref))
    {
      report_failure (e,
                      "unsplit run with a small memory pool parsed a request "
                      "differently than expected",
                      expected.d, ref.d);
      return;
    }
    if (verbose)
    {
      printf ("  %-22s degraded by the memory pool, relaxed checking\n",
              e->name);
      fflush (stdout);
    }
  }

  /* Derive the read strategy for the split runs from the reference run, so
     that the split runs never have to wait for a timeout. */
  ref_resp = 0;
  if (1)
  {
    const char *p = strstr (ref.d, "nresp=");

    if (NULL != p)
      ref_resp = (unsigned int) strtoul (p + 6, NULL, 10);
  }
  if (! degraded)
  {
    const char *p = strstr (ref.d, "closed=");

    min_resp = ref_resp;
    want_close = (NULL != p) ? ('0' != p[7]) : 0;
    stride = 1;
  }
  else
  {
    /* The client side numbers are not reproducible under memory pressure;
       stop as soon as the first reply is complete (or as soon as MHD closes
       the connection if it does not reply at all) and only compare the
       server side observations. */
    min_resp = (0 != ref_resp) ? 1 : 0;
    want_close = (0 != ref_resp) ? 0 : 1;
    stride = 3; /* Sample: these runs are slower and less informative */
  }

  cmp = ref_bad ? &expected : &ref;

  /* 2) Two-way splits. */
  offs = (size_t *) malloc (sizeof (size_t) * (len + 1));
  if (NULL == offs)
    externalErrorExitDesc ("malloc() failed");
  n_offs = build_split_offsets (len, offs, (unsigned int) len + 1);
  for (i = 0; i < n_offs; i += stride)
  {
    snprintf (cur_split, sizeof (cur_split), "%u", (unsigned int) offs[i]);
    run_stream (e, offs + i, 1, min_resp, want_close, 0, &got);
    combos++;
    (*split_counter)++;
    if (degraded)
    {
      combos_pool_limited++;
      if ((! check_relaxed (&expected, &got)) ||
          (! status_acceptable_degraded (&got, e)) ||
          (NULL != strstr (got.d, "TIMED_OUT")))
        report_failure (e,
                        "split point with a small memory pool parsed a "
                        "request differently than expected",
                        expected.d, got.d);
    }
    else if (0 != strcmp (cmp->d, got.d))
      report_failure (e,
                      ref_bad ?
                      "split point does not match the expectations" :
                      "split point yields a different parse than the "
                      "unsplit run",
                      cmp->d, got.d);
    if (MAX_FAILURES < failures)
    {
      free (offs);
      return;
    }
  }

  /* 3) Three-way splits for the marked entries. */
  if (e->deep && deep_enabled && (! degraded) && (2 < len))
  {
    unsigned int done = 0;
    unsigned int a;
    const unsigned int step =
      (unsigned int) (((len * len) / (2 * DEEP_SPLIT_MAX)) + 1);
    unsigned int ctr = 0;

    for (a = 1; (a + 1 < (unsigned int) len) && (done < DEEP_SPLIT_MAX); ++a)
    {
      unsigned int b;

      for (b = a + 1; (b < (unsigned int) len) && (done < DEEP_SPLIT_MAX); ++b)
      {
        size_t two[2];

        if (0 != (ctr++ % step))
          continue;
        two[0] = a;
        two[1] = b;
        snprintf (cur_split, sizeof (cur_split), "%u+%u", a, b);
        run_stream (e, two, 2, min_resp, want_close, 0, &got);
        combos++;
        (*split_counter)++;
        done++;
        if (0 != strcmp (cmp->d, got.d))
          report_failure (e,
                          ref_bad ?
                          "three-way split does not match the expectations" :
                          "three-way split yields a different parse than "
                          "the unsplit run",
                          cmp->d, got.d);
        if (MAX_FAILURES < failures)
        {
          free (offs);
          return;
        }
      }
    }
  }
  free (offs);
}


int
main (int argc, char *const *argv)
{
  const uint64_t t_start = now_ms ();
  unsigned int mi;
  int i;
  const char *only = NULL;
  unsigned long total_splits = 0;
  size_t sweep[MEM_LIMITS_SIZE];
  unsigned int sweep_size;
  unsigned long entries_skipped = 0;

  for (i = 1; i < argc; ++i)
  {
    if ((0 == strcmp (argv[i], "-v")) || (0 == strcmp (argv[i], "--verbose")))
      verbose++;
    else if (0 == strncmp (argv[i], "--entry=", 8))
      only = argv[i] + 8;
    else if ('-' != argv[i][0])
      only = argv[i];
  }

  strcpy (cur_split, "(not started)");

#if defined(HAVE_SIGNAL_H) && defined(SIGPIPE)
  if (MHD_YES != MHD_is_feature_supported (MHD_FEATURE_AUTOSUPPRESS_SIGPIPE))
  {
    if (SIG_ERR == signal (SIGPIPE, SIG_IGN))
      externalErrorExitDesc ("Error suppressing SIGPIPE signal");
  }
#endif /* HAVE_SIGNAL_H && SIGPIPE */
#if defined(HAVE_SIGNAL_H) && defined(SIGABRT)
  (void) signal (SIGABRT, &abort_handler);
#endif /* HAVE_SIGNAL_H && SIGABRT */

  /* Deliberately NOT mhd_panic_tripwire.h: this test installs its own
     panic and SIGABRT handlers, which print the failing input and the
     daemon options along with the diagnostic.  That context is worth
     more here than the generic tripwire, and the two would collide
     (whichever runs last wins).  See TESTING.md, P5. */
  MHD_set_panic_func (&test_panic, NULL);
  mhd_opt_matrix_print_notice ("test_raw_requests");

  test_prof = mhd_opt_matrix_from_env ();
  if (NULL != test_prof)
  {
    char desc[256];

    test_prof_copy = *test_prof;
    test_prof = &test_prof_copy;
    if (! mhd_opt_matrix_profile_supported (test_prof))
    {
      printf ("test_raw_requests: the selected profile %s is not supported "
              "by this build, the test is skipped.\n",
              mhd_opt_matrix_describe (test_prof, desc, sizeof (desc)));
      return 77;
    }
    /* One profile pins one memory limit; the built-in sweep is replaced. */
    sweep[0] = test_prof_copy.mem_limit;
    sweep_size = 1;
  }
  else
  {
    for (mi = 0; mi < MEM_LIMITS_SIZE; ++mi)
      sweep[mi] = mem_limits[mi];
    sweep_size = (unsigned int) MEM_LIMITS_SIZE;
  }
  test_discp = mhd_opt_matrix_effective_discipline (test_prof);

  for (mi = 0; mi < sweep_size; ++mi)
  {
    struct MHD_Daemon *d;
    const union MHD_DaemonInfo *dinfo;
    size_t ci;

    cur_mem_limit = sweep[mi];
    /* The three-way split pass is expensive; run it for the smallest pool
       size that is not permanently degraded and for the default pool. */
    deep_enabled = ((1 == sweep_size) || (1 == mi) || (sweep_size - 1 == mi));
    conn_started = 0;
    conn_closed = 0;
    d = start_daemon_with_limit (cur_mem_limit);
    if (NULL == d)
    {
      fprintf (stderr, "Failed to start the daemon with memory limit %u.\n",
               (unsigned int) cur_mem_limit);
      return 99;
    }
    dinfo = MHD_get_daemon_info (d, MHD_DAEMON_INFO_BIND_PORT);
    if ((NULL == dinfo) || (0 == dinfo->port))
    {
      MHD_stop_daemon (d);
      fprintf (stderr, "Cannot get the daemon port.\n");
      return 99;
    }
    global_port = dinfo->port;

    if (verbose)
    {
      printf ("--- connection memory limit: ");
      if (0 == cur_mem_limit)
        printf ("default ---\n");
      else
        printf ("%u ---\n", (unsigned int) cur_mem_limit);
      fflush (stdout);
    }

    for (ci = 0; ci < CORPUS_SIZE; ++ci)
    {
      unsigned long before = total_splits;

      if ((NULL != only) && (0 != strcmp (only, corpus[ci].name)))
        continue;
      if (! entry_in_discp_range (corpus[ci].name))
      {
        entries_skipped++;
        if (verbose)
          printf ("  %-22s skipped: its expectation is only valid for a "
                  "different client discipline level\n", corpus[ci].name);
        continue;
      }
      run_entry (&corpus[ci], &total_splits);
      if (1 < verbose)
      {
        printf ("  %-22s %lu runs\n", corpus[ci].name,
                total_splits - before);
        fflush (stdout);
      }
      if (MAX_FAILURES < failures)
        break;
    }
    MHD_stop_daemon (d);
    cur_entry = NULL;
    if (MAX_FAILURES < failures)
      break;
  }

  printf ("\ntest_raw_requests: %u corpus entries, %u memory limits, "
          "%lu combinations executed (%lu pool-limited, %lu entry runs "
          "skipped as out of the discipline range), %.1f s\n",
          (unsigned int) ((NULL == only) ? CORPUS_SIZE : 1),
          sweep_size,
          combos,
          combos_pool_limited,
          entries_skipped,
          (double) (now_ms () - t_start) / 1000.0);
  if (0 != failures)
  {
    printf ("test_raw_requests: FAILED (%lu failure(s))\n", failures);
    fflush (stdout);
    return 1;
  }
  printf ("test_raw_requests: PASSED\n");
  fflush (stdout);
  return 0;
}
