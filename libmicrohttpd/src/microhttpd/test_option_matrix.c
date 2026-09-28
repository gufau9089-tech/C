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
 * @file test_option_matrix.c
 * @brief  A battery of raw HTTP requests replayed against every supported
 *         point of the daemon option matrix.
 * @author Christian Grothoff
 *
 * ## Why this test exists
 *
 * Every other test in this directory pins one daemon configuration, so the
 * suite as a whole only ever visits a single point of a fairly large
 * configuration space: connection memory limit x client discipline level x
 * threading mode x polling backend.  Yet the code that a request travels
 * through depends on all four: a small connection pool unlocks the read
 * buffer "shift back" and buffer-grow paths, the discipline level switches
 * whole families of parser leniency, and the threading/polling mode decides
 * which of the four event loops re-enters the parser.
 *
 * This test walks the matrix defined in mhd_opt_matrix.c and replays the same
 * small battery of hand-written raw requests against every point of it.  The
 * requests are sent over raw sockets because several of them (chunk
 * extensions, pipelining, a whitespace-prefixed header line, an early close
 * in the middle of a request) cannot be produced with libcurl.
 *
 * Every failure names the profile it came from, so a report is directly
 * actionable.
 *
 * ## Command line
 *
 * * `-v`            - report every profile and every scenario;
 * * `-v -v`         - additionally print the MHD error log;
 * * `--profile=N`   - restrict the run to one profile (name or index), the
 *                     same as MHD_TEST_PROFILE=N in the environment;
 * * `--list-profiles` - print one profile name per line and exit; this is
 *                     what contrib/run-option-matrix.sh uses, so that the
 *                     matrix is defined in exactly one place;
 * * `--scenario=NAME` - restrict the run to one scenario.  Useful to walk
 *                     the whole battery of a profile that aborts the process
 *                     in the middle of it.
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
 * Convenience shorthand used all over the scenario table.
 */
#define CRLF "\r\n"

/**
 * The Host header used by (almost) every scenario.
 */
#define H_LOCAL "Host: localhost" CRLF

/**
 * Size of the textual observation buffer.
 */
#define OBS_SIZE 4096

/**
 * Size of the client receive buffer.
 */
#define RX_SIZE 8192

/**
 * Hard upper bound (ms) for reading the complete server answer.
 */
#define READ_DEADLINE_MS 700

/**
 * Silence (ms) accepted as "the server is done and keeps the connection
 * alive".
 */
#define READ_GRACE_MS 10

/**
 * Milliseconds to wait for the server side to finish tearing down the
 * connection, so that the observations become stable.
 */
#define CLOSE_WAIT_MS 1500

/**
 * Milliseconds the daemon is left running after a scenario that closes the
 * connection without reading an answer, so that a wrongly parsed request
 * still has a chance to show up.
 */
#define SETTLE_MS 60

/**
 * The connection timeout of the test daemons, in seconds.
 */
#define DAEMON_TIMEOUT 8

/**
 * Give up after that many reported failures.
 */
#define MAX_FAILURES 12


/* ------------------------------------------------------------------ */
/* Error exits                                                        */
/* ------------------------------------------------------------------ */

/* Forward declaration, needed by the error exit helpers. */
static void
print_context (FILE *out);


_MHD_NORETURN static void
external_error_exit (const char *desc, int line)
{
  fprintf (stderr,
           "%s at line %d.\nLast errno value: %d (%s)\n",
           (NULL != desc) ? desc : "System or external library call failed",
           line,
           (int) errno,
           strerror (errno));
  print_context (stderr);
  fflush (stderr);
  exit (99);
}


#define hard_error(desc) external_error_exit (desc, __LINE__)


/**
 * Pause execution for the given number of milliseconds.
 *
 * @param ms the number of milliseconds to sleep
 */
static void
sleep_ms (unsigned int ms)
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
      hard_error ("nanosleep() failed");
    if (num_retries++ > 8)
      break;
    slp = rmn;
  }
#elif defined(HAVE_USLEEP)
  usleep ((useconds_t) (ms * 1000));
#else
  hard_error ("No sleep function available on this system");
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
/* Textual observation buffer                                         */
/* ------------------------------------------------------------------ */

/**
 * A bounded, always NUL-terminated text accumulator.  Both the expected and
 * the actual observation are rendered into such a buffer, so that a single
 * strcmp() performs the whole check and also yields readable diagnostics.
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
/* The scenario battery                                               */
/* ------------------------------------------------------------------ */

/**
 * One request scenario.
 *
 * The expectation @e exp is the concatenation of one line per request that
 * MHD must parse, in the format
 *
 *     "METHOD URL [BODY] {ARG=VAL,ARG=VAL}\n"
 *
 * with every byte outside the printable ASCII range escaped as \\xNN and a
 * query argument without a value rendered as "ARG=<NULL>".
 */
struct scenario
{
  /**
   * Short identifier, printed on failure.
   */
  const char *name;

  /**
   * One line saying which behaviour this scenario pins down.
   */
  const char *desc;

  /**
   * The raw request byte stream (may hold several pipelined requests).
   */
  const char *raw;

  /**
   * The number of complete requests MHD must parse out of @e raw.
   */
  unsigned int n_req;

  /**
   * The number of complete responses the client must see.
   */
  unsigned int n_resp;

  /**
   * The expected status code of the first response, zero for "any".
   */
  int status;

  /**
   * 1 if the connection must stay alive afterwards, 0 if MHD must close it.
   */
  int alive;

  /**
   * If non-zero, the client closes the connection right after sending and
   * does not read any answer at all.
   */
  int close_after_send;

  /**
   * If non-zero, the only requirement is that the daemon survives: neither
   * the number of parsed requests nor the answer is checked.  Used by the
   * probes whose declared purpose is to reach a defect.
   */
  int loose;

  /**
   * The lowest client discipline level at which this scenario is meaningful.
   */
  int min_discp;

  /**
   * The highest client discipline level at which this scenario is
   * meaningful.
   */
  int max_discp;

  /**
   * The expected server side observation, see above.
   */
  const char *exp;
};


/**
 * A header block of ten headers with values of moderate length.  Kept small
 * enough to still fit into a connection memory pool of
 * 1024 bytes, so that the scenario is a real check rather than a permanent
 * "degraded by the pool" case.
 */
#define MANY_HDRS \
        "A-One: 1" CRLF "B-Two: 22" CRLF "C-Three: 333" CRLF \
        "D-Four: 4444" CRLF "E-Five: 55555" CRLF "F-Six: 666666" CRLF \
        "G-Seven: 7777777" CRLF "H-Eight: 88888888" CRLF \
        "I-Nine: 999999999" CRLF "J-Ten: aaaaaaaaaa" CRLF

/**
 * Forty characters of chunk-extension filler.
 */
#define EXT_40 "qqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqq"

/**
 * Four hundred characters of chunk-extension filler: longer than the whole
 * read buffer of a connection memory pool of 512 bytes, so that MHD has to
 * take the "chunk-size line does not fit" path, and comfortably shorter than
 * the read buffer of a 1024-byte pool, where the line still fits.
 */
#define EXT_400 \
        EXT_40 EXT_40 EXT_40 EXT_40 EXT_40 \
        EXT_40 EXT_40 EXT_40 EXT_40 EXT_40

/**
 * The expected rendering of #MANY_HDRS as GET arguments: none, the block is
 * a header block.  Only listed here to keep the table readable.
 */
#define E_MANY "GET /h [] {}\n"

static const struct scenario scenarios[] = {
  { "get_plain",
    "baseline: request line, one header, empty reply",
    "GET / HTTP/1.1" CRLF H_LOCAL CRLF,
    1, 1, 200, 1, 0, 0, -3, 3,
    "GET / [] {}\n" },
  { "get_query",
    "query arguments: '=' value, bare argument, '+' decoding",
    "GET /q?a=1&b&c=x+y HTTP/1.1" CRLF H_LOCAL CRLF,
    1, 1, 200, 1, 0, 0, -3, 3,
    "GET /q [] {a=1,b=<NULL>,c=x y}\n" },
  { "post_cl",
    "Content-Length body, delivered incrementally to the handler",
    "POST /p HTTP/1.1" CRLF H_LOCAL "Content-Length: 11" CRLF CRLF
    "Hello World",
    1, 1, 200, 1, 0, 0, -3, 3,
    "POST /p [Hello World] {}\n" },
  { "post_chunked",
    "chunked body without any chunk extension",
    "POST /c HTTP/1.1" CRLF H_LOCAL "Transfer-Encoding: chunked" CRLF CRLF
    "5" CRLF "Hello" CRLF "6" CRLF " World" CRLF "0" CRLF CRLF,
    1, 1, 200, 1, 0, 0, -3, 3,
    "POST /c [Hello World] {}\n" },
  { "post_chunk_ext",
    "chunk extensions, incl. a quoted value holding a ';' (commit c13f4c64)",
    "POST /c HTTP/1.1" CRLF H_LOCAL "Transfer-Encoding: chunked" CRLF CRLF
    "5;a=b" CRLF "Hello" CRLF "6;q=\"x;y\"" CRLF " World" CRLF "0;z" CRLF CRLF,
    1, 1, 200, 1, 0, 0, -3, 3,
    "POST /c [Hello World] {}\n" },
  /* With a connection memory limit of about 512 or less this chunk-size
     line does not fit into the read buffer. */
  { "post_chunk_ext_long",
    "chunk extension longer than the space reserved for the chunk header",
    "POST /c HTTP/1.1" CRLF H_LOCAL "Transfer-Encoding: chunked" CRLF CRLF
    "5;ext=\"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\"" CRLF
    "Hello" CRLF "0" CRLF CRLF,
    1, 1, 200, 1, 0, 0, -3, 3,
    "POST /c [Hello] {}\n" },
  /* Regression test for commits 68c83f22 and e04eb218: the chunk-size line
     is longer than the read buffer of a small connection memory pool, so MHD
     has to take handle_req_chunk_size_line_no_space().  With a pool of 1024
     bytes or more the line fits and the scenario is an ordinary
     chunk-extension check. */
  { "post_chunk_ext_huge",
    "chunk extension longer than the whole read buffer of a small pool",
    "POST /c HTTP/1.1" CRLF H_LOCAL "Transfer-Encoding: chunked" CRLF CRLF
    "5;ext=\"" EXT_400 "\"" CRLF "Hello" CRLF "0" CRLF CRLF,
    1, 1, 200, 1, 0, 0, -3, 3,
    "POST /c [Hello] {}\n" },
  /* The same, but with the over-long chunk-size line on the *second* chunk,
     so that the upload callback has already run once when MHD runs out of
     read buffer space.  That is the extra precondition of the assertion
     fixed in 68c83f22 (rq.some_payload_processed still describes the
     previous read). */
  { "post_chunk_ext_huge_2nd",
    "over-long chunk-size line after a chunk that was already delivered",
    "POST /c HTTP/1.1" CRLF H_LOCAL "Transfer-Encoding: chunked" CRLF CRLF
    "5" CRLF "Hello" CRLF
    "5;ext=\"" EXT_400 "\"" CRLF "World" CRLF "0" CRLF CRLF,
    1, 1, 200, 1, 0, 0, -3, 3,
    "POST /c [HelloWorld] {}\n" },
  { "pipelined",
    "two pipelined requests must yield exactly two parsed requests",
    "GET /1 HTTP/1.1" CRLF H_LOCAL CRLF
    "GET /2?x=1 HTTP/1.1" CRLF H_LOCAL CRLF,
    2, 2, 200, 1, 0, 0, -3, 3,
    "GET /1 [] {}\nGET /2 [] {x=1}\n" },
  { "many_headers",
    "ten header lines: pool allocation and read buffer growth",
    "GET /h HTTP/1.1" CRLF H_LOCAL MANY_HDRS CRLF,
    1, 1, 200, 1, 0, 0, -3, 3,
    E_MANY },
  { "early_close",
    "the client vanishes in the middle of the request header",
    "GET /e HTTP/1.1" CRLF H_LOCAL "X-Partial: abc",
    0, 0, 0, 0, 1, 0, -3, 3,
    "" },

  /* ---- probes for the relaxed client discipline levels ------------ */
  /* The three "strict" variants below are the control cases: at the
     discipline levels at which MHD promises to reject the input, it must
     really answer 400 and must not parse a request.  The three "lax"
     variants are the regression tests for the assertions fixed in commits
     0b750975 and 6fcdfd43; they only require that the daemon survives, since
     what those modes do with the input is deliberately unspecified beyond
     "do not abort". */
  { "wsp_first_hdr_strict",
    "whitespace-prefixed first header line is rejected at level 0 and above",
    "GET / HTTP/1.1" CRLF " " H_LOCAL "X-A: b" CRLF CRLF,
    0, 1, 400, 0, 0, 0, 0, 3,
    "" },
  { "wsp_first_hdr_lax",
    "whitespace-prefixed first header line at level -1 or below (0b750975)",
    "GET / HTTP/1.1" CRLF " " H_LOCAL "X-A: b" CRLF CRLF,
    0, 0, 0, 0, 0, 1, -3, -1,
    "" },
  { "empty_hdr_name_strict",
    "an empty header name is rejected at level -1 and above",
    "GET / HTTP/1.1" CRLF H_LOCAL ": value" CRLF CRLF,
    0, 1, 400, 0, 0, 0, -1, 3,
    "" },
  { "empty_hdr_name_lax",
    "an empty header name at level -2 or below (0b750975)",
    "GET / HTTP/1.1" CRLF H_LOCAL ": value" CRLF CRLF,
    0, 0, 0, 0, 0, 1, -3, -2,
    "" },
  { "bare_cr_strict",
    "a bare CR in a header value is rejected at level 0 and above",
    "GET / HTTP/1.1" CRLF H_LOCAL "X-Cr: va\rlue" CRLF CRLF,
    0, 1, 400, 0, 0, 0, 0, 3,
    "" },
  { "bare_cr_as_sp",
    "a bare CR becomes a space at level -1 and -2",
    "GET / HTTP/1.1" CRLF H_LOCAL "X-Cr: va\rlue" CRLF CRLF,
    1, 1, 200, 1, 0, 0, -2, -1,
    "GET / [] {}\n" },
  { "bare_cr_keep",
    "a bare CR is kept in the header value at level -3 (6fcdfd43)",
    "GET / HTTP/1.1" CRLF H_LOCAL "X-Cr: va\rlue" CRLF CRLF,
    0, 0, 0, 0, 0, 1, -3, -3,
    "" }
};

#define NUM_SCENARIOS (sizeof(scenarios) / sizeof(scenarios[0]))


/* ------------------------------------------------------------------ */
/* Global state                                                       */
/* ------------------------------------------------------------------ */

static int verbose;

/** The profile currently under test. */
static const struct MHD_OptMatrixProfile *cur_prof;
/** Rendered description of @a cur_prof. */
static char cur_prof_desc[256];
/** The scenario currently under test. */
static const struct scenario *cur_scen;
/** If not NULL, only the scenario with this name is run. */
static const char *only_scen;

/** The port of the running daemon. */
static uint16_t global_port;
/** The running daemon, only set when it has to be driven with MHD_run(). */
static struct MHD_Daemon *extern_daemon;

/** Server side observations of the connection currently under test. */
static struct obs_buf srv_obs;
/** Number of completed requests seen by the request handler. */
static volatile unsigned int srv_n_req;
/** Set if the handler noticed something structurally impossible. */
static volatile unsigned int srv_error;

static volatile unsigned int conn_started;
static volatile unsigned int conn_closed;

/** Number of (profile x scenario) combinations executed. */
static unsigned long combos;
/** Number of combinations that could not fit into the memory pool. */
static unsigned long combos_degraded;
/** Number of scenarios skipped because of the discipline level. */
static unsigned long scen_skipped;
/** Number of profiles skipped because this build cannot provide them. */
static unsigned long prof_skipped;
/** Number of failures found. */
static unsigned long failures;


static void
print_context (FILE *out)
{
  fprintf (out, "  context: profile %s scenario='%s'\n",
           cur_prof_desc,
           (NULL != cur_scen) ? cur_scen->name : "(none)");
  if (NULL != cur_scen)
    fprintf (out, "  scenario purpose: %s\n", cur_scen->desc);
}


#if defined(HAVE_SIGNAL_H) && defined(SIGABRT)
/**
 * Report the profile and the scenario when the library aborts (e.g. from an
 * internal assertion) instead of dying anonymously.
 */
static void
abort_handler (int sig)
{
  (void) sig;
  fprintf (stderr,
           "\nFATAL: the library aborted while running a scenario.\n");
  print_context (stderr);
  fflush (stderr);
  _exit (1);
}


#endif /* HAVE_SIGNAL_H && SIGABRT */


/**
 * Panic callback: a library panic is a test failure that names the profile
 * and the scenario.
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
    obs_addf (ctx->out, ",");
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
  /* The reply body is intentionally empty, which keeps the response framing
     on the client side trivial. */
  static const char rp_data[] = "";
  struct req_state *rs;
  struct MHD_Response *response;
  struct iter_ctx ctx;
  enum MHD_Result ret;

  (void) cls; (void) version;
  if (NULL == *req_cls)
  {
    rs = (struct req_state *) malloc (sizeof (struct req_state));
    if (NULL == rs)
      hard_error ("malloc() failed");
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

  /* The request is complete: record everything that is observable. */
  obs_addf (&srv_obs, "%s ", (NULL != method) ? method : "(null)");
  if (NULL != url)
    obs_add_escaped (&srv_obs, url, strlen (url));
  else
    obs_addf (&srv_obs, "(null)");
  obs_addf (&srv_obs, " [%s] {", rs->body.d);
  ctx.out = &srv_obs;
  ctx.num = 0;
  MHD_get_connection_values_n (connection, MHD_GET_ARGUMENT_KIND,
                               &value_iterator, &ctx);
  obs_addf (&srv_obs, "}\n");

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
 * The MHD error log, only printed with '-v -v': the matrix visits several
 * deliberately hostile configurations and the library complains a lot.
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


/**
 * Switch a socket to the non-blocking mode.
 *
 * @param sk the socket to modify
 * @return non-zero on success
 */
static int
set_nonblocking (MHD_socket sk)
{
#if defined(MHD_POSIX_SOCKETS)
  int flags;

  flags = fcntl (sk, F_GETFL);
  if (-1 == flags)
    return 0;
  return (-1 != fcntl (sk, F_SETFL, flags | O_NONBLOCK)) ? ! 0 : 0;
#else  /* ! MHD_POSIX_SOCKETS */
  unsigned long mode = 1;

  return (0 == ioctlsocket (sk, FIONBIO, &mode)) ? ! 0 : 0;
#endif /* ! MHD_POSIX_SOCKETS */
}


static MHD_socket
client_connect (void)
{
  MHD_socket sk;
  struct sockaddr_in sa;
  const MHD_SCKT_OPT_BOOL_ on_val = 1;

  sk = socket (AF_INET, SOCK_STREAM, IPPROTO_TCP);
  if (MHD_INVALID_SOCKET == sk)
    hard_error ("Cannot create the client socket");
#ifdef MHD_socket_nosignal_
  if (! MHD_socket_nosignal_ (sk))
    hard_error ("Cannot suppress SIGPIPE on the client socket");
#endif /* MHD_socket_nosignal_ */
  if (0 != setsockopt (sk, IPPROTO_TCP, TCP_NODELAY,
                       (const void *) &on_val, sizeof (on_val)))
    hard_error ("Cannot set the TCP_NODELAY option");

  memset (&sa, 0, sizeof (sa));
  sa.sin_family = AF_INET;
  sa.sin_port = htons (global_port);
  sa.sin_addr.s_addr = htonl (INADDR_LOOPBACK);
  if (0 != connect (sk, (struct sockaddr *) &sa, sizeof (sa)))
    hard_error ("Cannot connect() to the test daemon");
  if (! set_nonblocking (sk))
    hard_error ("Cannot switch the client socket to the non-blocking mode");
  return sk;
}


/**
 * Send @a data and read the answer, driving the daemon with MHD_run() when
 * the profile asks for external polling.
 *
 * @param sk the client socket
 * @param data the request bytes
 * @param size the number of bytes in @a data
 * @param[out] r the result
 * @param min_resp stop once that many complete responses have been read
 * @param want_close keep reading until the peer closes the connection
 * @param read_answer if zero, close right after sending
 */
static void
client_exchange (MHD_socket sk,
                 const char *data,
                 size_t size,
                 struct client_result *r,
                 unsigned int min_resp,
                 int want_close,
                 int read_answer)
{
  const uint64_t start = now_ms ();
  size_t sent = 0;
  uint64_t quiet_since = 0;

  memset (r, 0, sizeof (*r));
  while (1)
  {
    fd_set rs;
    fd_set ws;
    fd_set es;
    struct timeval tv;
    MHD_socket maxfd_mhd = MHD_INVALID_SOCKET;
    int maxfd;
    int sel;

    if (now_ms () - start >= READ_DEADLINE_MS)
    {
      r->timed_out = 1;
      break;
    }
    if ((sent >= size) && (! read_answer))
      break;
    r->n_resp = count_responses (r->rx, r->rx_len, &r->first_status);
    if ((sent >= size) && (! want_close) && (r->n_resp >= min_resp))
    {
      /* Everything that was expected has arrived; accept a short silence as
         "the server is done and keeps the connection alive". */
      if (0 == quiet_since)
        quiet_since = now_ms ();
      else if (now_ms () - quiet_since >= READ_GRACE_MS)
        break;
    }
    else
      quiet_since = 0;

    FD_ZERO (&rs);
    FD_ZERO (&ws);
    FD_ZERO (&es);
#if defined(MHD_POSIX_SOCKETS)
    if (FD_SETSIZE <= (int) sk)
      hard_error ("The client socket does not fit into fd_set");
#endif /* MHD_POSIX_SOCKETS */
    if (! r->peer_closed)
      FD_SET (sk, &rs);
    if (sent < size)
      FD_SET (sk, &ws);
    maxfd = (int) sk;
    if (NULL != extern_daemon)
    {
      if (MHD_YES != MHD_get_fdset (extern_daemon, &rs, &ws, &es, &maxfd_mhd))
        hard_error ("MHD_get_fdset() failed");
#ifndef MHD_WINSOCK_SOCKETS
      if ((int) maxfd_mhd > maxfd)
        maxfd = (int) maxfd_mhd;
#endif /* ! MHD_WINSOCK_SOCKETS */
    }
    tv.tv_sec = 0;
    tv.tv_usec = 2000;
    sel = select (maxfd + 1, &rs, &ws, &es, &tv);
    if ((0 > sel) && (EINTR != errno))
      hard_error ("select() failed");
    if (NULL != extern_daemon)
      MHD_run (extern_daemon);

    if (sent < size)
    {
      ssize_t s = MHD_send_ (sk, data + sent, size - sent);

      if (0 > s)
      {
        const int err = MHD_socket_get_error_ ();

        if (! (MHD_SCKT_ERR_IS_EINTR_ (err) || MHD_SCKT_ERR_IS_EAGAIN_ (err)))
        {
          /* MHD closed the connection early; that is an observation, not an
             error of the test. */
          sent = size;
          r->peer_closed = 1;
        }
      }
      else
        sent += (size_t) s;
    }
    if ((! r->peer_closed) && (r->rx_len < sizeof (r->rx)))
    {
      ssize_t got = MHD_recv_ (sk, r->rx + r->rx_len,
                               sizeof (r->rx) - r->rx_len);

      if (0 > got)
      {
        const int err = MHD_socket_get_error_ ();

        if (! (MHD_SCKT_ERR_IS_EINTR_ (err) || MHD_SCKT_ERR_IS_EAGAIN_ (err)))
          r->peer_closed = 1; /* A connection reset counts as "closed" */
      }
      else if (0 == got)
        r->peer_closed = 1;
      else
      {
        r->rx_len += (size_t) got;
        quiet_since = 0;
      }
    }
    if (r->peer_closed && (sent >= size))
      break;
  }
  r->n_resp = count_responses (r->rx, r->rx_len, &r->first_status);
}


/**
 * Let the daemon run for @a ms milliseconds without any client activity.
 *
 * @param ms the number of milliseconds to spend
 */
static void
settle (unsigned int ms)
{
  const uint64_t start = now_ms ();

  do
  {
    if (NULL != extern_daemon)
      MHD_run (extern_daemon);
    sleep_ms (1);
  } while (now_ms () - start < (uint64_t) ms);
}


/**
 * Wait until the daemon has finished tearing down all connections, so that
 * the server side observations are stable.
 *
 * @return non-zero on success, zero on timeout
 */
static int
wait_conns_closed (void)
{
  const uint64_t start = now_ms ();

  while (conn_closed != conn_started)
  {
    if (NULL != extern_daemon)
      MHD_run (extern_daemon);
    else
      sleep_ms (1);
    if (now_ms () - start > CLOSE_WAIT_MS)
      return 0;
  }
  return ! 0;
}


/* ------------------------------------------------------------------ */
/* One scenario against one profile                                   */
/* ------------------------------------------------------------------ */

static void
report_failure (const char *what, const char *exp, const char *got)
{
  failures++;
  fprintf (stderr, "\nFAILED: %s\n", what);
  print_context (stderr);
  if (NULL != exp)
    fprintf (stderr, "  expected:\n%s", exp);
  if (NULL != got)
    fprintf (stderr, "  observed:\n%s", got);
  fflush (stderr);
}


/**
 * Statuses with which MHD legitimately refuses a request that does not fit
 * into the connection memory pool.  A 400 is never one of them.
 *
 * @param status the status code of the first response
 * @return non-zero if the status is a resource limitation
 */
static int
is_resource_status (int status)
{
  return ((413 == status) || (414 == status) || (431 == status) ||
          (500 == status) || (503 == status)) ? ! 0 : 0;
}


/**
 * Run one scenario against the running daemon.
 */
static void
run_scenario (const struct scenario *s)
{
  struct client_result cr;
  struct obs_buf got;
  MHD_socket sk;
  const size_t len = strlen (s->raw);
  int degraded;

  cur_scen = s;
  obs_reset (&srv_obs);
  srv_n_req = 0;
  srv_error = 0;
  combos++;

  sk = client_connect ();
  client_exchange (sk, s->raw, len, &cr,
                   s->n_resp, (0 == s->alive) && (! s->close_after_send),
                   s->close_after_send ? 0 : 1);
  (void) MHD_socket_close_ (sk);
  /* The server side observation is complete as soon as MHD has closed the
     connection or has answered everything that was expected: the request
     handler always runs before the reply is sent.  Waiting for the whole
     connection teardown is therefore only useful when neither happened.
     MHD keeps a connection around for a while after an error reply in the
     'epoll' modes, so an unconditional wait would cost seconds per scenario
     for no gain at all. */
  if (s->close_after_send)
    settle (SETTLE_MS); /* Give MHD a chance to mis-parse the truncated stream */
  else if ((! s->loose) && (! cr.peer_closed) && (cr.n_resp < s->n_resp))
  {
    if (! wait_conns_closed ())
    {
      fprintf (stderr, "WARNING: timeout waiting for the connection teardown "
               "(started=%u closed=%u).\n", conn_started, conn_closed);
      print_context (stderr);
    }
  }

  obs_reset (&got);
  obs_addf (&got, "%s", srv_obs.d);

  if (0 != srv_error)
  {
    report_failure ("the request handler could not queue a response",
                    NULL, NULL);
    return;
  }
  if (s->loose)
  {
    /* The daemon survived, which is all this probe asks for. */
    if (1 < verbose)
      printf ("    %-22s survived (loose probe)\n", s->name);
    return;
  }

  /* A connection memory pool that is too small for the request is a
     legitimate resource limitation: MHD then answers 413/414/431/500 without
     ever invoking the handler, or it cannot even build the reply header and
     closes the connection without answering a request it did parse.
     Everything MHD *did* parse must still match, and MHD may never parse
     more requests than the stream contains.  A 400 Bad Request is never
     accepted as a resource limitation. */
  degraded = 0;
  if (! s->close_after_send)
  {
    if ((0 != cr.n_resp) && (cr.n_resp < s->n_resp) &&
        is_resource_status (cr.first_status))
      degraded = 1;
    else if ((0 != cr.n_resp) && (0 != strcmp (s->exp, got.d)) &&
             is_resource_status (cr.first_status))
      degraded = 1;
    else if ((0 == cr.n_resp) && (0 != s->n_resp) && cr.peer_closed)
      degraded = 1;
  }
  if (degraded)
  {
    combos_degraded++;
    if (0 != memcmp (s->exp, got.d, strlen (got.d)))
      report_failure ("a request parsed with a small memory pool differs "
                      "from the expectation", s->exp, got.d);
    else if (verbose)
      printf ("    %-22s degraded by the memory pool, relaxed checking\n",
              s->name);
    return;
  }

  if (0 != strcmp (s->exp, got.d))
  {
    report_failure ("the parsed requests do not match the expectation",
                    s->exp, got.d);
    return;
  }
  if (srv_n_req != s->n_req)
  {
    char msg[128];

    snprintf (msg, sizeof (msg),
              "MHD parsed %u request(s), %u expected",
              (unsigned int) srv_n_req, s->n_req);
    report_failure (msg, NULL, NULL);
    return;
  }
  if (s->close_after_send)
  {
    if (1 < verbose)
      printf ("    %-22s ok (no answer expected)\n", s->name);
    return;
  }
  if (cr.n_resp != s->n_resp)
  {
    char msg[160];

    snprintf (msg, sizeof (msg),
              "the client saw %u response(s), %u expected%s",
              cr.n_resp, s->n_resp, cr.timed_out ? " (timed out)" : "");
    report_failure (msg, NULL, cr.rx_len ? cr.rx : "(nothing)");
    return;
  }
  if ((0 != s->status) && (cr.first_status != s->status))
  {
    char msg[128];

    snprintf (msg, sizeof (msg),
              "the first response has status %d, %d expected",
              cr.first_status, s->status);
    report_failure (msg, NULL, cr.rx);
    return;
  }
  if (s->alive && cr.peer_closed)
  {
    report_failure ("MHD closed a connection that had to stay alive",
                    NULL, NULL);
    return;
  }
  if ((! s->alive) && (! cr.peer_closed))
  {
    report_failure ("MHD kept a connection that had to be closed",
                    NULL, NULL);
    return;
  }
  if (1 < verbose)
    printf ("    %-22s ok\n", s->name);
}


/* ------------------------------------------------------------------ */
/* Main test driver                                                   */
/* ------------------------------------------------------------------ */

/**
 * Start a daemon for @a prof.
 *
 * @param prof the profile to apply
 * @return the daemon, or NULL if it cannot be started
 */
static struct MHD_Daemon *
start_daemon_for (const struct MHD_OptMatrixProfile *prof)
{
  struct MHD_OptionItem ops[8];
  struct MHD_Daemon *d;
  unsigned int n;
  unsigned int flags;

  n = mhd_opt_matrix_fill_options (prof, ops,
                                   (unsigned int) (sizeof(ops)
                                                   / sizeof(ops[0])));
  if (0 == n)
    hard_error ("The option array is too small");
  if (mhd_opt_matrix_is_external (prof))
  {
    /* Only meaningful without an internal polling thread; MHD complains
       about the option in every other mode. */
    ops[n - 1].option = MHD_OPTION_APP_FD_SETSIZE;
    ops[n - 1].value = (intptr_t) (FD_SETSIZE);
    ops[n - 1].ptr_value = NULL;
    ops[n].option = MHD_OPTION_END;
    ops[n].value = 0;
    ops[n].ptr_value = NULL;
  }
  flags = mhd_opt_matrix_daemon_flags (prof, MHD_USE_ERROR_LOG, ! 0);
  /* MHD_OPTION_EXTERNAL_LOGGER has to be the first option, otherwise the
     complaints about the options that follow it go to the standard logger. */
  d = MHD_start_daemon (flags,
                        0, NULL, NULL,
                        &ahc_record, NULL,
                        MHD_OPTION_EXTERNAL_LOGGER, &test_log, NULL,
                        MHD_OPTION_ARRAY, ops,
                        MHD_OPTION_NOTIFY_CONNECTION, &conn_notify, NULL,
                        MHD_OPTION_NOTIFY_COMPLETED, &req_completed, NULL,
                        MHD_OPTION_CONNECTION_TIMEOUT,
                        (unsigned int) DAEMON_TIMEOUT,
                        MHD_OPTION_END);
  return d;
}


/**
 * Run the whole battery against one profile.
 *
 * @param prof the profile to test
 * @return zero on success, 99 if the daemon could not be started
 */
static int
run_profile (const struct MHD_OptMatrixProfile *prof)
{
  struct MHD_Daemon *d;
  const union MHD_DaemonInfo *dinfo;
  size_t i;
  int discp;

  cur_prof = prof;
  (void) mhd_opt_matrix_describe (prof, cur_prof_desc, sizeof(cur_prof_desc));
  if (! mhd_opt_matrix_profile_supported (prof))
  {
    prof_skipped++;
    if (verbose)
      printf ("--- profile %s SKIPPED (not supported by this build) ---\n",
              cur_prof_desc);
    return 0;
  }
  if (verbose)
  {
    printf ("--- profile %s ---\n", cur_prof_desc);
    fflush (stdout);
  }

  conn_started = 0;
  conn_closed = 0;
  extern_daemon = NULL;
  d = start_daemon_for (prof);
  if (NULL == d)
  {
    fprintf (stderr, "Failed to start the daemon for profile %s.\n",
             cur_prof_desc);
    return 99;
  }
  if (mhd_opt_matrix_is_external (prof))
    extern_daemon = d;
  dinfo = MHD_get_daemon_info (d, MHD_DAEMON_INFO_BIND_PORT);
  if ((NULL == dinfo) || (0 == dinfo->port))
  {
    MHD_stop_daemon (d);
    fprintf (stderr, "Cannot get the port of the daemon for profile %s.\n",
             cur_prof_desc);
    return 99;
  }
  global_port = dinfo->port;

  /* Not prof->discipline_lvl: MHD_OPTION_STRICT_FOR_CLIENT maps its value,
     so the "legacy-lax" profile really runs at level -3 although it asks for
     -1.  Deciding what a request must do from the configured value instead of
     from the effective one is a trap: MHD_OPTION_STRICT_FOR_CLIENT maps
     every value of -1 or below to level -3. */
  discp = mhd_opt_matrix_effective_discipline (prof);
  for (i = 0; i < NUM_SCENARIOS; ++i)
  {
    const struct scenario *const s = scenarios + i;

    if ((NULL != only_scen) && (0 != strcmp (only_scen, s->name)))
      continue;
    if ((discp < s->min_discp) || (discp > s->max_discp))
    {
      scen_skipped++;
      if (1 < verbose)
        printf ("    %-22s skipped (needs discipline level %d..%d)\n",
                s->name, s->min_discp, s->max_discp);
      continue;
    }
    run_scenario (s);
    if (MAX_FAILURES < failures)
      break;
  }
  cur_scen = NULL;
  extern_daemon = NULL;
  MHD_stop_daemon (d);
  return 0;
}


int
main (int argc, char *const *argv)
{
  const uint64_t t_start = now_ms ();
  const struct MHD_OptMatrixProfile *env_prof;
  const char *only = NULL;
  unsigned int num_prof;
  unsigned int i;
  int ret;

  for (i = 1; i < (unsigned int) argc; ++i)
  {
    if ((0 == strcmp (argv[i], "-v")) || (0 == strcmp (argv[i], "--verbose")))
      verbose++;
    else if (0 == strncmp (argv[i], "--profile=", 10))
      only = argv[i] + 10;
    else if (0 == strncmp (argv[i], "--scenario=", 11))
      only_scen = argv[i] + 11;
    else if (0 == strcmp (argv[i], "--list-profiles"))
    {
      unsigned int p;

      for (p = 0; p < mhd_opt_matrix_num_profiles (); ++p)
        printf ("%s\n", mhd_opt_matrix_profile (p)->name);
      return 0;
    }
  }

  strcpy (cur_prof_desc, "(not started)");

#if defined(HAVE_SIGNAL_H) && defined(SIGPIPE)
  if (MHD_YES != MHD_is_feature_supported (MHD_FEATURE_AUTOSUPPRESS_SIGPIPE))
  {
    if (SIG_ERR == signal (SIGPIPE, SIG_IGN))
      hard_error ("Cannot suppress the SIGPIPE signal");
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
  mhd_opt_matrix_print_notice ("test_option_matrix");

  env_prof = mhd_opt_matrix_from_env ();
  if (NULL != only)
  {
    /* The command line wins over the environment. */
    env_prof = mhd_opt_matrix_lookup (only);
    if (NULL == env_prof)
    {
      fprintf (stderr, "Unknown profile '%s'.\n", only);
      return 99;
    }
  }
  if (NULL != env_prof)
  {
    if (! mhd_opt_matrix_profile_supported (env_prof))
    {
      char desc[256];

      printf ("test_option_matrix: the selected profile %s is not supported "
              "by this build, the test is skipped.\n",
              mhd_opt_matrix_describe (env_prof, desc, sizeof(desc)));
      return 77;
    }
    num_prof = 1;
    ret = run_profile (env_prof);
    if (0 != ret)
      return ret;
  }
  else
  {
    num_prof = mhd_opt_matrix_num_profiles ();
    for (i = 0; i < num_prof; ++i)
    {
      ret = run_profile (mhd_opt_matrix_profile (i));
      if (0 != ret)
        return ret;
      if (MAX_FAILURES < failures)
        break;
    }
    if (num_prof == prof_skipped)
    {
      printf ("test_option_matrix: no profile of the matrix is supported by "
              "this build, the test is skipped.\n");
      return 77;
    }
  }

  printf ("\ntest_option_matrix: %u profile(s) (%lu skipped), "
          "%u scenario(s), %lu combinations executed "
          "(%lu pool-limited, %lu out of the discipline range), %.1f s\n",
          num_prof,
          prof_skipped,
          (unsigned int) NUM_SCENARIOS,
          combos,
          combos_degraded,
          scen_skipped,
          (double) (now_ms () - t_start) / 1000.0);
  if (0 != failures)
  {
    printf ("test_option_matrix: FAILED (%lu failure(s))\n", failures);
    fflush (stdout);
    return 1;
  }
  printf ("test_option_matrix: PASSED\n");
  fflush (stdout);
  return 0;
}
