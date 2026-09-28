/*
  This file is part of libmicrohttpd
  Copyright (C) 2026 Christian Grothoff

  This library is free software; you can redistribute it and/or
  modify it under the terms of the GNU Lesser General Public
  License as published by the Free Software Foundation; either
  version 2.1 of the License, or (at your option) any later version.

  This library is distributed in the hope that it will be useful,
  but WITHOUT ANY WARRANTY; without even the implied warranty of
  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
  Lesser General Public License for more details.

  You should have received a copy of the GNU Lesser General Public
  License along with this library.
  If not, see <http://www.gnu.org/licenses/>.
*/

/**
 * @file fuzz/fuzz_request.c
 * @brief End-to-end in-process fuzzer for the MHD request parser.
 * @author Christian Grothoff
 *
 * A real `struct MHD_Daemon` is created with #MHD_USE_NO_LISTEN_SOCKET
 * and driven through a `socketpair()` that is handed to MHD with
 * #MHD_add_connection().  The daemon runs in external-polling mode, so
 * everything happens in the fuzzer's thread: fully deterministic, no
 * TCP stack, no ports, no races.
 *
 * Input format (see README):
 *
 *   byte 0   configuration: connection memory limit
 *   byte 1   configuration: handler behaviour bitmask
 *   byte 2   configuration: client discipline / insanity level
 *   byte 3   configuration: digest-auth parameters
 *   byte 4   response construction: which MHD_create_response_*()
 *            to use, how many response headers to add, footers,
 *            header-manipulation API
 *   byte 5   which authentication entry point to call: the v1/v2
 *            compatibility wrappers, the username/request-info
 *            queries, or the differing fail-response variants
 *   byte 6   event-loop mode (MHD_run() vs MHD_get_fdset*() +
 *            MHD_run_from_select*()) and the connection-introspection
 *            calls
 *   byte 7   suspend/resume and HTTP "Upgrade"
 *   byte 8   seed for the generated response header names/values
 *   byte 9   seed for the content-reader callback behaviour
 *   byte 10. a sequence of send-segments, each introduced by a
 *            little-endian 16 bit header  (op << 14) | length
 *              op 0  send the payload
 *              op 1  the payload is the *expected* decoded request body
 *                    (ground truth for the body oracle); nothing is sent
 *              op 2  send the payload and pump the daemon extra rounds
 *              op 3  close the connection, open a fresh one, send
 *
 * All ten configuration bytes are always present; an input shorter
 * than that is rejected outright.  The all-zero configuration is the
 * plainest one -- a static two byte buffer response, MHD_run() as the
 * event loop, no suspend, no upgrade, no extra introspection -- so
 * zeroing bytes 4-9 of any input reduces it to what the harness did
 * before those bytes existed.
 *
 * Splitting the byte stream into explicit segments matters: MHD's
 * parser is incremental and several past bugs only showed up for
 * particular split points.
 *
 * The literal ASCII token "%%NONCE%%" inside a segment is replaced,
 * at send time, by the most recent `nonce="..."` value seen in a
 * response from the daemon.  This is what allows the fuzzer to walk
 * through the Digest-Auth challenge/response handshake and reach the
 * code that is only executed for a *valid* nonce.
 */

/* Must precede every #include: memfd_create() and MFD_CLOEXEC are only
   declared by <sys/mman.h> under _GNU_SOURCE, and the OSS-Fuzz build
   compiles this file with nothing but -DFUZZ_NO_MAIN (the library gets
   _GNU_SOURCE from configure, the hand-compiled harnesses do not).
   Without this the fd-backed response kinds silently fall back to a
   buffer response and MHD_create_response_from_fd*() is never reached
   -- a failure mode with no error message at all. */
#ifndef _GNU_SOURCE
#define _GNU_SOURCE 1
#endif

#define FUZZ_HARNESS_NAME "fuzz_request"
#include "fuzz_common.h"

#include <microhttpd.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <sys/select.h>

/* MHD_create_response_from_data() and MHD_create_response_from_buffer()
   with an explicit MHD_ResponseMemoryMode are deprecated but are still
   shipped API and are therefore still worth fuzzing; the deprecation
   warning would otherwise drown the build output. */
#if defined(__GNUC__) || defined(__clang__)
#pragma GCC diagnostic ignored "-Wdeprecated-declarations"
#endif

/* memfd_create() gives a file descriptor backed by anonymous memory,
   which is what makes the MHD_create_response_from_fd*() variants
   affordable at fuzzing rates: no filesystem is touched.  Where it is
   unavailable the fd-backed response kinds fall back to a buffer
   response (see make_response()). */
#if defined(__linux__)
#include <sys/mman.h>
#if defined(MFD_CLOEXEC)
#define FUZZ_HAVE_MEMFD 1
#endif
#endif

#define MAX_SEGMENTS 96
#define MAX_CONNECTIONS 8
#define RESP_BUF_SIZE 16384
#define GEN_BUF_SIZE 8192
#define MAX_EXPECT_BODY 4096

/** Number of entries in the response-construction table. */
#define RESP_KIND_COUNT 16
/** Number of authentication entry points selectable by byte 5. */
#define DAUTH_VARIANT_COUNT 10
/** Largest digest MHD_digest_auth_calc_userdigest() can produce. */
#define MAX_DIGEST_BIN 64

#define DIGEST_REALM "TestRealm"
#define DIGEST_USER "user"
#define DIGEST_PASS "pass"

/* ------------------------------------------------------------------ */
/* Per-iteration state                                                 */
/* ------------------------------------------------------------------ */

struct fuzz_cfg
{
  size_t mem_limit;
  int discipline;
  unsigned int insanity;
  unsigned int nonce_nc_size;
  enum MHD_DigestAuthMultiAlgo3 algo;
  enum MHD_DigestAuthMultiQOP qop;
  int do_digest;
  int do_basic;
  int do_postproc;
  int do_iterate;
  int chunked_reply;
  int error_reply;

  /* ---- configuration bytes 4-9; all zero is the plainest setting ---- */
  unsigned int resp_kind;      /**< index into the response constructors */
  unsigned int resp_nhdr;      /**< how many response headers to add */
  int resp_footer;             /**< also add a response footer/trailer */
  int resp_hdr_api;            /**< exercise get/del/set_response_options */
  unsigned int dauth_variant;  /**< which digest entry point to call */
  unsigned int fail_variant;   /**< which *_fail_response to queue */
  int basic_v1;                /**< use the v1 basic-auth getter */
  int calc_helpers;            /**< call the userdigest/userhash helpers */
  unsigned int loop_mode;      /**< 0 MHD_run, 1..3 external event loop */
  int use_timeouts;            /**< query MHD_get_timeout*() while pumping */
  int conn_lookup;             /**< MHD_lookup_connection_value*() */
  int conn_setvalue;           /**< MHD_set_connection_value() */
  int conn_info;               /**< MHD_get_connection_info/daemon_info */
  int conn_option;             /**< MHD_set_connection_option() */
  int quiesce;                 /**< MHD_quiesce_daemon() before stopping */
  unsigned int suspend_mode;   /**< 0 none, 1 immediate, 2 deferred */
  int allow_upgrade;           /**< MHD_ALLOW_UPGRADE + upgrade response */
  unsigned int upgrade_action; /**< which MHD_upgrade_action() to issue */
  uint8_t hdr_seed;            /**< picks response header name/value */
  uint8_t crc_seed;            /**< content-reader callback behaviour */
};

static struct fuzz_cfg cfg;

/** Most recent nonce harvested from a 401 response. */
static char nonce_val[192];
static size_t nonce_len;

/** Ground-truth body of a generated (pristine) request, see README. */
static uint8_t expect_body[MAX_EXPECT_BODY];
static size_t expect_body_len;
static int oracle_on;

/** Statistics, printed at exit with --verbose. */
static unsigned long stat_daemons;
static unsigned long stat_handler_calls;
static unsigned long stat_final_calls;
static unsigned long stat_body_bytes;
static unsigned long stat_challenges;
static unsigned long stat_auth_ok;
static int stats_registered;


static void
print_stats (void)
{
  if (! fuzz_verbose)
    return;
  fprintf (stderr,
           "%s: daemons=%lu handler calls=%lu (final=%lu) body bytes=%lu "
           "401 challenges=%lu authenticated=%lu\n",
           FUZZ_HARNESS_NAME,
           stat_daemons, stat_handler_calls, stat_final_calls,
           stat_body_bytes, stat_challenges, stat_auth_ok);
}


/** Bytes received from the daemon during the current iteration. */
static char resp_buf[RESP_BUF_SIZE];
static size_t resp_len;

static const size_t mem_limit_tbl[] = {
  0 /* MHD default */, 128, 192, 256, 320, 384, 512, 768, 1024, 1400, 1500,
  2048, 4096, 32768
};

static const int discipline_tbl[] = { -3, -2, -1, 0, 1, 2 };

/**
 * Lower bound for MHD_OPTION_CLIENT_DISCIPLINE_LVL, -3 is the full
 * range.  On a tree without the patches listed in README section 6,
 * levels below 0 reach two stale mhd_assert()s in get_req_header();
 * set MHD_FUZZ_MIN_DISCIPLINE=0 there so that the rest of the state
 * space keeps being explored.
 */
static int min_discipline = -3;
static int min_discipline_read;

/**
 * Restrict the generator to a single grammar shape (see enum gen_shape).
 * -1 (the default) means "pick a random shape every time".  Set with
 * MHD_FUZZ_SHAPE=<n>; handy for triage and for regression testing a
 * specific past bug.
 */
static int forced_shape = -1;
static int forced_shape_read;

/**
 * Lower bound for MHD_OPTION_CONNECTION_MEMORY_LIMIT.  0 (the default)
 * fuzzes the full range, including the 128 byte pools that are needed
 * to reach the read-buffer "shift back" code.  On a tree without the
 * patches listed in README section 6, pools below ~500 bytes combined
 * with a chunked request body reach two mhd_assert()s in connection.c;
 * set MHD_FUZZ_MIN_MEM_LIMIT=512 there.
 */
static size_t min_mem_limit;
static int min_mem_limit_read;

static const enum MHD_DigestAuthMultiAlgo3 algo_tbl[] = {
  MHD_DIGEST_AUTH_MULT_ALGO3_SHA256,
  MHD_DIGEST_AUTH_MULT_ALGO3_MD5,
  MHD_DIGEST_AUTH_MULT_ALGO3_SHA512_256,
  MHD_DIGEST_AUTH_MULT_ALGO3_SHA256
};

static const unsigned int nnc_tbl[] = { 4, 1, 8, 64 };

/** Fixed entropy so that nonces are reproducible across runs. */
static const char digest_rnd[32] =
  "\x01\x23\x45\x67\x89\xab\xcd\xef\x01\x23\x45\x67\x89\xab\xcd\xef"
  "\xfe\xdc\xba\x98\x76\x54\x32\x10\xfe\xdc\xba\x98\x76\x54\x32\x10";


/* ------------------------------------------------------------------ */
/* Configuration byte 4: response construction                       */
/* ------------------------------------------------------------------ */

/* Defined with the access handler further down; decorate_response()
   hands it to MHD_get_response_headers(). */
static enum MHD_Result
kv_iter (void *cls,
         enum MHD_ValueKind kind,
         const char *key,
         const char *value);

/** Daemon of the current iteration; needed by MHD_get_daemon_info(). */
static struct MHD_Daemon *cur_daemon;

/**
 * Connections suspended by suspend mode 2, which the pump loop still has
 * to resume.  An entry is cleared by completed_cb() so that a connection
 * MHD has finished with is never resumed afterwards.
 *
 * This has to be a set, not a single slot: op 3 opens a fresh connection
 * without waiting for the previous one to finish, so several connections
 * can be parked at the same time.  A single slot silently loses all but
 * the last, and the forgotten one is still suspended when the iteration
 * calls MHD_stop_daemon(), which answers with
 * MHD_PANIC ("MHD_stop_daemon() called while we have suspended
 * connections") -- a harness bug that looks exactly like an MHD bug.
 */
static struct MHD_Connection *pending_resume[MAX_CONNECTIONS];

/**
 * Set once the iteration has stopped feeding the daemon and only wants
 * to drain it.  suspend_maybe() then does nothing, which is what makes
 * the flush loop in the teardown provably terminate: without it,
 * resuming a connection lets the handler run and park it again, for as
 * many rounds as there are pipelined requests still buffered.
 */
static int tearing_down;


/**
 * Record @a c as suspended.  Silently ignores the overflow case: the
 * array has one slot per connection the harness can open, so it cannot
 * overflow, and a dropped entry would only cost the resume below.
 */
static void
pending_resume_add (struct MHD_Connection *c)
{
  unsigned int i;

  for (i = 0; i < MAX_CONNECTIONS; i++)
  {
    if (NULL == pending_resume[i])
    {
      pending_resume[i] = c;
      return;
    }
  }
}


/** Forget @a c without resuming it (it is gone). */
static void
pending_resume_drop (const struct MHD_Connection *c)
{
  unsigned int i;

  for (i = 0; i < MAX_CONNECTIONS; i++)
    if (pending_resume[i] == c)
      pending_resume[i] = NULL;
}


/**
 * Resume everything still parked.
 *
 * @return non-zero if at least one connection was resumed, so that the
 *         caller knows the daemon needs another round to act on it
 */
static int
pending_resume_flush (void)
{
  unsigned int i;
  int any = 0;

  for (i = 0; i < MAX_CONNECTIONS; i++)
  {
    struct MHD_Connection *c = pending_resume[i];

    if (NULL == c)
      continue;
    /* Clear first: MHD_resume_connection() can run the handler, which
       may suspend the very same connection again. */
    pending_resume[i] = NULL;
    MHD_resume_connection (c);
    any = 1;
  }
  return any;
}


/** Body used by the buffer / fd / pipe / iovec response kinds. */
static const char resp_body[] = "hello world, this is the response body";
#define RESP_BODY_LEN (sizeof (resp_body) - 1)

/**
 * Response header names and values, indexed by cfg.hdr_seed.  The list
 * mixes ordinary headers with ones MHD has to reject or handle
 * specially: an empty name, a name carrying a control character, and a
 * value containing CRLF -- the classic response-splitting vector, which
 * MHD_add_response_header() is supposed to refuse.  Exercising that
 * validator is the point of this table.
 *
 * The message-framing headers are deliberately NOT here.  MHD generates
 * Content-Length and Transfer-Encoding itself from the response object,
 * so an application that also sets them by hand is lying to the library
 * about its own body: a manual "Transfer-Encoding: chunked" on, say, an
 * iovec response sends MHD down the chunked path for a response that
 * has neither a content reader nor a flat buffer, and it aborts in
 * try_ready_chunked_body().  That is the harness misusing the API
 * rather than a defect worth reporting, and leaving it in would bury
 * every real finding under the same false report.  MHD_RF_INSANITY_-
 * HEADER_CONTENT_LENGTH, set through MHD_set_response_options() in
 * decorate_response(), is the sanctioned way to explore that corner.
 */
static const char *const hdr_names[] = {
  "X-Fuzz", "Content-Type", "Cache-Control", "Accept-Ranges",
  /* "\x01" is split from the rest so that the hex escape stops after
     one digit instead of swallowing the following "Bad". */
  "Connection", "Set-Cookie", "X-\x01" "Bad", "", "Trailer", "Date",
  "X-Fuzz", "Server", "Location", "ETag", "Vary", "Age"
};

static const char *const hdr_values[] = {
  "1", "text/plain", "no-cache", "bytes", "keep-alive", "a=b",
  "x\r\nInjected: yes", "", "X-Fuzz", "Thu, 01 Jan 1970 00:00:00 GMT",
  "\x7f", "mhd", "/", "\"tag\"", "*", "0"
};

#define HDR_COUNT (sizeof (hdr_names) / sizeof (hdr_names[0]))


/**
 * State of one MHD_create_response_from_callback() response.  Allocated
 * per response and released through the free callback that MHD invokes
 * from MHD_destroy_response().
 */
struct crc_state
{
  uint64_t total;      /**< bytes to produce before end-of-stream */
  int calls;           /**< how often the reader has been called */
  int err_at;          /**< fail after this many calls, -1 to never fail */
  unsigned int pattern;
};


static ssize_t
crc_cb (void *cls,
        uint64_t pos,
        char *buf,
        size_t max)
{
  struct crc_state *st = (struct crc_state *) cls;
  size_t n;
  size_t i;

  st->calls++;
  /* Deliberately reachable: an application content reader is allowed to
     fail half way through a response body, and how MHD terminates the
     connection in that case (especially a chunked one that can no
     longer be framed correctly) is worth exercising. */
  if ( (0 <= st->err_at) &&
       (st->calls > st->err_at) )
    return MHD_CONTENT_READER_END_WITH_ERROR;
  if (pos >= st->total)
    return MHD_CONTENT_READER_END_OF_STREAM;
  n = (size_t) (st->total - pos);
  if (n > max)
    n = max;
  if (0 == n)
    return MHD_CONTENT_READER_END_OF_STREAM;
  for (i = 0; i < n; i++)
    buf[i] = (char) ('a' + (int) ((pos + i + st->pattern) % 26));
  return (ssize_t) n;
}


static void
crc_free (void *cls)
{
  free (cls);
}


/**
 * Handler for an upgraded ("101 Switching Protocols") connection.
 *
 * @a extra_in holds whatever the client had already pipelined behind
 * the request, which is attacker-controlled and therefore read here.
 *
 * The connection MUST be closed through MHD_upgrade_action(): the
 * socket belongs to the application from this point on and
 * MHD_stop_daemon() cannot complete while an upgraded connection is
 * still outstanding.
 */
static void
upgrade_cb (void *cls,
            struct MHD_Connection *connection,
            void *req_cls,
            const char *extra_in,
            size_t extra_in_size,
            MHD_socket sock,
            struct MHD_UpgradeResponseHandle *urh)
{
  volatile size_t sink = 0;

  (void) cls;
  (void) connection;
  (void) req_cls;
  (void) sock;
  if ( (NULL != extra_in) &&
       (0 != extra_in_size) )
    sink += (size_t) (unsigned char) extra_in[extra_in_size - 1];
  (void) sink;
  if (0 != (cfg.upgrade_action & 0x01u))
    (void) MHD_upgrade_action (urh, MHD_UPGRADE_ACTION_CORK_ON);
  if (0 != (cfg.upgrade_action & 0x02u))
    (void) MHD_upgrade_action (urh, MHD_UPGRADE_ACTION_CORK_OFF);
  (void) MHD_upgrade_action (urh, MHD_UPGRADE_ACTION_CLOSE);
}


/**
 * A file descriptor holding RESP_BODY_LEN bytes, backed by anonymous
 * memory so that no filesystem is involved.
 *
 * @return -1 if unavailable, in which case the caller falls back to a
 *         buffer response
 */
static int
make_memfd (void)
{
#ifdef FUZZ_HAVE_MEMFD
  int fd;

  fd = memfd_create ("mhd-fuzz", MFD_CLOEXEC);
  if (0 > fd)
    return -1;
  if (RESP_BODY_LEN != (size_t) write (fd, resp_body, RESP_BODY_LEN))
  {
    (void) close (fd);
    return -1;
  }
  return fd;
#else
  return -1;
#endif
}


/**
 * The read end of a pipe holding RESP_BODY_LEN bytes.  The body is far
 * below the pipe capacity, so the write cannot block.
 */
static int
make_pipe_fd (void)
{
  int pf[2];

  if (0 != pipe (pf))
    return -1;
  if (RESP_BODY_LEN != (size_t) write (pf[1], resp_body, RESP_BODY_LEN))
  {
    (void) close (pf[0]);
    (void) close (pf[1]);
    return -1;
  }
  (void) close (pf[1]);
  return pf[0];
}


/**
 * Add response headers, footers and option flags as selected by byte 4
 * and the header seed in byte 8.
 *
 * Footers are only meaningful for a chunked response -- MHD emits them
 * as trailers after the last chunk -- which is why they are worth
 * fuzzing together with the callback-based response kinds.
 */
static void
decorate_response (struct MHD_Response *r)
{
  unsigned int i;

  for (i = 0; i < cfg.resp_nhdr; i++)
  {
    unsigned int k = (cfg.hdr_seed + i) % HDR_COUNT;

    (void) MHD_add_response_header (r, hdr_names[k], hdr_values[k]);
  }
  if (cfg.resp_footer)
  {
    unsigned int k = (unsigned int) (cfg.hdr_seed + 1u) % HDR_COUNT;

    (void) MHD_add_response_footer (r, hdr_names[k], hdr_values[k]);
  }
  if (cfg.resp_hdr_api)
  {
    unsigned int k = cfg.hdr_seed % HDR_COUNT;
    volatile size_t sink = 0;
    const char *v;

    v = MHD_get_response_header (r, hdr_names[k]);
    if (NULL != v)
      sink += strlen (v);
    (void) sink;
    (void) MHD_get_response_headers (r, &kv_iter, NULL);
    (void) MHD_del_response_header (r, hdr_names[k], hdr_values[k]);
    (void) MHD_set_response_options (r,
                                     (enum MHD_ResponseFlags)
                                     (((cfg.hdr_seed & 0x01) ?
                                       MHD_RF_HTTP_VERSION_1_0_RESPONSE : 0)
                                      | ((cfg.hdr_seed & 0x02) ?
                                         MHD_RF_SEND_KEEP_ALIVE_HEADER : 0)
                                      | ((cfg.hdr_seed & 0x04) ?
                                         MHD_RF_INSANITY_HEADER_CONTENT_LENGTH
                                         : 0)
                                      | ((cfg.hdr_seed & 0x08) ?
                                         MHD_RF_HEAD_ONLY_RESPONSE : 0)),
                                     MHD_RO_END);
  }
}


/**
 * Build the response body for this iteration.
 *
 * Every constructor that fails is responsible for nothing: MHD releases
 * neither the buffer nor the file descriptor when it returns NULL (see
 * MHD_create_response_from_buffer_with_free_callback_cls() and
 * MHD_create_response_from_pipe() in response.c), so ownership stays
 * here and the resource has to be released explicitly.  Getting this
 * backwards would produce double frees that look exactly like MHD bugs.
 */
static struct MHD_Response *
make_response (void)
{
  struct MHD_Response *r = NULL;
  struct crc_state *st;
  void *heap;
  int fd;

  switch (cfg.resp_kind)
  {
  case 0:
    /* The two responses the harness used before byte 4 existed.  Bit
       0x20 of byte 1 (cfg.chunked_reply) selects between them and has
       no other effect, so keeping the pair here is what keeps that bit
       meaningful. */
    if (cfg.chunked_reply)
      r = MHD_create_response_from_buffer_copy (11, "hello world");
    else
      r = MHD_create_response_from_buffer_static (2, "ok");
    break;
  case 1:
    r = MHD_create_response_from_buffer_copy (RESP_BODY_LEN, resp_body);
    break;
  case 2:
    r = MHD_create_response_empty (MHD_RF_NONE);
    break;
  case 3:
    r = MHD_create_response_from_buffer (RESP_BODY_LEN,
                                         (void *) (intptr_t) resp_body,
                                         MHD_RESPMEM_PERSISTENT);
    break;
  case 4:
    heap = malloc (RESP_BODY_LEN);
    if (NULL == heap)
      return NULL;
    memcpy (heap, resp_body, RESP_BODY_LEN);
    r = MHD_create_response_from_buffer (RESP_BODY_LEN,
                                         heap,
                                         MHD_RESPMEM_MUST_FREE);
    if (NULL == r)
      free (heap);
    break;
  case 5:
    r = MHD_create_response_from_buffer (RESP_BODY_LEN,
                                         (void *) (intptr_t) resp_body,
                                         MHD_RESPMEM_MUST_COPY);
    break;
  case 6:
    heap = malloc (RESP_BODY_LEN);
    if (NULL == heap)
      return NULL;
    memcpy (heap, resp_body, RESP_BODY_LEN);
    r = MHD_create_response_from_buffer_with_free_callback (RESP_BODY_LEN,
                                                            heap,
                                                            &free);
    if (NULL == r)
      free (heap);
    break;
  case 7:
    r = MHD_create_response_from_data (RESP_BODY_LEN,
                                       (void *) (intptr_t) resp_body,
                                       0 /* must_free */,
                                       1 /* must_copy */);
    break;
  case 8:
    heap = malloc (RESP_BODY_LEN);
    if (NULL == heap)
      return NULL;
    memcpy (heap, resp_body, RESP_BODY_LEN);
    r = MHD_create_response_from_data (RESP_BODY_LEN,
                                       heap,
                                       1 /* must_free */,
                                       0 /* must_copy */);
    if (NULL == r)
      free (heap);
    break;
  case 9:
  case 10:
    st = (struct crc_state *) calloc (1, sizeof (struct crc_state));
    if (NULL == st)
      return NULL;
    st->total = (uint64_t) (1u + (cfg.crc_seed & 0x7Fu));
    st->pattern = cfg.crc_seed;
    /* Injecting a reader error is only interesting some of the time;
       otherwise the body would rarely complete. */
    st->err_at = (0 != (cfg.crc_seed & 0x80u))
                 ? (int) (1u + (cfg.crc_seed & 0x03u))
                 : -1;
    r = MHD_create_response_from_callback (
      (9 == cfg.resp_kind) ? st->total : MHD_SIZE_UNKNOWN,
      (size_t) (16u + (cfg.crc_seed & 0x3Fu)),
      &crc_cb,
      st,
      &crc_free);
    if (NULL == r)
      free (st);
    break;
  case 11:
  case 12:
  case 13:
    fd = make_memfd ();
    if (0 > fd)
    {
      r = MHD_create_response_from_buffer_static (2, "ok");
      break;
    }
    if (11 == cfg.resp_kind)
      r = MHD_create_response_from_fd (RESP_BODY_LEN, fd);
    else if (12 == cfg.resp_kind)
      /* Parenthesised so that the deprecated *function* is called and
         not the same-named macro that redirects to the 64 bit variant;
         reaching the v1 entry point is the whole point here. */
      r = (MHD_create_response_from_fd_at_offset) (
        RESP_BODY_LEN / 2,
        fd,
        (off_t) (RESP_BODY_LEN / 4));
    else
      r = MHD_create_response_from_fd64 ((uint64_t) RESP_BODY_LEN, fd);
    if (NULL == r)
      (void) close (fd);
    break;
  case 14:
    fd = make_pipe_fd ();
    if (0 > fd)
    {
      r = MHD_create_response_from_buffer_static (2, "ok");
      break;
    }
    r = MHD_create_response_from_pipe (fd);
    if (NULL == r)
      (void) close (fd);
    break;
  case 15:
  default:
    {
      static struct MHD_IoVec iov[3];

      /* Static data, so no free callback is needed; MHD copies the
         array itself (see the documentation of the @a iov parameter). */
      iov[0].iov_base = resp_body;
      iov[0].iov_len = RESP_BODY_LEN / 2;
      iov[1].iov_base = resp_body + (RESP_BODY_LEN / 2);
      iov[1].iov_len = RESP_BODY_LEN - (RESP_BODY_LEN / 2);
      iov[2].iov_base = resp_body;
      iov[2].iov_len = (size_t) (cfg.crc_seed % (RESP_BODY_LEN + 1));
      r = MHD_create_response_from_iovec (iov,
                                          (0 != iov[2].iov_len) ? 3u : 2u,
                                          NULL,
                                          NULL);
    }
    break;
  }
  if (NULL != r)
    decorate_response (r);
  return r;
}


/* ------------------------------------------------------------------ */
/* Access handler                                                      */
/* ------------------------------------------------------------------ */

struct hstate
{
  size_t body_off;
  struct MHD_PostProcessor *pp;
  int pp_tried;
};


static enum MHD_Result
kv_iter (void *cls,
         enum MHD_ValueKind kind,
         const char *key,
         const char *value)
{
  volatile size_t sink = 0;

  (void) cls;
  (void) kind;
  if (NULL != key)
    sink += strlen (key);
  if (NULL != value)
    sink += strlen (value);
  (void) sink;
  return MHD_YES;
}


/**
 * Length-aware counterpart of kv_iter(), for
 * MHD_get_connection_values_n().  Unlike the NUL-terminated iterator it
 * is handed explicit sizes, so it reads exactly what MHD says is there
 * rather than trusting a terminator.
 */
static enum MHD_Result
kv_iter_n (void *cls,
           enum MHD_ValueKind kind,
           const char *key,
           size_t key_size,
           const char *value,
           size_t value_size)
{
  volatile size_t sink = 0;

  (void) cls;
  (void) kind;
  if ( (NULL != key) && (0 != key_size) )
    sink += (size_t) (unsigned char) key[key_size - 1];
  if ( (NULL != value) && (0 != value_size) )
    sink += (size_t) (unsigned char) value[value_size - 1];
  (void) sink;
  return MHD_YES;
}


static enum MHD_Result
post_iter (void *cls,
           enum MHD_ValueKind kind,
           const char *key,
           const char *filename,
           const char *content_type,
           const char *transfer_encoding,
           const char *data,
           uint64_t off,
           size_t size)
{
  volatile size_t sink = 0;

  (void) cls;
  (void) kind;
  (void) off;
  if (NULL != key)
    sink += strlen (key);
  if (NULL != filename)
    sink += strlen (filename);
  if (NULL != content_type)
    sink += strlen (content_type);
  if (NULL != transfer_encoding)
    sink += strlen (transfer_encoding);
  if ( (NULL != data) && (0 != size) )
    sink += (size_t) (unsigned char) data[size - 1];
  (void) sink;
  return MHD_YES;
}


/**
 * Check the body MHD hands to the application against the body that
 * the generator encoded into the request.  MHD is allowed to reject
 * the request at any point, but every byte that it *does* deliver must
 * be the next expected byte.  A mismatch means the framing layer
 * (Content-Length or chunked transfer coding) got out of sync, which
 * is exactly the class of bug that enables request smuggling.
 */
static void
oracle_check_body (struct hstate *hs,
                   const char *data,
                   size_t size)
{
  if ( (! oracle_on) ||
       (0 == size) )
    return;
  if ( (hs->body_off + size > expect_body_len) ||
       (0 != memcmp (expect_body + hs->body_off, data, size)) )
    fuzz_report_finding (
      "request body desync: the bytes MHD delivered to the application "
      "differ from the body encoded in the generated request "
      "(chunked/Content-Length framing bug, cf. HTTP request smuggling)");
  hs->body_off += size;
}


/* ------------------------------------------------------------------ */
/* Configuration byte 5: authentication entry points                 */
/* ------------------------------------------------------------------ */

static const enum MHD_DigestAuthAlgorithm algo1_tbl[] = {
  MHD_DIGEST_ALG_AUTO,
  MHD_DIGEST_ALG_MD5,
  MHD_DIGEST_ALG_SHA256,
  MHD_DIGEST_ALG_AUTO
};

static const enum MHD_DigestAuthAlgo3 algo3_tbl[] = {
  MHD_DIGEST_AUTH_ALGO3_MD5,
  MHD_DIGEST_AUTH_ALGO3_SHA256,
  MHD_DIGEST_AUTH_ALGO3_SHA512_256,
  MHD_DIGEST_AUTH_ALGO3_MD5_SESSION,
  MHD_DIGEST_AUTH_ALGO3_SHA256_SESSION,
  MHD_DIGEST_AUTH_ALGO3_SHA512_256_SESSION,
  MHD_DIGEST_AUTH_ALGO3_MD5,
  MHD_DIGEST_AUTH_ALGO3_SHA256
};

/** Outcome of run_digest_check(). */
#define DAUTH_CHALLENGE 0
#define DAUTH_PASSED    1
#define DAUTH_STALE     2


/**
 * Exercise the digest helpers that take no connection:
 * MHD_digest_get_hash_size(), MHD_digest_auth_calc_userdigest(),
 * MHD_digest_auth_calc_userhash() and
 * MHD_digest_auth_calc_userhash_hex().
 *
 * The output buffers are heap allocations of *exactly* the size that is
 * passed to MHD, and that size is deliberately varied down to zero.  A
 * correct implementation must reject every buffer that is too small; if
 * it instead writes the full digest, ASAN's redzone catches it
 * immediately.  This is the shape of the bug fixed in commit 5a73c1ae,
 * where an over-long userhash overflowed a fixed-size decode buffer.
 */
static void
call_calc_helpers (void)
{
  enum MHD_DigestAuthAlgo3 a = algo3_tbl[cfg.hdr_seed
                                         % (sizeof (algo3_tbl)
                                            / sizeof (algo3_tbl[0]))];
  size_t hs;
  size_t claim;
  void *bin;
  char *hex;

  hs = MHD_digest_get_hash_size (a);
  if ( (0 == hs) ||
       (hs > MAX_DIGEST_BIN) )
    return;
  claim = hs - (size_t) (cfg.crc_seed % (unsigned int) (hs + 1u));

  bin = malloc (claim);
  if (NULL != bin)
  {
    (void) MHD_digest_auth_calc_userdigest (a,
                                            DIGEST_USER,
                                            DIGEST_REALM,
                                            DIGEST_PASS,
                                            bin,
                                            claim);
    (void) MHD_digest_auth_calc_userhash (a,
                                          DIGEST_USER,
                                          DIGEST_REALM,
                                          bin,
                                          claim);
    free (bin);
  }
  /* The hex form needs 2*hs+1 bytes; ask for less about half the time. */
  claim = (2u * hs + 1u)
          - (size_t) (cfg.hdr_seed % (unsigned int) (2u * hs + 2u));
  hex = (char *) malloc (claim);
  if (NULL != hex)
  {
    (void) MHD_digest_auth_calc_userhash_hex (a,
                                              DIGEST_USER,
                                              DIGEST_REALM,
                                              hex,
                                              claim);
    free (hex);
  }
}


/**
 * Run the digest-authentication entry point selected by byte 5.
 *
 * Variant 0 is MHD_digest_auth_check3(), which is the plainest one and
 * what the all-zero configuration selects.  Variants 1-5 are the v1/v2 compatibility
 * wrappers and the pre-computed-digest forms, which do their own buffer
 * sizing and are therefore worth driving directly.  Variants 6-8 are
 * the query functions, which parse the client's Authorization header
 * but return no verdict, so they run *in addition* to check3().
 *
 * @return one of DAUTH_CHALLENGE, DAUTH_PASSED, DAUTH_STALE
 */
static int
run_digest_check (struct MHD_Connection *connection)
{
  unsigned int variant = cfg.dauth_variant;
  enum MHD_DigestAuthResult dres;
  uint8_t ud[MAX_DIGEST_BIN];
  size_t hs;
  int r1;
  volatile size_t sink = 0;

  switch (variant)
  {
  case 1:
    r1 = MHD_digest_auth_check (connection,
                                DIGEST_REALM,
                                DIGEST_USER,
                                DIGEST_PASS,
                                0);
    if (MHD_YES == r1)
      return DAUTH_PASSED;
    return (MHD_INVALID_NONCE == r1) ? DAUTH_STALE : DAUTH_CHALLENGE;
  case 2:
    r1 = MHD_digest_auth_check2 (connection,
                                 DIGEST_REALM,
                                 DIGEST_USER,
                                 DIGEST_PASS,
                                 0,
                                 algo1_tbl[cfg.hdr_seed & 0x03]);
    if (MHD_YES == r1)
      return DAUTH_PASSED;
    return (MHD_INVALID_NONCE == r1) ? DAUTH_STALE : DAUTH_CHALLENGE;
  case 3:
    /* MHD_digest_auth_check_digest() is MD5-only by definition. */
    if (MHD_YES != MHD_digest_auth_calc_userdigest (
          MHD_DIGEST_AUTH_ALGO3_MD5,
          DIGEST_USER, DIGEST_REALM, DIGEST_PASS,
          ud, MHD_MD5_DIGEST_SIZE))
      break;
    r1 = MHD_digest_auth_check_digest (connection,
                                       DIGEST_REALM,
                                       DIGEST_USER,
                                       ud,
                                       0);
    if (MHD_YES == r1)
      return DAUTH_PASSED;
    return (MHD_INVALID_NONCE == r1) ? DAUTH_STALE : DAUTH_CHALLENGE;
  case 4:
  case 5:
    {
      /* The pre-computed-digest entry points are stricter than the
         password-based ones: the digest and the algorithm have to
         agree, and naming more than one base hashing algorithm is an
         MHD_PANIC("API violation") rather than an error return.  So the
         algorithm is chosen first here and the digest, its length and
         the algorithm argument are all derived from that one choice.

         MHD_DIGEST_ALG_AUTO is deliberately not used for variant 4:
         MHD_digest_auth_check_digest2() maps it to
         MULT_ALGO3_ANY_NON_SESSION, which names three base algorithms
         and therefore trips that very panic.  See README section 6. */
      static const enum MHD_DigestAuthAlgo3 digest_algos[] = {
        MHD_DIGEST_AUTH_ALGO3_MD5,
        MHD_DIGEST_AUTH_ALGO3_SHA256,
        MHD_DIGEST_AUTH_ALGO3_SHA512_256,
        MHD_DIGEST_AUTH_ALGO3_MD5_SESSION,
        MHD_DIGEST_AUTH_ALGO3_SHA256_SESSION,
        MHD_DIGEST_AUTH_ALGO3_SHA512_256_SESSION
      };
      enum MHD_DigestAuthAlgo3 a3;

      if (4 == variant)
        /* check_digest2() only knows MD5 and SHA-256. */
        a3 = (0 != (cfg.hdr_seed & 0x01))
             ? MHD_DIGEST_AUTH_ALGO3_SHA256
             : MHD_DIGEST_AUTH_ALGO3_MD5;
      else
        a3 = digest_algos[cfg.hdr_seed
                          % (sizeof (digest_algos)
                             / sizeof (digest_algos[0]))];
      hs = MHD_digest_get_hash_size (a3);
      if ( (0 == hs) ||
           (hs > sizeof (ud)) ||
           (MHD_YES != MHD_digest_auth_calc_userdigest (a3,
                                                        DIGEST_USER,
                                                        DIGEST_REALM,
                                                        DIGEST_PASS,
                                                        ud,
                                                        hs)) )
        break;
      if (4 == variant)
      {
        r1 = MHD_digest_auth_check_digest2 (connection,
                                            DIGEST_REALM,
                                            DIGEST_USER,
                                            ud,
                                            hs,
                                            0,
                                            (MHD_DIGEST_AUTH_ALGO3_SHA256 == a3)
                                            ? MHD_DIGEST_ALG_SHA256
                                            : MHD_DIGEST_ALG_MD5);
        if (MHD_YES == r1)
          return DAUTH_PASSED;
        return (MHD_INVALID_NONCE == r1) ? DAUTH_STALE : DAUTH_CHALLENGE;
      }
      dres = MHD_digest_auth_check_digest3 (connection,
                                            DIGEST_REALM,
                                            DIGEST_USER,
                                            ud,
                                            hs,
                                            0,
                                            0,
                                            cfg.qop,
                                            /* Exactly one base algorithm.
                                               The MULT_ALGO3_* constants are
                                               numerically identical to their
                                               ALGO3_* counterparts. */
                                            (enum MHD_DigestAuthMultiAlgo3) a3);
      if (MHD_DAUTH_OK == dres)
        return DAUTH_PASSED;
      return (MHD_DAUTH_NONCE_STALE == dres) ? DAUTH_STALE : DAUTH_CHALLENGE;
    }
  case 6:
    {
      char *u = MHD_digest_auth_get_username (connection);

      if (NULL != u)
      {
        sink += strlen (u);
        MHD_free (u);
      }
    }
    break;
  case 7:
    {
      struct MHD_DigestAuthUsernameInfo *ui;

      ui = MHD_digest_auth_get_username3 (connection);
      if (NULL != ui)
      {
        if (NULL != ui->username)
          sink += ui->username_len;
        if (NULL != ui->userhash_hex)
          sink += ui->userhash_hex_len;
        MHD_free (ui);
      }
    }
    break;
  case 8:
    {
      struct MHD_DigestAuthInfo *ai;

      ai = MHD_digest_auth_get_request_info3 (connection);
      if (NULL != ai)
      {
        if (NULL != ai->username)
          sink += ai->username_len;
        if (NULL != ai->realm)
          sink += ai->realm_len;
        if (NULL != ai->opaque)
          sink += ai->opaque_len;
        if (NULL != ai->userhash_hex)
          sink += ai->userhash_hex_len;
        sink += ai->cnonce_len;
        sink += (size_t) ai->nc;
        MHD_free (ai);
      }
    }
    break;
  default:
    break;
  }
  (void) sink;

  /* Variant 0, the query variants and every early break end up here. */
  dres = MHD_digest_auth_check3 (connection,
                                 DIGEST_REALM,
                                 DIGEST_USER,
                                 DIGEST_PASS,
                                 0 /* daemon default nonce timeout */,
                                 0 /* daemon default max_nc */,
                                 cfg.qop,
                                 MHD_DIGEST_AUTH_MULT_ALGO3_ANY_NON_SESSION);
  if (MHD_DAUTH_OK == dres)
    return DAUTH_PASSED;
  return (MHD_DAUTH_NONCE_STALE == dres) ? DAUTH_STALE : DAUTH_CHALLENGE;
}


/**
 * Send the "authentication required" reply through the variant of the
 * API selected by byte 5.  The v1/v2 forms take a plain response and an
 * algorithm rather than the qop/algo pair of the v3 form.
 */
static enum MHD_Result
queue_auth_challenge (struct MHD_Connection *connection,
                      int stale)
{
  struct MHD_Response *resp;
  enum MHD_Result ret;

  resp = MHD_create_response_from_buffer_static (0, "");
  if (NULL == resp)
    return MHD_NO;
  switch (cfg.fail_variant)
  {
  case 1:
    ret = MHD_queue_auth_fail_response (connection,
                                        DIGEST_REALM,
                                        "0123456789abcdef",
                                        resp,
                                        stale ? MHD_YES : MHD_NO);
    break;
  case 2:
    ret = MHD_queue_auth_fail_response2 (connection,
                                         DIGEST_REALM,
                                         "0123456789abcdef",
                                         resp,
                                         stale ? MHD_YES : MHD_NO,
                                         algo1_tbl[cfg.hdr_seed & 0x03]);
    break;
  case 3:
    if (0 != (cfg.hdr_seed & 0x01))
      ret = MHD_queue_basic_auth_required_response3 (connection,
                                                     DIGEST_REALM,
                                                     (0 != (cfg.hdr_seed
                                                            & 0x02))
                                                     ? MHD_YES : MHD_NO,
                                                     resp);
    else
      ret = MHD_queue_basic_auth_fail_response (connection,
                                                DIGEST_REALM,
                                                resp);
    break;
  case 0:
  default:
    ret = MHD_queue_auth_required_response3 (connection,
                                             DIGEST_REALM,
                                             "0123456789abcdef" /* opaque */,
                                             "/",
                                             resp,
                                             stale ? MHD_YES : MHD_NO,
                                             cfg.qop,
                                             cfg.algo,
                                             MHD_YES /* userhash */,
                                             MHD_NO);
    break;
  }
  MHD_destroy_response (resp);
  return ret;
}


/* ------------------------------------------------------------------ */
/* Configuration byte 6: connection introspection                    */
/* ------------------------------------------------------------------ */

/**
 * Call the read-only connection accessors on attacker-supplied header
 * data.  MHD_lookup_connection_value*() run the case-insensitive header
 * matcher over whatever the client sent, which is exactly the sort of
 * input the fuzzer is good at producing.
 */
static void
exercise_connection_api (struct MHD_Connection *connection)
{
  volatile size_t sink = 0;

  if (cfg.conn_lookup)
  {
    static const char *const keys[] = {
      "Host", "Content-Length", "Transfer-Encoding", "Authorization",
      "Cookie", "", "X-Fuzz", "connection"
    };
    const char *k = keys[cfg.hdr_seed % (sizeof (keys) / sizeof (keys[0]))];
    const char *v;
    const char *vp = NULL;
    size_t vlen = 0;
    const char *uri = NULL;
    size_t ulen = 0;

    v = MHD_lookup_connection_value (connection, MHD_HEADER_KIND, k);
    if (NULL != v)
      sink += strlen (v);
    if (MHD_YES == MHD_lookup_connection_value_n (connection,
                                                  MHD_HEADER_KIND,
                                                  k,
                                                  strlen (k),
                                                  &vp,
                                                  &vlen))
      sink += vlen;
    if (MHD_YES == MHD_get_connection_URI_path_n (connection, &uri, &ulen))
      sink += ulen;
  }
  if (cfg.conn_setvalue)
    (void) MHD_set_connection_value (connection,
                                     MHD_HEADER_KIND,
                                     "X-Fuzz-Added",
                                     "1");
  if (cfg.conn_info)
  {
    static const enum MHD_ConnectionInfoType cinfo[] = {
      MHD_CONNECTION_INFO_CLIENT_ADDRESS,
      MHD_CONNECTION_INFO_DAEMON,
      MHD_CONNECTION_INFO_CONNECTION_FD,
      MHD_CONNECTION_INFO_SOCKET_CONTEXT,
      MHD_CONNECTION_INFO_CONNECTION_SUSPENDED,
      MHD_CONNECTION_INFO_CONNECTION_TIMEOUT,
      MHD_CONNECTION_INFO_REQUEST_HEADER_SIZE,
      MHD_CONNECTION_INFO_HTTP_STATUS
    };
    static const enum MHD_DaemonInfoType dinfo[] = {
      MHD_DAEMON_INFO_CURRENT_CONNECTIONS,
      MHD_DAEMON_INFO_FLAGS,
      MHD_DAEMON_INFO_LISTEN_FD,
      MHD_DAEMON_INFO_BIND_PORT
    };
    unsigned int i;

    for (i = 0; i < sizeof (cinfo) / sizeof (cinfo[0]); i++)
      if (NULL != MHD_get_connection_info (connection, cinfo[i]))
        sink++;
    for (i = 0; i < sizeof (dinfo) / sizeof (dinfo[0]); i++)
      if ( (NULL != cur_daemon) &&
           (NULL != MHD_get_daemon_info (cur_daemon, dinfo[i])) )
        sink++;
  }
  if (cfg.conn_option)
    (void) MHD_set_connection_option (connection,
                                      MHD_CONNECTION_OPTION_TIMEOUT,
                                      (unsigned int) (cfg.crc_seed & 0x0F));
  if (cfg.conn_info)
  {
    /* Constant-output accessors.  They cannot fail on attacker input,
       but they are cheap and leaving them uncovered makes the coverage
       report harder to read.
       MHD_fini() is deliberately NOT called anywhere: it tears down
       process-global library state, so a single call would break every
       later iteration in the same process. */
    const char *v = MHD_get_version ();

    if (NULL != v)
      sink += strlen (v);
    sink += (size_t) MHD_get_version_bin ();
  }
  (void) sink;
}


/**
 * Suspend the connection if byte 7 asks for it.
 *
 * Mode 1 suspends and resumes straight away, which exercises both state
 * transitions without leaving the connection parked.  Mode 2 leaves it
 * suspended and records it in @e pending_resume so that the pump loop
 * resumes it on its next round; completed_cb() drops the record, so a
 * connection MHD has finished with is never resumed after the fact, and
 * the iteration flushes the whole set before stopping the daemon.  A
 * connection left suspended makes MHD_stop_daemon() MHD_PANIC().
 */
static void
suspend_maybe (struct MHD_Connection *connection)
{
  if ( (0 == cfg.suspend_mode) ||
       tearing_down)
    return;
  MHD_suspend_connection (connection);
  if (1 == cfg.suspend_mode)
  {
    MHD_resume_connection (connection);
    return;
  }
  pending_resume_add (connection);
}


static enum MHD_Result
ahc (void *cls,
     struct MHD_Connection *connection,
     const char *url,
     const char *method,
     const char *version,
     const char *upload_data,
     size_t *upload_data_size,
     void **req_cls)
{
  struct hstate *hs = (struct hstate *) *req_cls;
  struct MHD_Response *resp;
  enum MHD_Result ret;
  volatile size_t sink = 0;
  const char *conn_hdr = NULL;
  char conn_lc[128];

  conn_lc[0] = '\0';
  (void) cls;
  if (NULL == hs)
  {
    hs = (struct hstate *) calloc (1, sizeof (struct hstate));
    if (NULL == hs)
      return MHD_NO;
    *req_cls = hs;
    return MHD_YES;
  }

  stat_handler_calls++;
  /* Touch the parsed request line the way a real application would. */
  if (NULL != url)
    sink += strlen (url);
  if (NULL != method)
    sink += strlen (method);
  if (NULL != version)
    sink += strlen (version);
  (void) sink;

  if (0 != *upload_data_size)
  {
    stat_body_bytes += (unsigned long) *upload_data_size;
    oracle_check_body (hs, upload_data, *upload_data_size);
    if (cfg.do_postproc)
    {
      if ( (NULL == hs->pp) &&
           (! hs->pp_tried) )
      {
        hs->pp_tried = 1;
        hs->pp = MHD_create_post_processor (connection,
                                            1024,
                                            &post_iter,
                                            NULL);
      }
      if (NULL != hs->pp)
        (void) MHD_post_process (hs->pp, upload_data, *upload_data_size);
    }
    *upload_data_size = 0;
    return MHD_YES;
  }

  stat_final_calls++;
  if (cfg.do_iterate)
  {
    const enum MHD_ValueKind kinds = MHD_HEADER_KIND
                                     | MHD_GET_ARGUMENT_KIND
                                     | MHD_COOKIE_KIND
                                     | MHD_FOOTER_KIND;

    /* Alternate between the NUL-terminated iterator and the
       length-aware one, which are separate code paths in MHD. */
    if (0 != (cfg.hdr_seed & 0x10))
      (void) MHD_get_connection_values_n (connection, kinds, &kv_iter_n, NULL);
    else
      (void) MHD_get_connection_values (connection, kinds, &kv_iter, NULL);
  }

  if (oracle_on &&
      (hs->body_off != expect_body_len) )
    fuzz_report_finding (
      "request body truncated: MHD completed the request but delivered "
      "fewer body bytes than the generated request contained");

  exercise_connection_api (connection);

  /* Lower-cased copy of the request's "Connection" header, used by the
     upgrade check further down.  MHD's own token matcher is internal,
     so a plain case-folded substring test is used here; it only has to
     be good enough to keep the harness from queueing an upgrade
     response on a connection that cannot be upgraded. */
  if (cfg.allow_upgrade)
  {
    conn_hdr = MHD_lookup_connection_value (connection,
                                            MHD_HEADER_KIND,
                                            MHD_HTTP_HEADER_CONNECTION);
    if (NULL != conn_hdr)
    {
      size_t i;

      for (i = 0; (i + 1 < sizeof (conn_lc)) && ('\0' != conn_hdr[i]); i++)
        conn_lc[i] = (char) (( ('A' <= conn_hdr[i]) && ('Z' >= conn_hdr[i]))
                             ? (conn_hdr[i] - 'A' + 'a') : conn_hdr[i]);
      conn_lc[i] = '\0';
    }
  }

  if (cfg.do_basic)
  {
    if (cfg.basic_v1)
    {
      /* The v1 getter returns two separate malloc()ed strings and is
         the one that historically had to be freed by hand. */
      char *pass = NULL;
      char *user;

      user = MHD_basic_auth_get_username_password (connection, &pass);
      if (NULL != user)
        sink += strlen (user);
      if (NULL != pass)
        sink += strlen (pass);
      if (NULL != user)
        MHD_free (user);
      if (NULL != pass)
        MHD_free (pass);
    }
    else
    {
      struct MHD_BasicAuthInfo *bai;

      bai = MHD_basic_auth_get_username_password3 (connection);
      if (NULL != bai)
      {
        if (NULL != bai->username)
          sink += bai->username_len;
        if (NULL != bai->password)
          sink += bai->password_len;
        MHD_free (bai);
      }
    }
  }

  if (cfg.calc_helpers)
    call_calc_helpers ();

  if (cfg.do_digest)
  {
    int dres = run_digest_check (connection);

    if (DAUTH_PASSED == dres)
      stat_auth_ok++;
    else
    {
      stat_challenges++;
      return queue_auth_challenge (connection, DAUTH_STALE == dres);
    }
  }

  /* Only answer 101 for a request that really is an upgrade request:
     HTTP/1.1, an "Upgrade" header, and a "Connection" header naming the
     upgrade token (RFC 9110 section 7.8).  This is the check a real
     application performs, and all three inputs come off the wire, so
     the path stays fully attacker-driven.

     It is deliberately NOT enough to predict whether MHD will accept
     the upgrade, and it is not meant to be: MHD may have decided during
     header parsing that the connection must close, and does not expose
     that decision.  That used to trip
     mhd_assert (NULL == r->upgrade_handler ||
                 MHD_CONN_MUST_UPGRADE == c->keepalive)
     in build_header_response() -- finding K7, see README section 6,
     reproducer corpus/known-findings/K7-upgrade-after-must-close.bin --
     and MHD_queue_response() now returns MHD_NO for it instead, which
     the code below already handles.  Do not "fix" this by tightening
     the condition here: the check above is what an application can
     actually do, and the harness has to behave like one. */
  if (cfg.allow_upgrade &&
      (NULL != version) &&
      (0 == strcmp (version, MHD_HTTP_VERSION_1_1)) &&
      (NULL != MHD_lookup_connection_value (connection,
                                            MHD_HEADER_KIND,
                                            MHD_HTTP_HEADER_UPGRADE)) &&
      (NULL != conn_hdr) &&
      (NULL != strstr (conn_lc, "upgrade")) &&
      (NULL == strstr (conn_lc, "close")))
  {
    resp = MHD_create_response_for_upgrade (&upgrade_cb, NULL);
    if (NULL != resp)
    {
      /* Mandatory: MHD_create_response_for_upgrade() documents that the
         upgrade headers are the application's job, and
         MHD_response_execute_upgrade_() asserts that "Upgrade" is
         present before it hands the socket over.  Omitting it is an
         application-contract violation, not something worth fuzzing. */
      (void) MHD_add_response_header (resp,
                                      MHD_HTTP_HEADER_UPGRADE,
                                      "fuzz-protocol");
      decorate_response (resp);
      ret = MHD_queue_response (connection,
                                MHD_HTTP_SWITCHING_PROTOCOLS,
                                resp);
      MHD_destroy_response (resp);
      return ret;
    }
  }

  resp = make_response ();
  if (NULL == resp)
    return MHD_NO;
  ret = MHD_queue_response (connection,
                            cfg.error_reply
                            ? MHD_HTTP_FORBIDDEN : MHD_HTTP_OK,
                            resp);
  MHD_destroy_response (resp);
  /* Only after a response was actually accepted.  Returning MHD_NO
     tells MHD to terminate the connection, and terminating a connection
     that this callback has just suspended trips
     mhd_assert (! connection->suspended) in MHD_connection_close_().
     That is the harness contradicting itself, not an MHD defect: the
     two requests are mutually exclusive by construction.  (MHD_NO is
     reachable here for real -- MHD_queue_response() rejects, for
     instance, a response carrying MHD_RF_HEAD_ONLY_RESPONSE on a GET,
     which decorate_response() can set.) */
  if (MHD_YES == ret)
    suspend_maybe (connection);
  return ret;
}


static void
completed_cb (void *cls,
              struct MHD_Connection *connection,
              void **req_cls,
              enum MHD_RequestTerminationCode toe)
{
  struct hstate *hs = (struct hstate *) *req_cls;

  (void) cls;
  (void) toe;
  /* MHD is done with this connection, so the deferred resume of
     suspend mode 2 must not fire for it any more. */
  pending_resume_drop (connection);
  if (NULL == hs)
    return;
  if (NULL != hs->pp)
    (void) MHD_destroy_post_processor (hs->pp);
  free (hs);
  *req_cls = NULL;
}


static void
panic_cb (void *cls,
          const char *file,
          unsigned int line,
          const char *reason)
{
  char msg[512];

  (void) cls;
  (void) snprintf (msg, sizeof (msg),
                   "MHD_PANIC() reached from network input at %s:%u: %s",
                   (NULL != file) ? file : "?",
                   line,
                   (NULL != reason) ? reason : "?");
  fuzz_report_finding (msg);
}


/* ------------------------------------------------------------------ */
/* Driving the daemon                                                  */
/* ------------------------------------------------------------------ */

/**
 * Read whatever the daemon has produced so far and look for a fresh
 * Digest-Auth nonce in it.
 */
static void
drain_and_harvest (int sock)
{
  for (;;)
  {
    ssize_t n;
    char tmp[4096];

    n = recv (sock, tmp, sizeof (tmp), MSG_DONTWAIT);
    if (0 >= n)
      break;
    if (resp_len + (size_t) n < RESP_BUF_SIZE)
    {
      memcpy (resp_buf + resp_len, tmp, (size_t) n);
      resp_len += (size_t) n;
      resp_buf[resp_len] = '\0';
    }
  }
  if (0 != resp_len)
  {
    const char *p = resp_buf;

    while (NULL != (p = strstr (p, "nonce=\"")))
    {
      const char *s = p + 7;
      const char *e = strchr (s, '"');

      p = s;
      if (NULL == e)
        break;
      if ((size_t) (e - s) < sizeof (nonce_val))
      {
        memcpy (nonce_val, s, (size_t) (e - s));
        nonce_len = (size_t) (e - s);
        nonce_val[nonce_len] = '\0';
      }
    }
  }
}


/**
 * Advance the daemon by one cycle, through the event-loop API selected
 * by byte 6 of the input.
 *
 * Mode 0 is MHD_run(), which is what the harness used before the
 * extension and which does the descriptor bookkeeping internally.
 * Modes 1-3 drive the daemon the way an application with its own event
 * loop does: MHD_get_fdset*() to collect the descriptors, select(), then
 * MHD_run_from_select*().  That is the most common production
 * integration and none of it was reachable before.
 *
 * The select() timeout is always zero.  The harness is single threaded
 * and whatever the daemon is waiting for has already been written into
 * the socketpair, so blocking would only burn wall clock; select() is
 * called purely to populate the ready sets.
 */
static void
run_once (struct MHD_Daemon *d)
{
  fd_set rs;
  fd_set ws;
  fd_set es;
  MHD_socket max_fd = MHD_INVALID_SOCKET;
  struct timeval tv;

  if (0 == cfg.loop_mode)
  {
    (void) MHD_run (d);
    return;
  }
  FD_ZERO (&rs);
  FD_ZERO (&ws);
  FD_ZERO (&es);
  if (1 == cfg.loop_mode)
  {
    /* Parenthesised so that the real v1 function is called:
       microhttpd.h also defines MHD_get_fdset as a macro that forwards
       to MHD_get_fdset2 with FD_SETSIZE, so the unparenthesised name
       would never reach the v1 entry point at all.  Same trick for
       MHD_run_from_select below. */
    if (MHD_YES != (MHD_get_fdset) (d, &rs, &ws, &es, &max_fd))
    {
      (void) MHD_run (d);
      return;
    }
  }
  else
  {
    if (MHD_YES != MHD_get_fdset2 (d, &rs, &ws, &es, &max_fd,
                                   (unsigned int) FD_SETSIZE))
    {
      (void) MHD_run (d);
      return;
    }
  }
  if (cfg.use_timeouts)
  {
    MHD_UNSIGNED_LONG_LONG tl = 0;
    uint64_t t64 = 0;
    volatile int64_t sink;

    (void) MHD_get_timeout (d, &tl);
    (void) MHD_get_timeout64 (d, &t64);
    sink = MHD_get_timeout64s (d);
    sink += (int64_t) MHD_get_timeout_i (d);
    (void) sink;
  }
  tv.tv_sec = 0;
  tv.tv_usec = 0;
  if (MHD_INVALID_SOCKET != max_fd)
    (void) select ((int) max_fd + 1, &rs, &ws, &es, &tv);
  if (1 == cfg.loop_mode)
    (void) (MHD_run_from_select) (d, &rs, &ws, &es);
  else
    (void) MHD_run_from_select2 (d, &rs, &ws, &es, (unsigned int) FD_SETSIZE);
}


static void
pump (struct MHD_Daemon *d,
      int sock,
      unsigned int rounds)
{
  unsigned int i;

  for (i = 0; i < rounds; i++)
  {
    /* Deferred resume of suspend mode 2.  Each slot is cleared before
       its connection is resumed, which keeps this correct even if the
       resume makes MHD complete (and forget) the connection, or run the
       handler again so that it suspends the same one anew. */
    (void) pending_resume_flush ();
    run_once (d);
    drain_and_harvest (sock);
  }
}


/**
 * Copy @a in to @a out, expanding every occurrence of the ASCII token
 * "%%NONCE%%" to the harvested nonce.
 *
 * @return number of bytes written to @a out
 */
static size_t
expand_nonce (const uint8_t *in,
              size_t in_len,
              uint8_t *out,
              size_t out_cap)
{
  static const char tok[] = "%%NONCE%%";
  const size_t tok_len = sizeof (tok) - 1;
  size_t i = 0;
  size_t o = 0;

  while (i < in_len)
  {
    if ( (i + tok_len <= in_len) &&
         (0 == memcmp (in + i, tok, tok_len)) )
    {
      if (o + nonce_len > out_cap)
        break;
      memcpy (out + o, nonce_val, nonce_len);
      o += nonce_len;
      i += tok_len;
      continue;
    }
    if (o >= out_cap)
      break;
    out[o++] = in[i++];
  }
  return o;
}


static void
send_all (struct MHD_Daemon *d,
          int sock,
          const uint8_t *data,
          size_t len)
{
  size_t off = 0;
  unsigned int stall = 0;

  while ( (off < len) &&
          (stall < 64) )
  {
    ssize_t s = send (sock, data + off, len - off, MSG_DONTWAIT);

    if (0 < s)
    {
      off += (size_t) s;
      stall = 0;
      continue;
    }
    stall++;
    pump (d, sock, 2);
    if ( (0 > s) &&
         (EAGAIN != errno) &&
         (EWOULDBLOCK != errno) &&
         (EINTR != errno) )
      break;
  }
}


static int
new_connection (struct MHD_Daemon *d,
                int *sock)
{
  int sv[2];
  struct sockaddr_in sa;

  if (0 != socketpair (AF_UNIX, SOCK_STREAM, 0, sv))
    return -1;
  memset (&sa, 0, sizeof (sa));
  sa.sin_family = AF_INET;
  sa.sin_port = htons (44444);
  sa.sin_addr.s_addr = htonl (INADDR_LOOPBACK);
  if (MHD_YES != MHD_add_connection (d,
                                     (MHD_socket) sv[1],
                                     (const struct sockaddr *) &sa,
                                     (socklen_t) sizeof (sa)))
  {
    /* MHD has already closed sv[1] in that case */
    (void) close (sv[0]);
    return -1;
  }
  *sock = sv[0];
  return 0;
}


static void
close_connection (struct MHD_Daemon *d,
                  int *sock)
{
  if (0 > *sock)
    return;
  (void) shutdown (*sock, SHUT_WR);
  pump (d, *sock, 4);
  (void) close (*sock);
  *sock = -1;
}


/* ------------------------------------------------------------------ */
/* The fuzz target                                                     */
/* ------------------------------------------------------------------ */

int
LLVMFuzzerTestOneInput (const uint8_t *data,
                        size_t size)
{
  struct MHD_Daemon *d;
  struct MHD_OptionItem opts[8];
  unsigned int nopt = 0;
  unsigned int flags;
  int sock = -1;
  size_t pos;
  unsigned int nseg = 0;
  unsigned int nconn = 1;
  static uint8_t xbuf[FUZZ_MAX_INPUT + 4096];

  /* Must happen before the first write() into the socketpair.  The
     built-in driver also does this from fuzz_install_handlers(), but
     that is compiled out under -DFUZZ_NO_MAIN, which is exactly the
     build every external fuzzing engine uses; the call is idempotent,
     so doing it from both places is harmless.  See fuzz_ignore_sigpipe()
     in fuzz_common.h for why the process dies without it. */
  fuzz_ignore_sigpipe ();

  /* The ten configuration bytes are mandatory.  Anything shorter has
     no segment stream either, so there is nothing to fuzz. */
  if (size < 10)
    return 0;

  nonce_len = 0;
  nonce_val[0] = '\0';
  resp_len = 0;
  resp_buf[0] = '\0';

  memset (&cfg, 0, sizeof (cfg));
  cfg.mem_limit =
    mem_limit_tbl[data[0] % (sizeof (mem_limit_tbl)
                             / sizeof (mem_limit_tbl[0]))];
  cfg.do_digest = (0 != (data[1] & 0x01));
  cfg.do_basic = (0 != (data[1] & 0x02));
  cfg.do_postproc = (0 != (data[1] & 0x04));
  cfg.do_iterate = (0 != (data[1] & 0x08));
  /* Bits 0x10 and 0x80 of byte 1 are unused.  0x10 used to gate the
     configuration bytes 4-9 back when they were optional; it is left
     free rather than reassigned so that the meaning of the corpus
     files written while it was a gate does not silently change. */
  cfg.chunked_reply = (0 != (data[1] & 0x20));
  cfg.error_reply = (0 != (data[1] & 0x40));
  if (! min_mem_limit_read)
  {
    const char *e = getenv ("MHD_FUZZ_MIN_MEM_LIMIT");

    min_mem_limit_read = 1;
    if (NULL != e)
      min_mem_limit = (size_t) strtoul (e, NULL, 10);
  }
  if ( (0 != cfg.mem_limit) &&
       (cfg.mem_limit < min_mem_limit) )
    cfg.mem_limit = min_mem_limit;
  if (! min_discipline_read)
  {
    const char *e = getenv ("MHD_FUZZ_MIN_DISCIPLINE");

    min_discipline_read = 1;
    if (NULL != e)
      min_discipline = atoi (e);
  }
  cfg.discipline =
    discipline_tbl[(data[2] & 0x0F) % (sizeof (discipline_tbl)
                                       / sizeof (discipline_tbl[0]))];
  if (cfg.discipline < min_discipline)
    cfg.discipline = min_discipline;
  cfg.insanity = (unsigned int) MHD_DSC_SANE;
  cfg.algo = algo_tbl[data[3] & 0x03];
  cfg.qop = (0 != (data[3] & 0x04))
            ? MHD_DIGEST_AUTH_MULT_QOP_AUTH
            : MHD_DIGEST_AUTH_MULT_QOP_ANY_NON_INT;
  cfg.nonce_nc_size = nnc_tbl[(data[3] >> 4) & 0x03];

  cfg.resp_kind = (unsigned int) (data[4] & 0x0F);
  cfg.resp_nhdr = (unsigned int) ((data[4] >> 4) & 0x03);
  cfg.resp_footer = (0 != (data[4] & 0x40));
  cfg.resp_hdr_api = (0 != (data[4] & 0x80));

  cfg.dauth_variant = (unsigned int) (data[5] & 0x0F) % DAUTH_VARIANT_COUNT;
  cfg.fail_variant = (unsigned int) ((data[5] >> 4) & 0x03);
  cfg.basic_v1 = (0 != (data[5] & 0x40));
  cfg.calc_helpers = (0 != (data[5] & 0x80));

  cfg.loop_mode = (unsigned int) (data[6] & 0x03);
  cfg.use_timeouts = (0 != (data[6] & 0x04));
  cfg.conn_lookup = (0 != (data[6] & 0x08));
  cfg.conn_setvalue = (0 != (data[6] & 0x10));
  cfg.conn_info = (0 != (data[6] & 0x20));
  cfg.conn_option = (0 != (data[6] & 0x40));
  cfg.quiesce = (0 != (data[6] & 0x80));

  /* Only modes 0-2 exist; 3 folds onto the immediate-resume mode
     rather than being a fourth, unimplemented behaviour. */
  cfg.suspend_mode = (unsigned int) (data[7] & 0x03);
  if (3 == cfg.suspend_mode)
    cfg.suspend_mode = 1;
  cfg.allow_upgrade =
    (0 != (data[7] & 0x04)) &&
    (MHD_YES == MHD_is_feature_supported (MHD_FEATURE_UPGRADE));
  cfg.upgrade_action = (unsigned int) ((data[7] >> 3) & 0x03);

  cfg.hdr_seed = data[8];
  cfg.crc_seed = data[9];

  oracle_on = 0;
  expect_body_len = 0;
  /* Must never carry over: the connections these pointed at belonged to
     the previous iteration's daemon and are long gone. */
  memset (pending_resume, 0, sizeof (pending_resume));
  tearing_down = 0;

  if (0 != cfg.mem_limit)
  {
    opts[nopt].option = MHD_OPTION_CONNECTION_MEMORY_LIMIT;
    opts[nopt].value = (intptr_t) cfg.mem_limit;
    opts[nopt].ptr_value = NULL;
    nopt++;
  }
  opts[nopt].option = MHD_OPTION_CLIENT_DISCIPLINE_LVL;
  opts[nopt].value = (intptr_t) cfg.discipline;
  opts[nopt].ptr_value = NULL;
  nopt++;
  opts[nopt].option = MHD_OPTION_SERVER_INSANITY;
  opts[nopt].value = (intptr_t) cfg.insanity;
  opts[nopt].ptr_value = NULL;
  nopt++;
  opts[nopt].option = MHD_OPTION_NONCE_NC_SIZE;
  opts[nopt].value = (intptr_t) cfg.nonce_nc_size;
  opts[nopt].ptr_value = NULL;
  nopt++;
  opts[nopt].option = MHD_OPTION_DIGEST_AUTH_RANDOM;
  opts[nopt].value = (intptr_t) sizeof (digest_rnd);
  opts[nopt].ptr_value = (void *) (intptr_t) digest_rnd;
  nopt++;
  opts[nopt].option = MHD_OPTION_END;
  opts[nopt].value = 0;
  opts[nopt].ptr_value = NULL;

  flags = MHD_USE_NO_LISTEN_SOCKET;
  if (fuzz_verbose)
    flags |= MHD_USE_ERROR_LOG;
  if (0 != cfg.suspend_mode)
    flags |= MHD_ALLOW_SUSPEND_RESUME;
  if (cfg.allow_upgrade)
    flags |= MHD_ALLOW_UPGRADE;

  MHD_set_panic_func (&panic_cb, NULL);
  d = MHD_start_daemon (flags,
                        0,
                        NULL, NULL,
                        &ahc, NULL,
                        MHD_OPTION_ARRAY, opts,
                        /* passed through the varargs rather than through
                           the option array: storing a function pointer in
                           the array's intptr_t member is not strictly
                           conforming C */
                        MHD_OPTION_NOTIFY_COMPLETED, &completed_cb, NULL,
                        MHD_OPTION_END);
  if (NULL == d)
    return 0;
  cur_daemon = d;
  stat_daemons++;
  if (! stats_registered)
  {
    stats_registered = 1;
    (void) atexit (&print_stats);
  }

  if (0 != new_connection (d, &sock))
  {
    MHD_stop_daemon (d);
    cur_daemon = NULL;
    return 0;
  }

  pos = 10u;
  while ( (pos + 2 <= size) &&
          (nseg < MAX_SEGMENTS) )
  {
    unsigned int hdr = (unsigned int) data[pos]
                       | ((unsigned int) data[pos + 1] << 8);
    unsigned int op = hdr >> 14;
    size_t slen = (size_t) (hdr & 0x3FFF);
    size_t elen;

    pos += 2;
    nseg++;
    if (slen > size - pos)
      slen = size - pos;

    if (1 == op)
    {
      /* Ground-truth declaration, not wire data. */
      if (fuzz_pristine && (slen <= MAX_EXPECT_BODY))
      {
        memcpy (expect_body, data + pos, slen);
        expect_body_len = slen;
        oracle_on = 1;
      }
      pos += slen;
      continue;
    }
    if ( (3 == op) &&
         (nconn < MAX_CONNECTIONS) )
    {
      close_connection (d, &sock);
      if (0 != new_connection (d, &sock))
        break;
      nconn++;
    }

    elen = expand_nonce (data + pos, slen, xbuf, sizeof (xbuf));
    pos += slen;
    if (0 != elen)
      send_all (d, sock, xbuf, elen);
    pump (d, sock, (2 == op) ? 12u : 3u);
    if (0 == slen)
      pump (d, sock, 4);
  }

  close_connection (d, &sock);
  pump (d, sock, 4);
  /* A connection left suspended makes MHD_stop_daemon() MHD_PANIC()
     ("called while we have suspended connections"), and
     MHD_resume_connection() alone is not enough: it only raises a flag,
     and the connection is taken off the daemon's suspended list by
     MHD_run().  So flush and run until nothing is parked any more.
     tearing_down stops the handler from parking anything new, which is
     what bounds this loop; the cap is only a backstop. */
  tearing_down = 1;
  {
    unsigned int i;

    for (i = 0; i < MAX_CONNECTIONS + 2u; i++)
    {
      if (! pending_resume_flush ())
        break;
      (void) MHD_run (d);
    }
  }
  if (cfg.quiesce)
    (void) MHD_quiesce_daemon (d);
  MHD_stop_daemon (d);
  cur_daemon = NULL;
  return 0;
}


/* ------------------------------------------------------------------ */
/* Structure-aware HTTP request generator                              */
/* ------------------------------------------------------------------ */

struct sbuf
{
  uint8_t *p;
  size_t len;
  size_t cap;
};


static void
sb_raw (struct sbuf *b,
        const void *v,
        size_t n)
{
  if (b->len + n > b->cap)
    n = b->cap - b->len;
  memcpy (b->p + b->len, v, n);
  b->len += n;
}


static void
sb_str (struct sbuf *b,
        const char *s)
{
  sb_raw (b, s, strlen (s));
}


static void
sb_u64 (struct sbuf *b,
        uint64_t v,
        int hex,
        unsigned int min_digits)
{
  char tmp[32];
  unsigned int n = 0;

  do
  {
    unsigned int dig = (unsigned int) (v % (hex ? 16u : 10u));
    tmp[n++] = (char) ((dig < 10) ? ('0' + dig) : ('a' + dig - 10));
    v /= (hex ? 16u : 10u);
  }
  while ( (0 != v) && (n < sizeof (tmp)) );
  while ( (n < min_digits) && (n < sizeof (tmp)) )
    tmp[n++] = '0';
  while (0 != n)
  {
    char c = tmp[--n];
    sb_raw (b, &c, 1);
  }
}


static const char *const gen_methods[] = {
  "GET", "POST", "PUT", "HEAD", "DELETE", "OPTIONS", "TRACE", "PATCH",
  "CONNECT", "BREW", "get", "M-SEARCH", "\tGET", "GET "
};

static const char *const gen_versions[] = {
  "HTTP/1.1", "HTTP/1.0", "HTTP/1.1", "HTTP/1.1", "HTTP/0.9", "HTTP/1.2",
  "HTTP/2.0", "http/1.1", "HTTP/1.", "HTTP/11"
};

static const char *const gen_targets[] = {
  "/", "/a", "/a/b/c", "/a?x=1", "/a?x=1&y=2", "/?novalue", "/?a=1&b",
  "/?a&b&c", "/%41%42", "/a%00b", "/%zz", "/a?%41=%42", "*",
  "http://example.org/a", "/a?x=1&novalue", "/..%2f..%2fetc",
  "/a?=", "/a?&", "/very/long/path/that/keeps/going/and/going/and/going"
};

static const char *const gen_hdr_names[] = {
  "Host", "Accept", "User-Agent", "Connection", "Cookie", "Content-Type",
  "Expect", "TE", "Trailer", "X-Custom", "Referer", "Accept-Encoding",
  "content-length", "transfer-encoding", "X-A-Very-Long-Header-Name-Indeed"
};

static const char *const gen_hdr_values[] = {
  "example.org", "*/*", "fuzz/1.0", "keep-alive", "close",
  "a=1; b=2; c", "100-continue", "trailers", "X-Trail", "value",
  "", " ", "\ttabbed", "a, b, c", "chunked", "identity, chunked"
};

/** Deliberately includes tokens MHD does not know: bug #1 lives here. */
static const char *const gen_algos[] = {
  "MD5", "SHA-256", "SHA-512-256", "MD5-sess", "SHA-256-sess",
  "SHA-512-256-sess", "sha-256", "SHA256", "BOGUS", "", "\"SHA-256\"",
  "MD5 ", "SHA-1", "xyzzy", "SHA-512", "\"BOGUS\"", "0"
};

static const char *const gen_ctypes[] = {
  "application/x-www-form-urlencoded",
  "multipart/form-data; boundary=--abc",
  "multipart/form-data; boundary=\"XY\"",
  "multipart/form-data",
  "text/plain"
};


/**
 * Append a random query string, optionally ending in an argument
 * without '=' (which is the shape needed for the read-buffer shift-back
 * bug).
 */
static void
gen_query (struct fuzz_rng *rng,
           struct sbuf *b,
           int force_trailing_novalue)
{
  unsigned int n = fuzz_below (rng, 4);
  unsigned int i;

  if ( (0 == n) && (! force_trailing_novalue) )
    return;
  sb_str (b, "?");
  for (i = 0; i < n; i++)
  {
    if (0 != i)
      sb_str (b, "&");
    sb_str (b, "k");
    sb_u64 (b, i, 0, 1);
    if (! fuzz_chance (rng, 3))
    {
      sb_str (b, "=");
      sb_str (b, fuzz_chance (rng, 4) ? "%41%42" : "v");
    }
  }
  if (force_trailing_novalue)
  {
    if (0 != n)
      sb_str (b, "&");
    sb_str (b, "novalue");
  }
}


static void
gen_headers (struct fuzz_rng *rng,
             struct sbuf *b,
             unsigned int n)
{
  unsigned int i;

  for (i = 0; i < n; i++)
  {
    sb_str (b, gen_hdr_names[fuzz_below (rng,
                                         (uint32_t) (sizeof (gen_hdr_names)
                                                     / sizeof (char *)))]);
    sb_str (b, fuzz_chance (rng, 8) ? " :" : ":");
    if (! fuzz_chance (rng, 6))
      sb_str (b, " ");
    sb_str (b, gen_hdr_values[fuzz_below (rng,
                                          (uint32_t) (sizeof (gen_hdr_values)
                                                      / sizeof (char *)))]);
    if (fuzz_chance (rng, 12))
      sb_str (b, "\r\n\tfolded-continuation");
    if (fuzz_chance (rng, 20))
      sb_str (b, "\n");     /* bare LF */
    else if (fuzz_chance (rng, 25))
      sb_str (b, "\r");     /* bare CR */
    else
      sb_str (b, "\r\n");
  }
}


/**
 * Emit a chunked body.  When @a oracle is non-zero the body is
 * strictly RFC 9112 conformant and the decoded payload is recorded in
 * #expect_body, so that the harness can verify what MHD hands to the
 * application.  Chunk extensions are emitted frequently on purpose.
 */
static void
gen_chunked_body (struct fuzz_rng *rng,
                  struct sbuf *b,
                  int oracle)
{
  unsigned int nchunks = 1 + fuzz_below (rng, 4);
  unsigned int i;

  if (oracle)
    expect_body_len = 0;
  for (i = 0; i < nchunks; i++)
  {
    unsigned int clen = 1 + fuzz_below (rng, 24);
    unsigned int j;

    sb_u64 (b, clen, 1, fuzz_chance (rng, 4) ? 4 : 1);
    /* chunk extension -- the parsing of the terminating CRLF of this
       very line was broken (bug #3) */
    if (! fuzz_chance (rng, 2))
    {
      switch (fuzz_below (rng, 5))
      {
      case 0:
        sb_str (b, ";ext");
        break;
      case 1:
        sb_str (b, ";ext=val");
        break;
      case 2:
        sb_str (b, ";ext=\"quoted value\"");
        break;
      case 3:
        sb_str (b, ";a=1;b=2;c");
        break;
      default:
        sb_str (b, ";x=\"a;b\"");
        break;
      }
    }
    sb_str (b, "\r\n");
    for (j = 0; j < clen; j++)
    {
      char c = (char) ('A' + ((i * 7 + j) % 26));

      sb_raw (b, &c, 1);
      if (oracle && (expect_body_len < MAX_EXPECT_BODY))
        expect_body[expect_body_len++] = (uint8_t) c;
    }
    sb_str (b, "\r\n");
  }
  sb_str (b, "0");
  if (fuzz_chance (rng, 4))
    sb_str (b, ";final=\"x\"");
  sb_str (b, "\r\n");
  if (fuzz_chance (rng, 3))
    sb_str (b, "X-Trailer: value\r\n");
  sb_str (b, "\r\n");
}


static void
gen_digest_header (struct fuzz_rng *rng,
                   struct sbuf *b,
                   const char *uri,
                   int use_nonce_token,
                   int overlong_response,
                   int prefer_valid)
{
  unsigned int nresp;
  unsigned int i;

  sb_str (b, "Authorization: Digest ");
  sb_str (b, "username=\"");
  if (fuzz_chance (rng, prefer_valid ? 20 : 6))
  {
    /* userhash notation: a long hex string is accepted here too */
    unsigned int n = 2 * (16 + fuzz_below (rng, 48));
    for (i = 0; i < n; i++)
      sb_str (b, "a");
  }
  else
    sb_str (b, DIGEST_USER);
  sb_str (b, "\", ");
  if (fuzz_chance (rng, prefer_valid ? 25 : 8))
    sb_str (b, "userhash=true, ");
  sb_str (b, "realm=\"");
  sb_str (b, fuzz_chance (rng, prefer_valid ? 25 : 8)
          ? "OtherRealm" : DIGEST_REALM);
  sb_str (b, "\", nonce=\"");
  if (use_nonce_token)
    sb_str (b, "%%NONCE%%");
  else
  {
    unsigned int n = 8 + fuzz_below (rng, 80);
    for (i = 0; i < n; i++)
      sb_str (b, "0");
  }
  sb_str (b, "\", uri=\"");
  sb_str (b, uri);
  sb_str (b, "\", qop=");
  sb_str (b, fuzz_chance (rng, prefer_valid ? 25 : 8) ? "auth-int" : "auth");
  sb_str (b, ", nc=");
  sb_u64 (b, 1 + fuzz_below (rng, 3), 1, 8);
  sb_str (b, ", cnonce=\"deadbeef\", algorithm=");
  if (prefer_valid && (! fuzz_chance (rng, 5)))
    sb_str (b, "SHA-256");   /* must match the algorithm of the challenge */
  else
    sb_str (b, gen_algos[fuzz_below (rng,
                                     (uint32_t) (sizeof (gen_algos)
                                                 / sizeof (char *)))]);
  sb_str (b, ", opaque=\"0123456789abcdef\", response=\"");
  if (overlong_response)
    nresp = 66 + 2 * fuzz_below (rng, 32);      /* 66 .. 128 hex digits */
  else
    nresp = 2 * (1 + fuzz_below (rng, 66));
  for (i = 0; i < nresp; i++)
  {
    char c = "0123456789abcdef"[fuzz_below (rng, 16)];

    sb_raw (b, &c, 1);
  }
  sb_str (b, "\"\r\n");
}


enum gen_shape
{
  SHAPE_PLAIN = 0,
  SHAPE_NOHDR_QARG,
  SHAPE_CL_BODY,
  SHAPE_CHUNKED,
  SHAPE_DIGEST_SIMPLE,
  SHAPE_DIGEST_REPLAY,
  SHAPE_BASIC,
  SHAPE_POST_FORM,
  SHAPE_WEIRD,
  SHAPE_COUNT
};


/**
 * Build one HTTP request into @a b.
 *
 * @return non-zero if the request is exactly reproducible, i.e. the
 *         #expect_body oracle may be used
 */
static int
gen_one_request (struct fuzz_rng *rng,
                 struct sbuf *b,
                 enum gen_shape shape,
                 int second_of_pair)
{
  switch (shape)
  {
  case SHAPE_NOHDR_QARG:
    /* No header lines at all + a trailing query argument without '=';
       combined with a small connection memory pool this is the shape
       that reaches the read-buffer "shift back" computation. */
    sb_str (b, "GET /");
    gen_query (rng, b, 1);
    sb_str (b, " ");
    sb_str (b, fuzz_chance (rng, 2) ? "HTTP/1.0" : "HTTP/1.1");
    sb_str (b, "\r\n\r\n");
    return 0;

  case SHAPE_CL_BODY:
    {
      unsigned int blen = fuzz_below (rng, 64);
      unsigned int i;

      sb_str (b, "POST /a HTTP/1.1\r\nHost: x\r\nContent-Length: ");
      sb_u64 (b, blen, 0, 1);
      sb_str (b, "\r\n\r\n");
      expect_body_len = 0;
      for (i = 0; i < blen; i++)
      {
        char c = (char) ('a' + (i % 26));

        sb_raw (b, &c, 1);
        if (expect_body_len < MAX_EXPECT_BODY)
          expect_body[expect_body_len++] = (uint8_t) c;
      }
      return 1;
    }

  case SHAPE_CHUNKED:
    sb_str (b, "POST /a HTTP/1.1\r\nHost: x\r\n"
            "Transfer-Encoding: chunked\r\n\r\n");
    gen_chunked_body (rng, b, 1);
    return 1;

  case SHAPE_DIGEST_SIMPLE:
    sb_str (b, "GET /a HTTP/1.1\r\nHost: x\r\n");
    gen_digest_header (rng, b, "/a", 0, fuzz_chance (rng, 2), 0);
    sb_str (b, "\r\n");
    return 0;

  case SHAPE_DIGEST_REPLAY:
    if (! second_of_pair)
      sb_str (b, "GET /a HTTP/1.1\r\nHost: x\r\n\r\n");
    else
    {
      sb_str (b, "GET /a HTTP/1.1\r\nHost: x\r\n");
      gen_digest_header (rng, b, "/a", 1, 1, 1);
      sb_str (b, "\r\n");
    }
    return 0;

  case SHAPE_BASIC:
    sb_str (b, "GET /a HTTP/1.1\r\nHost: x\r\nAuthorization: Basic ");
    {
      unsigned int n = fuzz_below (rng, 40);
      unsigned int i;

      for (i = 0; i < n; i++)
      {
        char c =
          "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/="
          [fuzz_below (rng, 65)];

        sb_raw (b, &c, 1);
      }
    }
    sb_str (b, "\r\n\r\n");
    return 0;

  case SHAPE_POST_FORM:
    {
      const char *ct = gen_ctypes[fuzz_below (rng,
                                              (uint32_t) (sizeof (gen_ctypes)
                                                          / sizeof (char *)))];

      sb_str (b, "POST /a HTTP/1.1\r\nHost: x\r\nContent-Type: ");
      sb_str (b, ct);
      sb_str (b, "\r\nTransfer-Encoding: chunked\r\n\r\n");
      gen_chunked_body (rng, b, 0);
      return 0;
    }

  case SHAPE_WEIRD:
    sb_str (b, gen_methods[fuzz_below (rng,
                                       (uint32_t) (sizeof (gen_methods)
                                                   / sizeof (char *)))]);
    sb_str (b, " ");
    sb_str (b, gen_targets[fuzz_below (rng,
                                       (uint32_t) (sizeof (gen_targets)
                                                   / sizeof (char *)))]);
    sb_str (b, " ");
    sb_str (b, gen_versions[fuzz_below (rng,
                                        (uint32_t) (sizeof (gen_versions)
                                                    / sizeof (char *)))]);
    sb_str (b, fuzz_chance (rng, 8) ? "\n" : "\r\n");
    gen_headers (rng, b, fuzz_below (rng, 6));
    sb_str (b, "\r\n");
    return 0;

  case SHAPE_PLAIN:
  case SHAPE_COUNT:
  default:
    sb_str (b, gen_methods[fuzz_below (rng, 3)]);
    sb_str (b, " /");
    gen_query (rng, b, fuzz_chance (rng, 3));
    sb_str (b, " HTTP/1.1\r\n");
    gen_headers (rng, b, fuzz_below (rng, 4));
    sb_str (b, "\r\n");
    return 0;
  }
}


/**
 * Serialise @a body into the segment format understood by
 * LLVMFuzzerTestOneInput(), starting at @a out[*out_len].
 */
static void
emit_segments (struct fuzz_rng *rng,
               struct sbuf *out,
               const uint8_t *body,
               size_t body_len,
               int new_conn_first)
{
  size_t off = 0;
  int first = 1;

  while (off < body_len)
  {
    size_t chunk;
    unsigned int op;
    uint8_t hdr[2];
    unsigned int hv;

    switch (fuzz_below (rng, 6))
    {
    case 0:
      chunk = 1;
      break;
    case 1:
      chunk = 2 + fuzz_below (rng, 6);
      break;
    case 2:
      chunk = 8 + fuzz_below (rng, 40);
      break;
    default:
      chunk = body_len - off;
      break;
    }
    if (chunk > body_len - off)
      chunk = body_len - off;
    if (chunk > 0x3FFF)
      chunk = 0x3FFF;
    op = (first && new_conn_first) ? 3u : (fuzz_chance (rng, 4) ? 2u : 0u);
    hv = (op << 14) | (unsigned int) chunk;
    hdr[0] = (uint8_t) (hv & 0xFF);
    hdr[1] = (uint8_t) (hv >> 8);
    if (out->len + 2 + chunk > out->cap)
      return;
    sb_raw (out, hdr, 2);
    sb_raw (out, body + off, chunk);
    off += chunk;
    first = 0;
  }
}


static size_t
fuzz_generate (struct fuzz_rng *rng,
               uint8_t *buf,
               size_t cap)
{
  struct sbuf out;
  uint8_t req[GEN_BUF_SIZE];
  struct sbuf rb;
  enum gen_shape shape;
  uint8_t cfg_bytes[4];
  int oracle;
  unsigned int nreq;
  unsigned int i;

  expect_body_len = 0;

  out.p = buf;
  out.len = 0;
  out.cap = cap;

  if (! forced_shape_read)
  {
    const char *e = getenv ("MHD_FUZZ_SHAPE");

    forced_shape_read = 1;
    if (NULL != e)
      forced_shape = atoi (e);
  }
  if (0 <= forced_shape)
    shape = (enum gen_shape) (forced_shape % (int) SHAPE_COUNT);
  else
    shape = (enum gen_shape) fuzz_below (rng, (uint32_t) SHAPE_COUNT);

  /* --- configuration bytes --- */
  cfg_bytes[0] = fuzz_byte (rng);
  cfg_bytes[1] = fuzz_byte (rng);
  cfg_bytes[2] = fuzz_byte (rng);
  cfg_bytes[3] = fuzz_byte (rng);
  switch (shape)
  {
  case SHAPE_NOHDR_QARG:
    /* small connection memory pool: indices 1..9 of mem_limit_tbl */
    cfg_bytes[0] = (uint8_t) (1 + fuzz_below (rng, 9));
    break;
  case SHAPE_DIGEST_SIMPLE:
  case SHAPE_DIGEST_REPLAY:
    cfg_bytes[0] = (uint8_t) (fuzz_chance (rng, 2) ? 0 : 12);
    cfg_bytes[1] = (uint8_t) ((cfg_bytes[1] | 0x01u) & ~0x04u);
    /* SHA-256 challenge: 32 byte digest -> 128 hex chars pass the
       'response' length check while hash1_bin[] is only 32 bytes */
    cfg_bytes[3] = (uint8_t) ((cfg_bytes[3] & 0xF0u) | 0x00u);
    break;
  case SHAPE_POST_FORM:
    cfg_bytes[1] |= 0x04u;
    break;
  case SHAPE_CHUNKED:
  case SHAPE_CL_BODY:
    cfg_bytes[1] &= (uint8_t) ~0x04u;   /* keep the body oracle clean */
    break;
  default:
    break;
  }
  cfg_bytes[1] |= 0x08u;                /* always iterate the values */
  sb_raw (&out, cfg_bytes, 4);

  nreq = (SHAPE_DIGEST_REPLAY == shape) ? 2u : (1u + (fuzz_chance (rng, 6)
                                                      ? 1u : 0u));
  oracle = 0;
  for (i = 0; i < nreq; i++)
  {
    rb.p = req;
    rb.len = 0;
    rb.cap = sizeof (req);
    oracle = gen_one_request (rng, &rb, shape, (int) i);
    if (oracle && (1 == nreq) && (expect_body_len <= MAX_EXPECT_BODY))
    {
      /* Declare the ground truth for the body oracle (op 1). */
      unsigned int hv = (1u << 14) | (unsigned int) expect_body_len;
      uint8_t hdr[2];

      hdr[0] = (uint8_t) (hv & 0xFF);
      hdr[1] = (uint8_t) (hv >> 8);
      sb_raw (&out, hdr, 2);
      sb_raw (&out, expect_body, expect_body_len);
    }
    emit_segments (rng, &out, req, rb.len,
                   (0 != i) || fuzz_chance (rng, 8));
  }
  (void) oracle;
  return out.len;
}


/* ------------------------------------------------------------------ */
/* Built-in seed corpus                                                */
/* ------------------------------------------------------------------ */

/**
 * The built-in seed corpus is described symbolically and rendered into
 * the wire format at run time, so that segment lengths never have to be
 * spelled out by hand.
 */
struct seed_part
{
  unsigned int op;              /**< 0 send, 1 expected body, 3 new conn */
  const char *txt;              /**< NUL terminated payload */
};

struct seed_def
{
  const char *name;
  unsigned char cfg[4];
  struct seed_part parts[4];
  /* Configuration bytes 4-9.  Declared after @e parts so that a seed
     which only cares about the wire data can leave the member out of
     its brace initialiser and get the all-zero (plainest) setting. */
  unsigned char ext[6];
};

#define P_END { 0, NULL }

static const struct seed_def seeds[] = {
  /* There is deliberately no bare "GET / HTTP/1.1" seed: every seed
     below opens with a request at least as simple, so a plain one adds
     no coverage of its own (libFuzzer -merge=1 drops it). */
  { "content-length-body", { 0x00, 0x08, 0x03, 0x00 },
    { { 1, "hello" },
      { 0, "POST /a HTTP/1.1\r\nHost: x\r\nContent-Length: 5\r\n\r\nhello" },
      P_END, P_END } },

  /* chunk extensions: the terminating CRLF of the chunk-size line used
     to be left in the stream (bug #3, commit c13f4c64) */
  { "chunked-with-extensions", { 0x00, 0x08, 0x03, 0x00 },
    { { 1, "ABCDE" },
      { 0, "POST /a HTTP/1.1\r\nHost: x\r\nTransfer-Encoding: chunked\r\n"
        "\r\n2;ext=val\r\nAB\r\n3;a=\"b;c\"\r\nCDE\r\n0\r\n\r\n" },
      P_END, P_END } },

  { "chunked-split", { 0x00, 0x08, 0x03, 0x00 },
    { { 1, "ABCDEF" },
      { 0, "POST /a HTTP/1.1\r\nHost: x\r\nTransfer-Encoding: chunked\r\n"
        "\r\n3\r\nABC\r\n3;x=\"y\"" },
      { 2, "\r\nDEF\r\n0\r\n\r\n" },
      P_END } },

  /* small connection memory pool + trailing query argument without '='
     and no header lines at all (bug #2, commit 29eaa56b) */
  { "small-pool-trailing-query-arg", { 0x06, 0x08, 0x03, 0x00 },
    { { 0, "GET /?novalue HTTP/1.0\r\n\r\n" }, P_END, P_END, P_END } },

  { "small-pool-trailing-query-arg-2", { 0x03, 0x08, 0x03, 0x00 },
    { { 0, "GET /?a=1&b HTTP/1.0\r\n\r\n" }, P_END, P_END, P_END } },

  /* unrecognised 'algorithm' token -> MHD_DIGEST_AUTH_ALGO3_INVALID
     (bug #1, commit bd49ce93) */
  { "digest-unknown-algorithm", { 0x00, 0x09, 0x03, 0x00 },
    { { 0, "GET /a HTTP/1.1\r\nHost: x\r\nAuthorization: Digest "
        "username=\"user\", realm=\"TestRealm\", nonce=\"0000\", "
        "uri=\"/a\", algorithm=BOGUS, response=\"00\"\r\n\r\n" },
      P_END, P_END, P_END } },

  /* full digest handshake: harvest the nonce from the 401 and replay it
     with a 128 hex digit 'response' value (bug #4, commit 5a73c1ae) */
  { "digest-overlong-response", { 0x00, 0x09, 0x03, 0x00 },
    { { 0, "GET /a HTTP/1.1\r\nHost: x\r\n\r\n" },
      { 3, "GET /a HTTP/1.1\r\nHost: x\r\nAuthorization: Digest "
        "username=\"user\", realm=\"TestRealm\", nonce=\"%%NONCE%%\", "
        "uri=\"/a\", qop=auth, nc=00000001, cnonce=\"deadbeef\", "
        "algorithm=SHA-256, response=\""
        "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
        "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
        "\"\r\n\r\n" },
      P_END, P_END } },

  { "digest-userhash", { 0x00, 0x09, 0x03, 0x00 },
    { { 0, "GET /a HTTP/1.1\r\nHost: x\r\n\r\n" },
      { 3, "GET /a HTTP/1.1\r\nHost: x\r\nAuthorization: Digest "
        "username=\""
        "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
        "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
        "\", userhash=true, realm=\"TestRealm\", nonce=\"%%NONCE%%\", "
        "uri=\"/a\", qop=auth, nc=00000001, cnonce=\"deadbeef\", "
        "algorithm=SHA-256, response=\"0123456789abcdef\"\r\n\r\n" },
      P_END, P_END } },

  { "basic-auth", { 0x00, 0x0a, 0x03, 0x00 },
    { { 0, "GET /a HTTP/1.1\r\nHost: x\r\n"
        "Authorization: Basic dXNlcjpwYXNz\r\n\r\n" },
      P_END, P_END, P_END } },

  { "multipart-post", { 0x00, 0x0c, 0x03, 0x00 },
    { { 0, "POST /a HTTP/1.1\r\nHost: x\r\n"
        "Content-Type: multipart/form-data; boundary=--abc\r\n"
        "Transfer-Encoding: chunked\r\n\r\n"
        "52\r\n----abc\r\nContent-Disposition: form-data; name=\"k\"\r\n\r\n"
        "value\r\n----abc--\r\n\r\n0\r\n\r\n" },
      P_END, P_END, P_END } },

  { "urlencoded-post", { 0x00, 0x0c, 0x03, 0x00 },
    { { 1, "a=1&b=%41&c" },
      { 0, "POST /a HTTP/1.1\r\nHost: x\r\n"
        "Content-Type: application/x-www-form-urlencoded\r\n"
        "Content-Length: 11\r\n\r\na=1&b=%41&c" },
      P_END, P_END } },

  { "folded-header", { 0x00, 0x08, 0x00, 0x00 },
    { { 0, "GET /a HTTP/1.1\r\nHost: x\r\nX-Fold: a\r\n\tb\r\n\r\n" },
      P_END, P_END, P_END } },

  { "pipelined", { 0x00, 0x08, 0x03, 0x00 },
    { { 0, "GET /a HTTP/1.1\r\nHost: x\r\n\r\n"
        "GET /b?q HTTP/1.1\r\nHost: x\r\n\r\n" },
      P_END, P_END, P_END } },

  /* ------------- seeds driving configuration bytes 4-9 -------------
     The seeds above leave those bytes zero and only exercise the
     parser.  Without at least one seed per area below, the rest of the
     API stays practically unreachable: libFuzzer would have to guess
     six configuration bytes before anything new runs.  Each seed turns
     on exactly one area so that a minimiser keeps them distinguishable.
     ext[] is { response, auth, event-loop/introspection, suspend and
     upgrade, header seed, content-reader seed }. */

  /* Chunked reply produced by a content-reader callback, with response
     headers and a trailer -- the reply-side counterpart of the chunk
     parsing that commit c13f4c64 fixed on the request side. */
  { "ext-callback-chunked", { 0x00, 0x08, 0x03, 0x00 },
    { { 0, "GET / HTTP/1.1\r\nHost: x\r\n\r\n" }, P_END, P_END, P_END },
    { 0x0A | 0x20 | 0x40, 0x00, 0x00, 0x00, 0x01, 0x20 } },

  /* Known-length callback body, with a reader error injected part way
     through (crc_seed bit 0x80). */
  { "ext-callback-error", { 0x00, 0x08, 0x03, 0x00 },
    { { 0, "GET / HTTP/1.1\r\nHost: x\r\n\r\n" }, P_END, P_END, P_END },
    { 0x09, 0x00, 0x00, 0x00, 0x02, 0x82 } },

  { "ext-fd-response", { 0x00, 0x08, 0x03, 0x00 },
    { { 0, "GET / HTTP/1.1\r\nHost: x\r\n\r\n" }, P_END, P_END, P_END },
    { 0x0B, 0x00, 0x00, 0x00, 0x00, 0x10 } },

  { "ext-fd-at-offset-response", { 0x00, 0x08, 0x03, 0x00 },
    { { 0, "GET / HTTP/1.1\r\nHost: x\r\n\r\n" }, P_END, P_END, P_END },
    { 0x0C, 0x00, 0x00, 0x00, 0x00, 0x10 } },

  { "ext-pipe-response", { 0x00, 0x08, 0x03, 0x00 },
    { { 0, "GET / HTTP/1.1\r\nHost: x\r\n\r\n" }, P_END, P_END, P_END },
    { 0x0E, 0x00, 0x00, 0x00, 0x00, 0x10 } },

  { "ext-iovec-response", { 0x00, 0x08, 0x03, 0x00 },
    { { 0, "GET / HTTP/1.1\r\nHost: x\r\n\r\n" }, P_END, P_END, P_END },
    { 0x0F, 0x00, 0x00, 0x00, 0x00, 0x07 } },

  /* Empty response plus the header manipulation API (get/del/options). */
  { "ext-empty-response-hdrapi", { 0x00, 0x08, 0x03, 0x00 },
    { { 0, "GET / HTTP/1.1\r\nHost: x\r\n\r\n" }, P_END, P_END, P_END },
    { 0x02 | 0x30 | 0x40 | 0x80, 0x00, 0x00, 0x00, 0x05, 0x00 } },

  /* Digest through the pre-computed-userdigest entry point. */
  { "ext-digest-check-digest3", { 0x00, 0x09, 0x03, 0x00 },
    { { 0, "GET / HTTP/1.1\r\nHost: x\r\n\r\n" },
      { 0, "GET / HTTP/1.1\r\nHost: x\r\nAuthorization: Digest "
        "username=\"user\", realm=\"TestRealm\", nonce=\"%%NONCE%%\", "
        "uri=\"/\", response=\"00000000000000000000000000000000\"\r\n\r\n" },
      P_END, P_END },
    { 0x00, 0x05 | 0x80, 0x00, 0x00, 0x01, 0x00 } },

  /* The v1 wrappers and the request-info query. */
  { "ext-digest-v1-wrappers", { 0x00, 0x09, 0x03, 0x00 },
    { { 0, "GET / HTTP/1.1\r\nHost: x\r\n\r\n" }, P_END, P_END, P_END },
    { 0x00, 0x01 | 0x10, 0x00, 0x00, 0x00, 0x00 } },

  { "ext-digest-request-info", { 0x00, 0x09, 0x03, 0x00 },
    { { 0, "GET / HTTP/1.1\r\nHost: x\r\n\r\n" }, P_END, P_END, P_END },
    { 0x00, 0x08 | 0x20, 0x00, 0x00, 0x03, 0x00 } },

  /* Application-driven event loop: MHD_get_fdset2() + select() +
     MHD_run_from_select2(), with the timeout accessors. */
  { "ext-external-event-loop", { 0x00, 0x08, 0x03, 0x00 },
    { { 0, "GET / HTTP/1.1\r\nHost: x\r\n\r\n" }, P_END, P_END, P_END },
    { 0x01, 0x00, 0x02 | 0x04, 0x00, 0x00, 0x00 } },

  /* The v1 fdset/run_from_select pair. */
  { "ext-external-event-loop-v1", { 0x00, 0x08, 0x03, 0x00 },
    { { 0, "GET / HTTP/1.1\r\nHost: x\r\n\r\n" }, P_END, P_END, P_END },
    { 0x01, 0x00, 0x01 | 0x04, 0x00, 0x00, 0x00 } },

  /* Every connection-introspection accessor at once. */
  { "ext-connection-api", { 0x00, 0x08, 0x03, 0x00 },
    { { 0, "GET /path?a=1 HTTP/1.1\r\nHost: x\r\nCookie: a=b\r\n\r\n" },
      P_END, P_END, P_END },
    { 0x01, 0x00, 0x08 | 0x10 | 0x20 | 0x40 | 0x80, 0x00, 0x10, 0x00 } },

  /* Suspend the connection and resume it from the pump loop. */
  { "ext-suspend-resume", { 0x00, 0x08, 0x03, 0x00 },
    { { 0, "GET / HTTP/1.1\r\nHost: x\r\n\r\n" },
      { 2, "" }, P_END, P_END },
    { 0x01, 0x00, 0x00, 0x02, 0x00, 0x00 } },

  /* Two connections parked at the same time (op 3 opens the second
     without waiting for the first).  The bookkeeping behind suspend
     mode 2 has to be a set for this: while it was a single slot the
     first connection was forgotten and stayed suspended, and
     MHD_stop_daemon() answered with
     MHD_PANIC ("called while we have suspended connections"). */
  { "ext-suspend-two-connections", { 0x00, 0x08, 0x03, 0x00 },
    { { 0, "GET /a HTTP/1.1\r\nHost: x\r\n\r\n" },
      { 3, "GET /b HTTP/1.1\r\nHost: x\r\n\r\n" },
      { 2, "" }, P_END },
    { 0x01, 0x00, 0x00, 0x02, 0x00, 0x00 } },

  /* HTTP "Upgrade": the client asks for it and the handler answers 101
     with an upgrade response, after which the socket is handed over. */
  { "ext-upgrade", { 0x00, 0x08, 0x03, 0x00 },
    { { 0, "GET / HTTP/1.1\r\nHost: x\r\nConnection: Upgrade\r\n"
        "Upgrade: fuzz-protocol\r\n\r\n" },
      { 2, "" }, P_END, P_END },
    { 0x01, 0x00, 0x00, 0x04 | 0x08, 0x00, 0x00 } },

  /* The remaining response constructors.  One seed each, because the
     constructor is picked by the low nibble of ext[0] and a seed that
     does not name it leaves that entry point unreachable until the
     fuzzer happens to mutate the nibble. */
  { "ext-buffer-persistent", { 0x00, 0x08, 0x03, 0x00 },
    { { 0, "GET / HTTP/1.1\r\nHost: x\r\n\r\n" }, P_END, P_END, P_END },
    { 0x03, 0x00, 0x00, 0x00, 0x00, 0x00 } },

  { "ext-buffer-free-callback", { 0x00, 0x08, 0x03, 0x00 },
    { { 0, "GET / HTTP/1.1\r\nHost: x\r\n\r\n" }, P_END, P_END, P_END },
    { 0x06, 0x00, 0x00, 0x00, 0x00, 0x00 } },

  { "ext-from-data", { 0x00, 0x08, 0x03, 0x00 },
    { { 0, "GET / HTTP/1.1\r\nHost: x\r\n\r\n" }, P_END, P_END, P_END },
    { 0x07, 0x00, 0x00, 0x00, 0x00, 0x00 } },

  { "ext-fd64-response", { 0x00, 0x08, 0x03, 0x00 },
    { { 0, "GET / HTTP/1.1\r\nHost: x\r\n\r\n" }, P_END, P_END, P_END },
    { 0x0D, 0x00, 0x00, 0x00, 0x00, 0x00 } },

  /* The v1 basic-auth getter, which returns two separate malloc()ed
     strings rather than one struct. */
  { "ext-basic-auth-v1", { 0x00, 0x0a, 0x03, 0x00 },
    { { 0, "GET / HTTP/1.1\r\nHost: x\r\n"
        "Authorization: Basic dXNlcjpwYXNz\r\n\r\n" },
      P_END, P_END, P_END },
    { 0x01, 0x40, 0x00, 0x00, 0x00, 0x00 } },

  /* Answer the challenge with the basic-auth responses instead of the
     digest ones (fail_variant 3). */
  { "ext-basic-auth-challenge", { 0x00, 0x09, 0x03, 0x00 },
    { { 0, "GET / HTTP/1.1\r\nHost: x\r\n\r\n" }, P_END, P_END, P_END },
    { 0x01, 0x30, 0x00, 0x00, 0x00, 0x00 } },

  { "ext-basic-auth-challenge-utf8", { 0x00, 0x09, 0x03, 0x00 },
    { { 0, "GET / HTTP/1.1\r\nHost: x\r\n\r\n" }, P_END, P_END, P_END },
    { 0x01, 0x30, 0x00, 0x00, 0x03, 0x00 } },

  /* The MD5-only and algorithm-parametrised pre-computed digest
     wrappers. */
  { "ext-digest-check-digest-v1", { 0x00, 0x09, 0x03, 0x00 },
    { { 0, "GET / HTTP/1.1\r\nHost: x\r\n\r\n" }, P_END, P_END, P_END },
    { 0x01, 0x03, 0x00, 0x00, 0x00, 0x00 } },

  { "ext-digest-check-digest2", { 0x00, 0x09, 0x03, 0x00 },
    { { 0, "GET / HTTP/1.1\r\nHost: x\r\n\r\n" }, P_END, P_END, P_END },
    { 0x01, 0x04, 0x00, 0x00, 0x01, 0x00 } },

  /* The username queries. */
  { "ext-digest-get-username-v1", { 0x00, 0x09, 0x03, 0x00 },
    { { 0, "GET / HTTP/1.1\r\nHost: x\r\n"
        "Authorization: Digest username=\"user\", realm=\"TestRealm\"\r\n\r\n" }
      ,
      P_END, P_END, P_END },
    { 0x01, 0x06, 0x00, 0x00, 0x00, 0x00 } },

  { "ext-digest-get-username3", { 0x00, 0x09, 0x03, 0x00 },
    { { 0, "GET / HTTP/1.1\r\nHost: x\r\n"
        "Authorization: Digest userhash=true, username=\"aabb\", "
        "realm=\"TestRealm\"\r\n\r\n" },
      P_END, P_END, P_END },
    { 0x01, 0x07, 0x00, 0x00, 0x00, 0x00 } }
};

static uint8_t seed_render_buf[4096];


static size_t
fuzz_seed_count (void)
{
  return sizeof (seeds) / sizeof (seeds[0]);
}


static const uint8_t *
fuzz_seed_get (size_t idx,
               size_t *len)
{
  const struct seed_def *sd = &seeds[idx];
  struct sbuf b;
  unsigned int i;

  b.p = seed_render_buf;
  b.len = 0;
  b.cap = sizeof (seed_render_buf);
  sb_raw (&b, sd->cfg, 4);
  sb_raw (&b, sd->ext, sizeof (sd->ext));
  for (i = 0; i < sizeof (sd->parts) / sizeof (sd->parts[0]); i++)
  {
    size_t n;
    unsigned int hv;
    uint8_t hdr[2];

    if (NULL == sd->parts[i].txt)
      break;
    n = strlen (sd->parts[i].txt);
    if (n > 0x3FFF)
      n = 0x3FFF;
    hv = (sd->parts[i].op << 14) | (unsigned int) n;
    hdr[0] = (uint8_t) (hv & 0xFF);
    hdr[1] = (uint8_t) (hv >> 8);
    sb_raw (&b, hdr, 2);
    sb_raw (&b, sd->parts[i].txt, n);
  }
  *len = b.len;
  return seed_render_buf;
}
