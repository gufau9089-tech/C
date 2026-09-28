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
 * @file fuzz/fuzz_eventloop.c
 * @brief In-process fuzzer for MHD's external event loop and for the
 *        scheduling of the connection life cycle.
 * @author Christian Grothoff
 *
 * fuzz_request.c already touches these entry points, but only as a side
 * channel: it picks one event-loop mode per iteration and then always
 * pumps in the same rhythm.  The bugs this harness is after are in the
 * *scheduling* -- what MHD does when the application polls at adversarial
 * times, ignores the timeout it was given, calls MHD_run_from_select()
 * with descriptor sets that do not match what MHD asked for, or
 * suspends/resumes connections across those calls.
 *
 * The input is therefore not an HTTP request but a *schedule*: a short
 * configuration block followed by a program of one-byte opcodes that is
 * interpreted against a live `struct MHD_Daemon` with up to
 * #MAX_CONNS socketpair connections.  Request bytes enter the program
 * through two of those opcodes (a fragment table and a raw literal), so
 * the parser is still driven, just not fuzzed.
 *
 * Input format
 * ------------
 *
 *   byte 0   daemon configuration
 *              bits 0-1  MHD_OPTION_CONNECTION_TIMEOUT selector,
 *                        index into {1, 2, 0, 1} seconds
 *              bit  2    give the daemon a real listening socket (port 0)
 *                        instead of MHD_USE_NO_LISTEN_SOCKET, so that
 *                        MHD_quiesce_daemon() has something to do and the
 *                        listen FD shows up in the descriptor sets
 *              bit  3    pass MHD_OPTION_APP_FD_SETSIZE
 *              bits 4-5  MHD_OPTION_CONNECTION_MEMORY_LIMIT selector,
 *                        index into {default, 256, 1024, 4096}
 *              bit  6    MHD_OPTION_CONNECTION_LIMIT = 2, so that
 *                        MHD_add_connection() starts failing
 *              bit  7    shrink SO_SNDBUF/SO_RCVBUF of the socketpair, so
 *                        that responses do not fit and connections stay
 *                        blocked on write
 *   byte 1   access-handler behaviour
 *              bits 0-1  response kind: 0 small static buffer,
 *                        1 chunked callback (MHD_SIZE_UNKNOWN),
 *                        2 large (128 KiB) static buffer, 3 empty
 *              bit  2    answer 500 instead of 200
 *              bit  3    suspend in the handler and leave it parked
 *              bit  4    suspend and resume immediately in the handler
 *              bit  5    call MHD_set_connection_option() from the handler
 *              bit  6    call MHD_get_connection_info() from the handler
 *              bit  7    drain the client side after every run
 *   byte 2   event-loop defaults
 *              bits 0-2  default MHD_get_fdset*() variant
 *              bits 3-4  default run entry point
 *              bit  5    honour the timeout MHD returns
 *              bit  6    query the timeouts after every run
 *              bit  7    MHD_quiesce_daemon() before stopping
 *   byte 3   schedule knobs
 *              bits 0-1  number of connections opened up front (1-4)
 *              bit  2    run the timeout oracle after every operation
 *              bit  3    allow a real-time wait for a connection timeout
 *                        to expire (globally budgeted, see below)
 *              bit  4    queue one more connection at the very end and
 *                        stop the daemon without running the loop again,
 *                        so that MHD has to dispose of a connection it
 *                        never started (see queue_unprocessed_conn())
 *              bits 5-7  unused
 *   byte 4   artificial-clock step base
 *   byte 5.  the operation program.  Each operation is one byte,
 *            `(opcode << 4) | argument`; see enum op below.  OP_SEND_RAW
 *            is the only one with an operand: a length byte followed by
 *            that many payload bytes.
 *
 * An input shorter than five bytes is rejected: the configuration block
 * is mandatory and an input that short carries no program either.
 *
 * Oracles
 * -------
 *
 * Beyond ASAN/UBSAN and the MHD_set_panic_func() tripwire (any
 * MHD_PANIC() reached this way is a finding, including the
 * "MHD_stop_daemon() called while we have suspended connections" one
 * that answers the "the daemon must always be stoppable" requirement):
 *
 *  a) the four timeout accessors must agree.  MHD_get_timeout(),
 *     MHD_get_timeout64(), MHD_get_timeout64s() and MHD_get_timeout_i()
 *     read the same state, so either all of them report a timeout or
 *     none of them does.  Their values are read in sequence, so the
 *     clock may advance between two of them and the value may only
 *     *decrease*; connection_get_wait() has a documented 100 ms floor
 *     for the "exact match" case, hence the 100 ms slack.
 *
 *  b) a reported timeout must never exceed the largest connection
 *     timeout in effect.  MHD only ever derives it from
 *     `last_activity + connection_timeout_ms`, so a larger value would
 *     mean the deadline is somewhere the application cannot reach.
 *
 *  c) MHD must never ask the application to wait forever while it has a
 *     live, not-suspended connection with a non-zero timeout: that is
 *     precisely the "timeout in the past" situation, i.e. a connection
 *     that can never be reaped.  Live connections are tracked through
 *     MHD_OPTION_NOTIFY_CONNECTION, which brackets exactly the interval
 *     in which MHD owns the connection object.
 *
 *     Both inputs of (b) and (c) -- whether a connection is suspended and
 *     what its timeout is -- are read back from MHD rather than modelled,
 *     because both diverge from what the application asked for:
 *     MHD_set_connection_option() silently does nothing while a
 *     connection is suspended.  A harness that models them ends up
 *     reporting findings against its own model.
 *
 *  d) MHD_get_fdset*() must not set a descriptor at or above the
 *     FD_SETSIZE limit it was given, `*max_fd` must be at least as large
 *     as every descriptor that was added, and `*max_fd` itself must be
 *     one of them.
 *
 *  e) after MHD_quiesce_daemon() the listening socket must be gone from
 *     the descriptor sets.
 *
 * Two contract rules the harness has to respect (violating either makes
 * MHD abort on a schedule that is perfectly legal, so the harness would
 * only be finding its own bugs):
 *
 *  * a connection is only suspended when the access handler is about to
 *    return MHD_YES.  MHD_NO asks MHD to terminate the connection, and
 *    terminating one that the same callback just suspended trips
 *    mhd_assert (! connection->suspended) in MHD_connection_close_();
 *
 *  * every suspended connection is resumed before MHD_stop_daemon().
 *    Several connections can be parked at once, so this is a set
 *    (@e lives[i].susp), not a single slot, and @e tearing_down stops
 *    the handler from parking anything new while the set is drained.
 *
 * MHD_suspend_connection() is additionally only called when MHD does not
 * already consider the connection suspended, *unless* a resume of it is
 * still pending -- that is the one case internal_suspend_connection_()
 * handles itself (it cancels the resume), and the harness mirrors the
 * resulting state.  Calling it on an already-suspended connection would
 * unlink it from a list it is not on.
 *
 * One more trap: with MHD_USE_ITC -- which MHD_ALLOW_SUSPEND_RESUME
 * implies, so this harness always has it -- MHD_add_connection() only
 * *queues* the socket, and the `struct MHD_Connection` is created later,
 * from inside a run.  There is therefore no moment at which the
 * application could pair its own socket up with the connection object,
 * and the registry of live connections has to be built purely from
 * MHD_OPTION_NOTIFY_CONNECTION.  This is why the client sockets
 * (@e csock) and the connections (@e lives) are two separate arrays.
 *
 * Note on MHD_get_timeout_expiration(): no such function exists in the
 * MHD 1.x API.  The four accessors above are the complete family; the
 * absolute-deadline form is a MHD 2.x addition.
 */

#define FUZZ_HARNESS_NAME "fuzz_eventloop"
#include "fuzz_common.h"

#include <microhttpd.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <sys/select.h>
#include <limits.h>

/** Largest number of connections a single iteration may have open. */
#define MAX_CONNS 8

/** Upper bound on the number of operations interpreted per iteration. */
#define MAX_OPS 400

/** Size of the "large response" body. */
#define BIG_BODY_LEN 131072

/** Bytes read back from the daemon are counted, never inspected. */
#define DRAIN_BUF 4096


/* ------------------------------------------------------------------ */
/* Per-iteration configuration                                         */
/* ------------------------------------------------------------------ */

struct el_cfg
{
  unsigned int timeout_s;      /**< MHD_OPTION_CONNECTION_TIMEOUT */
  int listen_sock;             /**< real listening socket wanted */
  int app_fd_setsize;          /**< pass MHD_OPTION_APP_FD_SETSIZE */
  size_t mem_limit;            /**< MHD_OPTION_CONNECTION_MEMORY_LIMIT */
  int conn_limit;              /**< MHD_OPTION_CONNECTION_LIMIT = 2 */
  int small_sockbuf;           /**< shrink the socketpair buffers */

  unsigned int resp_kind;      /**< which response the handler queues */
  int error_reply;             /**< answer 500 instead of 200 */
  int susp_park;               /**< handler suspends and leaves it parked */
  int susp_now;                /**< handler suspends and resumes at once */
  int hnd_connopt;             /**< handler calls set_connection_option */
  int hnd_info;                /**< handler calls get_connection_info */
  int auto_drain;              /**< drain the client sockets after a run */

  unsigned int fdset_var;      /**< default MHD_get_fdset*() variant */
  unsigned int run_var;        /**< default run entry point */
  int honour_timeout;          /**< act on the timeout MHD returns */
  int timeout_every_run;       /**< query the timeouts after every run */
  int quiesce_end;             /**< quiesce before stopping */

  unsigned int nconn_up_front; /**< connections opened before the program */
  int check_always;            /**< run the timeout oracle after every op */
  int allow_real_wait;         /**< may burn real time on a timeout expiry */
  int stop_with_queued;        /**< stop with a connection still queued */
  uint8_t clock_seed;          /**< artificial-clock step base */
};

static struct el_cfg cfg;

/** Connection memory limits selectable by byte 0. */
static const size_t mem_limit_tbl[] = { 0, 256, 1024, 4096 };

/** Connection timeouts (seconds) selectable by byte 0. */
static const unsigned int timeout_tbl[] = { 1, 2, 0, 1 };

/**
 * FD_SETSIZE values handed to MHD_get_fdset2()/MHD_run_from_select2().
 *
 * All of them are <= FD_SETSIZE on purpose.  Passing a *larger* value
 * than the `fd_set` objects actually hold would let MHD write past them,
 * which is the application lying about its own buffers rather than
 * anything MHD could defend against; the interesting direction is the
 * smaller one, where MHD has to refuse descriptors that do not fit.
 */
static const unsigned int setsize_tbl[] = {
  (unsigned int) FD_SETSIZE,
  (unsigned int) FD_SETSIZE,
  (unsigned int) FD_SETSIZE / 2,
  64, 16, 4, 1, (unsigned int) FD_SETSIZE
};


/* ------------------------------------------------------------------ */
/* Per-iteration state                                                 */
/* ------------------------------------------------------------------ */

/**
 * The client end of one socketpair.  Deliberately *not* tied to a
 * `struct MHD_Connection`: with MHD_USE_ITC (which
 * MHD_ALLOW_SUSPEND_RESUME implies) MHD_add_connection() only queues the
 * socket and the connection object is created later, from inside a run.
 * There is therefore no moment at which the harness could pair the two
 * up, and trying to would silently mistrack every connection.
 */
static int csock[MAX_CONNS];
static unsigned int nconns;
static unsigned int cur_conn;

/**
 * A connection MHD currently owns.
 *
 * The registry is maintained purely from MHD_OPTION_NOTIFY_CONNECTION,
 * which brackets exactly the interval in which the object exists: after
 * MHD_CONNECTION_NOTIFY_CLOSED nothing may reference it any more, in
 * particular not a deferred resume and not the "is there a live
 * connection" oracle.
 */
struct live_conn
{
  struct MHD_Connection *mc;   /**< NULL if the slot is free */
  int susp;                    /**< suspended by us, not resumed yet */
};

/** A few more slots than connections, so the registry cannot overflow. */
#define MAX_LIVE (MAX_CONNS + 4)

static struct live_conn lives[MAX_LIVE];

/** Daemon of the current iteration. */
static struct MHD_Daemon *cur_daemon;

/**
 * Set once the iteration only wants to drain the daemon.  The handler
 * then stops parking connections, which is what makes the flush loop in
 * the teardown terminate.
 */
static int tearing_down;

/** Listening socket returned by MHD_quiesce_daemon(), ours to close. */
static MHD_socket quiesced_fd = MHD_INVALID_SOCKET;

/** Artificial clock; only the harness's own scheduling depends on it. */
static uint64_t clk_ms;
static uint64_t deadline_ms;
static int deadline_valid;

/** Descriptor sets collected by the last OP_FDSET. */
static fd_set g_rs;
static fd_set g_ws;
static fd_set g_es;
static MHD_socket g_max_fd = MHD_INVALID_SOCKET;
static unsigned int g_setsize = (unsigned int) FD_SETSIZE;
static int g_have_sets;

/** The large response body, filled once. */
static char big_body[BIG_BODY_LEN];
static int big_body_ready;

/**
 * Budget for iterations that are allowed to wait in real time for a
 * connection timeout to expire.  MHD_OPTION_CONNECTION_TIMEOUT has a
 * resolution of one second, so the expiry path cannot be reached without
 * actually burning about that much wall clock; the budget keeps the
 * whole run in the "couple of seconds" range while still exercising it.
 * Override with MHD_FUZZ_EXPIRY_BUDGET.
 */
static int expiry_budget = 2;
static int expiry_budget_read;

/** Statistics, printed at exit with --verbose. */
static unsigned long stat_daemons;
static unsigned long stat_handler_calls;
static unsigned long stat_fdset_v1;
static unsigned long stat_fdset_v2;
static unsigned long stat_rfs_v1;
static unsigned long stat_rfs_v2;
static unsigned long stat_run;
static unsigned long stat_run_wait;
static unsigned long stat_timeouts;
static unsigned long stat_quiesce;
static unsigned long stat_suspend;
static unsigned long stat_resume;
static unsigned long stat_expiry_waits;
static unsigned long stat_queued_at_stop;
static int stats_registered;


static void
print_stats (void)
{
  if (! fuzz_verbose)
    return;
  fprintf (stderr,
           "%s: daemons=%lu handler=%lu get_fdset=%lu get_fdset2=%lu "
           "run_from_select=%lu run_from_select2=%lu run=%lu run_wait=%lu "
           "timeout queries=%lu quiesce=%lu suspend=%lu resume=%lu "
           "expiry waits=%lu queued at stop=%lu\n",
           FUZZ_HARNESS_NAME,
           stat_daemons, stat_handler_calls, stat_fdset_v1, stat_fdset_v2,
           stat_rfs_v1, stat_rfs_v2, stat_run, stat_run_wait,
           stat_timeouts, stat_quiesce, stat_suspend, stat_resume,
           stat_expiry_waits, stat_queued_at_stop);
}


/* ------------------------------------------------------------------ */
/* Callbacks                                                           */
/* ------------------------------------------------------------------ */

static void
panic_cb (void *cls,
          const char *file,
          unsigned int line,
          const char *reason)
{
  char msg[512];

  (void) cls;
  (void) snprintf (msg, sizeof (msg),
                   "MHD_PANIC() reached from an event-loop schedule "
                   "at %s:%u: %s",
                   (NULL != file) ? file : "?",
                   line,
                   (NULL != reason) ? reason : "?");
  fuzz_report_finding (msg);
}


/**
 * Find the registry slot of @a c, or -1.
 */
static int
slot_of (const struct MHD_Connection *c)
{
  unsigned int i;

  for (i = 0; i < MAX_LIVE; i++)
    if ( (NULL != lives[i].mc) &&
         (lives[i].mc == c) )
      return (int) i;
  return -1;
}


static void
notify_conn_cb (void *cls,
                struct MHD_Connection *connection,
                void **socket_context,
                enum MHD_ConnectionNotificationCode toe)
{
  unsigned int i;
  int idx;

  (void) cls;
  (void) socket_context;
  if (MHD_CONNECTION_NOTIFY_STARTED == toe)
  {
    for (i = 0; i < MAX_LIVE; i++)
    {
      if (NULL != lives[i].mc)
        continue;
      lives[i].mc = connection;
      lives[i].susp = 0;
      return;
    }
    return;
  }
  /* MHD_CONNECTION_NOTIFY_CLOSED: the object is about to be freed. */
  idx = slot_of (connection);
  if (0 <= idx)
  {
    lives[idx].mc = NULL;
    lives[idx].susp = 0;
  }
}


/* ------------------------------------------------------------------ */
/* Suspend / resume bookkeeping                                        */
/* ------------------------------------------------------------------ */

/**
 * Ask MHD whether it considers slot @a i suspended.
 */
static int
mhd_thinks_suspended (unsigned int i)
{
  const union MHD_ConnectionInfo *ci;

  if (NULL == lives[i].mc)
    return 0;
  ci = MHD_get_connection_info (lives[i].mc,
                                MHD_CONNECTION_INFO_CONNECTION_SUSPENDED);
  if (NULL == ci)
    return 0;
  return (MHD_YES == ci->suspended);
}


/**
 * Suspend slot @a i, if that is legal right now.
 *
 * MHD_suspend_connection() unlinks the connection from the timeout and
 * connection lists, so calling it on a connection MHD already has on the
 * suspended list corrupts those lists.  The one exception is a
 * connection with a resume still pending: internal_suspend_connection_()
 * detects that itself and merely cancels the resume, leaving the
 * connection suspended -- which is why @e susp is set in both branches.
 */
static void
do_suspend (unsigned int i)
{
  int mhd_susp;

  if ( (i >= MAX_LIVE) ||
       (NULL == lives[i].mc) )
    return;
  mhd_susp = mhd_thinks_suspended (i);
  if (mhd_susp && lives[i].susp)
    return;                     /* really suspended already */
  MHD_suspend_connection (lives[i].mc);
  lives[i].susp = 1;
  stat_suspend++;
}


static void
do_resume (unsigned int i)
{
  if ( (i >= MAX_LIVE) ||
       (NULL == lives[i].mc) ||
       (! lives[i].susp) )
    return;
  /* Clear first: MHD_resume_connection() may end up running the handler
     later, which is allowed to suspend the very same connection again. */
  lives[i].susp = 0;
  MHD_resume_connection (lives[i].mc);
  stat_resume++;
}


/**
 * Resume everything still parked.
 *
 * @return non-zero if at least one connection was resumed, so that the
 *         caller knows the daemon needs another round to act on it
 */
static int
resume_all (void)
{
  unsigned int i;
  int any = 0;

  for (i = 0; i < MAX_LIVE; i++)
  {
    if ( (NULL == lives[i].mc) ||
         (! lives[i].susp) )
      continue;
    lives[i].susp = 0;
    MHD_resume_connection (lives[i].mc);
    stat_resume++;
    any = 1;
  }
  return any;
}


/**
 * Summarise the connections MHD currently owns.
 *
 * Both properties are read back from MHD rather than modelled: a
 * connection leaves the timeout lists exactly when MHD sets
 * `connection->suspended`, and its timeout is exactly what
 * MHD_set_connection_option() left there -- which is *not* what the
 * application passed if the connection happened to be suspended at the
 * time.  Modelling either of them means the oracle eventually fires on
 * the model rather than on MHD.
 *
 * @param[out] max_ms largest timeout, in milliseconds, of the
 *        connections that are in a timeout list right now
 * @return non-zero if at least one such connection exists, i.e. if MHD
 *         must report a timeout
 */
static int
scan_live_timeouts (uint64_t *max_ms)
{
  unsigned int i;
  int any = 0;

  *max_ms = 0;
  for (i = 0; i < MAX_LIVE; i++)
  {
    const union MHD_ConnectionInfo *ci;
    uint64_t ms;

    if (NULL == lives[i].mc)
      continue;
    ci = MHD_get_connection_info (lives[i].mc,
                                  MHD_CONNECTION_INFO_CONNECTION_SUSPENDED);
    if ( (NULL != ci) &&
         (MHD_YES == ci->suspended) )
      continue;                 /* not in any timeout list */
    ci = MHD_get_connection_info (lives[i].mc,
                                  MHD_CONNECTION_INFO_CONNECTION_TIMEOUT);
    if (NULL == ci)
      continue;
    ms = ((uint64_t) ci->connection_timeout) * 1000;
    if (0 == ms)
      continue;                 /* in a list, but exempt from timeouts */
    any = 1;
    if (ms > *max_ms)
      *max_ms = ms;
  }
  return any;
}


/* ------------------------------------------------------------------ */
/* The access handler                                                  */
/* ------------------------------------------------------------------ */

struct crc_state
{
  uint64_t total;
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


static struct MHD_Response *
make_response (void)
{
  struct crc_state *st;
  struct MHD_Response *r;

  switch (cfg.resp_kind)
  {
  case 1:
    st = (struct crc_state *) calloc (1, sizeof (struct crc_state));
    if (NULL == st)
      return NULL;
    st->total = 700;
    st->pattern = cfg.clock_seed;
    r = MHD_create_response_from_callback (MHD_SIZE_UNKNOWN,
                                           128,
                                           &crc_cb,
                                           st,
                                           &crc_free);
    if (NULL == r)
      free (st);
    return r;
  case 2:
    /* Large enough not to fit into the socket buffers, so that the
       connection stays blocked on write and MHD has to schedule it
       through the write descriptor set over several rounds. */
    return MHD_create_response_from_buffer_static (BIG_BODY_LEN, big_body);
  case 3:
    return MHD_create_response_empty (MHD_RF_NONE);
  default:
    return MHD_create_response_from_buffer_static (2, "ok");
  }
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
  struct MHD_Response *resp;
  enum MHD_Result ret;
  int idx;

  (void) cls;
  (void) url;
  (void) method;
  (void) version;
  (void) upload_data;
  if (NULL == *req_cls)
  {
    *req_cls = (void *) (intptr_t) 1;
    return MHD_YES;
  }
  stat_handler_calls++;
  if (0 != *upload_data_size)
  {
    *upload_data_size = 0;
    return MHD_YES;
  }

  idx = slot_of (connection);
  if (cfg.hnd_connopt)
  {
    /* Moves the connection between the "normal" and the "manual" timeout
       list, i.e. changes which connection MHD_get_timeout*() reports. */
    unsigned int nt = (0 == cfg.timeout_s) ? 1u : (cfg.timeout_s + 1u);

    (void) MHD_set_connection_option (connection,
                                      MHD_CONNECTION_OPTION_TIMEOUT,
                                      nt);
  }
  if (cfg.hnd_info)
  {
    volatile size_t sink = 0;
    const union MHD_ConnectionInfo *ci;

    ci = MHD_get_connection_info (connection,
                                  MHD_CONNECTION_INFO_CONNECTION_FD);
    if (NULL != ci)
      sink += (size_t) (ci->connect_fd + 1);
    ci = MHD_get_connection_info (connection,
                                  MHD_CONNECTION_INFO_CONNECTION_TIMEOUT);
    if (NULL != ci)
      sink += (size_t) ci->connection_timeout;
    (void) sink;
  }

  resp = make_response ();
  if (NULL == resp)
    return MHD_NO;
  ret = MHD_queue_response (connection,
                            cfg.error_reply
                            ? MHD_HTTP_INTERNAL_SERVER_ERROR : MHD_HTTP_OK,
                            resp);
  MHD_destroy_response (resp);
  if (MHD_YES != ret)
    return ret;
  /* Only once the response was accepted: returning MHD_NO tells MHD to
     terminate the connection, and terminating one that this very callback
     suspended trips mhd_assert (! connection->suspended) in
     MHD_connection_close_(). */
  if (tearing_down ||
      (0 > idx))
    return ret;
  if (cfg.susp_now)
  {
    MHD_suspend_connection (connection);
    MHD_resume_connection (connection);
    stat_suspend++;
    stat_resume++;
  }
  else if (cfg.susp_park &&
           (! lives[idx].susp))
  {
    MHD_suspend_connection (connection);
    lives[idx].susp = 1;
    stat_suspend++;
  }
  return ret;
}


/* ------------------------------------------------------------------ */
/* Oracles                                                             */
/* ------------------------------------------------------------------ */

/**
 * Query all four timeout accessors and cross-check them.
 *
 * The values are read one after the other, so the monotonic clock may
 * advance in between and a later reading may be *smaller*.  It may never
 * be larger, except for the 100 ms floor connection_get_wait() falls back
 * to when the elapsed time exactly matches the timeout.
 */
static void
check_timeouts (struct MHD_Daemon *d)
{
  MHD_UNSIGNED_LONG_LONG tl = 0;
  uint64_t t64 = 0;
  int64_t t64s;
  int ti;
  enum MHD_Result r1;
  enum MHD_Result r2;
  int have[4];
  uint64_t val[4];
  unsigned int k;
  uint64_t max_ms;
  int any_timed;
  char msg[256];

  stat_timeouts++;
  r1 = MHD_get_timeout (d, &tl);
  r2 = MHD_get_timeout64 (d, &t64);
  t64s = MHD_get_timeout64s (d);
  ti = MHD_get_timeout_i (d);

  have[0] = (MHD_YES == r1);
  have[1] = (MHD_YES == r2);
  have[2] = (0 <= t64s);
  have[3] = (0 <= ti);
  val[0] = (uint64_t) tl;
  val[1] = t64;
  val[2] = (uint64_t) (t64s < 0 ? 0 : t64s);
  val[3] = (uint64_t) (ti < 0 ? 0 : ti);

  for (k = 1; k < 4; k++)
    if (have[k] != have[0])
      fuzz_report_finding (
        "MHD_get_timeout*(): the four accessors disagree about whether "
        "a timeout is in effect");

  any_timed = scan_live_timeouts (&max_ms);
  if (! have[0])
  {
    /* An indefinite wait while a live, not-suspended connection has a
       non-zero timeout means that connection can never be reaped: its
       deadline is already unreachable for the application. */
    if (any_timed)
      fuzz_report_finding (
        "MHD_get_timeout*() reported no timeout although the daemon has a "
        "live, not suspended connection with a non-zero timeout");
    deadline_valid = 0;
    return;
  }

  for (k = 0; k < 4; k++)
  {
    if (val[k] <= max_ms)
      continue;
    (void) snprintf (msg, sizeof (msg),
                     "MHD_get_timeout*() [accessor %u] returned %llu ms, "
                     "larger than the largest connection timeout in effect "
                     "(%llu ms)",
                     k,
                     (unsigned long long) val[k],
                     (unsigned long long) max_ms);
    fuzz_report_finding (msg);
  }
  for (k = 1; k < 4; k++)
    if ( (val[k] > val[k - 1]) &&
         (val[k] > 100) )
      fuzz_report_finding (
        "MHD_get_timeout*(): a later accessor reported a larger timeout "
        "than an earlier one, although the deadline cannot have moved");

  deadline_ms = clk_ms + val[1];
  deadline_valid = 1;
}


/**
 * Check the descriptor sets that the last MHD_get_fdset*() produced.
 *
 * @param setsize the FD_SETSIZE limit that was passed to MHD
 * @param max_fd the reported maximum, #MHD_INVALID_SOCKET if none
 * @param had_max whether a @a max_fd pointer was passed at all
 * @param with_es whether an except set was passed
 */
static void
check_fdsets (unsigned int setsize,
              MHD_socket max_fd,
              int had_max,
              int with_es)
{
  int f;
  int hi = -1;
  int max_seen = 0;

  for (f = 0; f < (int) FD_SETSIZE; f++)
  {
    int in_set = FD_ISSET (f, &g_rs) || FD_ISSET (f, &g_ws);

    if (with_es && FD_ISSET (f, &g_es))
      in_set = 1;
    if (! in_set)
      continue;
    if ((unsigned int) f >= setsize)
      fuzz_report_finding (
        "MHD_get_fdset*() added a descriptor at or above the FD_SETSIZE "
        "limit it was given");
    if (f > hi)
      hi = f;
    if ( (had_max) &&
         (MHD_INVALID_SOCKET != max_fd) &&
         (f == (int) max_fd) )
      max_seen = 1;
  }
  if (! had_max)
    return;
  if (0 > hi)
  {
    if (MHD_INVALID_SOCKET != max_fd)
      fuzz_report_finding (
        "MHD_get_fdset*() set max_fd although it added no descriptor");
    return;
  }
  if (MHD_INVALID_SOCKET == max_fd)
    fuzz_report_finding (
      "MHD_get_fdset*() added descriptors but left max_fd unset");
  if (hi > (int) max_fd)
    fuzz_report_finding (
      "MHD_get_fdset*() added a descriptor larger than the max_fd it "
      "reported");
  if ((unsigned int) max_fd >= setsize)
    fuzz_report_finding (
      "MHD_get_fdset*() reported a max_fd at or above the FD_SETSIZE "
      "limit it was given");
  if (! max_seen)
    fuzz_report_finding (
      "MHD_get_fdset*() reported a max_fd that is not in any of the sets");
}


/* ------------------------------------------------------------------ */
/* Event-loop primitives                                               */
/* ------------------------------------------------------------------ */

/**
 * Collect the descriptor sets.
 *
 * Variant 0 goes through the *real* v1 entry point.  microhttpd.h also
 * defines MHD_get_fdset as a macro forwarding to MHD_get_fdset2 with
 * FD_SETSIZE, so the name has to be parenthesised or the v1 function is
 * never reached at all.  Same trick for MHD_run_from_select below.
 */
static void
op_fdset (struct MHD_Daemon *d,
          unsigned int var)
{
  MHD_socket max_fd = MHD_INVALID_SOCKET;
  unsigned int setsize = (unsigned int) FD_SETSIZE;
  int had_max = 1;
  int with_es = 1;

  FD_ZERO (&g_rs);
  FD_ZERO (&g_ws);
  FD_ZERO (&g_es);
  switch (var % 5)
  {
  case 0:
    stat_fdset_v1++;
    (void) (MHD_get_fdset) (d, &g_rs, &g_ws, &g_es, &max_fd);
    break;
  case 1:
    stat_fdset_v2++;
    (void) MHD_get_fdset2 (d, &g_rs, &g_ws, &g_es, &max_fd,
                           (unsigned int) FD_SETSIZE);
    break;
  case 2:
    stat_fdset_v2++;
    setsize = setsize_tbl[(var + cfg.clock_seed)
                          % (sizeof (setsize_tbl)
                             / sizeof (setsize_tbl[0]))];
    (void) MHD_get_fdset2 (d, &g_rs, &g_ws, &g_es, &max_fd, setsize);
    break;
  case 3:
    /* max_fd is documented as optional */
    stat_fdset_v2++;
    had_max = 0;
    (void) MHD_get_fdset2 (d, &g_rs, &g_ws, &g_es, NULL,
                           (unsigned int) FD_SETSIZE);
    break;
  default:
    /* no except set: deprecated, but shipped API */
    stat_fdset_v2++;
    with_es = 0;
    (void) MHD_get_fdset2 (d, &g_rs, &g_ws, NULL, &max_fd,
                           (unsigned int) FD_SETSIZE);
    break;
  }
  check_fdsets (setsize, max_fd, had_max, with_es);
  g_max_fd = max_fd;
  g_setsize = setsize;
  g_have_sets = 1;
  if ( (MHD_INVALID_SOCKET != quiesced_fd) &&
       ((unsigned int) quiesced_fd < (unsigned int) FD_SETSIZE) &&
       FD_ISSET (quiesced_fd, &g_rs) )
    fuzz_report_finding (
      "MHD_get_fdset*() still watches the listening socket after "
      "MHD_quiesce_daemon() handed it back to the application");
}


/**
 * select() on the sets collected last, with a zero timeout.
 *
 * The harness is single threaded and everything MHD could be waiting for
 * has already been written into the socketpairs, so blocking would only
 * burn wall clock; select() is called purely to fill in the readiness.
 */
static void
op_poll (void)
{
  struct timeval tv;

  if ( (! g_have_sets) ||
       (MHD_INVALID_SOCKET == g_max_fd) )
    return;
  tv.tv_sec = 0;
  tv.tv_usec = 0;
  (void) select ((int) g_max_fd + 1, &g_rs, &g_ws, &g_es, &tv);
}


/**
 * Drain whatever the daemon has produced on slot @a i, so that a large
 * response can make progress.
 */
static void
drain_conn (unsigned int i)
{
  char tmp[DRAIN_BUF];

  if ( (i >= MAX_CONNS) ||
       (0 > csock[i]) )
    return;
  for (;;)
  {
    ssize_t n = recv (csock[i], tmp, sizeof (tmp), MSG_DONTWAIT);

    if (0 >= n)
      break;
  }
}


static void
drain_all (void)
{
  unsigned int i;

  for (i = 0; i < MAX_CONNS; i++)
    drain_conn (i);
}


/**
 * Advance the daemon once.
 *
 * @param d the daemon
 * @param var which entry point to use
 * @param flavour which descriptor sets to hand over:
 *        0 the ones MHD asked for, 1 all-zero, 2 all-ones,
 *        3 only the read set as collected
 */
static void
op_run (struct MHD_Daemon *d,
        unsigned int var,
        unsigned int flavour)
{
  fd_set rs;
  fd_set ws;
  fd_set es;

  switch (flavour % 4)
  {
  case 1:
    FD_ZERO (&rs);
    FD_ZERO (&ws);
    FD_ZERO (&es);
    break;
  case 2:
    /* Every descriptor number reported ready.  MHD only tests the bits of
       the sockets it owns, so this is an application that lies about
       readiness, not an invalid descriptor. */
    memset (&rs, 0xFF, sizeof (rs));
    memset (&ws, 0xFF, sizeof (ws));
    memset (&es, 0xFF, sizeof (es));
    break;
  case 3:
    rs = g_rs;
    FD_ZERO (&ws);
    FD_ZERO (&es);
    break;
  default:
    rs = g_rs;
    ws = g_ws;
    es = g_es;
    break;
  }
  switch (var % 4)
  {
  case 0:
    stat_rfs_v1++;
    (void) (MHD_run_from_select) (d, &rs, &ws, &es);
    break;
  case 1:
    stat_rfs_v2++;
    (void) MHD_run_from_select2 (d, &rs, &ws, &es,
                                 (g_setsize > (unsigned int) FD_SETSIZE)
                                 ? (unsigned int) FD_SETSIZE : g_setsize);
    break;
  case 2:
    stat_run++;
    (void) MHD_run (d);
    break;
  default:
    stat_run_wait++;
    (void) MHD_run_wait (d, 0);
    break;
  }
  deadline_valid = 0;
  if (cfg.auto_drain)
    drain_all ();
  if (cfg.timeout_every_run)
    check_timeouts (d);
}


/* ------------------------------------------------------------------ */
/* Connections                                                         */
/* ------------------------------------------------------------------ */

static int
new_connection (struct MHD_Daemon *d)
{
  int sv[2];
  struct sockaddr_in sa;
  unsigned int idx;

  if (nconns >= MAX_CONNS)
    return -1;
  idx = nconns;
  if (0 != socketpair (AF_UNIX, SOCK_STREAM, 0, sv))
    return -1;
  if (cfg.small_sockbuf)
  {
    int bs = 2048;

    (void) setsockopt (sv[0], SOL_SOCKET, SO_RCVBUF, &bs, sizeof (bs));
    (void) setsockopt (sv[1], SOL_SOCKET, SO_SNDBUF, &bs, sizeof (bs));
  }
  memset (&sa, 0, sizeof (sa));
  sa.sin_family = AF_INET;
  sa.sin_port = htons (44444);
  sa.sin_addr.s_addr = htonl (INADDR_LOOPBACK);
  csock[idx] = sv[0];
  if (MHD_YES != MHD_add_connection (d,
                                     (MHD_socket) sv[1],
                                     (const struct sockaddr *) &sa,
                                     (socklen_t) sizeof (sa)))
  {
    /* MHD has already closed sv[1] in that case. */
    (void) close (sv[0]);
    csock[idx] = -1;
    return -1;
  }
  nconns++;
  cur_conn = idx;
  return (int) idx;
}


/**
 * Hand the daemon one more connection and do not run the loop again.
 *
 * MHD_add_connection() on a thread-safe daemon does not build the
 * `struct MHD_Connection` right away; it puts the socket on
 * `daemon->new_connections_head` and leaves the rest to the next run.
 * Stopping the daemon before that run is the only way to reach
 * new_connection_close_() in daemon.c, which is where MHD disposes of a
 * connection it accepted but never started.  The ordinary teardown below
 * always calls MHD_run() once more, which is why 1.6 billion executions
 * left that function at zero coverage.
 *
 * The socket pair is deliberately kept out of the harness's own
 * connection table: nothing is ever sent on it, no notify callback fires
 * for it, and by this point the teardown has already closed every
 * tracked slot.  Our end is returned so that the caller can close it
 * after MHD_stop_daemon().
 *
 * @param d the daemon, about to be stopped
 * @return our end of the socket pair, or -1 if nothing was queued
 */
static int
queue_unprocessed_conn (struct MHD_Daemon *d)
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
    /* MHD has closed sv[1] already. */
    (void) close (sv[0]);
    return -1;
  }
  stat_queued_at_stop++;
  return sv[0];
}


/**
 * Drop our end of connection @a i.
 *
 * @param graceful non-zero to shut the write side down first (an orderly
 *        client close), zero to just close (an abrupt one, which MHD sees
 *        as a reset)
 */
static void
close_conn (unsigned int i,
            int graceful)
{
  if ( (i >= MAX_CONNS) ||
       (0 > csock[i]) )
    return;
  if (graceful)
    (void) shutdown (csock[i], SHUT_WR);
  (void) close (csock[i]);
  csock[i] = -1;
}


static void
send_bytes (unsigned int i,
            const void *buf,
            size_t len)
{
  const char *p = (const char *) buf;
  size_t off = 0;
  unsigned int tries = 0;

  if ( (i >= MAX_CONNS) ||
       (0 > csock[i]) ||
       (0 == len) )
    return;
  while ( (off < len) &&
          (tries < 4) )
  {
    ssize_t s = send (csock[i], p + off, len - off, MSG_DONTWAIT);

    if (0 < s)
    {
      off += (size_t) s;
      continue;
    }
    tries++;
    /* The peer's receive buffer is full because MHD has not run yet, or
       MHD is gone.  One round is enough to tell the two apart; the rest
       of the fragment is simply dropped, which is a split point like any
       other. */
    if (NULL != cur_daemon)
      (void) MHD_run (cur_daemon);
    if ( (0 > s) &&
         (EAGAIN != errno) &&
         (EWOULDBLOCK != errno) &&
         (EINTR != errno) )
      break;
  }
}


/**
 * Request fragments.  Whole requests, halves of requests and pipelines,
 * so that a schedule can leave a connection in any parser state while it
 * plays with the event loop.
 */
static const char *const frag_tbl[16] = {
  "GET / HTTP/1.1\r\nHost: x\r\n\r\n",
  "GET /a HTTP/1.1\r\nHost: x\r\n",
  "\r\n",
  "POST /p HTTP/1.1\r\nHost: x\r\nContent-Length: 10\r\n\r\n",
  "0123456789",
  "POST /c HTTP/1.1\r\nHost: x\r\nTransfer-Encoding: chunked\r\n\r\n",
  "5\r\nabcde\r\n",
  "0\r\n\r\n",
  "GET / HTTP/1.1\r\nHost: x\r\nConnection: close\r\n\r\n",
  "GET / HTTP/1.0\r\n\r\n",
  "HEAD / HTTP/1.1\r\nHost: x\r\n\r\n",
  "GET / HTTP/1.1\r\nHost: x\r\n\r\nGET /2 HTTP/1.1\r\nHost: x\r\n\r\n",
  "G",
  "ET / HTTP/1.1\r\n",
  "Host: x\r\n\r\n",
  "\r\n\r\n"
};


/* ------------------------------------------------------------------ */
/* The operation program                                               */
/* ------------------------------------------------------------------ */

enum op
{
  OP_SEND_FRAG = 0,
  OP_SEND_RAW = 1,
  OP_FDSET = 2,
  OP_RUN = 3,
  OP_TIMEOUT = 4,
  OP_CLOCK = 5,
  OP_SUSPEND = 6,
  OP_RESUME = 7,
  OP_NEWCONN = 8,
  OP_CLOSECONN = 9,
  OP_SWITCH = 10,
  OP_QUIESCE = 11,
  OP_DRAIN = 12,
  OP_CONNOPT = 13,
  OP_INFO = 14,
  OP_POLL = 15
};


/**
 * Wait in real time until the connection timeout of the current daemon
 * has certainly expired, so that the expiry path is actually reached.
 *
 * MHD_OPTION_CONNECTION_TIMEOUT has a resolution of one second, so this
 * costs about that much wall clock and is therefore globally budgeted.
 */
static void
wait_for_expiry (struct MHD_Daemon *d)
{
  struct timeval tv;

  if ( (! cfg.allow_real_wait) ||
       (1 != cfg.timeout_s) ||
       (0 >= expiry_budget) )
    return;
  expiry_budget--;
  stat_expiry_waits++;
  tv.tv_sec = 1;
  tv.tv_usec = 50000;
  (void) select (0, NULL, NULL, NULL, &tv);
  clk_ms += 1050;
  /* Everything parked has to come back first, or the expiry cannot be
     observed for it at all. */
  (void) resume_all ();
  (void) MHD_run (d);
  (void) MHD_run (d);
}


static void
op_quiesce (struct MHD_Daemon *d)
{
  MHD_socket ls;

  stat_quiesce++;
  ls = MHD_quiesce_daemon (d);
  if (MHD_INVALID_SOCKET == ls)
    return;
  if (MHD_INVALID_SOCKET != quiesced_fd)
  {
    /* MHD_quiesce_daemon() is documented to hand the socket over once
       and to answer MHD_INVALID_SOCKET afterwards. */
    (void) close (ls);
    fuzz_report_finding (
      "MHD_quiesce_daemon() handed out the listening socket twice");
    return;
  }
  quiesced_fd = ls;
}


static void
op_info (struct MHD_Daemon *d,
         unsigned int arg)
{
  const union MHD_DaemonInfo *di;
  const union MHD_ConnectionInfo *ci;
  volatile size_t sink = 0;
  unsigned int i = arg % MAX_LIVE;

  di = MHD_get_daemon_info (d, MHD_DAEMON_INFO_CURRENT_CONNECTIONS);
  if (NULL != di)
    sink += (size_t) di->num_connections;
  di = MHD_get_daemon_info (d, MHD_DAEMON_INFO_FLAGS);
  if (NULL != di)
    sink += (size_t) di->flags;
  if (NULL != lives[i].mc)
  {
    ci = MHD_get_connection_info (lives[i].mc,
                                  MHD_CONNECTION_INFO_CONNECTION_SUSPENDED);
    if (NULL != ci)
      sink += (size_t) ci->suspended;
    ci = MHD_get_connection_info (lives[i].mc,
                                  MHD_CONNECTION_INFO_DAEMON);
    if (NULL != ci)
      sink += (NULL != ci->daemon) ? 1u : 0u;
  }
  (void) sink;
}


static void
op_connopt (unsigned int i,
            unsigned int val)
{
  if ( (i >= MAX_LIVE) ||
       (NULL == lives[i].mc) )
    return;
  /* Note that MHD skips the whole update while connection->suspended is
     set, so this is not necessarily the timeout the connection ends up
     with -- which is why the oracle reads it back instead. */
  (void) MHD_set_connection_option (lives[i].mc,
                                    MHD_CONNECTION_OPTION_TIMEOUT,
                                    val);
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
  size_t pos;
  unsigned int nops = 0;
  unsigned int i;
  int queued_fd = -1;          /**< see queue_unprocessed_conn() */

  /* Must happen before the first write() into a socketpair.  The built-in
     driver also does this, but that code is compiled out under
     -DFUZZ_NO_MAIN, which is exactly the build every external fuzzing
     engine uses; the call is idempotent.  See fuzz_ignore_sigpipe() in
     fuzz_common.h for why the process dies without it. */
  fuzz_ignore_sigpipe ();

  if (size < 5)
    return 0;

  if (! big_body_ready)
  {
    big_body_ready = 1;
    for (i = 0; i < BIG_BODY_LEN; i++)
      big_body[i] = (char) ('a' + (i % 26));
  }
  if (! expiry_budget_read)
  {
    const char *e = getenv ("MHD_FUZZ_EXPIRY_BUDGET");

    expiry_budget_read = 1;
    if (NULL != e)
      expiry_budget = atoi (e);
  }

  memset (&cfg, 0, sizeof (cfg));
  /* Must never carry over: everything these point at belonged to the
     previous iteration's daemon and is long gone. */
  memset (lives, 0, sizeof (lives));
  for (i = 0; i < MAX_CONNS; i++)
    csock[i] = -1;
  nconns = 0;
  cur_conn = 0;
  tearing_down = 0;
  quiesced_fd = MHD_INVALID_SOCKET;
  clk_ms = 0;
  deadline_ms = 0;
  deadline_valid = 0;
  g_have_sets = 0;
  g_max_fd = MHD_INVALID_SOCKET;
  g_setsize = (unsigned int) FD_SETSIZE;

  cfg.timeout_s = timeout_tbl[data[0] & 0x03];
  cfg.listen_sock = (0 != (data[0] & 0x04));
  cfg.app_fd_setsize = (0 != (data[0] & 0x08));
  cfg.mem_limit = mem_limit_tbl[(data[0] >> 4) & 0x03];
  cfg.conn_limit = (0 != (data[0] & 0x40));
  cfg.small_sockbuf = (0 != (data[0] & 0x80));

  cfg.resp_kind = (unsigned int) (data[1] & 0x03);
  cfg.error_reply = (0 != (data[1] & 0x04));
  cfg.susp_park = (0 != (data[1] & 0x08));
  cfg.susp_now = (0 != (data[1] & 0x10));
  cfg.hnd_connopt = (0 != (data[1] & 0x20));
  cfg.hnd_info = (0 != (data[1] & 0x40));
  cfg.auto_drain = (0 != (data[1] & 0x80));

  cfg.fdset_var = (unsigned int) (data[2] & 0x07);
  cfg.run_var = (unsigned int) ((data[2] >> 3) & 0x03);
  cfg.honour_timeout = (0 != (data[2] & 0x20));
  cfg.timeout_every_run = (0 != (data[2] & 0x40));
  cfg.quiesce_end = (0 != (data[2] & 0x80));

  cfg.nconn_up_front = 1u + (unsigned int) (data[3] & 0x03);
  cfg.check_always = (0 != (data[3] & 0x04));
  cfg.allow_real_wait = (0 != (data[3] & 0x08));
  cfg.stop_with_queued = (0 != (data[3] & 0x10));
  cfg.clock_seed = data[4];

  if (0 != cfg.mem_limit)
  {
    opts[nopt].option = MHD_OPTION_CONNECTION_MEMORY_LIMIT;
    opts[nopt].value = (intptr_t) cfg.mem_limit;
    opts[nopt].ptr_value = NULL;
    nopt++;
  }
  opts[nopt].option = MHD_OPTION_CONNECTION_TIMEOUT;
  opts[nopt].value = (intptr_t) cfg.timeout_s;
  opts[nopt].ptr_value = NULL;
  nopt++;
  if (cfg.conn_limit)
  {
    opts[nopt].option = MHD_OPTION_CONNECTION_LIMIT;
    opts[nopt].value = (intptr_t) 2;
    opts[nopt].ptr_value = NULL;
    nopt++;
  }
  if (cfg.app_fd_setsize)
  {
    opts[nopt].option = MHD_OPTION_APP_FD_SETSIZE;
    opts[nopt].value = (intptr_t) FD_SETSIZE;
    opts[nopt].ptr_value = NULL;
    nopt++;
  }
  opts[nopt].option = MHD_OPTION_END;
  opts[nopt].value = 0;
  opts[nopt].ptr_value = NULL;

  /* MHD_ALLOW_SUSPEND_RESUME is always on: it is what this harness is
     about, and it implies MHD_USE_ITC, whose descriptor is one more thing
     MHD_get_fdset*() has to report correctly. */
  flags = MHD_ALLOW_SUSPEND_RESUME;
  if (! cfg.listen_sock)
    flags |= MHD_USE_NO_LISTEN_SOCKET;
  if (fuzz_verbose)
    flags |= MHD_USE_ERROR_LOG;

  MHD_set_panic_func (&panic_cb, NULL);
  d = MHD_start_daemon (flags,
                        0,
                        NULL, NULL,
                        &ahc, NULL,
                        MHD_OPTION_ARRAY, opts,
                        /* through the varargs rather than the option
                           array: storing a function pointer in the
                           array's intptr_t member is not strictly
                           conforming C */
                        MHD_OPTION_NOTIFY_CONNECTION, &notify_conn_cb, NULL,
                        MHD_OPTION_END);
  if ( (NULL == d) &&
       cfg.listen_sock)
  {
    /* No networking available: fall back to the socketpair-only daemon
       rather than losing the whole iteration. */
    cfg.listen_sock = 0;
    flags |= MHD_USE_NO_LISTEN_SOCKET;
    d = MHD_start_daemon (flags,
                          0,
                          NULL, NULL,
                          &ahc, NULL,
                          MHD_OPTION_ARRAY, opts,
                          MHD_OPTION_NOTIFY_CONNECTION, &notify_conn_cb, NULL,
                          MHD_OPTION_END);
  }
  if (NULL == d)
    return 0;
  cur_daemon = d;
  stat_daemons++;
  if (! stats_registered)
  {
    stats_registered = 1;
    (void) atexit (&print_stats);
  }

  for (i = 0; i < cfg.nconn_up_front; i++)
    if (0 > new_connection (d))
      break;

  pos = 5;
  while ( (pos < size) &&
          (nops < MAX_OPS) )
  {
    const unsigned int b = data[pos++];
    const unsigned int opc = b >> 4;
    const unsigned int arg = b & 0x0F;

    nops++;
    switch (opc)
    {
    case OP_SEND_FRAG:
      {
        const char *f = frag_tbl[arg];

        send_bytes (cur_conn, f, strlen (f));
        break;
      }
    case OP_SEND_RAW:
      {
        size_t l;

        if (pos >= size)
          break;
        l = data[pos++];
        if (l > size - pos)
          l = size - pos;
        send_bytes (cur_conn, data + pos, l);
        pos += l;
        break;
      }
    case OP_FDSET:
      op_fdset (d, (0 != (arg & 0x08)) ? cfg.fdset_var : arg);
      break;
    case OP_RUN:
      op_run (d, arg & 0x03, (arg >> 2) & 0x03);
      break;
    case OP_TIMEOUT:
      check_timeouts (d);
      if ( (cfg.honour_timeout) &&
           (deadline_valid) &&
           (deadline_ms <= clk_ms) )
        op_run (d, cfg.run_var, 0);
      break;
    case OP_CLOCK:
      if (15 == arg)
        wait_for_expiry (d);
      else
      {
        clk_ms += (uint64_t) (1u + arg) * (uint64_t) (1u + cfg.clock_seed % 64u)
        ;
        if ( (cfg.honour_timeout) &&
             (deadline_valid) &&
             (deadline_ms <= clk_ms) )
          op_run (d, cfg.run_var, 0);
      }
      break;
    case OP_SUSPEND:
      do_suspend (arg % MAX_LIVE);
      break;
    case OP_RESUME:
      do_resume (arg % MAX_LIVE);
      break;
    case OP_NEWCONN:
      (void) new_connection (d);
      break;
    case OP_CLOSECONN:
      close_conn ((0 != (arg & 0x08)) ? cur_conn : (arg % MAX_CONNS),
                  (0 != (arg & 0x04)));
      break;
    case OP_SWITCH:
      if ( (arg % MAX_CONNS) < nconns)
        cur_conn = arg % MAX_CONNS;
      break;
    case OP_QUIESCE:
      op_quiesce (d);
      break;
    case OP_DRAIN:
      if (0 != (arg & 0x08))
        drain_all ();
      else
        drain_conn (arg % MAX_CONNS);
      break;
    case OP_CONNOPT:
      op_connopt (arg % MAX_LIVE, (arg >> 3) & 0x01);
      break;
    case OP_INFO:
      op_info (d, arg);
      break;
    default:
      op_poll ();
      break;
    }
    if (cfg.check_always)
      check_timeouts (d);
  }

  /* ---- teardown ---- */
  tearing_down = 1;
  queued_fd = -1;
  for (i = 0; i < MAX_CONNS; i++)
    close_conn (i, 1);
  /* A connection left suspended makes MHD_stop_daemon() MHD_PANIC()
     ("called while we have suspended connections"), and
     MHD_resume_connection() alone is not enough: it only raises a flag,
     and the connection leaves the suspended list in MHD_run().  So flush
     and run until nothing is parked any more.  tearing_down keeps the
     handler from parking anything new, which is what bounds this loop;
     the cap is only a backstop. */
  for (i = 0; i < MAX_CONNS + 2u; i++)
  {
    if (! resume_all ())
      break;
    (void) MHD_run (d);
  }
  (void) MHD_run (d);
  if (cfg.quiesce_end)
    op_quiesce (d);
  /* Last, so that no run can drain the list again. */
  if (cfg.stop_with_queued)
    queued_fd = queue_unprocessed_conn (d);
  MHD_stop_daemon (d);
  cur_daemon = NULL;
  if (0 <= queued_fd)
  {
    (void) close (queued_fd);
    queued_fd = -1;
  }
  if (MHD_INVALID_SOCKET != quiesced_fd)
  {
    (void) close (quiesced_fd);
    quiesced_fd = MHD_INVALID_SOCKET;
  }
  for (i = 0; i < MAX_CONNS; i++)
    close_conn (i, 0);
  memset (lives, 0, sizeof (lives));
  return 0;
}


/* ------------------------------------------------------------------ */
/* Structure-aware schedule generator                                  */
/* ------------------------------------------------------------------ */

struct sbuf
{
  uint8_t *p;
  size_t len;
  size_t cap;
};


static void
sb_byte (struct sbuf *b,
         uint8_t v)
{
  if (b->len < b->cap)
    b->p[b->len++] = v;
}


static void
sb_op (struct sbuf *b,
       unsigned int opc,
       unsigned int arg)
{
  sb_byte (b, (uint8_t) ((opc << 4) | (arg & 0x0F)));
}


/**
 * Fragment indices, weighted towards the ones that complete a request:
 * a schedule that never reaches the access handler exercises very little
 * of the connection life cycle.
 */
static const unsigned char gen_frag_bias[] = {
  0, 0, 0, 3, 4, 5, 6, 7, 8, 9, 10, 11, 11, 1, 2, 12, 13, 14, 15
};


static unsigned int
gen_frag (struct fuzz_rng *rng)
{
  if (fuzz_chance (rng, 4))
    return fuzz_below (rng, 16);
  return gen_frag_bias[fuzz_below (rng,
                                   (uint32_t) sizeof (gen_frag_bias))];
}


/**
 * Emit "collect the descriptors, poll, run" -- the shape a real external
 * event loop has -- with a randomly chosen variant of each step.
 */
static void
gen_loop_round (struct fuzz_rng *rng,
                struct sbuf *b)
{
  unsigned int v;
  unsigned int fl;

  if (! fuzz_chance (rng, 5))
    sb_op (b, OP_FDSET, fuzz_below (rng, 16));
  if (! fuzz_chance (rng, 3))
    sb_op (b, OP_POLL, 0);
  if (fuzz_chance (rng, 3))
    sb_op (b, OP_TIMEOUT, fuzz_below (rng, 16));
  v = fuzz_below (rng, 4);
  /* Half the runs use the descriptor sets MHD actually asked for, so
     that requests make progress; the other half are the adversarial
     ones (all-zero, all-ones, read set only). */
  fl = fuzz_chance (rng, 2) ? 0u : fuzz_below (rng, 4);
  sb_op (b, OP_RUN, v | (fl << 2));
}


static size_t
fuzz_generate (struct fuzz_rng *rng,
               uint8_t *buf,
               size_t cap)
{
  struct sbuf b;
  unsigned int nrounds;
  unsigned int i;
  unsigned int r;

  b.p = buf;
  b.len = 0;
  b.cap = cap;

  /* --- configuration block --- */
  sb_byte (&b, fuzz_byte (rng));
  sb_byte (&b, fuzz_byte (rng));
  sb_byte (&b, fuzz_byte (rng));
  sb_byte (&b, fuzz_byte (rng));
  sb_byte (&b, fuzz_byte (rng));

  nrounds = 3u + fuzz_below (rng, 40);
  for (i = 0; i < nrounds; i++)
  {
    switch (fuzz_below (rng, 24))
    {
    case 0:
    case 1:
    case 2:
    case 3:
    case 4:
    case 5:
      /* feed the current connection */
      sb_op (&b, OP_SEND_FRAG, gen_frag (rng));
      gen_loop_round (rng, &b);
      break;
    case 6:
      /* raw literal, so that a mutator has somewhere to put bytes */
      {
        unsigned int n = fuzz_below (rng, 24);
        unsigned int k;

        sb_op (&b, OP_SEND_RAW, 0);
        sb_byte (&b, (uint8_t) n);
        for (k = 0; k < n; k++)
          sb_byte (&b, fuzz_byte (rng));
        break;
      }
    case 7:
    case 8:
      gen_loop_round (rng, &b);
      break;
    case 9:
      r = fuzz_below (rng, 16);
      sb_op (&b, OP_SUSPEND, r);
      break;
    case 10:
      r = fuzz_below (rng, 16);
      sb_op (&b, OP_RESUME, r);
      break;
    case 11:
      sb_op (&b, OP_NEWCONN, 0);
      sb_op (&b, OP_SEND_FRAG, gen_frag (rng));
      break;
    case 12:
      r = fuzz_below (rng, 16);
      sb_op (&b, OP_CLOSECONN, r);
      break;
    case 13:
      r = fuzz_below (rng, 16);
      sb_op (&b, OP_SWITCH, r);
      break;
    case 14:
      sb_op (&b, OP_QUIESCE, 0);
      break;
    case 15:
      r = fuzz_below (rng, 16);
      sb_op (&b, OP_DRAIN, r);
      break;
    case 16:
      r = fuzz_below (rng, 16);
      sb_op (&b, OP_CONNOPT, r);
      break;
    case 17:
      r = fuzz_below (rng, 16);
      sb_op (&b, OP_INFO, r);
      break;
    case 18:
      r = fuzz_below (rng, 16);
      sb_op (&b, OP_TIMEOUT, r);
      break;
    case 19:
      /* an artificial clock jump, occasionally the real one that lets a
         connection time out */
      r = fuzz_chance (rng, 40) ? 15u : fuzz_below (rng, 15);
      sb_op (&b, OP_CLOCK, r);
      break;
    case 20:
      /* a run without ever asking MHD what it wanted */
      r = fuzz_below (rng, 16);
      sb_op (&b, OP_RUN, r);
      break;
    case 21:
      sb_op (&b, OP_POLL, 0);
      break;
    default:
      sb_op (&b, OP_SEND_FRAG, gen_frag (rng));
      break;
    }
  }
  /* Make sure most schedules end with the daemon actually run, so that
     the interesting states are reached rather than only set up. */
  gen_loop_round (rng, &b);
  return b.len;
}


/* ------------------------------------------------------------------ */
/* Built-in seed corpus                                                */
/* ------------------------------------------------------------------ */

/**
 * A seed is the five configuration bytes plus a literal operation
 * program.  Programs are short on purpose: each one is meant to pin down
 * one entry point or one life-cycle transition, and libFuzzer's -merge
 * keeps the shortest input reaching a given edge.
 */
struct seed_def
{
  const char *name;
  unsigned char cfg[5];
  unsigned char ops[24];
  unsigned char nops;
};

#define OPB(o,a) (unsigned char) (((o) << 4) | (a))

static const struct seed_def seeds[] = {
  /* MHD_get_fdset() (the real v1 entry point) + select() +
     MHD_run_from_select() (also v1) */
  { "fdset-v1-run-from-select-v1", { 0x00, 0x80, 0x00, 0x00, 0x00 },
    { OPB (OP_SEND_FRAG, 0), OPB (OP_FDSET, 0), OPB (OP_POLL, 0),
      OPB (OP_RUN, 0), OPB (OP_TIMEOUT, 0), OPB (OP_FDSET, 0),
      OPB (OP_POLL, 0), OPB (OP_RUN, 0) }, 8 },

  /* MHD_get_fdset2() + MHD_run_from_select2() */
  { "fdset2-run-from-select2", { 0x00, 0x80, 0x09, 0x00, 0x00 },
    { OPB (OP_SEND_FRAG, 0), OPB (OP_FDSET, 1), OPB (OP_POLL, 0),
      OPB (OP_RUN, 1), OPB (OP_TIMEOUT, 0), OPB (OP_FDSET, 1),
      OPB (OP_POLL, 0), OPB (OP_RUN, 1) }, 8 },

  /* a small FD_SETSIZE limit, which MHD has to refuse descriptors for */
  { "fdset2-small-setsize", { 0x00, 0x80, 0x02, 0x00, 0x04 },
    { OPB (OP_SEND_FRAG, 0), OPB (OP_FDSET, 2), OPB (OP_RUN, 1),
      OPB (OP_FDSET, 2), OPB (OP_TIMEOUT, 0), OPB (OP_RUN, 1) }, 6 },

  /* max_fd == NULL and except_fd_set == NULL, both documented shapes */
  { "fdset2-null-args", { 0x00, 0x80, 0x00, 0x00, 0x00 },
    { OPB (OP_SEND_FRAG, 0), OPB (OP_FDSET, 3), OPB (OP_RUN, 1),
      OPB (OP_FDSET, 4), OPB (OP_RUN, 1), OPB (OP_TIMEOUT, 0) }, 6 },

  /* MHD_run() and MHD_run_wait() */
  { "run-and-run-wait", { 0x00, 0x80, 0x10, 0x00, 0x00 },
    { OPB (OP_SEND_FRAG, 0), OPB (OP_RUN, 2), OPB (OP_RUN, 3),
      OPB (OP_TIMEOUT, 0), OPB (OP_RUN, 2) }, 5 },

  /* descriptor sets MHD never asked for: all-zero and all-ones */
  { "run-from-select-bogus-sets", { 0x00, 0x80, 0x00, 0x00, 0x00 },
    { OPB (OP_SEND_FRAG, 0), OPB (OP_RUN, 0x04), OPB (OP_RUN, 0x08),
      OPB (OP_RUN, 0x05), OPB (OP_RUN, 0x09), OPB (OP_TIMEOUT, 0),
      OPB (OP_RUN, 0x0C) }, 7 },

  /* stale sets: collect, close the connection, then run with them */
  { "run-from-select-stale-sets", { 0x00, 0x80, 0x00, 0x00, 0x00 },
    { OPB (OP_SEND_FRAG, 1), OPB (OP_FDSET, 1), OPB (OP_CLOSECONN, 0),
      OPB (OP_RUN, 0), OPB (OP_RUN, 1), OPB (OP_TIMEOUT, 0) }, 6 },

  /* suspend from the pump loop, across a full fdset/poll/run round */
  { "suspend-across-loop", { 0x00, 0x80, 0x00, 0x00, 0x00 },
    { OPB (OP_SEND_FRAG, 1), OPB (OP_RUN, 2), OPB (OP_SUSPEND, 0),
      OPB (OP_FDSET, 1), OPB (OP_TIMEOUT, 0), OPB (OP_POLL, 0),
      OPB (OP_RUN, 1), OPB (OP_RESUME, 0), OPB (OP_RUN, 2) }, 9 },

  /* the handler parks the connection; several are parked at once */
  { "handler-parks-two-connections", { 0x00, 0x88, 0x00, 0x00, 0x00 },
    { OPB (OP_SEND_FRAG, 0), OPB (OP_RUN, 2), OPB (OP_NEWCONN, 0),
      OPB (OP_SEND_FRAG, 0), OPB (OP_RUN, 2), OPB (OP_TIMEOUT, 0),
      OPB (OP_RESUME, 0), OPB (OP_RUN, 2) }, 8 },

  /* suspend while a resume is still pending (cancels the resume) */
  { "suspend-cancels-pending-resume", { 0x00, 0x80, 0x00, 0x00, 0x00 },
    { OPB (OP_SEND_FRAG, 1), OPB (OP_RUN, 2), OPB (OP_SUSPEND, 0),
      OPB (OP_RESUME, 0), OPB (OP_SUSPEND, 0), OPB (OP_TIMEOUT, 0),
      OPB (OP_RESUME, 0), OPB (OP_RUN, 2) }, 8 },

  /* quiesce a daemon that really has a listening socket, then check that
     it is gone from the descriptor sets */
  { "quiesce-listening-daemon", { 0x04, 0x80, 0x00, 0x00, 0x00 },
    { OPB (OP_SEND_FRAG, 0), OPB (OP_FDSET, 1), OPB (OP_RUN, 1),
      OPB (OP_QUIESCE, 0), OPB (OP_FDSET, 1), OPB (OP_TIMEOUT, 0),
      OPB (OP_RUN, 1), OPB (OP_QUIESCE, 0) }, 8 },

  /* a large response on a small socket buffer: the connection stays
     blocked on write over many rounds */
  { "blocked-write-scheduling", { 0x80, 0x02, 0x00, 0x00, 0x00 },
    { OPB (OP_SEND_FRAG, 0), OPB (OP_FDSET, 1), OPB (OP_POLL, 0),
      OPB (OP_RUN, 1), OPB (OP_FDSET, 1), OPB (OP_POLL, 0),
      OPB (OP_RUN, 1), OPB (OP_DRAIN, 8), OPB (OP_FDSET, 1),
      OPB (OP_RUN, 1), OPB (OP_TIMEOUT, 0) }, 11 },

  /* a real connection-timeout expiry */
  { "connection-timeout-expiry", { 0x00, 0x80, 0x00, 0x08, 0x00 },
    { OPB (OP_SEND_FRAG, 1), OPB (OP_RUN, 2), OPB (OP_TIMEOUT, 0),
      OPB (OP_CLOCK, 15), OPB (OP_TIMEOUT, 0), OPB (OP_RUN, 2) }, 6 },

  /* per-connection timeouts, which move the connection to the "manual"
     timeout list that MHD_get_timeout*() has to scan separately */
  { "manual-timeout-list", { 0x00, 0x80, 0x00, 0x03, 0x00 },
    { OPB (OP_SEND_FRAG, 1), OPB (OP_CONNOPT, 8), OPB (OP_TIMEOUT, 0),
      OPB (OP_CONNOPT, 1), OPB (OP_TIMEOUT, 0), OPB (OP_RUN, 2),
      OPB (OP_TIMEOUT, 0) }, 7 },

  /* pipelined requests plus a chunked upload, driven one run at a time */
  { "pipelined-and-chunked", { 0x00, 0x81, 0x00, 0x00, 0x00 },
    { OPB (OP_SEND_FRAG, 11), OPB (OP_RUN, 2), OPB (OP_SEND_FRAG, 5),
      OPB (OP_RUN, 2), OPB (OP_SEND_FRAG, 6), OPB (OP_RUN, 2),
      OPB (OP_SEND_FRAG, 7), OPB (OP_RUN, 2), OPB (OP_TIMEOUT, 0) }, 9 },

  /* never poll, never ask for descriptors, only run from empty sets */
  { "never-poll", { 0x00, 0x80, 0x00, 0x00, 0x00 },
    { OPB (OP_SEND_FRAG, 0), OPB (OP_RUN, 0x04), OPB (OP_RUN, 0x04),
      OPB (OP_RUN, 0x04), OPB (OP_RUN, 0x04), OPB (OP_TIMEOUT, 0) }, 6 },

  /* abrupt close in the middle of a request, with the descriptor sets
     collected before it */
  { "abrupt-close-mid-request", { 0x00, 0x80, 0x00, 0x00, 0x00 },
    { OPB (OP_SEND_FRAG, 3), OPB (OP_FDSET, 1), OPB (OP_CLOSECONN, 0),
      OPB (OP_RUN, 1), OPB (OP_TIMEOUT, 0), OPB (OP_RUN, 2) }, 6 },

  /* connection limit of two, so that MHD_add_connection() starts to fail */
  { "connection-limit", { 0x40, 0x80, 0x00, 0x03, 0x00 },
    { OPB (OP_NEWCONN, 0), OPB (OP_NEWCONN, 0), OPB (OP_SEND_FRAG, 0),
      OPB (OP_RUN, 2), OPB (OP_TIMEOUT, 0) }, 5 },

  /* no connection timeout at all: MHD_get_timeout*() must report that an
     indefinite wait is fine */
  { "no-timeout-configured", { 0x02, 0x80, 0x00, 0x04, 0x00 },
    { OPB (OP_SEND_FRAG, 1), OPB (OP_TIMEOUT, 0), OPB (OP_RUN, 2),
      OPB (OP_TIMEOUT, 0), OPB (OP_SEND_FRAG, 2), OPB (OP_RUN, 2) }, 6 },

  /* byte 3 bit 4: after the program has run and everything has been torn
     down, hand MHD one more connection and stop it without another run,
     so that it has to dispose of a connection it never started.  That is
     new_connection_close_() in daemon.c, which nothing else reaches. */
  { "stop-with-queued-connection", { 0x00, 0x80, 0x00, 0x10, 0x00 },
    { OPB (OP_SEND_FRAG, 0), OPB (OP_RUN, 2), OPB (OP_TIMEOUT, 0) }, 3 },

  /* the same after MHD_quiesce_daemon() on a daemon that really has a
     listening socket, which is the other order the two can happen in */
  { "stop-with-queued-after-quiesce", { 0x04, 0x80, 0x80, 0x10, 0x00 },
    { OPB (OP_SEND_FRAG, 0), OPB (OP_RUN, 2) }, 2 }
};

static uint8_t seed_render_buf[64];


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
  size_t n = sd->nops;

  if (n > sizeof (sd->ops))
    n = sizeof (sd->ops);
  if (n + sizeof (sd->cfg) > sizeof (seed_render_buf))
    n = sizeof (seed_render_buf) - sizeof (sd->cfg);
  memcpy (seed_render_buf, sd->cfg, sizeof (sd->cfg));
  memcpy (seed_render_buf + sizeof (sd->cfg), sd->ops, n);
  *len = sizeof (sd->cfg) + n;
  return seed_render_buf;
}
