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
 * @file fuzz/fuzz_options.c
 * @brief In-process fuzzer for MHD's daemon option handling and for the
 *        daemon start-up / shutdown paths.
 * @author Christian Grothoff
 *
 * fuzz_request.c fuzzes what MHD does with the *bytes on the wire*, but
 * it always starts the daemon in one single shape: external polling, no
 * listen socket, five fixed options.  Everything in daemon.c that is
 * reached through any other configuration -- the flag validation in
 * MHD_start_daemon(), parse_options_va(), the internal polling thread,
 * the thread pool, epoll/poll/select, the listen socket, the per-IP and
 * per-daemon connection limits, quiesce -- is therefore dead code as far
 * as the fuzzing suite is concerned.  This harness closes that gap: the
 * input bytes pick a *combination* of MHD_FLAG bits and an MHD_OPTION
 * array, the daemon is started with them, one short HTTP request is
 * driven through it over a socketpair, and the daemon is stopped again.
 *
 * The request-driving machinery is the one from fuzz_request.c:
 * MHD_USE_NO_LISTEN_SOCKET plus MHD_add_connection() on an AF_UNIX
 * socketpair(), with a fake 127.0.0.1 peer address so that the per-IP
 * accounting sees something sane, and MHD_set_panic_func() installed as
 * a tripwire.  What is new here is that the *daemon* is a variable.
 *
 * Two shapes of daemon exist, and the harness drives them differently:
 *
 *   - "external polling" (no MHD_USE_INTERNAL_POLLING_THREAD and no
 *     MHD_USE_THREAD_PER_CONNECTION).  Single threaded and fully
 *     deterministic: the segments are fed in one at a time and the
 *     daemon is pumped with MHD_run() / MHD_get_fdset2() + select() +
 *     MHD_run_from_select2() / MHD_run_wait() between them.  This is the
 *     majority of the iterations and the only shape in which the harness
 *     suspends a connection.
 *
 *   - "internal thread" (an internal polling thread, a thread pool, or
 *     thread-per-connection).  MHD_add_connection() is explicitly
 *     supported in these modes -- it is how an application with its own
 *     accept() loop hands sockets over -- but the harness must not also
 *     poll the daemon, and it cannot know when the worker is done.  So
 *     the whole request is written at once, the write side is shut down
 *     (which makes MHD finish the request immediately rather than
 *     waiting for more data), and the answer is awaited with a short
 *     bounded poll() before the daemon is stopped.  MHD_USE_ITC is
 *     forced on in this shape so that the worker picks the new
 *     connection up at once instead of waiting for its poll timeout.
 *     No connection is ever suspended here.
 *
 * Input format (see README section 2.2 for the fuzz_request one, which
 * the segment stream below is deliberately identical to):
 *
 *   byte 0    daemon shape: index into mode_tbl[] (event loop and
 *             threading; the entries are the combinations MHD documents
 *             as valid, so that most iterations get a live daemon)
 *   byte 1    MHD_FLAG bits, group A (see flags_from_input())
 *   byte 2    MHD_FLAG bits, group B; 0xC0 in the top two bits switches
 *             on the "raw" escape, which feeds bytes 1, 2 and 15
 *             straight into the flags word.  That is what fuzzes
 *             MHD_start_daemon()'s own combination checks; MHD answering
 *             NULL is a normal outcome and simply ends the iteration.
 *   byte 3    option presence mask A (sizes and limits)
 *   byte 4    option presence mask B (discipline, insanity, fd_setsize)
 *   byte 5    option presence mask C (the callbacks and the pointers)
 *   byte 6    value selector: connection memory limit / increment
 *   byte 7    value selector: connection limit / per-IP limit
 *   byte 8    value selector: connection timeout / pool size / stack
 *   byte 9    value selector: nonce-nc size / digest random / bind type
 *   byte 10   value selector: discipline / strict / insanity / bzero URI
 *   byte 11   value selector: backlog / fd_setsize / reuse / fastopen
 *   byte 12   driver behaviour: event loop variant, quiesce,
 *             introspection, suspend mode, number of connections
 *   byte 13   handler behaviour (which response, MHD_NO, per-connection
 *             option) and the accept path: whether an accept policy
 *             callback is installed, what it answers, and whether the
 *             iteration additionally connect()s to the daemon's real
 *             listening socket
 *   byte 14   option presence mask D (the digest and TLS-adjacent
 *             options, MHD_OPTION_LISTEN_SOCKET, and the deliberately
 *             invalid option number)
 *   byte 15   spare entropy; also supplies flag bits 14+ in raw mode
 *   byte 16.  a sequence of send segments, each introduced by a little
 *             endian 16 bit header  (op << 14) | length
 *               op 0  send the payload on the current connection
 *               op 1  send the payload, then pump extra rounds
 *               op 2  send the payload, then pump extra rounds
 *               op 3  close the current connection, open a fresh one on
 *                     the same daemon, then send
 *
 * The sixteen configuration bytes are mandatory; a shorter input is
 * rejected.  An input of exactly sixteen bytes is meaningful and is not
 * a degenerate case: it starts and stops a daemon with one connection
 * and no traffic at all, which is precisely the start-up/shutdown path
 * this harness is about.
 *
 * Two rules the harness obeys, both of them application contract rather
 * than anything worth fuzzing:
 *
 *   - every daemon that starts is stopped, and no connection is left
 *     suspended when that happens, because MHD_stop_daemon() answers a
 *     suspended connection with MHD_PANIC().  Suspended connections are
 *     tracked in pending_resume[] and flushed during teardown, exactly
 *     as in fuzz_request.c;
 *   - the socket that MHD_quiesce_daemon() returns belongs to the
 *     caller.  It is closed after MHD_stop_daemon() (not before: with
 *     internal threads a worker may still be using it), otherwise the
 *     harness runs out of file descriptors within a few thousand
 *     iterations.
 *
 * Environment:
 *
 *   MHD_FUZZ_QUIESCE_EPOLL_RACE=1  let the harness call
 *       MHD_quiesce_daemon() on an epoll daemon that runs its own
 *       thread(s).  Off by default because that combination reaches an
 *       open MHD defect; see quiesce_epoll_race_allowed() below.
 */

#define FUZZ_HARNESS_NAME "fuzz_options"
#include "fuzz_common.h"

#include <microhttpd.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <sys/select.h>
#include <poll.h>
#include <limits.h>

/* MHD_OPTION_STRICT_FOR_CLIENT is superseded by
   MHD_OPTION_CLIENT_DISCIPLINE_LVL but is still shipped API, and its
   mapping onto the discipline level is exactly the kind of thing this
   harness is for. */
#if defined(__GNUC__) || defined(__clang__)
#pragma GCC diagnostic ignored "-Wdeprecated-declarations"
#endif

/** Number of mandatory configuration bytes at the start of the input. */
#define CFG_BYTES 16

#define MAX_SEGMENTS 48
#define MAX_CONNECTIONS 6
#define MAX_OPTS 40
#define RESP_DRAIN_BUF 4096
#define GEN_BUF_SIZE 4096

/**
 * Milliseconds the internal-thread shape waits for the daemon to answer.
 * The write side of the socketpair is shut down before the wait, so the
 * daemon never sits on an incomplete request: either it answers (the
 * common case, tens of microseconds) or it closes the connection, and
 * both wake poll() up immediately.  The timeout is therefore only paid
 * by inputs that make MHD drop the connection without a reply.
 */
#define THREAD_WAIT_MS 2

/** Rounds of MHD_run() after each segment in the external shape. */
#define PUMP_ROUNDS 3
/** Rounds of MHD_run() after a segment sent with op 1 or 2. */
#define PUMP_ROUNDS_LONG 10


/* ------------------------------------------------------------------ */
/* Per-iteration configuration                                         */
/* ------------------------------------------------------------------ */

struct fuzz_cfg
{
  /** Daemon runs its own thread(s); the harness must not call MHD_run(). */
  int uses_threads;
  /** A real listening socket was requested (no MHD_USE_NO_LISTEN_SOCKET). */
  int listen_sock;
  /** MHD_USE_ERROR_LOG was requested, so an external logger is mandatory. */
  int err_log;
  /** 0 none, 1 suspend+resume in the handler, 2 resume from the pump. */
  int suspend_mode;
  /** 0 MHD_run(), 1 MHD_get_fdset2()+select()+MHD_run_from_select2(),
      2 MHD_run_wait(0), 3 the v1 MHD_get_fdset()/MHD_run_from_select(). */
  unsigned int loop_mode;
  /** Call MHD_quiesce_daemon() before stopping. */
  int quiesce;
  /** Query MHD_get_daemon_info() / MHD_get_timeout*() while pumping. */
  int daemon_info;
  /** Call MHD_set_connection_option() from the handler. */
  int conn_option;
  /** Which response constructor the handler uses. */
  unsigned int resp_kind;
  /** Handler answers MHD_NO instead of queueing a response. */
  int handler_no;
  /** Upper bound on the number of connections the iteration opens. */
  unsigned int nconn_max;
  /** Really connect() to the daemon's listening socket. */
  int real_connect;
  /** Install an accept policy callback, and what it should answer. */
  int accept_policy;
  int accept_policy_deny;
};

static struct fuzz_cfg cfg;

/**
 * Connections suspended by suspend mode 2, which the pump loop still has
 * to resume.  Cleared by completed_cb() so that a connection MHD has
 * finished with is never resumed afterwards.  A connection that is still
 * suspended when MHD_stop_daemon() runs makes MHD answer with
 * MHD_PANIC ("MHD_stop_daemon() called while we have suspended
 * connections"), which would look exactly like an MHD bug.
 */
static struct MHD_Connection *pending_resume[MAX_CONNECTIONS];

/**
 * Set once the iteration only wants to drain the daemon.  The handler
 * then stops parking new connections, which is what makes the flush loop
 * in the teardown provably terminate.
 */
static int tearing_down;

/** Statistics, printed at exit with --verbose. */
static unsigned long stat_daemons;
static unsigned long stat_daemons_failed;
static unsigned long stat_threaded;
static unsigned long stat_handler_calls;
static unsigned long stat_conns_added;
static unsigned long stat_conns_refused;
static unsigned long stat_real_conns;
static int stats_registered;


static void
print_stats (void)
{
  if (! fuzz_verbose)
    return;
  fprintf (stderr,
           "%s: daemons=%lu (failed to start=%lu, threaded=%lu) "
           "connections=%lu (refused=%lu, accepted from a real socket=%lu) "
           "handler calls=%lu\n",
           FUZZ_HARNESS_NAME,
           stat_daemons, stat_daemons_failed, stat_threaded,
           stat_conns_added, stat_conns_refused, stat_real_conns,
           stat_handler_calls);
}


/* ------------------------------------------------------------------ */
/* Flags                                                               */
/* ------------------------------------------------------------------ */

/**
 * The event-loop / threading core of the flags word.  Every entry is a
 * combination MHD documents as valid, so that the ordinary path through
 * this harness gets a live daemon and actually exercises the option
 * handling; the deliberately invalid combinations are reached through
 * the raw escape of byte 2 instead.
 *
 * The distribution is on purpose: entries 0..17 are the external polling
 * modes, 18..23 the ones with internal threads.  An iteration with
 * internal threads costs a thread creation, a join and a short wait for
 * the answer, i.e. roughly an order of magnitude more than an external
 * one, so they are a quarter of the iterations rather than a half.
 */
static const unsigned int mode_tbl[] = {
  0, 0, 0, 0, 0, 0,                              /* external, select()  */
  0, 0, 0, 0, 0, 0,
  MHD_USE_EPOLL, MHD_USE_EPOLL,                  /* external, epoll     */
  MHD_USE_EPOLL, MHD_USE_EPOLL,
  MHD_USE_AUTO, MHD_USE_AUTO,                    /* external, MHD picks */
  MHD_USE_INTERNAL_POLLING_THREAD,
  MHD_USE_INTERNAL_POLLING_THREAD | MHD_USE_POLL,
  MHD_USE_INTERNAL_POLLING_THREAD | MHD_USE_EPOLL,
  MHD_USE_THREAD_PER_CONNECTION | MHD_USE_INTERNAL_POLLING_THREAD,
  MHD_USE_THREAD_PER_CONNECTION | MHD_USE_INTERNAL_POLLING_THREAD
  | MHD_USE_POLL,
  MHD_USE_AUTO | MHD_USE_INTERNAL_POLLING_THREAD
};

#define MODE_COUNT (sizeof (mode_tbl) / sizeof (mode_tbl[0]))

/**
 * Flag bits the raw escape is allowed to set.  MHD_USE_TLS is masked
 * out: without a certificate the daemon merely fails to start, so it
 * would only waste iterations, and fuzzing GnuTLS is not what this
 * harness is for.  Everything else, including the bits above
 * MHD_USE_NO_THREAD_SAFETY that no MHD_FLAG uses, is fair game.
 */
#define RAW_FLAG_MASK (~((unsigned int) MHD_USE_TLS))

/**
 * The bit that MHD_suspend_connection() actually tests.
 *
 * MHD_ALLOW_SUSPEND_RESUME is a *compound* value (8192 | MHD_USE_ITC),
 * so "0 != (flags & MHD_ALLOW_SUSPEND_RESUME)" is already true for a
 * daemon that merely asked for MHD_USE_ITC -- and suspending such a
 * connection is answered with
 * MHD_PANIC ("Cannot suspend connections without enabling
 * MHD_ALLOW_SUSPEND_RESUME"), which is the harness violating the API
 * rather than a finding.  internal.h calls the single bit
 * MHD_TEST_ALLOW_SUSPEND_RESUME; this is the same value, expressed
 * without reaching into a private header.
 */
#define SUSPEND_BIT \
        (((unsigned int) MHD_ALLOW_SUSPEND_RESUME) \
         & ~((unsigned int) MHD_USE_ITC))


/**
 * Build the flags word from bytes 0, 1, 2 and 15 of the input.
 *
 * @param data the input
 * @return the flags to pass to MHD_start_daemon()
 */
static unsigned int
flags_from_input (const uint8_t *data)
{
  unsigned int flags;

  if (0xC0 == (data[2] & 0xC0))
  {
    /* Raw escape: the flags word comes straight off the input.  This is
       what exercises MHD_start_daemon()'s combination checks (POLL with
       EPOLL, EPOLL with thread-per-connection, AUTO with either, ...),
       every one of which answers NULL. */
    flags = ((unsigned int) data[1])
            | (((unsigned int) (data[2] & 0x3F)) << 8)
            | (((unsigned int) data[15]) << 14);
    flags &= RAW_FLAG_MASK;
    cfg.listen_sock = (0 == (flags & MHD_USE_NO_LISTEN_SOCKET));
    cfg.err_log = (0 != (flags & MHD_USE_ERROR_LOG));
    return flags;
  }

  flags = mode_tbl[data[0] % MODE_COUNT];

  if (0 != (data[1] & 0x01))
    flags |= MHD_USE_PEDANTIC_CHECKS;
  if (0 != (data[1] & 0x02))
    flags |= MHD_USE_SUPPRESS_DATE_NO_CLOCK;
  if (0 != (data[1] & 0x04))
    flags |= MHD_ALLOW_SUSPEND_RESUME;
  if ( (0 != (data[1] & 0x08)) &&
       (MHD_YES == MHD_is_feature_supported (MHD_FEATURE_UPGRADE)) )
    flags |= MHD_ALLOW_UPGRADE;
  if (0 != (data[1] & 0x10))
    flags |= MHD_USE_TURBO;
  if (0 != (data[1] & 0x20))
    flags |= MHD_USE_ITC;
  if (0 != (data[1] & 0x40))
    cfg.err_log = 1;
  if (0 != (data[1] & 0x80))
    flags |= MHD_USE_POST_HANDSHAKE_AUTH_SUPPORT;   /* ignored without TLS */

  if (0 != (data[2] & 0x01))
    cfg.listen_sock = 1;
  if (0 != (data[2] & 0x02))
    flags |= MHD_USE_IPv6;
  if (0 != (data[2] & 0x04))
    flags |= MHD_USE_DUAL_STACK;
  if (0 != (data[2] & 0x08))
    flags |= MHD_USE_TCP_FASTOPEN;
  if (0 != (data[2] & 0x10))
    flags |= MHD_USE_NO_THREAD_SAFETY;
  if (0 != (data[2] & 0x20))
    flags |= MHD_USE_INSECURE_TLS_EARLY_DATA;       /* ignored without TLS */

  /* MHD_USE_NO_THREAD_SAFETY together with any internal thread is
     documented as unsupported and answered with NULL.  Drop it here
     rather than burning the iteration; the raw escape above still
     reaches that check. */
  if (0 != (flags & (MHD_USE_INTERNAL_POLLING_THREAD
                     | MHD_USE_THREAD_PER_CONNECTION)))
    flags &= ~((unsigned int) MHD_USE_NO_THREAD_SAFETY);
  return flags;
}


/**
 * @return non-zero if @a flags make MHD use epoll
 *
 * MHD_USE_AUTO resolves to epoll for everything except
 * thread-per-connection, which it resolves to poll.
 */
static int
uses_epoll (unsigned int flags)
{
  if (0 != (flags & MHD_USE_EPOLL))
    return 1;
  return (0 != (flags & MHD_USE_AUTO)) &&
         (0 == (flags & MHD_USE_THREAD_PER_CONNECTION));
}


/**
 * Is the harness allowed to call MHD_quiesce_daemon() on an epoll
 * daemon that runs its own thread(s)?
 *
 * It is not, by default, because that combination reaches an *open* MHD
 * defect and would make "make check" fail at random:
 *
 *   MHD_quiesce_daemon() sets daemon->was_quiesced and then removes the
 *   listen FD from the epoll set itself (daemon.c:6208), tolerating
 *   ENOENT with the comment "can happen due to race with MHD_epoll()".
 *   MHD_epoll() removes the very same FD in two places.  The first
 *   (daemon.c:5556) mirrors that and tolerates ENOENT.  The second
 *   (daemon.c:5593), the "at the connection limit, disable listen
 *   socket" branch, also fires when daemon->was_quiesced is set -- and
 *   it does not tolerate anything:
 *
 *       if (0 != epoll_ctl (daemon->epoll_fd, EPOLL_CTL_DEL, ls, NULL))
 *         MHD_PANIC (_ ("Failed to remove listen FD from epoll set."));
 *
 *   The worker can read daemon->was_quiesced as already true and
 *   daemon->listen_socket_in_epoll as still true -- neither is atomic
 *   and neither is under a lock -- and then lose the race for the
 *   removal, so epoll_ctl() answers ENOENT and MHD aborts the process.
 *   Confirmed with errno == ENOENT, was_quiesced == 1, connections == 0.
 *   The same unguarded MHD_PANIC() sits in the worker-pool loop of
 *   MHD_quiesce_daemon() itself (daemon.c:6189).
 *
 * Set MHD_FUZZ_QUIESCE_EPOLL_RACE=1 to reach it.  Quiescing is left
 * enabled everywhere else, so the poll()/select() side of
 * MHD_quiesce_daemon(), including its worker-pool loop, keeps being
 * exercised.
 */
static int
quiesce_epoll_race_allowed (void)
{
  static int val = -1;

  if (0 > val)
  {
    const char *e = getenv ("MHD_FUZZ_QUIESCE_EPOLL_RACE");

    val = ((NULL != e) && (0 != atoi (e))) ? 1 : 0;
  }
  return val;
}


/* ------------------------------------------------------------------ */
/* Option values                                                       */
/* ------------------------------------------------------------------ */

static const size_t mem_limit_tbl[] = {
  0 /* MHD default */, 128, 192, 256, 384, 512, 1024, 1400,
  1500, 2048, 4096, 8192, 32768, 64, 0, 0
};

static const size_t mem_increment_tbl[] = {
  0 /* MHD default */, 1, 16, 64, 128, 256, 1024, 4096,
  1500, 32768, 0, 0, 0, 0, 0, 0
};

static const unsigned int conn_limit_tbl[] = {
  0, 1, 2, 3, 8, 64, 1024, 100000
};

static const unsigned int per_ip_limit_tbl[] = {
  0, 1, 2, 3, 4, 8, 64, 1000
};

static const unsigned int timeout_tbl[] = {
  0, 1, 2, 5, 60, 3600, 86400, UINT_MAX
};

static const unsigned int pool_size_tbl[] = { 2, 3, 4, 2 };

/* Small stacks make pthread_create() fail outright under ASAN, which
   only produces a NULL daemon; keep the values plausible. */
static const size_t stack_size_tbl[] = {
  0, 1024u * 1024u, 2048u * 1024u, 8192u * 1024u
};

/* Bounded on purpose: the nonce-nc array is nonce_nc_size *
   sizeof(struct MHD_NonceNc) (about 130 bytes per slot) and is
   allocated and freed once per iteration. */
static const unsigned int nonce_nc_tbl[] = { 0, 1, 4, 32 };

static const int discipline_tbl[] = { -3, -2, -1, 0, 1, 2, 3, -4 };

static const int strict_tbl[] = { -1, 0, 1, 2 };

static const unsigned int backlog_tbl[] = { 0, 1, 5, 511 };

static const unsigned int fastopen_tbl[] = { 0, 1, 5, 10 };

/* Anything but the platform's own FD_SETSIZE is rejected unless MHD was
   built with HAS_FD_SETSIZE_OVERRIDABLE, so the odd values are a small
   minority: they cost a whole iteration each. */
static const int fd_setsize_tbl[] = {
  (int) FD_SETSIZE, (int) FD_SETSIZE, (int) FD_SETSIZE, (int) FD_SETSIZE,
  (int) FD_SETSIZE, (int) FD_SETSIZE, 64, 0
};

/** Fixed entropy, so that a digest nonce is reproducible across runs. */
static const char digest_rnd[32] =
  "\x01\x23\x45\x67\x89\xab\xcd\xef\x01\x23\x45\x67\x89\xab\xcd\xef"
  "\xfe\xdc\xba\x98\x76\x54\x32\x10\xfe\xdc\xba\x98\x76\x54\x32\x10";

/* Bind addresses for MHD_OPTION_SOCK_ADDR / MHD_OPTION_SOCK_ADDR_LEN.
   Filled in by prepare_sock_addrs() because htons()/htonl() are not
   constant expressions. */
static struct sockaddr_in bind4;
#ifdef AF_INET6
static struct sockaddr_in6 bind6;
#endif
static int bind_addrs_ready;


static void
prepare_sock_addrs (void)
{
  if (bind_addrs_ready)
    return;
  bind_addrs_ready = 1;
  memset (&bind4, 0, sizeof (bind4));
  bind4.sin_family = AF_INET;
  bind4.sin_port = htons (0);            /* ephemeral */
  bind4.sin_addr.s_addr = htonl (INADDR_LOOPBACK);
#ifdef AF_INET6
  memset (&bind6, 0, sizeof (bind6));
  bind6.sin6_family = AF_INET6;
  bind6.sin6_port = htons (0);
  bind6.sin6_addr = in6addr_loopback;
#endif
}


/* ------------------------------------------------------------------ */
/* The daemon callbacks                                                */
/* ------------------------------------------------------------------ */

/**
 * MHD_OPTION_EXTERNAL_LOGGER.  Swallows the message unless --verbose is
 * in effect.  This is what makes MHD_USE_ERROR_LOG affordable: with the
 * flag set, MHD executes several hundred MHD_DLOG() call sites in
 * daemon.c that are otherwise dead, and without a logger of our own all
 * of that would land on stderr.
 */
static void
logger_cb (void *cls,
           const char *fmt,
           va_list ap)
{
  (void) cls;
  if (! fuzz_verbose)
    return;
  (void) vfprintf (stderr, fmt, ap);
}


/**
 * MHD_OPTION_URI_LOG_CALLBACK.  The return value becomes the initial
 * `*req_cls` of the request, so it has to stay NULL: the access handler
 * uses "req_cls is still NULL" to recognise its first invocation, and a
 * non-NULL value here would also have to be freed somewhere, which is
 * not possible when MHD_OPTION_NOTIFY_COMPLETED is not set.
 */
static void *
uri_log_cb (void *cls,
            const char *uri,
            struct MHD_Connection *con)
{
  volatile size_t sink;

  (void) cls;
  (void) con;
  sink = (NULL != uri) ? strlen (uri) : 0;
  (void) sink;
  return NULL;
}


/**
 * MHD_OPTION_UNESCAPE_CALLBACK.  Replaces MHD's own unescaping, so it
 * must honour the contract: unescape @a s in place and return the new
 * length.  Leaving the string alone is a legal implementation and keeps
 * the harness out of the business of re-testing mhd_str.c, which
 * fuzz_str does.
 */
static size_t
unescape_cb (void *cls,
             struct MHD_Connection *conn,
             char *s)
{
  (void) cls;
  (void) conn;
  return strlen (s);
}


static void
completed_cb (void *cls,
              struct MHD_Connection *connection,
              void **req_cls,
              enum MHD_RequestTerminationCode toe)
{
  (void) cls;
  (void) toe;
  /* MHD is done with this connection, so the deferred resume of suspend
     mode 2 must not fire for it any more. */
  if (! cfg.uses_threads)
  {
    unsigned int i;

    for (i = 0; i < MAX_CONNECTIONS; i++)
      if (pending_resume[i] == connection)
        pending_resume[i] = NULL;
  }
  *req_cls = NULL;
}


static void
notify_connection_cb (void *cls,
                      struct MHD_Connection *connection,
                      void **socket_context,
                      enum MHD_ConnectionNotificationCode toe)
{
  (void) cls;
  (void) connection;
  if (MHD_CONNECTION_NOTIFY_STARTED == toe)
    *socket_context = NULL;
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
                   "MHD_PANIC() reached at %s:%u: %s",
                   (NULL != file) ? file : "?",
                   line,
                   (NULL != reason) ? reason : "?");
  fuzz_report_finding (msg);
}


/* ------------------------------------------------------------------ */
/* Suspend bookkeeping                                                 */
/* ------------------------------------------------------------------ */

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
    /* Clear first: MHD_resume_connection() can make MHD run the handler,
       which may suspend the very same connection again. */
    pending_resume[i] = NULL;
    MHD_resume_connection (c);
    any = 1;
  }
  return any;
}


/**
 * Suspend the connection if the input asks for it.  Only ever called in
 * the external-polling shape: resuming from the harness thread while an
 * internal worker owns the connection is legal but untimed, and this
 * harness has no way to tell whether the resume happened before or after
 * the worker looked at the connection.
 */
static void
suspend_maybe (struct MHD_Connection *connection)
{
  if ( (0 == cfg.suspend_mode) ||
       cfg.uses_threads ||
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


/* ------------------------------------------------------------------ */
/* The access handler                                                  */
/* ------------------------------------------------------------------ */

static const char resp_body[] = "hello";

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
  /* The address of this object is the "request already started" marker.
     Nothing is allocated per request on purpose: this harness runs
     millions of iterations in one process and the daemon shapes with
     internal threads cannot guarantee that MHD_OPTION_NOTIFY_COMPLETED
     is even set, so anything malloc()ed here could leak. */
  static int req_marker;
  struct MHD_Response *resp;
  enum MHD_Result ret;
  unsigned int code;
  volatile size_t sink = 0;

  (void) cls;
  (void) upload_data;

  if (&req_marker != *req_cls)
  {
    *req_cls = &req_marker;
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
    *upload_data_size = 0;
    return MHD_YES;
  }

  if (cfg.conn_option)
    (void) MHD_set_connection_option (connection,
                                      MHD_CONNECTION_OPTION_TIMEOUT,
                                      (unsigned int) 30);
  if (cfg.handler_no)
    return MHD_NO;    /* never suspend on this path: MHD_NO terminates the
                         connection and terminating a suspended one trips
                         mhd_assert (! connection->suspended) */

  code = MHD_HTTP_OK;
  switch (cfg.resp_kind)
  {
  case 1:
    resp = MHD_create_response_empty (MHD_RF_NONE);
    code = MHD_HTTP_NO_CONTENT;
    break;
  case 2:
    resp = MHD_create_response_from_buffer (sizeof (resp_body) - 1,
                                            (void *) (intptr_t) resp_body,
                                            MHD_RESPMEM_MUST_COPY);
    code = MHD_HTTP_FORBIDDEN;
    break;
  case 3:
    resp = MHD_create_response_from_buffer_static (0, "");
    code = MHD_HTTP_INTERNAL_SERVER_ERROR;
    break;
  default:
    resp = MHD_create_response_from_buffer_static (sizeof (resp_body) - 1,
                                                   resp_body);
    break;
  }
  if (NULL == resp)
    return MHD_NO;
  ret = MHD_queue_response (connection, code, resp);
  MHD_destroy_response (resp);
  if (MHD_YES == ret)
    suspend_maybe (connection);
  return ret;
}


/* ------------------------------------------------------------------ */
/* Driving the daemon                                                  */
/* ------------------------------------------------------------------ */

/**
 * Read and discard whatever the daemon has produced so far.  The harness
 * has no response oracle -- fuzz_request owns that job -- but the data
 * has to be taken off the socket so that MHD's writes keep succeeding.
 */
static void
drain (int sock)
{
  char tmp[RESP_DRAIN_BUF];

  if (0 > sock)
    return;
  while (0 < recv (sock, tmp, sizeof (tmp), MSG_DONTWAIT))
    /* nothing */;
}


/**
 * Advance an externally polled daemon by one cycle, through whichever of
 * the four event-loop entry points byte 12 selected.
 *
 * The select() timeout is always zero: the harness is single threaded
 * and everything the daemon could be waiting for has already been
 * written into the socketpair, so blocking would only burn wall clock.
 */
static void
run_once (struct MHD_Daemon *d)
{
  fd_set rs;
  fd_set ws;
  fd_set es;
  MHD_socket max_fd = MHD_INVALID_SOCKET;
  struct timeval tv;

  if (cfg.daemon_info)
  {
    MHD_UNSIGNED_LONG_LONG tl = 0;
    volatile int64_t sink;

    (void) MHD_get_timeout (d, &tl);
    sink = MHD_get_timeout64s (d);
    sink += (int64_t) MHD_get_timeout_i (d);
    (void) sink;
  }
  switch (cfg.loop_mode)
  {
  case 1:
  case 3:
    FD_ZERO (&rs);
    FD_ZERO (&ws);
    FD_ZERO (&es);
    /* MHD_get_fdset and MHD_run_from_select are also macros forwarding
       to the *2 variants, so the names have to be parenthesised for the
       v1 entry points to be reached at all. */
    if (1 == cfg.loop_mode)
    {
      if (MHD_YES != MHD_get_fdset2 (d, &rs, &ws, &es, &max_fd,
                                     (unsigned int) FD_SETSIZE))
      {
        (void) MHD_run (d);
        return;
      }
    }
    else
    {
      if (MHD_YES != (MHD_get_fdset) (d, &rs, &ws, &es, &max_fd))
      {
        (void) MHD_run (d);
        return;
      }
    }
    tv.tv_sec = 0;
    tv.tv_usec = 0;
    if (MHD_INVALID_SOCKET != max_fd)
      (void) select ((int) max_fd + 1, &rs, &ws, &es, &tv);
    if (1 == cfg.loop_mode)
      (void) MHD_run_from_select2 (d, &rs, &ws, &es, (unsigned int) FD_SETSIZE);
    else
      (void) (MHD_run_from_select) (d, &rs, &ws, &es);
    break;
  case 2:
    (void) MHD_run_wait (d, 0);
    break;
  default:
    (void) MHD_run (d);
    break;
  }
}


static void
pump (struct MHD_Daemon *d,
      int sock,
      unsigned int rounds)
{
  unsigned int i;

  if (cfg.uses_threads)
    return;
  for (i = 0; i < rounds; i++)
  {
    /* Deferred resume of suspend mode 2.  Each slot is cleared before
       its connection is resumed, which stays correct even when the
       resume makes MHD complete (and forget) the connection. */
    (void) pending_resume_flush ();
    run_once (d);
    drain (sock);
  }
}


/**
 * Wait, briefly and with a hard bound, for a daemon with internal
 * threads to answer.  The caller has already shut the write side down,
 * so MHD sees end-of-stream and either answers or closes; both wake
 * poll() immediately.  An input that makes MHD do neither pays the full
 * timeout, which is why it is only a couple of milliseconds.
 */
static void
wait_threaded (int sock)
{
  unsigned int round;

  if (0 > sock)
    return;
  for (round = 0; round < 4; round++)
  {
    struct pollfd p;
    char tmp[RESP_DRAIN_BUF];
    ssize_t n;

    p.fd = sock;
    p.events = POLLIN;
    p.revents = 0;
    if (0 >= poll (&p, 1, THREAD_WAIT_MS))
      return;
    if (0 == (p.revents & POLLIN))
      return;                   /* POLLHUP/POLLERR only: peer is gone */
    n = recv (sock, tmp, sizeof (tmp), MSG_DONTWAIT);
    if (0 >= n)
      return;
  }
}


static void
send_all (struct MHD_Daemon *d,
          int sock,
          const uint8_t *data,
          size_t len)
{
  size_t off = 0;
  unsigned int stall = 0;

  if (0 > sock)
    return;
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
    if (cfg.uses_threads)
    {
      struct pollfd p;

      p.fd = sock;
      p.events = POLLOUT;
      p.revents = 0;
      if (0 >= poll (&p, 1, THREAD_WAIT_MS))
        break;
    }
    else
    {
      pump (d, sock, 2);
    }
    if ( (0 > s) &&
         (EAGAIN != errno) &&
         (EWOULDBLOCK != errno) &&
         (EINTR != errno) )
      break;
  }
}


/**
 * Hand a fresh socketpair to the daemon.
 *
 * @param d the daemon
 * @param[out] sock set to the harness side of the pair
 * @return 0 on success, -1 if MHD refused the connection (which is a
 *         perfectly ordinary outcome: MHD_OPTION_CONNECTION_LIMIT and
 *         MHD_OPTION_PER_IP_CONNECTION_LIMIT are part of what is fuzzed)
 */
static int
new_connection (struct MHD_Daemon *d,
                int *sock)
{
  int sv[2];
  struct sockaddr_in sa;

  *sock = -1;
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
    stat_conns_refused++;
    return -1;
  }
  stat_conns_added++;
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
  if (cfg.uses_threads)
    wait_threaded (*sock);
  else
    pump (d, *sock, 4);
  (void) close (*sock);
  *sock = -1;
}


/* ------------------------------------------------------------------ */
/* Building the option array                                           */
/* ------------------------------------------------------------------ */

#define PICK(tbl, idx) ((tbl)[(idx) % (sizeof (tbl) / sizeof ((tbl)[0]))])

static void
add_opt (struct MHD_OptionItem *opts,
         unsigned int *nopt,
         enum MHD_OPTION option,
         intptr_t value,
         void *ptr_value)
{
  if (*nopt + 1 >= MAX_OPTS)
    return;
  opts[*nopt].option = option;
  opts[*nopt].value = value;
  opts[*nopt].ptr_value = ptr_value;
  (*nopt)++;
}


/**
 * Translate the presence masks (bytes 3, 4, 14) and the value selectors
 * (bytes 6..11, 15) into an MHD_OptionItem array.
 *
 * Only the options that can be expressed through MHD_OPTION_ARRAY are
 * built here.  The five callback options take two pointers, and putting
 * a function pointer into the array's `intptr_t value` member is not
 * strictly conforming C, so those go through the varargs of
 * MHD_start_daemon() instead (see start_daemon_variant()).
 */
static unsigned int
build_options (const uint8_t *data,
               struct MHD_OptionItem *opts,
               unsigned int flags)
{
  unsigned int nopt = 0;
  const uint8_t mask_a = data[3];
  const uint8_t mask_b = data[4];
  const uint8_t mask_d = data[14];
  /* A thread pool needs an internal polling thread and is incompatible
     with thread-per-connection. */
  const int pool_ok =
    (0 != (flags & MHD_USE_INTERNAL_POLLING_THREAD)) &&
    (0 == (flags & MHD_USE_THREAD_PER_CONNECTION));
  /* Offer options in configurations where MHD rejects them.  One input
     in eight: the rejection branches are worth reaching, but each one
     costs the whole rest of the iteration, because the daemon does not
     start at all. */
  const int misfit = (0xE0 == (data[15] & 0xE0));

  if (0 != (mask_a & 0x01))
    add_opt (opts, &nopt, MHD_OPTION_CONNECTION_MEMORY_LIMIT,
             (intptr_t) PICK (mem_limit_tbl, data[6] & 0x0F), NULL);
  if (0 != (mask_a & 0x02))
    add_opt (opts, &nopt, MHD_OPTION_CONNECTION_MEMORY_INCREMENT,
             (intptr_t) PICK (mem_increment_tbl, (data[6] >> 4) & 0x0F), NULL);
  if (0 != (mask_a & 0x04))
    add_opt (opts, &nopt, MHD_OPTION_CONNECTION_LIMIT,
             (intptr_t) PICK (conn_limit_tbl, data[7] & 0x07), NULL);
  if (0 != (mask_a & 0x08))
    add_opt (opts, &nopt, MHD_OPTION_PER_IP_CONNECTION_LIMIT,
             (intptr_t) PICK (per_ip_limit_tbl, (data[7] >> 4) & 0x07), NULL);
  if (0 != (mask_a & 0x10))
    add_opt (opts, &nopt, MHD_OPTION_CONNECTION_TIMEOUT,
             (intptr_t) PICK (timeout_tbl, data[8] & 0x07), NULL);
  /* MHD_OPTION_THREAD_POOL_SIZE is rejected outright without an
     internal polling thread, and again when combined with
     MHD_USE_THREAD_PER_CONNECTION.  Both branches are worth reaching,
     but a daemon that fails to start exercises nothing else, so the
     mismatched combinations are gated behind an extra bit instead of
     being half of all the inputs that name the option. */
  if ( (0 != (mask_a & 0x20)) &&
       (pool_ok || misfit) )
    add_opt (opts, &nopt, MHD_OPTION_THREAD_POOL_SIZE,
             (intptr_t) PICK (pool_size_tbl, (data[8] >> 3) & 0x03), NULL);
  if (0 != (mask_a & 0x40))
    add_opt (opts, &nopt, MHD_OPTION_THREAD_STACK_SIZE,
             (intptr_t) PICK (stack_size_tbl, (data[8] >> 5) & 0x03), NULL);
  if (0 != (mask_a & 0x80))
    add_opt (opts, &nopt, MHD_OPTION_LISTENING_ADDRESS_REUSE,
             (intptr_t) (unsigned int) (data[11] & 0x01), NULL);

  if (0 != (mask_b & 0x01))
    add_opt (opts, &nopt, MHD_OPTION_LISTEN_BACKLOG_SIZE,
             (intptr_t) PICK (backlog_tbl, (data[11] >> 1) & 0x03), NULL);
  if (0 != (mask_b & 0x02))
    add_opt (opts, &nopt, MHD_OPTION_NONCE_NC_SIZE,
             (intptr_t) PICK (nonce_nc_tbl, data[9] & 0x03), NULL);
  if (0 != (mask_b & 0x04))
    add_opt (opts, &nopt, MHD_OPTION_SERVER_INSANITY,
             (intptr_t) (unsigned int) ((data[10] >> 6) & 0x03), NULL);
  if (0 != (mask_b & 0x08))
    add_opt (opts, &nopt, MHD_OPTION_STRICT_FOR_CLIENT,
             (intptr_t) PICK (strict_tbl, (data[10] >> 4) & 0x03), NULL);
  if (0 != (mask_b & 0x10))
    add_opt (opts, &nopt, MHD_OPTION_CLIENT_DISCIPLINE_LVL,
             (intptr_t) PICK (discipline_tbl, data[10] & 0x07), NULL);
  if (0 != (mask_b & 0x20))
    add_opt (opts, &nopt, MHD_OPTION_SIGPIPE_HANDLED_BY_APP,
             /* Truthful: LLVMFuzzerTestOneInput() ignores SIGPIPE
                process-wide before anything else happens. */
             (intptr_t) 1, NULL);
  if (0 != (mask_b & 0x40))
    add_opt (opts, &nopt, MHD_OPTION_APP_FD_SETSIZE,
             (intptr_t) PICK (fd_setsize_tbl, (data[11] >> 3) & 0x07), NULL);
  if (0 != (mask_b & 0x80))
    add_opt (opts, &nopt, MHD_OPTION_ALLOW_BIN_ZERO_IN_URI_PATH,
             (intptr_t) (int) ((data[11] >> 5) & 0x03), NULL);

  if (0 != (mask_d & 0x01))
    add_opt (opts, &nopt, MHD_OPTION_DIGEST_AUTH_NONCE_BIND_TYPE,
             (intptr_t) (unsigned int) ((data[9] >> 2) & 0x0F), NULL);
  if (0 != (mask_d & 0x02))
    add_opt (opts, &nopt, MHD_OPTION_DIGEST_AUTH_DEFAULT_NONCE_TIMEOUT,
             (intptr_t) (unsigned int) (data[15] & 0x7F), NULL);
  if (0 != (mask_d & 0x04))
    add_opt (opts, &nopt, MHD_OPTION_DIGEST_AUTH_DEFAULT_MAX_NC,
             (intptr_t) (uint32_t) data[15], NULL);
  if (0 != (mask_d & 0x08))
    add_opt (opts, &nopt, MHD_OPTION_TCP_FASTOPEN_QUEUE_SIZE,
             (intptr_t) PICK (fastopen_tbl, (data[11] >> 6) & 0x03), NULL);
  if (0 != (mask_d & 0x10))
    add_opt (opts, &nopt, MHD_OPTION_TLS_NO_ALPN,
             (intptr_t) (int) (data[15] & 0x01), NULL);
  if (0 != (mask_d & 0x20))
    /* MHD_INVALID_SOCKET means "use the socket MHD creates itself"; a
       real descriptor is deliberately not offered, because MHD takes
       ownership of it and the harness would have to track that. */
    add_opt (opts, &nopt, MHD_OPTION_LISTEN_SOCKET,
             (intptr_t) MHD_INVALID_SOCKET, NULL);

  /* MHD_OPTION_DIGEST_AUTH_RANDOM keeps the caller's buffer, the _COPY
     variant makes MHD malloc() a copy that MHD_stop_daemon() has to free
     again -- a leak this harness would notice immediately. */
  if (0 != (data[5] & 0x20))
    add_opt (opts, &nopt,
             (0 != (data[5] & 0x40))
             ? MHD_OPTION_DIGEST_AUTH_RANDOM_COPY
             : MHD_OPTION_DIGEST_AUTH_RANDOM,
             (intptr_t) sizeof (digest_rnd),
             (void *) (intptr_t) digest_rnd);

  /* A bind address is rejected together with MHD_USE_NO_LISTEN_SOCKET;
     same reasoning as for the thread pool above. */
  if ( (0 != (data[5] & 0x80)) &&
       (cfg.listen_sock || misfit) )
  {
    prepare_sock_addrs ();
    /* The address family has to match MHD_USE_IPv6, otherwise MHD
       rejects the daemon; that check is reached through the raw flag
       escape rather than by feeding a mismatched address on purpose. */
#ifdef AF_INET6
    if (0 != (flags & MHD_USE_IPv6))
    {
      if (0 != (data[15] & 0x02))
        add_opt (opts, &nopt, MHD_OPTION_SOCK_ADDR_LEN,
                 (intptr_t) (socklen_t) sizeof (bind6), &bind6);
      else
        add_opt (opts, &nopt, MHD_OPTION_SOCK_ADDR, 0, &bind6);
    }
    else
#endif
    if (0 != (data[15] & 0x02))
      add_opt (opts, &nopt, MHD_OPTION_SOCK_ADDR_LEN,
               (intptr_t) (socklen_t) sizeof (bind4), &bind4);
    else
      add_opt (opts, &nopt, MHD_OPTION_SOCK_ADDR, 0, &bind4);
  }

  /* An option number MHD does not know at all.  parse_options_va()
     answers MHD_NO for it and MHD_start_daemon() returns NULL, which is
     the branch this reaches; keep it last so that everything above has
     already been parsed. */
  if (0 != (mask_d & 0x40))
    add_opt (opts, &nopt, (enum MHD_OPTION) (200 + (data[15] & 0x0F)),
             0, NULL);

  opts[nopt].option = MHD_OPTION_END;
  opts[nopt].value = 0;
  opts[nopt].ptr_value = NULL;
  return nopt;
}


/* The three callback options whose "not set" state is representable as a
   NULL function pointer; MHD checks all three for NULL before calling
   them, so passing NULL is exactly equivalent to omitting the option. */
typedef void *(*fuzz_uri_log_cb)(void *, const char *,
                                 struct MHD_Connection *);

#define VARARG_CALLBACKS \
        MHD_OPTION_NOTIFY_COMPLETED, cb_completed, NULL, \
        MHD_OPTION_NOTIFY_CONNECTION, cb_notify, NULL, \
        MHD_OPTION_URI_LOG_CALLBACK, cb_uri_log, NULL

/* The accept policy callback, defined with the accept path further
   down. */
static enum MHD_Result
apc_cb (void *cls,
        const struct sockaddr *addr,
        socklen_t addrlen);


/**
 * Start the daemon.
 *
 * MHD_OPTION_EXTERNAL_LOGGER and MHD_OPTION_UNESCAPE_CALLBACK cannot be
 * "passed as NULL": MHD calls both unconditionally, so their absence has
 * to be expressed by leaving the option out of the varargs, which is why
 * there are four spellings of the same call.  The logger comes first on
 * purpose -- MHD_OPTION_EXTERNAL_LOGGER only catches the messages
 * emitted after it has been parsed, and parsing the option array emits
 * several.
 */
static struct MHD_Daemon *
start_daemon_variant (unsigned int flags,
                      struct MHD_OptionItem *opts,
                      unsigned int cbsel)
{
  MHD_AcceptPolicyCallback apc = cfg.accept_policy ? &apc_cb : NULL;
  MHD_RequestCompletedCallback cb_completed =
    (0 != (cbsel & 0x01)) ? &completed_cb : NULL;
  MHD_NotifyConnectionCallback cb_notify =
    (0 != (cbsel & 0x02)) ? &notify_connection_cb : NULL;
  fuzz_uri_log_cb cb_uri_log =
    (0 != (cbsel & 0x04)) ? &uri_log_cb : NULL;

  switch ((cbsel >> 3) & 0x03)
  {
  case 1:
    return MHD_start_daemon (flags, 0, apc, NULL, &ahc, NULL,
                             MHD_OPTION_ARRAY, opts,
                             VARARG_CALLBACKS,
                             MHD_OPTION_UNESCAPE_CALLBACK, &unescape_cb, NULL,
                             MHD_OPTION_END);
  case 2:
    return MHD_start_daemon (flags, 0, apc, NULL, &ahc, NULL,
                             MHD_OPTION_EXTERNAL_LOGGER, &logger_cb, NULL,
                             MHD_OPTION_ARRAY, opts,
                             VARARG_CALLBACKS,
                             MHD_OPTION_END);
  case 3:
    return MHD_start_daemon (flags, 0, apc, NULL, &ahc, NULL,
                             MHD_OPTION_EXTERNAL_LOGGER, &logger_cb, NULL,
                             MHD_OPTION_ARRAY, opts,
                             VARARG_CALLBACKS,
                             MHD_OPTION_UNESCAPE_CALLBACK, &unescape_cb, NULL,
                             MHD_OPTION_END);
  default:
    return MHD_start_daemon (flags, 0, apc, NULL, &ahc, NULL,
                             MHD_OPTION_ARRAY, opts,
                             VARARG_CALLBACKS,
                             MHD_OPTION_END);
  }
}


/**
 * The accept policy callback.  MHD_accept_connection() calls it with the
 * peer address of every socket it accepts, and answering MHD_NO makes
 * new_connection_prepare_() close the socket and drop the IP-limit entry
 * before any connection object exists -- a path nothing else here
 * reaches.  (It does *not* reach new_connection_close_(): that one is
 * only called from close_all_connections(), for connections queued by
 * MHD_add_connection() and never started.  See the byte 3 bit 4
 * scenario in fuzz_eventloop.c.)
 */
static enum MHD_Result
apc_cb (void *cls,
        const struct sockaddr *addr,
        socklen_t addrlen)
{
  volatile size_t sink;

  (void) cls;
  sink = (size_t) addrlen + ((NULL != addr) ? (size_t) addr->sa_family : 0u);
  (void) sink;
  return cfg.accept_policy_deny ? MHD_NO : MHD_YES;
}


/**
 * Really connect to the daemon's listening socket.
 *
 * MHD_add_connection() bypasses accept(), so without this the whole
 * accept path -- MHD_accept_connection(), the accept policy callback,
 * the listen-socket branches of the three event loops -- is unreachable.
 * The client end is given SO_LINGER {1, 0} so that close() sends a RST
 * and neither side ends up in TIME_WAIT: at fuzzing rates the ephemeral
 * port range would otherwise be exhausted within a couple of minutes.
 *
 * @param d the daemon, which must have a listening socket
 * @param flags the flags it was started with, to pick the address family
 * @return the connected socket, or -1
 */
static int
connect_real (struct MHD_Daemon *d,
              unsigned int flags)
{
  const union MHD_DaemonInfo *di;
  struct linger lg;
  int s;
  uint16_t port;

  di = MHD_get_daemon_info (d, MHD_DAEMON_INFO_BIND_PORT);
  if ( (NULL == di) ||
       (0 == di->port) )
    return -1;
  port = (uint16_t) di->port;
  prepare_sock_addrs ();
#ifdef AF_INET6
  if (0 != (flags & MHD_USE_IPv6))
  {
    struct sockaddr_in6 to = bind6;

    to.sin6_port = htons (port);
    s = socket (AF_INET6, SOCK_STREAM, 0);
    if (0 > s)
      return -1;
    if (0 != connect (s, (const struct sockaddr *) &to, sizeof (to)))
    {
      (void) close (s);
      return -1;
    }
  }
  else
#endif
  {
    struct sockaddr_in to = bind4;

    to.sin_port = htons (port);
    s = socket (AF_INET, SOCK_STREAM, 0);
    if (0 > s)
      return -1;
    if (0 != connect (s, (const struct sockaddr *) &to, sizeof (to)))
    {
      (void) close (s);
      return -1;
    }
  }
  lg.l_onoff = 1;
  lg.l_linger = 0;
  (void) setsockopt (s, SOL_SOCKET, SO_LINGER, &lg, sizeof (lg));
  stat_real_conns++;
  return s;
}


/**
 * Ask MHD_is_feature_supported() about one feature.  The function is a
 * large switch in daemon.c that no other harness touches; the index
 * comes off the input so that invalid values reach its default branch
 * as well.
 */
static void
query_feature (uint8_t sel)
{
  volatile int sink;

  sink = (int) MHD_is_feature_supported ((enum MHD_FEATURE) (sel % 40u));
  (void) sink;
}


/**
 * Read everything MHD_get_daemon_info() offers.  All of it lives in
 * daemon.c and none of it is reachable from the other harnesses.
 */
static void
query_daemon_info (struct MHD_Daemon *d)
{
  volatile unsigned int sink = 0;
  const union MHD_DaemonInfo *di;

  sink += (unsigned int) (NULL != MHD_get_version ());
  sink += MHD_get_version_bin ();

  di = MHD_get_daemon_info (d, MHD_DAEMON_INFO_CURRENT_CONNECTIONS);
  if (NULL != di)
    sink += di->num_connections;
  di = MHD_get_daemon_info (d, MHD_DAEMON_INFO_FLAGS);
  if (NULL != di)
    sink += (unsigned int) di->flags;
  di = MHD_get_daemon_info (d, MHD_DAEMON_INFO_BIND_PORT);
  if (NULL != di)
    sink += di->port;
  di = MHD_get_daemon_info (d, MHD_DAEMON_INFO_LISTEN_FD);
  if (NULL != di)
    sink += (unsigned int) (di->listen_fd + 1);
  di = MHD_get_daemon_info (d, MHD_DAEMON_INFO_EPOLL_FD);
  if (NULL != di)
    sink += (unsigned int) (di->listen_fd + 1);
  (void) sink;
}


/* ------------------------------------------------------------------ */
/* The fuzz target                                                     */
/* ------------------------------------------------------------------ */

int
LLVMFuzzerTestOneInput (const uint8_t *data,
                        size_t size)
{
  struct MHD_Daemon *d;
  struct MHD_OptionItem opts[MAX_OPTS];
  unsigned int flags;
  int sock = -1;
  int rsock = -1;
  size_t pos;
  unsigned int nseg = 0;
  unsigned int nconn = 1;
  unsigned int cbsel;
  MHD_socket quiesced = MHD_INVALID_SOCKET;

  /* Must happen before the first write() into the socketpair, and must
     not be left to the built-in driver: fuzz_install_handlers() is
     compiled out under -DFUZZ_NO_MAIN, which is exactly the build every
     external fuzzing engine uses.  The call is idempotent.  See
     fuzz_ignore_sigpipe() in fuzz_common.h for what happens without it. */
  fuzz_ignore_sigpipe ();

  /* The sixteen configuration bytes are mandatory.  An input of exactly
     that length is fine and starts a daemon with no traffic. */
  if (size < CFG_BYTES)
    return 0;

  memset (&cfg, 0, sizeof (cfg));
  memset (pending_resume, 0, sizeof (pending_resume));
  tearing_down = 0;

  flags = flags_from_input (data);
  if (cfg.listen_sock)
    flags &= ~((unsigned int) MHD_USE_NO_LISTEN_SOCKET);
  else
    flags |= MHD_USE_NO_LISTEN_SOCKET;
  if (cfg.err_log)
    flags |= MHD_USE_ERROR_LOG;
  else
    flags &= ~((unsigned int) MHD_USE_ERROR_LOG);

  cfg.uses_threads = (0 != (flags & (MHD_USE_INTERNAL_POLLING_THREAD
                                     | MHD_USE_THREAD_PER_CONNECTION)));
  if (cfg.uses_threads &&
      (0 == (flags & MHD_USE_NO_THREAD_SAFETY)))
  {
    /* Without the inter-thread communication channel a worker only
       notices a connection handed to it by MHD_add_connection() when its
       own poll times out, so every threaded iteration would pay the full
       wait.  MHD forces ITC on anyway whenever there is no listen
       socket; this extends that to the daemons that have one. */
    flags |= MHD_USE_ITC;
  }

  cfg.loop_mode = (unsigned int) (data[12] & 0x03);
  cfg.quiesce = (0 != (data[12] & 0x04));
  if (cfg.quiesce &&
      cfg.uses_threads &&
      uses_epoll (flags) &&
      (! quiesce_epoll_race_allowed ()))
    cfg.quiesce = 0;
  cfg.daemon_info = (0 != (data[12] & 0x08));
  cfg.suspend_mode = (0 != (flags & SUSPEND_BIT))
                     ? (int) ((data[12] >> 4) & 0x03)
                     : 0;
  if (3 == cfg.suspend_mode)
    cfg.suspend_mode = 1;
  cfg.nconn_max = 1u + (unsigned int) ((data[12] >> 6) & 0x03);
  if (cfg.nconn_max > MAX_CONNECTIONS)
    cfg.nconn_max = MAX_CONNECTIONS;

  cfg.resp_kind = (unsigned int) (data[13] & 0x03);
  cfg.handler_no = (0 != (data[13] & 0x04));
  cfg.conn_option = (0 != (data[13] & 0x08));
  cfg.accept_policy = (0 != (data[13] & 0x10));
  cfg.accept_policy_deny = (0 != (data[13] & 0x20));
  /* One iteration in four of those that have a listening socket at all;
     a real connect()/accept() pair is much more expensive than
     MHD_add_connection() on a socketpair. */
  cfg.real_connect = cfg.listen_sock && (0xC0 == (data[13] & 0xC0));

  (void) build_options (data, opts, flags);

  cbsel = (unsigned int) data[5];
  /* MHD_USE_ERROR_LOG without MHD_OPTION_EXTERNAL_LOGGER sends every
     message MHD produces to stderr through MHD_default_logger_, which
     at fuzzing rates is tens of megabytes of noise.  The flag is far too
     valuable to drop -- with it set, several hundred MHD_DLOG() call
     sites in daemon.c become live -- so the logger is forced on instead
     (bit 4 of the callback selector). */
  if (cfg.err_log)
    cbsel |= 0x10u;

  MHD_set_panic_func (&panic_cb, NULL);
  d = start_daemon_variant (flags, opts, cbsel);
  if (NULL == d)
  {
    /* Entirely normal: an unsupported flag combination, an option MHD
       rejects, a bind() failure, ... */
    stat_daemons_failed++;
    return 0;
  }
  stat_daemons++;
  if (cfg.uses_threads)
    stat_threaded++;
  if (! stats_registered)
  {
    stats_registered = 1;
    (void) atexit (&print_stats);
  }

  if (cfg.daemon_info)
    query_daemon_info (d);
  query_feature (data[15]);

  if (cfg.real_connect)
  {
    rsock = connect_real (d, flags);
    if (0 <= rsock)
    {
      static const char req[] = "GET / HTTP/1.1\r\nHost: x\r\n\r\n";

      (void) send (rsock, req, sizeof (req) - 1, MSG_DONTWAIT);
      if (cfg.uses_threads)
        wait_threaded (rsock);
      else
        pump (d, rsock, PUMP_ROUNDS_LONG);
    }
  }

  (void) new_connection (d, &sock);

  pos = CFG_BYTES;
  while ( (pos + 2 <= size) &&
          (nseg < MAX_SEGMENTS) )
  {
    unsigned int hdr = (unsigned int) data[pos]
                       | ((unsigned int) data[pos + 1] << 8);
    unsigned int op = hdr >> 14;
    size_t slen = (size_t) (hdr & 0x3FFF);

    pos += 2;
    nseg++;
    if (slen > size - pos)
      slen = size - pos;

    if ( (3 == op) &&
         (nconn < cfg.nconn_max) )
    {
      close_connection (d, &sock);
      (void) new_connection (d, &sock);
      nconn++;
    }
    if (0 != slen)
      send_all (d, sock, data + pos, slen);
    pos += slen;
    if (cfg.uses_threads)
      continue;                 /* the threaded shape drains at close */
    pump (d, sock, (0 == op) ? PUMP_ROUNDS : PUMP_ROUNDS_LONG);
  }

  close_connection (d, &sock);
  pump (d, sock, 4);
  if (0 <= rsock)
  {
    (void) shutdown (rsock, SHUT_WR);
    if (cfg.uses_threads)
      wait_threaded (rsock);
    else
      pump (d, rsock, 4);
    (void) close (rsock);
    rsock = -1;
  }

  /* A connection left suspended makes MHD_stop_daemon() MHD_PANIC(), and
     MHD_resume_connection() alone is not enough: it only raises a flag,
     and the connection is taken off the daemon's suspended list by
     MHD_run().  So flush and run until nothing is parked any more.
     tearing_down keeps the handler from parking anything new, which is
     what bounds this loop; the cap is only a backstop. */
  tearing_down = 1;
  if (! cfg.uses_threads)
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
  {
    /* The returned socket belongs to the caller from here on, and with
       internal threads it must not be closed before MHD_stop_daemon()
       has joined them. */
    quiesced = MHD_quiesce_daemon (d);
  }
  MHD_stop_daemon (d);
  if (MHD_INVALID_SOCKET != quiesced)
    (void) close ((int) quiesced);
  return 0;
}


/* ------------------------------------------------------------------ */
/* Structure-aware generator                                           */
/* ------------------------------------------------------------------ */

/* Defined unconditionally, exactly like the rest of the harness API:
   only main() may live behind #ifndef FUZZ_NO_MAIN, and fuzz_common.h
   already declares these three with FUZZ_UNUSED so that the libFuzzer
   and AFL++ builds, which never call them, compile without a warning. */

struct sbuf
{
  uint8_t *p;
  size_t len;
  size_t cap;
};


static void
sb_raw (struct sbuf *b,
        const void *s,
        size_t n)
{
  if (b->len + n > b->cap)
    n = b->cap - b->len;
  memcpy (b->p + b->len, s, n);
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
        int hex)
{
  char tmp[32];

  (void) snprintf (tmp, sizeof (tmp),
                   hex ? "%llx" : "%llu",
                   (unsigned long long) v);
  sb_str (b, tmp);
}


static const char *const gen_methods[] = {
  "GET", "POST", "HEAD", "PUT", "OPTIONS", "DELETE", "TRACE", "CONNECT",
  "PATCH", "get", "BREW", ""
};

static const char *const gen_targets[] = {
  "/", "/a", "/a/b/c", "*", "http://x/a", "/%41%42", "/a?b=c&d",
  "/very/long/path/that/does/not/fit/into/a/small/connection/memory/pool",
  "/a?novalue", "//", "/.%2e/", "/\x01"
};

static const char *const gen_versions[] = {
  "HTTP/1.1", "HTTP/1.0", "HTTP/1.2", "HTTP/0.9", "HTTP/1", ""
};

static const char *const gen_hdr_names[] = {
  "Host", "Connection", "Accept", "User-Agent", "Cookie", "Expect",
  "Content-Type", "X-Fuzz", "Upgrade", "Accept-Encoding", "Range",
  "If-Modified-Since"
};

static const char *const gen_hdr_values[] = {
  "x", "keep-alive", "close", "*/*", "a=b; c=d", "100-continue",
  "text/plain", "1", "fuzz-protocol", "gzip", "bytes=0-1", "chunked"
};


/**
 * Emit one HTTP request into @a b.
 *
 * The shapes are deliberately unambitious -- the request parser is
 * fuzz_request's subject, not this harness's.  What matters here is that
 * the bytes form something MHD will actually take through its state
 * machine under whatever daemon configuration the configuration bytes
 * describe, so that the option handling is exercised against a live
 * connection rather than against a connection MHD drops on the first
 * byte.
 */
static void
gen_request (struct fuzz_rng *rng,
             struct sbuf *b,
             unsigned int shape)
{
  unsigned int nhdr;
  unsigned int i;

  switch (shape % 10)
  {
  case 9:
    /* Not HTTP at all: MHD has to reject it, which is its own path. */
    for (i = 0; i < 24; i++)
    {
      uint8_t c = fuzz_byte (rng);

      sb_raw (b, &c, 1);
    }
    return;
  case 6:
    /* Two pipelined requests on one connection. */
    sb_str (b, "GET /a HTTP/1.1\r\nHost: x\r\n\r\n");
    sb_str (b, "GET /b HTTP/1.1\r\nHost: x\r\nConnection: close\r\n\r\n");
    return;
  default:
    break;
  }

  sb_str (b, gen_methods[fuzz_below (rng, (uint32_t) (sizeof (gen_methods)
                                                      / sizeof (gen_methods[0]
                                                                )))]);
  sb_str (b, " ");
  sb_str (b, gen_targets[fuzz_below (rng, (uint32_t) (sizeof (gen_targets)
                                                      / sizeof (gen_targets[0]
                                                                )))]);
  sb_str (b, " ");
  sb_str (b, gen_versions[fuzz_below (rng,
                                      (uint32_t) (sizeof (gen_versions)
                                                  / sizeof (gen_versions[0])))
          ]);
  sb_str (b, "\r\n");

  nhdr = (5 == (shape % 10)) ? (8 + fuzz_below (rng, 24)) : fuzz_below (rng, 5);
  for (i = 0; i < nhdr; i++)
  {
    sb_str (b, gen_hdr_names[fuzz_below (rng,
                                         (uint32_t) (sizeof (gen_hdr_names)
                                                     / sizeof (gen_hdr_names[0]
                                                               )))]);
    sb_str (b, ": ");
    sb_str (b, gen_hdr_values[fuzz_below (rng,
                                          (uint32_t) (sizeof (gen_hdr_values)
                                                      / sizeof (gen_hdr_values[
                                                                  0])))]);
    sb_str (b, "\r\n");
  }

  switch (shape % 10)
  {
  case 2:                      /* Content-Length body */
    {
      uint32_t n = fuzz_below (rng, 64);

      sb_str (b, "Content-Length: ");
      sb_u64 (b, n, 0);
      sb_str (b, "\r\n\r\n");
      for (i = 0; i < n; i++)
        sb_str (b, "A");
      break;
    }
  case 3:                      /* chunked body */
    {
      unsigned int nch = 1 + fuzz_below (rng, 3);

      sb_str (b, "Transfer-Encoding: chunked\r\n\r\n");
      for (i = 0; i < nch; i++)
      {
        uint32_t n = 1 + fuzz_below (rng, 16);
        uint32_t k;

        sb_u64 (b, n, 1);
        sb_str (b, "\r\n");
        for (k = 0; k < n; k++)
          sb_str (b, "B");
        sb_str (b, "\r\n");
      }
      sb_str (b, "0\r\n\r\n");
      break;
    }
  case 4:                      /* expect 100-continue */
    sb_str (b, "Expect: 100-continue\r\nContent-Length: 4\r\n\r\nabcd");
    break;
  case 7:                      /* upgrade request */
    sb_str (b, "Connection: Upgrade\r\nUpgrade: fuzz-protocol\r\n\r\n");
    break;
  case 8:                      /* truncated: MHD keeps waiting for more */
    sb_str (b, "X-Trunc: ");
    break;
  default:
    sb_str (b, "\r\n");
    break;
  }
}


/**
 * Serialise @a body into the segment stream understood by
 * LLVMFuzzerTestOneInput().
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

    switch (fuzz_below (rng, 5))
    {
    case 0:
      chunk = 1;
      break;
    case 1:
      chunk = 2 + fuzz_below (rng, 8);
      break;
    default:
      chunk = body_len - off;
      break;
    }
    if (chunk > body_len - off)
      chunk = body_len - off;
    if (chunk > 0x3FFF)
      chunk = 0x3FFF;
    op = (first && new_conn_first) ? 3u : (fuzz_chance (rng, 5) ? 2u : 0u);
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


/**
 * The generator.
 *
 * Purely random configuration bytes are already useful for this harness
 * -- unlike an HTTP request, an option array has no grammar to get wrong
 * -- but two things still need help.  Byte 0 is biased into the range of
 * mode_tbl[] so that most iterations get a daemon that actually starts,
 * and the tail of the input has to look like HTTP, or MHD closes every
 * connection before any of the configured behaviour has a chance to
 * matter.
 */
static size_t
fuzz_generate (struct fuzz_rng *rng,
               uint8_t *buf,
               size_t cap)
{
  struct sbuf out;
  uint8_t cfg_bytes[CFG_BYTES];
  uint8_t req[GEN_BUF_SIZE];
  struct sbuf rb;
  unsigned int nreq;
  unsigned int i;

  out.p = buf;
  out.len = 0;
  out.cap = cap;

  for (i = 0; i < CFG_BYTES; i++)
    cfg_bytes[i] = fuzz_byte (rng);

  /* Byte 0 selects the daemon shape; keep it inside the table so that
     the value is not folded by the modulo in an uneven way. */
  cfg_bytes[0] = (uint8_t) fuzz_below (rng, (uint32_t) MODE_COUNT);
  /* The raw flag escape is 1 in 4 of the byte-2 values, which is far too
     often: those daemons mostly fail to start and never reach the option
     handling.  Clear the escape unless it is explicitly rolled. */
  if (! fuzz_chance (rng, 10))
    cfg_bytes[2] &= (uint8_t) ~0xC0u;
  else
    cfg_bytes[2] |= (uint8_t) 0xC0u;
  /* Likewise the deliberately invalid option number: useful, but every
     input carrying it ends in MHD_start_daemon() == NULL. */
  if (! fuzz_chance (rng, 20))
    cfg_bytes[14] &= (uint8_t) ~0x40u;

  sb_raw (&out, cfg_bytes, CFG_BYTES);

  nreq = 1u + (fuzz_chance (rng, 4) ? 1u : 0u);
  for (i = 0; i < nreq; i++)
  {
    rb.p = req;
    rb.len = 0;
    rb.cap = sizeof (req);
    gen_request (rng, &rb, fuzz_below (rng, 10));
    emit_segments (rng, &out, req, rb.len,
                   (0 != i) || fuzz_chance (rng, 6));
  }
  return out.len;
}


/* ------------------------------------------------------------------ */
/* Built-in seed corpus                                                */
/* ------------------------------------------------------------------ */

/**
 * A seed is sixteen configuration bytes plus one request, rendered into
 * the wire format at run time so that segment lengths never have to be
 * spelled out by hand.
 *
 * Every seed turns on exactly one area, so that a corpus minimiser keeps
 * them distinguishable, and the configuration bytes of a seed that does
 * not care about an area are zero -- which is the plainest setting:
 * external polling with select(), no listen socket, no options at all,
 * one connection, MHD_run() as the event loop.
 */
struct seed_def
{
  const char *name;
  unsigned char cfg[CFG_BYTES];
  const char *req;
};

/* Byte positions inside seed_def::cfg, for readability. */
#define C_MODE 0
#define C_FLAGA 1
#define C_FLAGB 2
#define C_OPTA 3
#define C_OPTB 4
#define C_OPTC 5
#define C_VAL_MEM 6
#define C_VAL_CONN 7
#define C_VAL_THR 8
#define C_VAL_DAUTH 9
#define C_VAL_DISC 10
#define C_VAL_SOCK 11
#define C_DRIVE 12
#define C_HANDLER 13
#define C_OPTD 14
#define C_SPARE 15

#define REQ_PLAIN "GET /a HTTP/1.1\r\nHost: x\r\n\r\n"
#define REQ_CLOSE "GET /a HTTP/1.1\r\nHost: x\r\nConnection: close\r\n\r\n"
#define REQ_POST \
        "POST /a HTTP/1.1\r\nHost: x\r\nContent-Length: 4\r\n\r\nabcd"
#define REQ_CHUNKED \
        "POST /a HTTP/1.1\r\nHost: x\r\nTransfer-Encoding: chunked\r\n" \
        "\r\n3\r\nabc\r\n0\r\n\r\n"

static const struct seed_def seeds[] = {
  /* ---- the event loops, all external ---- */
  { "plain-external-run",
    { 0 }, REQ_PLAIN },
  { "external-fdset2",
    { 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x01 | 0x08, 0, 0, 0 },
    REQ_PLAIN },
  { "external-run-wait",
    { 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x02, 0, 0, 0 },
    REQ_PLAIN },
  { "external-fdset-v1",
    { 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x03, 0, 0, 0 },
    REQ_PLAIN },
  { "external-epoll",
    { 12, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0 },
    REQ_PLAIN },
  { "external-auto",
    { 16, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0 },
    REQ_PLAIN },

  /* ---- the daemon shapes that run their own threads ---- */
  { "internal-thread-select",
    { 18, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0 },
    REQ_CLOSE },
  { "internal-thread-poll",
    { 19, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0 },
    REQ_CLOSE },
  { "internal-thread-epoll",
    { 20, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0 },
    REQ_CLOSE },
  { "thread-per-connection",
    { 21, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0 },
    REQ_CLOSE },
  { "thread-per-connection-poll",
    { 22, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0 },
    REQ_CLOSE },
  /* A thread pool needs MHD_OPTION_THREAD_POOL_SIZE (option mask A bit
     5) on top of an internal polling thread, and is rejected outright
     with thread-per-connection. */
  { "thread-pool",
    { 18, 0, 0, 0x20, 0, 0, 0, 0, 0x00, 0, 0, 0, 0, 0, 0, 0 },
    REQ_CLOSE },
  { "thread-pool-epoll-stack",
    { 20, 0, 0, 0x20 | 0x40, 0, 0, 0, 0, 0x10 | 0x20, 0, 0, 0, 0, 0, 0, 0 },
    REQ_CLOSE },

  /* ---- a real listening socket ---- */
  { "listen-socket",
    { 0, 0, 0x01, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0 },
    REQ_PLAIN },
  { "listen-socket-reuse-backlog",
    { 0, 0, 0x01, 0x80, 0x01, 0, 0, 0, 0, 0, 0, 0x01 | 0x06, 0, 0, 0, 0 },
    REQ_PLAIN },
  { "listen-socket-sockaddr",
    { 0, 0, 0x01, 0, 0, 0x80, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0 },
    REQ_PLAIN },
  { "listen-socket-ipv6-dual",
    { 0, 0, 0x01 | 0x02 | 0x04, 0, 0, 0x80, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0 },
    REQ_PLAIN },
  { "listen-socket-quiesce",
    { 0, 0, 0x01, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x04 | 0x08, 0, 0, 0 },
    REQ_PLAIN },
  { "listen-socket-internal-thread",
    { 18, 0, 0x01, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x04, 0, 0, 0 },
    REQ_CLOSE },

  /* ---- the accept() path: a real client on the listening socket ----
     Byte 13 bit 0x40|0x80 asks for the connect(), bit 0x10 installs the
     accept policy callback and bit 0x20 makes it say no.  Without these
     MHD_accept_connection() and the listen-socket branches of the three
     event loops are never entered at all: MHD_add_connection() bypasses
     accept() completely. */
  { "real-connect",
    { 0, 0, 0x01, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xC0, 0, 0 },
    REQ_PLAIN },
  { "real-connect-accept-policy",
    { 0, 0, 0x01, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xC0 | 0x10, 0, 0 },
    REQ_PLAIN },
  { "real-connect-accept-denied",
    { 0, 0, 0x01, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xC0 | 0x10 | 0x20, 0, 0 },
    REQ_PLAIN },
  { "real-connect-internal-thread",
    { 18, 0, 0x01, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xC0, 0, 0 },
    REQ_CLOSE },
  { "real-connect-external-epoll",
    { 12, 0, 0x01, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xC0, 0, 0 },
    REQ_PLAIN },

  /* ---- the memory options ---- */
  { "tiny-pool",
    { 0, 0, 0, 0x01 | 0x02, 0, 0, 0x01 | 0x10, 0, 0, 0, 0, 0, 0, 0, 0, 0 },
    REQ_PLAIN },
  { "big-pool-big-increment",
    { 0, 0, 0, 0x01 | 0x02, 0, 0, 0x0C | 0x60, 0, 0, 0, 0, 0, 0, 0, 0, 0 },
    REQ_POST },

  /* ---- the connection limits ---- */
  { "connection-limit-one",
    { 0, 0, 0, 0x04, 0, 0, 0, 0x01, 0, 0, 0, 0, 0xC0, 0, 0, 0 },
    REQ_PLAIN },
  { "per-ip-limit-one",
    { 0, 0, 0, 0x08, 0, 0, 0, 0x10, 0, 0, 0, 0, 0xC0, 0, 0, 0 },
    REQ_PLAIN },
  { "connection-limit-zero",
    { 0, 0, 0, 0x04, 0, 0, 0, 0x00, 0, 0, 0, 0, 0, 0, 0, 0 },
    REQ_PLAIN },
  { "connection-timeout",
    { 0, 0, 0, 0x10, 0, 0, 0, 0, 0x01, 0, 0, 0, 0, 0, 0, 0 },
    REQ_PLAIN },

  /* ---- parsing discipline and insanity ---- */
  { "discipline-lowest",
    { 0, 0, 0, 0, 0x10, 0, 0, 0, 0, 0, 0x00, 0, 0, 0, 0, 0 },
    "GET /a HTTP/1.1\r\n Host: x\r\n\r\n" },
  { "discipline-highest-pedantic",
    { 0, 0x01, 0, 0, 0x10, 0, 0, 0, 0, 0, 0x05, 0, 0, 0, 0, 0 },
    REQ_PLAIN },
  { "strict-for-client",
    { 0, 0, 0, 0, 0x08, 0, 0, 0, 0, 0, 0x00, 0, 0, 0, 0, 0 },
    REQ_PLAIN },
  { "server-insanity",
    { 0, 0, 0, 0, 0x04, 0, 0, 0, 0, 0, 0x40, 0, 0, 0, 0, 0 },
    REQ_PLAIN },
  { "bin-zero-in-uri-path",
    { 0, 0, 0, 0, 0x80, 0, 0, 0, 0, 0, 0, 0x20, 0, 0, 0, 0 },
    "GET /a%00b HTTP/1.1\r\nHost: x\r\n\r\n" },
  { "app-fd-setsize",
    { 0, 0, 0, 0, 0x40, 0, 0, 0, 0, 0, 0, 0x00, 0x01, 0, 0, 0 },
    REQ_PLAIN },

  /* ---- the callbacks ---- */
  { "notify-completed",
    { 0, 0, 0, 0, 0, 0x01, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0 },
    REQ_PLAIN },
  { "notify-connection",
    { 0, 0, 0, 0, 0, 0x02, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0 },
    REQ_PLAIN },
  { "uri-log-callback",
    { 0, 0, 0, 0, 0, 0x04, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0 },
    "GET /a?q=%41 HTTP/1.1\r\nHost: x\r\n\r\n" },
  { "external-logger",
    { 0, 0x40, 0, 0, 0, 0x10, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0 },
    REQ_PLAIN },
  { "unescape-callback",
    { 0, 0, 0, 0, 0, 0x08, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0 },
    "GET /%41%42?a=%43 HTTP/1.1\r\nHost: x\r\n\r\n" },
  { "all-callbacks-error-log",
    { 0, 0x40, 0, 0, 0, 0x01 | 0x02 | 0x04 | 0x08 | 0x10,
      0, 0, 0, 0, 0, 0, 0, 0, 0, 0 },
    REQ_PLAIN },

  /* ---- digest-auth related options ---- */
  { "digest-random",
    { 0, 0, 0, 0, 0x02, 0x20, 0, 0, 0, 0x02, 0, 0, 0, 0, 0, 0 },
    REQ_PLAIN },
  { "digest-random-copy",
    { 0, 0, 0, 0, 0x02, 0x20 | 0x40, 0, 0, 0, 0x01, 0, 0, 0, 0, 0, 0 },
    REQ_PLAIN },
  { "digest-nonce-bind-and-defaults",
    { 0, 0, 0, 0, 0, 0x20, 0, 0, 0, 0x3C, 0, 0, 0, 0,
      0x01 | 0x02 | 0x04, 0x11 },
    REQ_PLAIN },

  /* ---- suspend / resume ---- */
  { "suspend-immediate",
    { 0, 0x04, 0, 0, 0, 0x01, 0, 0, 0, 0, 0, 0, 0x10, 0, 0, 0 },
    REQ_PLAIN },
  { "suspend-deferred",
    { 0, 0x04, 0, 0, 0, 0x01, 0, 0, 0, 0, 0, 0, 0x20, 0, 0, 0 },
    REQ_PLAIN },
  { "suspend-deferred-two-connections",
    { 0, 0x04, 0, 0, 0, 0x01, 0, 0, 0, 0, 0, 0, 0x20 | 0x40, 0, 0, 0 },
    REQ_PLAIN },

  /* ---- the remaining flag bits ---- */
  { "turbo-itc-suppress-date",
    { 0, 0x02 | 0x10 | 0x20, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0 },
    REQ_PLAIN },
  { "allow-upgrade",
    { 0, 0x08, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0 },
    "GET / HTTP/1.1\r\nHost: x\r\nConnection: Upgrade\r\n"
    "Upgrade: fuzz-protocol\r\n\r\n" },
  { "no-thread-safety",
    { 0, 0, 0x10, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0 },
    REQ_PLAIN },
  { "tcp-fastopen-listen",
    { 0, 0, 0x01 | 0x08, 0, 0, 0, 0, 0, 0, 0, 0, 0x40, 0, 0, 0x08, 0 },
    REQ_PLAIN },
  { "sigpipe-handled-by-app",
    { 0, 0, 0, 0, 0x20, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0 },
    REQ_PLAIN },
  { "listen-socket-option-invalid-fd",
    { 0, 0, 0x01, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x20, 0 },
    REQ_PLAIN },

  /* ---- inputs whose daemon must not start ---- */
  /* Raw flag escape: MHD_USE_POLL together with MHD_USE_EPOLL. */
  { "raw-flags-poll-and-epoll",
    { 0, 0x40, 0xC0 | 0x02, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0 },
    REQ_PLAIN },
  /* Raw flag escape: MHD_USE_EPOLL with MHD_USE_THREAD_PER_CONNECTION. */
  { "raw-flags-epoll-thread-per-conn",
    { 0, 0x04 | 0x08, 0xC0 | 0x02, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0 },
    REQ_PLAIN },
  /* An option number MHD does not know. */
  { "invalid-option-number",
    { 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x40, 0 },
    REQ_PLAIN },
  /* MHD_OPTION_THREAD_POOL_SIZE without an internal polling thread. */
  { "thread-pool-without-threads",
    { 0, 0, 0, 0x20, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0 },
    REQ_PLAIN },

  /* ---- the handler behaviours ---- */
  { "handler-returns-no",
    { 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x04, 0, 0 },
    REQ_PLAIN },
  { "empty-and-copied-responses",
    { 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x01 | 0x08, 0, 0 },
    REQ_CHUNKED },
  { "error-response",
    { 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x03, 0, 0 },
    REQ_POST },

  /* ---- everything at once ---- */
  { "kitchen-sink-external",
    { 0, 0x02 | 0x04 | 0x10 | 0x20 | 0x40, 0x01,
      0x01 | 0x02 | 0x04 | 0x08 | 0x10 | 0x80,
      0x02 | 0x10 | 0x20 | 0x40 | 0x80,
      0x01 | 0x02 | 0x04 | 0x08 | 0x10 | 0x20,
      0x63, 0x45, 0x21, 0x13, 0x02, 0x0A,
      0x01 | 0x04 | 0x08 | 0x20, 0x08, 0x01 | 0x02 | 0x04 | 0x10, 0x33 },
    REQ_POST },
  { "kitchen-sink-thread-pool",
    { 18, 0x02 | 0x10 | 0x20 | 0x40, 0x01,
      0x01 | 0x04 | 0x08 | 0x10 | 0x20 | 0x40 | 0x80,
      0x01 | 0x02 | 0x80,
      0x01 | 0x02 | 0x04 | 0x08 | 0x10 | 0x20,
      0x03, 0x46, 0x39, 0x02, 0x00, 0x0A,
      0x04 | 0x08, 0x00, 0x01 | 0x08, 0x22 },
    REQ_CLOSE }
};

static uint8_t seed_render_buf[1024];


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

  b.p = seed_render_buf;
  b.len = 0;
  b.cap = sizeof (seed_render_buf);
  sb_raw (&b, sd->cfg, CFG_BYTES);
  if (NULL != sd->req)
  {
    size_t n = strlen (sd->req);
    unsigned int hv;
    uint8_t hdr[2];

    if (n > 0x3FFF)
      n = 0x3FFF;
    hv = (0u << 14) | (unsigned int) n;
    hdr[0] = (uint8_t) (hv & 0xFF);
    hdr[1] = (uint8_t) (hv >> 8);
    sb_raw (&b, hdr, 2);
    sb_raw (&b, sd->req, n);
  }
  *len = b.len;
  return seed_render_buf;
}
