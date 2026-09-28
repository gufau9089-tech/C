/*
     This file is part of GNU libmicrohttpd
     Copyright (C) 2026 Christian Grothoff

     GNU libmicrohttpd is free software; you can redistribute it and/or
     modify it under the terms of the GNU Lesser General Public
     License as published by the Free Software Foundation; either
     version 2.1 of the License, or (at your option) any later version.

     This library is distributed in the hope that it will be useful,
     but WITHOUT ANY WARRANTY; without even the implied warranty of
     MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
     Lesser General Public License for more details.

     You should have received a copy of the GNU Lesser General Public
     License along with GNU libmicrohttpd.
     If not, see <http://www.gnu.org/licenses/>.
*/

/**
 * @file testzzuf/mhd_zzuf_common.c
 * @brief  Shared support code for the fuzzing tests in this directory
 * @author Christian Grothoff
 */

#include "platform.h"
#include <curl/curl.h>
#include <microhttpd.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <errno.h>

#ifdef HAVE_NETINET_IN_H
#include <netinet/in.h>
#endif /* HAVE_NETINET_IN_H */
#ifdef HAVE_ARPA_INET_H
#include <arpa/inet.h>
#endif /* HAVE_ARPA_INET_H */
#ifdef HAVE_NETINET_TCP_H
#include <netinet/tcp.h>
#endif /* HAVE_NETINET_TCP_H */

#include "mhd_zzuf_common.h"
#include "mhd_debug_funcs.h"
#include "test_helpers.h"


int zzuf_run_with_socat;
int zzuf_dry_run;
int zzuf_oneone;
int zzuf_use_close;

const struct zzuf_opt_profile *zzuf_active_profile;

/**
 * The name of the running program, as given in argv[0].
 */
static const char *zzuf_prog_name = "";


/* ***  Platform abstraction for the raw socket client  *** */

#if defined(MHD_POSIX_SOCKETS)
#define ZZUF_CLOSE_SOCKET(s) close (s)
#define ZZUF_SOCK_ERR (errno)
#define ZZUF_ERR_IS_AGAIN(e) \
        ((EAGAIN == (e)) || (EWOULDBLOCK == (e)) || (EINTR == (e)))
#define ZZUF_ERR_IS_INPROGRESS(e) \
        ((EINPROGRESS == (e)) || (EALREADY == (e)) || ZZUF_ERR_IS_AGAIN (e))
#else  /* ! MHD_POSIX_SOCKETS */
#define ZZUF_CLOSE_SOCKET(s) closesocket (s)
#define ZZUF_SOCK_ERR ((int) WSAGetLastError ())
#define ZZUF_ERR_IS_AGAIN(e) (WSAEWOULDBLOCK == (e))
#define ZZUF_ERR_IS_INPROGRESS(e) \
        ((WSAEWOULDBLOCK == (e)) || (WSAEINPROGRESS == (e)) || \
         (WSAEALREADY == (e)))
#endif /* ! MHD_POSIX_SOCKETS */

#ifdef MSG_NOSIGNAL
#define ZZUF_SEND_FLAGS MSG_NOSIGNAL
#else  /* ! MSG_NOSIGNAL */
#define ZZUF_SEND_FLAGS 0
#endif /* ! MSG_NOSIGNAL */


void
zzuf_parse_common_args (int argc, char *const *argv)
{
  const char *name;

  name = (NULL != argv[0]) ? argv[0] : "";
  zzuf_prog_name = name;
  zzuf_oneone = ! has_in_name (name, "10");
  zzuf_use_close = has_in_name (name, "_close");
  zzuf_run_with_socat = has_param (argc, argv, "--with-socat");
  zzuf_dry_run = has_param (argc, argv, "--dry-run") ||
                 has_param (argc, argv, "-n");
#ifdef SIGPIPE
  /* The raw client writes to sockets that MHD may close at any moment
     because of the fuzzed input.  Do not die from SIGPIPE. */
  (void) signal (SIGPIPE, SIG_IGN);
#endif /* SIGPIPE */
}


int
zzuf_name_has (const char *marker)
{
  return has_in_name (zzuf_prog_name, marker);
}


unsigned int
zzuf_loop_count (void)
{
  return zzuf_dry_run ? 0 : (unsigned int) ZZUF_LOOP_COUNT;
}


/* ***  The option matrix  *** */

/**
 * The matrix of daemon options exercised by the fuzzing tests.
 *
 * Entry zero must stay "neutral": it reproduces the configuration that was
 * used before the option matrix was introduced.
 *
 * The memory limits below 1500 (MHD_BUF_INC_SIZE) are the interesting ones:
 * only with such a small connection pool MHD tries to re-use the tail of the
 * request header buffer ("shift back"), and only then the buffer arithmetic
 * around the last parsed header/argument element is reachable at all.
 *
 * #MHD_OPTION_SERVER_INSANITY is deliberately *not* used: in this MHD version
 * the only value of `enum MHD_DisableSanityCheck` is #MHD_DSC_SANE (zero), so
 * the option cannot disable anything and setting it would be a no-op.
 *
 */
static const struct zzuf_opt_profile opt_profiles[] = {
  /* name             mem  conn timeout discipline legacy */
  { "plain",            0,   0, ZZUF_MHD_TIMEOUT,      0, 0 },
  { "pool-128",       128,   0, ZZUF_MHD_TIMEOUT,      0, 0 },
  { "pool-256-strict", 256,  0, ZZUF_MHD_TIMEOUT,      1, 0 },
  { "pool-512-lax",    512,  0, ZZUF_MHD_TIMEOUT,     -1, 0 },
  { "pool-1024-conn",  1024, 4, ZZUF_MHD_TIMEOUT,      2, 0 },
  { "pool-1400-hard",  1400, 2, 1,                     3, 0 },
  { "pool-768-loose",   768, 0, 1,                    -3, 0 },
  { "legacy-strict",    192, 0, ZZUF_MHD_TIMEOUT,      1, 1 },
  { "legacy-lax",       320, 0, ZZUF_MHD_TIMEOUT,     -1, 1 }
};


unsigned int
zzuf_num_opt_profiles (void)
{
  return (unsigned int) (sizeof(opt_profiles) / sizeof(opt_profiles[0]));
}


const struct zzuf_opt_profile *
zzuf_opt_profile (unsigned int idx)
{
  return opt_profiles + (idx % zzuf_num_opt_profiles ());
}


/* ***  Daemon handling  *** */

uint16_t
zzuf_pick_port (uint16_t offset)
{
  if (zzuf_run_with_socat)
    return (uint16_t) ZZUF_BASE_PORT; /* socat forwards to this fixed port */
  if (MHD_NO != MHD_is_feature_supported (MHD_FEATURE_AUTODETECT_BIND_PORT))
    return 0;                         /* Use system automatic assignment */
  /* Use a predefined port; may break parallel testing of another MHD build */
  return (uint16_t) (ZZUF_BASE_PORT + offset + (zzuf_oneone ? 100 : 0));
}


struct MHD_Daemon *
zzuf_start_daemon (unsigned int daemon_flags,
                   uint16_t *pport,
                   const struct zzuf_opt_profile *prof,
                   size_t mem_limit_override,
                   MHD_AccessHandlerCallback ahc,
                   void *ahc_cls,
                   MHD_RequestCompletedCallback rcc,
                   void *rcc_cls,
                   const struct MHD_OptionItem *extra_opts)
{
  struct MHD_Daemon *d;
  struct MHD_OptionItem ops[16];
  size_t num_opt;
  size_t mem_limit;

  num_opt = 0;
  mem_limit = (0 != mem_limit_override) ? mem_limit_override : prof->mem_limit;
  if (0 != mem_limit)
  {
    ops[num_opt].option = MHD_OPTION_CONNECTION_MEMORY_LIMIT;
    ops[num_opt].value = (intptr_t) mem_limit;
    ops[num_opt].ptr_value = NULL;
    ++num_opt;
  }
  if (0 != prof->conn_limit)
  {
    ops[num_opt].option = MHD_OPTION_CONNECTION_LIMIT;
    ops[num_opt].value = (intptr_t) prof->conn_limit;
    ops[num_opt].ptr_value = NULL;
    ++num_opt;
  }
  if (0 != prof->discipline_lvl)
  {
    ops[num_opt].option = prof->use_legacy_strict ?
                          MHD_OPTION_STRICT_FOR_CLIENT :
                          MHD_OPTION_CLIENT_DISCIPLINE_LVL;
    ops[num_opt].value = (intptr_t) prof->discipline_lvl;
    ops[num_opt].ptr_value = NULL;
    ++num_opt;
  }
  if (0 == (MHD_USE_INTERNAL_POLLING_THREAD & daemon_flags))
  {
    ops[num_opt].option = MHD_OPTION_APP_FD_SETSIZE;
    ops[num_opt].value = (intptr_t) (FD_SETSIZE);
    ops[num_opt].ptr_value = NULL;
    ++num_opt;
  }
  if (NULL != rcc)
  {
    ops[num_opt].option = MHD_OPTION_NOTIFY_COMPLETED;
    ops[num_opt].value = (intptr_t) rcc;
    ops[num_opt].ptr_value = rcc_cls;
    ++num_opt;
  }
  if (NULL != extra_opts)
  {
    size_t i;

    for (i = 0; MHD_OPTION_END != extra_opts[i].option; ++i)
    {
      if (num_opt + 2 > sizeof(ops) / sizeof(ops[0]))
      {
        fprintf (stderr, "Too many daemon options at line %d.\n",
                 (int) __LINE__);
        fflush (stderr);
        abort (); /* Broken test code */
      }
      ops[num_opt++] = extra_opts[i];
    }
  }
  if (num_opt + 1 > sizeof(ops) / sizeof(ops[0]))
  {
    fprintf (stderr, "Too many daemon options at line %d.\n", (int) __LINE__);
    fflush (stderr);
    abort (); /* Broken test code */
  }
  ops[num_opt].option = MHD_OPTION_END;
  ops[num_opt].value = 0;
  ops[num_opt].ptr_value = NULL;
  ++num_opt;

  d = MHD_start_daemon (daemon_flags /* | MHD_USE_ERROR_LOG */,
                        *pport, NULL, NULL,
                        ahc, ahc_cls,
                        MHD_OPTION_CONNECTION_TIMEOUT,
                        (unsigned int) prof->timeout,
                        MHD_OPTION_ARRAY, ops,
                        MHD_OPTION_END);
  if (NULL == d)
  {
    fprintf (stderr, "MHD_start_daemon() failed "
             "at line %d.\n", (int) __LINE__);
    return NULL;
  }

  /* Do not use accept4() as only accept() is intercepted by zzuf */
  if (! zzuf_run_with_socat)
    MHD_avoid_accept4_ (d);

  if (0 == *pport)
  {
    const union MHD_DaemonInfo *dinfo;

    dinfo = MHD_get_daemon_info (d, MHD_DAEMON_INFO_BIND_PORT);
    if ((NULL == dinfo) || (0 == dinfo->port))
    {
      fprintf (stderr, "MHD_get_daemon_info() failed "
               "at line %d.\n", (int) __LINE__);
      MHD_stop_daemon (d);
      return NULL;
    }
    *pport = dinfo->port;
  }
  return d;
}


/**
 * Print a description of the daemon that is about to be tested.
 *
 * @param daemon_flags the daemon flags
 * @param prof the option profile in use
 */
static void
print_test_starting (unsigned int daemon_flags,
                     const struct zzuf_opt_profile *prof)
{
  const char *mode;

  fflush (stderr);
  if (0 != (MHD_USE_INTERNAL_POLLING_THREAD & daemon_flags))
  {
    if (0 != (MHD_USE_THREAD_PER_CONNECTION & daemon_flags))
      mode = (0 != (MHD_USE_POLL & daemon_flags)) ?
             "internal poll(), thread-per-connection" :
             "internal select(), thread-per-connection";
    else if (0 != (MHD_USE_POLL & daemon_flags))
      mode = "internal poll()";
    else if (0 != (MHD_USE_EPOLL & daemon_flags))
      mode = "internal 'epoll'";
    else
      mode = "internal select()";
  }
  else
  {
    if (0 != (MHD_USE_NO_THREAD_SAFETY & daemon_flags))
      mode = "external polling, no thread safety";
    else
      mode = "external polling";
  }
  printf ("\nStarting test with %s; options profile '%s' "
          "(mem_limit=%lu, conn_limit=%u, timeout=%u, %s=%d).\n",
          mode, prof->name,
          (unsigned long) prof->mem_limit,
          prof->conn_limit,
          prof->timeout,
          prof->use_legacy_strict ? "strict_for_client" : "discipline_lvl",
          prof->discipline_lvl);
  fflush (stdout);
}


/**
 * Run a single check: start a daemon, run the client, stop the daemon.
 *
 * @param[in,out] p the parameters
 * @param daemon_flags the flags for the daemon
 * @param[in,out] pprofile_num the number of the next profile to use
 * @return the result of the client callback, or 1 if the daemon could not
 *         be started
 */
static unsigned int
run_one_mode (struct zzuf_run_params *p,
              unsigned int daemon_flags,
              unsigned int *pprofile_num)
{
  struct MHD_Daemon *d;
  const struct zzuf_opt_profile *prof;
  unsigned int ret;

  if (p->sweep_profiles)
    prof = zzuf_opt_profile ((*pprofile_num)++);
  else
    prof = zzuf_opt_profile (0);
  zzuf_active_profile = prof;
  print_test_starting (daemon_flags, prof);
  d = zzuf_start_daemon (daemon_flags, &p->port, prof, p->mem_limit_override,
                         p->ahc, p->ahc_cls, p->rcc, p->rcc_cls,
                         p->extra_opts);
  if (NULL == d)
    return 1;
  ret = p->client ((0 == (MHD_USE_INTERNAL_POLLING_THREAD & daemon_flags)) ?
                   d : NULL,
                   p->port,
                   p->client_cls);
  fprintf (stderr, "\n");
  MHD_stop_daemon (d);
  fflush (stderr);
  return ret;
}


unsigned int
zzuf_check_runnable (void)
{
  if (zzuf_run_with_socat)
    return 0;
  if (MHD_are_sanitizers_enabled_ ())
  {
    fprintf (stderr, "Direct run with zzuf does not work with sanitizers. "
             "At line %d.\n", (int) __LINE__);
    return 77;
  }
  if (! MHD_is_avoid_accept4_possible_ ())
  {
    fprintf (stderr,
             "Non-debug build of MHD on this platform use accept4() function. "
             "Direct run with zzuf is not possible. "
             "At line %d.\n", (int) __LINE__);
    return 77;
  }
  return 0;
}


unsigned int
zzuf_run_polling_modes (struct zzuf_run_params *p)
{
  unsigned int profile_num = p->profile_start;
  unsigned int testRes;
  unsigned int ret = 0;

  if (! zzuf_dry_run &&
      (MHD_YES == MHD_is_feature_supported (MHD_FEATURE_THREADS)))
  {
    testRes = run_one_mode (p, MHD_USE_SELECT_INTERNALLY, &profile_num);
    if ((77 == testRes) || (99 == testRes))
      return testRes;
    ret += testRes;
    testRes = run_one_mode (p, MHD_USE_SELECT_INTERNALLY
                            | MHD_USE_THREAD_PER_CONNECTION, &profile_num);
    if ((77 == testRes) || (99 == testRes))
      return testRes;
    ret += testRes;

    if (MHD_YES == MHD_is_feature_supported (MHD_FEATURE_POLL))
    {
      testRes = run_one_mode (p, MHD_USE_POLL_INTERNALLY, &profile_num);
      if ((77 == testRes) || (99 == testRes))
        return testRes;
      ret += testRes;
      testRes = run_one_mode (p, MHD_USE_POLL_INTERNALLY
                              | MHD_USE_THREAD_PER_CONNECTION, &profile_num);
      if ((77 == testRes) || (99 == testRes))
        return testRes;
      ret += testRes;
    }

    if (MHD_YES == MHD_is_feature_supported (MHD_FEATURE_EPOLL))
    {
      testRes = run_one_mode (p, MHD_USE_EPOLL_INTERNALLY, &profile_num);
      if ((77 == testRes) || (99 == testRes))
        return testRes;
      ret += testRes;
    }

    testRes = run_one_mode (p, MHD_NO_FLAG, &profile_num);
    if ((77 == testRes) || (99 == testRes))
      return testRes;
    ret += testRes;
  }
  testRes = run_one_mode (p, MHD_USE_NO_THREAD_SAFETY, &profile_num);
  if ((77 == testRes) || (99 == testRes))
    return testRes;
  ret += testRes;

  return ret;
}


/* ***  The raw socket client  *** */

/**
 * Switch the socket to the non-blocking mode.
 *
 * @param fd the socket to modify
 * @return non-zero on success, zero on failure
 */
static int
set_nonblocking (MHD_socket fd)
{
#if defined(MHD_POSIX_SOCKETS)
  int flags;

  flags = fcntl (fd, F_GETFL);
  if (-1 == flags)
    return 0;
  if (0 != (flags & O_NONBLOCK))
    return ! 0;
  return (-1 != fcntl (fd, F_SETFL, flags | O_NONBLOCK)) ? ! 0 : 0;
#else  /* ! MHD_POSIX_SOCKETS */
  unsigned long mode = 1;

  return (0 == ioctlsocket (fd, FIONBIO, &mode)) ? ! 0 : 0;
#endif /* ! MHD_POSIX_SOCKETS */
}


/**
 * Create the client socket and start connecting to the daemon.
 *
 * @param port the port MHD is listening on (ignored if socat is used)
 * @return the socket, or #MHD_INVALID_SOCKET on failure
 */
static MHD_socket
raw_connect (uint16_t port, int bypass_relay)
{
  MHD_socket fd;
  struct sockaddr_in sa;
  const char *dst_ip;
  uint16_t dst_port;
  int on = 1;

  if (zzuf_run_with_socat && ! bypass_relay)
  {
    dst_ip = ZZUF_SOCAT_IP;
    dst_port = (uint16_t) ZZUF_SOCAT_PORT;
  }
  else
  {
    dst_ip = ZZUF_MHD_LISTEN_IP;
    dst_port = port;
  }

  fd = socket (AF_INET, SOCK_STREAM, IPPROTO_TCP);
  if (MHD_INVALID_SOCKET == fd)
    return MHD_INVALID_SOCKET;
  (void) setsockopt (fd, SOL_SOCKET, SO_REUSEADDR,
                     (const void *) &on, (socklen_t) sizeof(on));
  /* Use the same source address as libcurl does in the other tests, so that
     zzuf treats the traffic of this client exactly like libcurl's traffic. */
  memset (&sa, 0, sizeof(sa));
  sa.sin_family = AF_INET;
  sa.sin_port = 0;
  sa.sin_addr.s_addr = inet_addr (ZZUF_CLIENT_BIND_IP);
  /* Best effort only: some platforms do not have the whole 127.0.0.0/8
     range available. */
  (void) bind (fd, (const struct sockaddr *) &sa, (socklen_t) sizeof(sa));

  if (! set_nonblocking (fd))
  {
    (void) ZZUF_CLOSE_SOCKET (fd);
    return MHD_INVALID_SOCKET;
  }

  memset (&sa, 0, sizeof(sa));
  sa.sin_family = AF_INET;
  sa.sin_port = htons (dst_port);
  sa.sin_addr.s_addr = inet_addr (dst_ip);
  if (0 != connect (fd, (const struct sockaddr *) &sa, (socklen_t) sizeof(sa)))
  {
    const int err = ZZUF_SOCK_ERR;
    if (! ZZUF_ERR_IS_INPROGRESS (err))
    {
      (void) ZZUF_CLOSE_SOCKET (fd);
      return MHD_INVALID_SOCKET;
    }
  }
  return fd;
}


int
zzuf_raw_exchange2 (struct MHD_Daemon *d_extern,
                    uint16_t port,
                    int bypass_relay,
                    const struct zzuf_raw_part *parts,
                    size_t num_parts,
                    unsigned int timeout_sec,
                    char *resp_buf,
                    size_t resp_buf_size,
                    size_t *resp_len)
{
  MHD_socket fd;
  size_t cur_part = 0;
  size_t cur_off = 0;
  size_t resp_pos = 0;
  int send_done = 0;
  int peer_closed = 0;
  time_t start;
  char rbuf[1024];

  if (NULL != resp_len)
    *resp_len = 0;
  fd = raw_connect (port, bypass_relay);
  if (MHD_INVALID_SOCKET == fd)
    return ZZUF_RAW_SETUP_FAILED;

  if (0 == num_parts)
    send_done = 1;

  start = time (NULL);
  while (1)
  {
    fd_set rs;
    fd_set ws;
    fd_set es;
    struct timeval tv;
    int maxfd;
    MHD_socket maxfd_mhd = MHD_INVALID_SOCKET;

    if (send_done && peer_closed)
      break;
    if (((time_t) timeout_sec) < (time (NULL) - start))
      break; /* The peer did not close the connection in time */

    FD_ZERO (&rs);
    FD_ZERO (&ws);
    FD_ZERO (&es);
#if defined(MHD_POSIX_SOCKETS)
    if (FD_SETSIZE <= (int) fd)
    {
      (void) ZZUF_CLOSE_SOCKET (fd);
      return ZZUF_RAW_SETUP_FAILED;
    }
#endif /* MHD_POSIX_SOCKETS */
    if (! peer_closed)
      FD_SET (fd, &rs);
    if (! send_done)
      FD_SET (fd, &ws);
    maxfd = (int) fd;
    if (NULL != d_extern)
    {
      if (MHD_YES != MHD_get_fdset (d_extern, &rs, &ws, &es, &maxfd_mhd))
      {
        fprintf (stderr, "MHD_get_fdset() failed "
                 "at line %d.\n", (int) __LINE__);
        (void) ZZUF_CLOSE_SOCKET (fd);
        return ZZUF_RAW_SETUP_FAILED;
      }
#ifndef MHD_WINSOCK_SOCKETS
      if ((int) maxfd_mhd > maxfd)
        maxfd = (int) maxfd_mhd;
#endif /* ! MHD_WINSOCK_SOCKETS */
    }
    tv.tv_sec = 0;
    tv.tv_usec = 25 * 1000;
    if (-1 == select (maxfd + 1, &rs, &ws, &es, &tv))
    {
#if defined(MHD_POSIX_SOCKETS)
      if (EINTR != errno)
        fprintf (stderr, "Unexpected select() error "
                 "at line %d.\n", (int) __LINE__);
#endif /* MHD_POSIX_SOCKETS */
    }
    if (NULL != d_extern)
      MHD_run (d_extern);

    if (! send_done)
    {
      ssize_t res;

      res = (ssize_t) send (fd,
                            (const void *) (parts[cur_part].data + cur_off),
                            parts[cur_part].size - cur_off,
                            ZZUF_SEND_FLAGS);
      if (0 > res)
      {
        const int err = ZZUF_SOCK_ERR;
        if (! ZZUF_ERR_IS_AGAIN (err))
        {
          /* MHD (or socat) closed the connection: a perfectly normal
             outcome when the traffic is being fuzzed. */
          send_done = 1;
          peer_closed = 1;
        }
      }
      else
      {
        cur_off += (size_t) res;
        if (cur_off >= parts[cur_part].size)
        {
          cur_off = 0;
          if (++cur_part >= num_parts)
            send_done = 1;
        }
      }
    }

    if (! peer_closed)
    {
      ssize_t res;

      res = (ssize_t) recv (fd, rbuf, sizeof(rbuf), 0);
      if (0 == res)
        peer_closed = 1;
      else if (0 > res)
      {
        const int err = ZZUF_SOCK_ERR;
        if (! ZZUF_ERR_IS_AGAIN (err))
          peer_closed = 1;
      }
      else if ((NULL != resp_buf) && (resp_pos < resp_buf_size))
      {
        size_t to_copy = (size_t) res;
        if (to_copy > resp_buf_size - resp_pos)
          to_copy = resp_buf_size - resp_pos;
        memcpy (resp_buf + resp_pos, rbuf, to_copy);
        resp_pos += to_copy;
        if (NULL != resp_len)
          *resp_len = resp_pos;
      }
    }
  }
  (void) ZZUF_CLOSE_SOCKET (fd);

  if (NULL != d_extern)
  {
    /* Give MHD a chance to notice the closed connection and to clean up. */
    unsigned int i;
    for (i = 0; i < 10; ++i)
      MHD_run (d_extern);
  }
  return ZZUF_RAW_OK;
}


int
zzuf_raw_exchange (struct MHD_Daemon *d_extern,
                   uint16_t port,
                   const struct zzuf_raw_part *parts,
                   size_t num_parts,
                   unsigned int timeout_sec)
{
  return zzuf_raw_exchange2 (d_extern, port, 0, parts, num_parts, timeout_sec,
                             NULL, 0, NULL);
}


int
zzuf_raw_request (struct MHD_Daemon *d_extern,
                  uint16_t port,
                  const char *request)
{
  struct zzuf_raw_part part;

  part.data = request;
  part.size = strlen (request);
  return zzuf_raw_exchange (d_extern, port, &part, 1,
                            (unsigned int) ZZUF_CLIENT_TIMEOUT);
}


/* ***  libcurl helpers  *** */

#ifndef CURL_VERSION_BITS
#define CURL_VERSION_BITS(x,y,z) ((x) << 16 | (y) << 8 | (z))
#endif /* ! CURL_VERSION_BITS */
#ifndef CURL_AT_LEAST_VERSION
#define CURL_AT_LEAST_VERSION(x,y,z) \
        (LIBCURL_VERSION_NUM >= CURL_VERSION_BITS (x, y, z))
#endif /* ! CURL_AT_LEAST_VERSION */

#define ZZUF_CURL_HOST "http:/" "/" ZZUF_MHD_LISTEN_IP
#define ZZUF_CURL_HOST_SOCAT "http:/" "/" ZZUF_SOCAT_IP


/**
 * The libcurl write callback: discards the data.
 *
 * @param ptr the received data
 * @param size the size of the item
 * @param nmemb the number of items
 * @param ctx the sink
 * @return the number of processed bytes
 */
static size_t
curl_sink_cb (void *ptr, size_t size, size_t nmemb, void *ctx)
{
  struct zzuf_curl_sink *sink = (struct zzuf_curl_sink *) ctx;

  (void) ptr; /* Unused. Mute compiler warning. */
  if (sink->dn_pos + size * nmemb > sizeof(sink->buf))
    return 0;   /* Overflow, abort the transfer */
  memcpy (sink->buf + sink->dn_pos, ptr, size * nmemb);
  sink->dn_pos += size * nmemb;
  return size * nmemb;
}


CURL *
zzuf_curl_setup (uint16_t port,
                 const char *uri_tail,
                 struct zzuf_curl_sink *sink)
{
  CURL *c;
  CURLcode e;
  char *uri;
  size_t host_len;
  size_t tail_len;
  const char *host;

  host = zzuf_run_with_socat ? ZZUF_CURL_HOST_SOCAT : ZZUF_CURL_HOST;
  if (zzuf_run_with_socat)
    port = (uint16_t) ZZUF_SOCAT_PORT;
  host_len = strlen (host);
  tail_len = strlen (uri_tail);
  uri = malloc (host_len + tail_len + 1);
  if (NULL == uri)
  {
    fprintf (stderr, "malloc() failed at line %d.\n", (int) __LINE__);
    return NULL;
  }
  memcpy (uri, host, host_len);
  memcpy (uri + host_len, uri_tail, tail_len + 1);

  sink->dn_pos = 0;
  c = curl_easy_init ();
  if (NULL == c)
  {
    fprintf (stderr, "curl_easy_init() failed at line %d.\n", (int) __LINE__);
    free (uri);
    return NULL;
  }
  if ((CURLE_OK == (e = curl_easy_setopt (c, CURLOPT_URL, uri))) &&
      (CURLE_OK == (e = curl_easy_setopt (c, CURLOPT_NOSIGNAL, 1L))) &&
      (CURLE_OK == (e = curl_easy_setopt (c, CURLOPT_WRITEFUNCTION,
                                          &curl_sink_cb))) &&
      (CURLE_OK == (e = curl_easy_setopt (c, CURLOPT_WRITEDATA, sink))) &&
      (CURLE_OK == (e = curl_easy_setopt (c, CURLOPT_CONNECTTIMEOUT,
                                          ((long) ZZUF_CLIENT_TIMEOUT)))) &&
      (CURLE_OK == (e = curl_easy_setopt (c, CURLOPT_TIMEOUT,
                                          ((long) ZZUF_CLIENT_TIMEOUT)))) &&
      (CURLE_OK == (e = curl_easy_setopt (c, CURLOPT_FAILONERROR, 0L))) &&
#if CURL_AT_LEAST_VERSION (7, 45, 0)
      (CURLE_OK == (e = curl_easy_setopt (c, CURLOPT_DEFAULT_PROTOCOL,
                                          "http"))) &&
#endif /* CURL_AT_LEAST_VERSION (7, 45, 0) */
#if CURL_AT_LEAST_VERSION (7, 85, 0)
      (CURLE_OK == (e = curl_easy_setopt (c, CURLOPT_PROTOCOLS_STR,
                                          "http"))) &&
#elif CURL_AT_LEAST_VERSION (7, 19, 4)
      (CURLE_OK == (e = curl_easy_setopt (c, CURLOPT_PROTOCOLS,
                                          CURLPROTO_HTTP))) &&
#endif /* CURL_AT_LEAST_VERSION (7, 19, 4) */
      (CURLE_OK == (e = curl_easy_setopt (c, CURLOPT_HTTP_VERSION,
                                          zzuf_oneone ?
                                          CURL_HTTP_VERSION_1_1 :
                                          CURL_HTTP_VERSION_1_0))) &&
#if CURL_AT_LEAST_VERSION (7, 24, 0)
      (CURLE_OK == (e = curl_easy_setopt (c, CURLOPT_INTERFACE,
                                          "host!" ZZUF_CLIENT_BIND_IP))) &&
#else  /* ! CURL_AT_LEAST_VERSION (7, 24, 0) */
      (CURLE_OK == (e = curl_easy_setopt (c, CURLOPT_INTERFACE,
                                          ZZUF_CLIENT_BIND_IP))) &&
#endif /* ! CURL_AT_LEAST_VERSION (7, 24, 0) */
      (CURLE_OK == (e = curl_easy_setopt (c, CURLOPT_PORT, ((long) port)))))
  {
    free (uri);
    return c; /* Success exit point */
  }
  fprintf (stderr, "curl_easy_setopt() failed at line %d, error: %s\n",
           (int) __LINE__, curl_easy_strerror (e));
  curl_easy_cleanup (c);
  free (uri);
  return NULL; /* Failure exit point */
}


int
zzuf_curl_driver_init (struct zzuf_curl_driver *drv,
                       struct MHD_Daemon *d_extern)
{
  drv->d_extern = d_extern;
  drv->multi = NULL;
  if (NULL == d_extern)
    return ! 0;
  drv->multi = curl_multi_init ();
  if (NULL == drv->multi)
  {
    fprintf (stderr, "curl_multi_init() failed at line %d.\n", (int) __LINE__);
    return 0;
  }
  return ! 0;
}


void
zzuf_curl_driver_deinit (struct zzuf_curl_driver *drv)
{
  if (NULL != drv->multi)
    curl_multi_cleanup (drv->multi);
  drv->multi = NULL;
  drv->d_extern = NULL;
}


void
zzuf_curl_driver_perform (struct zzuf_curl_driver *drv,
                          CURL *c)
{
  CURLMcode mret;
  time_t start;

  if (NULL == drv->d_extern)
  {
    /* The daemon has an internal polling thread, just run the transfer. */
    (void) curl_easy_perform (c);
    return;
  }
  mret = curl_multi_add_handle (drv->multi, c);
  if (CURLM_OK != mret)
  {
    fprintf (stderr, "curl_multi_add_handle() failed at line %d, error: %s\n",
             (int) __LINE__, curl_multi_strerror (mret));
    return;
  }
  start = time (NULL);
  do
  {
    fd_set rs;
    fd_set ws;
    fd_set es;
    int maxfd_curl;
    MHD_socket maxfd_mhd;
    int maxfd;
    int running;
    struct timeval tv;

    maxfd_curl = 0;
    maxfd_mhd = MHD_INVALID_SOCKET;
    FD_ZERO (&rs);
    FD_ZERO (&ws);
    FD_ZERO (&es);
    curl_multi_perform (drv->multi, &running);
    if (0 == running)
    {
      int msgs_left;
      do
      {
        (void) curl_multi_info_read (drv->multi, &msgs_left);
      } while (0 != msgs_left);
      break; /* The transfer has been finished */
    }
    mret = curl_multi_fdset (drv->multi, &rs, &ws, &es, &maxfd_curl);
    if (CURLM_OK != mret)
    {
      fprintf (stderr, "curl_multi_fdset() failed at line %d, error: %s\n",
               (int) __LINE__, curl_multi_strerror (mret));
      break;
    }
    if (MHD_YES != MHD_get_fdset (drv->d_extern, &rs, &ws, &es, &maxfd_mhd))
    {
      fprintf (stderr, "MHD_get_fdset() failed at line %d.\n", (int) __LINE__);
      break;
    }
#ifndef MHD_WINSOCK_SOCKETS
    if ((int) maxfd_mhd > maxfd_curl)
      maxfd = (int) maxfd_mhd;
    else
#endif /* ! MHD_WINSOCK_SOCKETS */
    maxfd = maxfd_curl;
    tv.tv_sec = 0;
    tv.tv_usec = 25 * 1000;
    if (0 == MHD_get_timeout64s (drv->d_extern))
      tv.tv_usec = 0;
    else
    {
      long curl_to = -1;
      curl_multi_timeout (drv->multi, &curl_to);
      if (0 == curl_to)
        tv.tv_usec = 0;
    }
    if (-1 == select (maxfd + 1, &rs, &ws, &es, &tv))
    {
#if defined(MHD_POSIX_SOCKETS)
      if (EINTR != errno)
        fprintf (stderr, "Unexpected select() error at line %d.\n",
                 (int) __LINE__);
#else  /* ! MHD_POSIX_SOCKETS */
      if ((WSAEINVAL != WSAGetLastError ()) ||
          (0 != rs.fd_count) || (0 != ws.fd_count) || (0 != es.fd_count))
        fprintf (stderr, "Unexpected select() error at line %d.\n",
                 (int) __LINE__);
      Sleep ((unsigned long) tv.tv_usec / 1000);
#endif /* ! MHD_POSIX_SOCKETS */
    }
    MHD_run (drv->d_extern);
  } while (time (NULL) - start <= (time_t) ZZUF_CLIENT_TIMEOUT);
  curl_multi_remove_handle (drv->multi, c);
}
