/*
     This file is part of libmicrohttpd
     Copyright (C) 2026 Christian Grothoff (and other contributing authors)

     This library is free software; you can redistribute it and/or
     modify it under the terms of the GNU Lesser General Public
     License as published by the Free Software Foundation; either
     version 2.1 of the License, or (at your option) any later version.

     This library is distributed in the hope that it will be useful,
     but WITHOUT ANY WARRANTY; without even the implied warranty of
     MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
     Lesser General Public License for more details.

     You should have received a copy of the GNU Lesser General Public
     License along with this library; if not, write to the Free Software
     Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301  USA
*/
/**
 * @file test_suspend_resume_epoll.c
 * @brief Test for the suspend_resume_epoll example.  The example itself
 *        is started as a child process and then driven over HTTP, so
 *        what is tested is exactly the code that ships as the example.
 *
 *        The example parks every request for one second on a timerfd
 *        that lives in the application's own epoll set, next to the
 *        daemon's epoll FD.  Checking that the right bytes come back is
 *        the easy part; the checks that matter are that the process
 *        burns no CPU while a connection is suspended, and that two
 *        requests are parked at the same time rather than one after the
 *        other.  Both would still deliver identical bytes if suspending
 *        were broken.
 * @author Christian Grothoff
 */

#include <sys/types.h>
#include <sys/socket.h>
#include <sys/wait.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <curl/curl.h>
#include <errno.h>
#include <signal.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

/**
 * How long the example parks a request, in milliseconds.  This is the
 * one-second timer hard-coded in suspend_resume_epoll.c.
 */
#define PARK_MS 1000

/**
 * Upper bound for any single request, in seconds.
 */
#define REQUEST_TIMEOUT 30

/**
 * How long to wait for the freshly started example to answer, in
 * milliseconds.
 */
#define STARTUP_TIMEOUT_MS 5000

/**
 * How often to retry with a different port if the one we picked turned
 * out to be taken after all.
 */
#define PORT_ATTEMPTS 5

/**
 * Largest response body we are prepared to keep.
 */
#define MAX_BODY 4096


/**
 * What one HTTP request collected.
 */
struct Fetch
{
  /**
   * The body, as far as it was received.
   */
  char body[MAX_BODY];

  /**
   * Number of valid bytes in @e body.
   */
  size_t len;

  /**
   * Result of the transfer.
   */
  CURLcode res;
};


/**
 * The example's process ID, or -1 once it has been reaped.
 */
static pid_t server_pid = -1;

/**
 * The port the example was told to bind.
 */
static unsigned int server_port;

/**
 * Number of checks that failed.
 */
static unsigned int failures;


/**
 * Report the outcome of one check.
 *
 * @param ok non-zero if the check passed
 * @param what what was being checked
 */
static void
check (int ok,
       const char *what)
{
  if (! ok)
    failures++;
  fprintf (stderr,
           "%s: %s\n",
           ok ? "PASS" : "FAIL",
           what);
}


/**
 * @return the current value of the monotonic clock, in milliseconds
 */
static long
now_ms (void)
{
  struct timespec ts;

  if (0 != clock_gettime (CLOCK_MONOTONIC,
                          &ts))
    return 0;
  return (long) ts.tv_sec * 1000 + ts.tv_nsec / 1000000;
}


/**
 * Read the CPU time consumed by process @a pid so far.  Only
 * implemented for Linux; everywhere else the test simply skips the
 * check that uses it.
 *
 * @param pid the process to look at
 * @param[out] ms where to store the sum of user and system time in
 *             milliseconds
 * @return non-zero on success
 */
static int
cpu_time_ms (pid_t pid,
             long *ms)
{
#ifdef __linux__
  char path[64];
  char buf[1024];
  char *p;
  FILE *f;
  size_t got;
  unsigned long utime;
  unsigned long stime;
  long ticks;

  snprintf (path,
            sizeof (path),
            "/proc/%ld/stat",
            (long) pid);
  f = fopen (path,
             "r");
  if (NULL == f)
    return 0;
  got = fread (buf,
               1,
               sizeof (buf) - 1,
               f);
  fclose (f);
  if (0 == got)
    return 0;
  buf[got] = '\0';
  /* The second field is the executable name and may contain spaces and
     parentheses, so start parsing behind its closing one. */
  p = strrchr (buf,
               ')');
  if (NULL == p)
    return 0;
  if (2 != sscanf (p + 1,
                   " %*c %*d %*d %*d %*d %*d %*u %*u %*u %*u %*u %lu %lu",
                   &utime,
                   &stime))
    return 0;
  ticks = sysconf (_SC_CLK_TCK);
  if (0 >= ticks)
    return 0;
  *ms = (long) ((utime + stime) * 1000 / (unsigned long) ticks);
  return 1;
#else
  (void) pid;
  (void) ms;
  return 0;
#endif
}


static size_t
write_cb (void *ptr,
          size_t size,
          size_t nmemb,
          void *cls)
{
  struct Fetch *f = cls;
  size_t total = size * nmemb;

  if (total > sizeof (f->body) - f->len - 1)
    total = sizeof (f->body) - f->len - 1;
  memcpy (&f->body[f->len],
          ptr,
          total);
  f->len += total;
  f->body[f->len] = '\0';
  return size * nmemb;
}


/**
 * Create an easy handle that will GET @a path from the example.
 *
 * @param path the path to request
 * @param[out] f where to store what is received; cleared here
 * @return the handle, or NULL on error
 */
static CURL *
make_handle (const char *path,
             struct Fetch *f)
{
  CURL *curl;
  char url[128];

  memset (f,
          0,
          sizeof (struct Fetch));
  f->res = CURLE_FAILED_INIT;
  snprintf (url,
            sizeof (url),
            "http://127.0.0.1:%u%s",
            server_port,
            path);
  curl = curl_easy_init ();
  if (NULL == curl)
    return NULL;
  curl_easy_setopt (curl, CURLOPT_URL, url);
  curl_easy_setopt (curl, CURLOPT_WRITEFUNCTION, &write_cb);
  curl_easy_setopt (curl, CURLOPT_WRITEDATA, f);
  curl_easy_setopt (curl, CURLOPT_TIMEOUT, (long) REQUEST_TIMEOUT);
  curl_easy_setopt (curl, CURLOPT_NOSIGNAL, 1L);
  return curl;
}


/**
 * Perform one GET against the example.
 *
 * @param path the path to request
 * @param[out] f where to store what was received
 * @return milliseconds the request took
 */
static long
fetch (const char *path,
       struct Fetch *f)
{
  CURL *curl;
  long start;

  curl = make_handle (path,
                      f);
  if (NULL == curl)
    return 0;
  start = now_ms ();
  f->res = curl_easy_perform (curl);
  curl_easy_cleanup (curl);
  return now_ms () - start;
}


/**
 * Perform two GETs against the example at the same time.
 *
 * @param path1 the path for the first request
 * @param path2 the path for the second request
 * @param[out] f1 where to store what the first request received
 * @param[out] f2 where to store what the second request received
 * @return milliseconds until both were done
 */
static long
fetch_both (const char *path1,
            const char *path2,
            struct Fetch *f1,
            struct Fetch *f2)
{
  CURLM *multi;
  CURL *c1;
  CURL *c2;
  CURLMsg *msg;
  int running;
  int left;
  long start;

  c1 = make_handle (path1,
                    f1);
  c2 = make_handle (path2,
                    f2);
  multi = curl_multi_init ();
  if ( (NULL == c1) ||
       (NULL == c2) ||
       (NULL == multi) )
  {
    if (NULL != c1)
      curl_easy_cleanup (c1);
    if (NULL != c2)
      curl_easy_cleanup (c2);
    if (NULL != multi)
      curl_multi_cleanup (multi);
    return 0;
  }
  curl_multi_add_handle (multi, c1);
  curl_multi_add_handle (multi, c2);
  start = now_ms ();
  running = 1;
  while (0 != running)
  {
    if (CURLM_OK != curl_multi_perform (multi,
                                        &running))
      break;
    if (0 == running)
      break;
    if (CURLM_OK != curl_multi_wait (multi,
                                     NULL,
                                     0,
                                     100,
                                     NULL))
      break;
    if (now_ms () - start > REQUEST_TIMEOUT * 1000)
      break;
  }
  while (NULL != (msg = curl_multi_info_read (multi,
                                              &left)))
  {
    if (CURLMSG_DONE != msg->msg)
      continue;
    if (msg->easy_handle == c1)
      f1->res = msg->data.result;
    else if (msg->easy_handle == c2)
      f2->res = msg->data.result;
  }
  curl_multi_remove_handle (multi, c1);
  curl_multi_remove_handle (multi, c2);
  curl_easy_cleanup (c1);
  curl_easy_cleanup (c2);
  curl_multi_cleanup (multi);
  return now_ms () - start;
}


/**
 * Ask the operating system for a port that is currently free.  The
 * example insists on being given a port number, so the test has to pick
 * one; if the guess goes stale between here and the child's bind() the
 * child exits at once and the caller simply tries again.
 *
 * @param[out] port where to store the port number
 * @return non-zero on success
 */
static int
pick_free_port (unsigned int *port)
{
  struct sockaddr_in addr;
  socklen_t addrlen = sizeof (addr);
  int sock;

  sock = socket (AF_INET,
                 SOCK_STREAM,
                 0);
  if (-1 == sock)
    return 0;
  memset (&addr,
          0,
          sizeof (addr));
  addr.sin_family = AF_INET;
  addr.sin_addr.s_addr = htonl (INADDR_ANY);
  addr.sin_port = 0;
  if ( (0 != bind (sock,
                   (struct sockaddr *) &addr,
                   sizeof (addr))) ||
       (0 != getsockname (sock,
                          (struct sockaddr *) &addr,
                          &addrlen)) )
  {
    close (sock);
    return 0;
  }
  close (sock);
  *port = ntohs (addr.sin_port);
  return (0 != *port);
}


/**
 * Start the example and wait until it answers.
 *
 * @return 1 on success, 0 if it could not be started, -1 if the binary
 *         could not be executed at all (in which case the test skips)
 */
static int
start_server (void)
{
  unsigned int attempt;

  for (attempt = 0; attempt < PORT_ATTEMPTS; attempt++)
  {
    char port_arg[16];
    long deadline;

    if (! pick_free_port (&server_port))
      return 0;
    snprintf (port_arg,
              sizeof (port_arg),
              "%u",
              server_port);
    server_pid = fork ();
    if (-1 == server_pid)
      return 0;
    if (0 == server_pid)
    {
      execl ("./suspend_resume_epoll",
             "suspend_resume_epoll",
             port_arg,
             (char *) NULL);
      fprintf (stderr,
               "Failed to exec ./suspend_resume_epoll: %s\n",
               strerror (errno));
      _exit (77);
    }
    deadline = now_ms () + STARTUP_TIMEOUT_MS;
    while (now_ms () < deadline)
    {
      struct Fetch f;
      int status;

      if (server_pid == waitpid (server_pid,
                                 &status,
                                 WNOHANG))
      {
        /* The example gave up, most likely because the port was taken
           after all.  Unless it could not even be started, try again. */
        if (WIFEXITED (status) && (77 == WEXITSTATUS (status)))
        {
          server_pid = -1;
          return -1;
        }
        server_pid = -1;
        break;
      }
      (void) fetch ("/startup",
                    &f);
      if (CURLE_OK == f.res)
        return 1;
      usleep (100 * 1000);
    }
    if (-1 != server_pid)
    {
      kill (server_pid,
            SIGKILL);
      waitpid (server_pid,
               NULL,
               0);
      server_pid = -1;
      return 0;   /* it is running but not answering; retrying will not help */
    }
  }
  return 0;
}


/**
 * The example echoes the requested URL back, but only after the timer
 * it armed has fired.
 */
static void
test_echo (void)
{
  struct Fetch f;
  long ms;

  ms = fetch ("/hello/world",
              &f);
  check (CURLE_OK == f.res,
         "request completed");
  check (0 == strcmp (f.body,
                      "/hello/world"),
         "example echoed the requested URL");
  /* Only a lower bound is checked: a loaded machine may take longer,
     but nothing can make the one-second timer fire early. */
  fprintf (stderr,
           "request was parked for %ld ms\n",
           ms);
  check (ms >= PARK_MS / 2,
         "answer waited for the timer to fire");
}


/**
 * While the connection is parked the process must be asleep in
 * epoll_wait().  This is the check that tells a suspended connection
 * apart from an access handler that is polled in a loop --- both return
 * the same bytes after the same delay.
 */
static void
test_idle_while_suspended (void)
{
  struct Fetch f;
  long cpu_before;
  long cpu_after;
  long ms;

  if (! cpu_time_ms (server_pid,
                     &cpu_before))
  {
    fprintf (stderr,
             "SKIP: no way to read the server's CPU time on this "
             "platform\n");
    return;
  }
  ms = fetch ("/idle",
              &f);
  check (CURLE_OK == f.res,
         "request completed");
  if (! cpu_time_ms (server_pid,
                     &cpu_after))
  {
    fprintf (stderr,
             "SKIP: could not read the server's CPU time\n");
    return;
  }
  fprintf (stderr,
           "server used %ld ms of CPU during %ld ms of waiting\n",
           cpu_after - cpu_before,
           ms);
  /* "<=" rather than "<" so that a degenerate run in which nothing was
     waited for at all is left for test_echo() to report, instead of
     being blamed on CPU usage here. */
  check ((cpu_after - cpu_before) * 4 <= ms,
         "server stayed idle while the connection was suspended");
}


/**
 * Suspending must not serialise requests: two connections parked at the
 * same time have to come back after one timer period, not two.  With a
 * single-threaded daemon this only works because the connection is
 * taken out of the event loop rather than blocking it.
 */
static void
test_two_at_once (void)
{
  struct Fetch f1;
  struct Fetch f2;
  long ms;

  ms = fetch_both ("/first",
                   "/second",
                   &f1,
                   &f2);
  check ( (CURLE_OK == f1.res) &&
          (CURLE_OK == f2.res),
          "both concurrent requests completed");
  check ( (0 == strcmp (f1.body,
                        "/first")) &&
          (0 == strcmp (f2.body,
                        "/second")),
          "each concurrent request got its own answer");
  fprintf (stderr,
           "two concurrent requests took %ld ms\n",
           ms);
  check (ms < 2 * PARK_MS - PARK_MS / 4,
         "the two requests were parked at the same time");
}


/**
 * A client that hangs up while its connection is parked must not take
 * the server down, and must not leak the timer either.
 */
static void
test_client_hangs_up (void)
{
  struct sockaddr_in addr;
  struct Fetch f;
  static const char *req = "GET /gone HTTP/1.1\r\nHost: localhost\r\n\r\n";
  int sock;

  sock = socket (AF_INET,
                 SOCK_STREAM,
                 0);
  if (-1 == sock)
  {
    check (0,
           "could not create a socket");
    return;
  }
  memset (&addr,
          0,
          sizeof (addr));
  addr.sin_family = AF_INET;
  addr.sin_addr.s_addr = htonl (INADDR_LOOPBACK);
  addr.sin_port = htons ((uint16_t) server_port);
  if (0 != connect (sock,
                    (struct sockaddr *) &addr,
                    sizeof (addr)))
  {
    close (sock);
    check (0,
           "could not connect to the example");
    return;
  }
  if (-1 == send (sock,
                  req,
                  strlen (req),
                  0))
  {
    close (sock);
    check (0,
           "could not send a request");
    return;
  }
  /* Hang up well before the timer fires, so that the connection is
     still suspended when the FIN arrives. */
  usleep ((useconds_t) (PARK_MS / 4) * 1000);
  close (sock);

  (void) fetch ("/still/here",
                &f);
  check ( (CURLE_OK == f.res) &&
          (0 == strcmp (f.body,
                        "/still/here")),
          "server survived a client that hung up while suspended");
}


int
main (void)
{
  int started;

  if (0 != curl_global_init (CURL_GLOBAL_ALL))
    return 77;
  started = start_server ();
  if (1 != started)
  {
    fprintf (stderr,
             "Could not start ./suspend_resume_epoll\n");
    curl_global_cleanup ();
    return (-1 == started) ? 77 : 1;
  }
  fprintf (stderr,
           "example listening on port %u\n",
           server_port);

  test_echo ();
  test_idle_while_suspended ();
  test_two_at_once ();
  test_client_hangs_up ();

  /* The example runs an endless loop by design, so there is nothing to
     ask it to do but die. */
  kill (server_pid,
        SIGKILL);
  waitpid (server_pid,
           NULL,
           0);
  server_pid = -1;
  curl_global_cleanup ();
  if (0 != failures)
    fprintf (stderr,
             "%u check(s) failed\n",
             failures);
  return (0 == failures) ? 0 : 1;
}
