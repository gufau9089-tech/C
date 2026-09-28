/* Feel free to use this example code in any way
   you see fit (Public Domain) */

/**
 * @file test_asyncresponse.c
 * @brief   Test for the "asyncresponse" tutorial example.  The example
 *          is started as a child process on an ephemeral port and then
 *          exercised over HTTP, so that what is tested is exactly the
 *          code the tutorial prints.
 *
 *          Beyond checking that the right bytes come back, the test
 *          verifies the two properties that the chapter is actually
 *          about: that the body of "/events" really trickles in rather
 *          than arriving in one piece at the end, and that the server
 *          burns no CPU while it waits.  The latter is what tells a
 *          properly suspended connection apart from a content reader
 *          that returns zero in a loop---both deliver the same bytes.
 * @author  Christian Grothoff
 */

#include <sys/types.h>
#include <sys/wait.h>
#include <curl/curl.h>
#include <errno.h>
#include <pthread.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

/**
 * Milliseconds the example should spend per step.
 */
#define STEP_MS 50

/**
 * Number of steps per job, and thus (STEPS * STEP_MS) milliseconds of
 * work for one request.
 */
#define STEPS 20

/**
 * Nominal duration of one job in milliseconds.
 */
#define JOB_MS (STEPS * STEP_MS)

/**
 * Upper bound for any single request, in seconds.
 */
#define REQUEST_TIMEOUT 30

/**
 * Largest response body we are prepared to keep.
 */
#define MAX_BODY 65536


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
   * Number of times the write callback was invoked.
   */
  unsigned int chunks;

  /**
   * Time of the first invocation of the write callback, in
   * milliseconds since the start of the request.
   */
  long first_ms;

  /**
   * Time of the last invocation of the write callback, in
   * milliseconds since the start of the request.
   */
  long last_ms;

  /**
   * Start of the request.
   */
  struct timespec start;

  /**
   * Abort the transfer after this many callbacks; zero to never abort.
   */
  unsigned int abort_after;

  /**
   * Result of curl_easy_perform().
   */
  CURLcode res;
};


/**
 * The example's process ID.
 */
static pid_t server_pid;

/**
 * The port the example bound.
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
 * @param since the earlier point in time
 * @return milliseconds elapsed since @a since
 */
static long
elapsed_ms (const struct timespec *since)
{
  struct timespec ts;

  if (0 != clock_gettime (CLOCK_MONOTONIC,
                          &ts))
    return 0;
  return (long) (ts.tv_sec - since->tv_sec) * 1000
         + (ts.tv_nsec - since->tv_nsec) / 1000000;
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

  f->chunks++;
  if (1 == f->chunks)
    f->first_ms = elapsed_ms (&f->start);
  f->last_ms = elapsed_ms (&f->start);
  if ( (0 != f->abort_after) &&
       (f->chunks >= f->abort_after) )
    return 0;                   /* makes curl abort the transfer */
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
 * Perform one GET against the example.
 *
 * @param path the path to request
 * @param[out] f where to store what was received; @e abort_after has to
 *             be set by the caller, everything else is initialised here
 * @return milliseconds the request took
 */
static long
fetch (const char *path,
       struct Fetch *f)
{
  CURL *curl;
  char url[128];
  unsigned int abort_after = f->abort_after;

  memset (f,
          0,
          sizeof (struct Fetch));
  f->abort_after = abort_after;
  f->res = CURLE_FAILED_INIT;
  snprintf (url,
            sizeof (url),
            "http://127.0.0.1:%u%s",
            server_port,
            path);
  curl = curl_easy_init ();
  if (NULL == curl)
    return 0;
  curl_easy_setopt (curl, CURLOPT_URL, url);
  curl_easy_setopt (curl, CURLOPT_WRITEFUNCTION, &write_cb);
  curl_easy_setopt (curl, CURLOPT_WRITEDATA, f);
  curl_easy_setopt (curl, CURLOPT_TIMEOUT, (long) REQUEST_TIMEOUT);
  curl_easy_setopt (curl, CURLOPT_NOSIGNAL, 1L);
  clock_gettime (CLOCK_MONOTONIC,
                 &f->start);
  f->res = curl_easy_perform (curl);
  curl_easy_cleanup (curl);
  return elapsed_ms (&f->start);
}


/**
 * Thread body that streams "/events" in the background while the main
 * thread does something else.
 *
 * @param cls a `struct Fetch` whose @e abort_after is already set
 * @return always NULL
 */
static void *
background_stream (void *cls)
{
  (void) fetch ("/events",
                cls);
  return NULL;
}


/**
 * Start the example on an ephemeral port and learn which one it got.
 *
 * @return non-zero on success
 */
static int
start_server (void)
{
  char steps[16];
  char step_ms[16];
  int fds[2];
  FILE *out;
  char line[128];

  if (0 != pipe (fds))
    return 0;
  snprintf (step_ms,
            sizeof (step_ms),
            "%u",
            (unsigned int) STEP_MS);
  snprintf (steps,
            sizeof (steps),
            "%u",
            (unsigned int) STEPS);
  server_pid = fork ();
  if (-1 == server_pid)
  {
    close (fds[0]);
    close (fds[1]);
    return 0;
  }
  if (0 == server_pid)
  {
    close (fds[0]);
    if (STDOUT_FILENO != fds[1])
    {
      dup2 (fds[1],
            STDOUT_FILENO);
      close (fds[1]);
    }
    execl ("./asyncresponse",
           "asyncresponse",
           "0",
           step_ms,
           steps,
           (char *) NULL);
    fprintf (stderr,
             "Failed to exec ./asyncresponse: %s\n",
             strerror (errno));
    _exit (77);
  }
  close (fds[1]);
  out = fdopen (fds[0],
                "r");
  if (NULL == out)
  {
    close (fds[0]);
    return 0;
  }
  if (NULL == fgets (line,
                     sizeof (line),
                     out))
  {
    fclose (out);
    return 0;
  }
  fclose (out);
  if (1 != sscanf (line,
                   "Listening on port %u",
                   &server_port))
  {
    fprintf (stderr,
             "Unexpected greeting from the example: %s",
             line);
    return 0;
  }
  return 1;
}


/**
 * "GET /slow" suspends in the access handler and is answered as a
 * whole once the worker is done.
 */
static void
test_slow (void)
{
  struct Fetch f;
  long ms;

  memset (&f,
          0,
          sizeof (f));
  ms = fetch ("/slow",
              &f);
  check (CURLE_OK == f.res,
         "/slow completed");
  check (NULL != strstr (f.body,
                         "all 20 steps done"),
         "/slow delivered the complete answer");
  /* The worker sleeps STEP_MS per step, so the answer cannot possibly
     be ready earlier.  Only a lower bound is checked: a loaded machine
     may take arbitrarily longer. */
  check (ms >= JOB_MS / 2,
         "/slow waited for the worker");
}


/**
 * "GET /events" streams as the worker produces, and the server stays
 * idle in between.  This is the check that a content reader returning
 * zero in a loop would fail.
 */
static void
test_events_are_incremental (void)
{
  struct Fetch f;
  long cpu_before;
  long cpu_after;
  long ms;
  int have_cpu;

  memset (&f,
          0,
          sizeof (f));
  have_cpu = cpu_time_ms (server_pid,
                          &cpu_before);
  ms = fetch ("/events",
              &f);
  check (CURLE_OK == f.res,
         "/events completed");
  check (NULL != strstr (f.body,
                         "event: done"),
         "/events delivered the final event");
  check (5 <= f.chunks,
         "/events arrived in several pieces");
  /* The decisive one: the first piece has to show up long before the
     last.  A response that is assembled first and sent afterwards would
     have first_ms very close to last_ms. */
  check (f.last_ms - f.first_ms >= JOB_MS / 2,
         "/events trickled in rather than arriving at once");

  if (! have_cpu)
  {
    fprintf (stderr,
             "SKIP: no way to read the server's CPU time on this "
             "platform\n");
    return;
  }
  if (! cpu_time_ms (server_pid,
                     &cpu_after))
  {
    fprintf (stderr,
             "SKIP: could not read the server's CPU time\n");
    return;
  }
  /* The server spent almost all of that second waiting.  If the
     connection were not suspended, MHD would poll the content reader
     as fast as it can and this would be close to 100% of one core. */
  fprintf (stderr,
           "server used %ld ms of CPU during %ld ms of streaming\n",
           cpu_after - cpu_before,
           ms);
  check ((cpu_after - cpu_before) * 4 < ms,
         "server stayed idle while the connection was suspended");
}


/**
 * The event loop keeps serving other requests while jobs are parked.
 */
static void
test_loop_stays_responsive (void)
{
  struct Fetch stream;
  struct Fetch ping;
  pthread_t tid;
  long worst = 0;
  long ms;
  unsigned int i;

  memset (&stream,
          0,
          sizeof (stream));
  if (0 != pthread_create (&tid,
                           NULL,
                           &background_stream,
                           &stream))
  {
    check (0,
           "could not start the background stream");
    return;
  }
  for (i = 0; i < 5; i++)
  {
    memset (&ping,
            0,
            sizeof (ping));
    ms = fetch ("/fast",
                &ping);
    if ( (CURLE_OK != ping.res) ||
         (NULL == strstr (ping.body,
                          "pong")) )
      worst = REQUEST_TIMEOUT * 1000;
    else if (ms > worst)
      worst = ms;
    usleep (50 * 1000);
  }
  pthread_join (tid,
                NULL);
  fprintf (stderr,
           "slowest /fast while a job was running: %ld ms\n",
           worst);
  check (worst < 500,
         "/fast was served promptly while a job was suspended");
}


/**
 * A client that goes away in the middle must not take the server with
 * it, and the worker behind it has to be cleaned up.
 */
static void
test_client_abort (void)
{
  struct Fetch f;
  struct Fetch ping;

  memset (&f,
          0,
          sizeof (f));
  f.abort_after = 3;
  (void) fetch ("/events",
                &f);
  check (CURLE_OK != f.res,
         "aborted transfer was reported as such");
  memset (&ping,
          0,
          sizeof (ping));
  (void) fetch ("/fast",
                &ping);
  check ( (CURLE_OK == ping.res) &&
          (NULL != strstr (ping.body,
                           "pong")),
          "server survived a client that hung up mid-stream");
}


/**
 * Stopping the daemon while a connection is suspended is an API
 * violation, so the example has to resume everything first.  If it got
 * that wrong we would see a panic or a hang here instead of a clean
 * exit.
 */
static void
test_clean_shutdown (void)
{
  struct Fetch stream;
  pthread_t tid;
  int status;
  pid_t got;

  memset (&stream,
          0,
          sizeof (stream));
  if (0 != pthread_create (&tid,
                           NULL,
                           &background_stream,
                           &stream))
  {
    check (0,
           "could not start the background stream");
    return;
  }
  /* Give the job time to get going, so that its connection really is
     suspended when the signal arrives. */
  usleep ((useconds_t) (STEP_MS * 3) * 1000);
  kill (server_pid,
        SIGTERM);
  pthread_join (tid,
                NULL);
  got = waitpid (server_pid,
                 &status,
                 0);
  server_pid = -1;
  check (0 < got,
         "reaped the server");
  check (WIFEXITED (status) && (0 == WEXITSTATUS (status)),
         "server shut down cleanly with a suspended connection");
}


int
main (void)
{
  long deadline;

  if (0 != curl_global_init (CURL_GLOBAL_ALL))
    return 77;
  if (! start_server ())
  {
    fprintf (stderr,
             "Could not start ./asyncresponse\n");
    curl_global_cleanup ();
    return 77;
  }
  fprintf (stderr,
           "example listening on port %u\n",
           server_port);

  /* Wait for the listen socket to be usable. */
  deadline = now_ms () + 5000;
  while (now_ms () < deadline)
  {
    struct Fetch f;

    memset (&f,
            0,
            sizeof (f));
    (void) fetch ("/fast",
                  &f);
    if (CURLE_OK == f.res)
      break;
    usleep (50 * 1000);
  }

  test_slow ();
  test_events_are_incremental ();
  test_loop_stays_responsive ();
  test_client_abort ();
  test_clean_shutdown ();

  if (-1 != server_pid)
  {
    kill (server_pid,
          SIGKILL);
    waitpid (server_pid,
             NULL,
             0);
  }
  curl_global_cleanup ();
  if (0 != failures)
    fprintf (stderr,
             "%u check(s) failed\n",
             failures);
  return (0 == failures) ? 0 : 1;
}
