/* Feel free to use this example code in any way
   you see fit (Public Domain) */

/**
 * @file asyncresponse.c
 * @brief   Example for answering a request from another thread while
 *          the daemon is driven by an external select() loop.  The
 *          main thread owns libmicrohttpd and does nothing but poll;
 *          every slow request gets a worker thread of its own and the
 *          connection is suspended for as long as that worker has
 *          nothing to say.
 *
 *          "GET /" serves a small page whose JavaScript renders the
 *          data as it trickles in, "GET /events" is the stream behind
 *          it (a response is queued immediately and the content reader
 *          suspends between chunks), "GET /slow" suspends in the access
 *          handler until a complete answer is ready, and "GET /fast" is
 *          answered on the spot so that it can be used to show that the
 *          event loop never blocks.
 *
 *          This example needs POSIX threads.
 * @author  Christian Grothoff
 */

#include <sys/types.h>
#include <sys/select.h>
#include <sys/socket.h>
#include <microhttpd.h>
#include <errno.h>
#include <pthread.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

/**
 * Port to listen on if none was given on the command line.  Pass 0 to
 * let the operating system pick a free port; the port that was
 * actually bound is then printed on standard output.
 */
#define DEFAULT_PORT 8888

/**
 * Time the worker thread pretends to need for one step, in
 * milliseconds.
 */
#define DEFAULT_STEP_MS 250

/**
 * Number of steps that make up one job.
 */
#define DEFAULT_STEPS 20

/**
 * Size of the buffer in which a job collects the bytes that the
 * content reader has not picked up yet.
 */
#define MAX_PAYLOAD 4096

/**
 * Block size we ask MHD to use when it queries our content reader.
 */
#define IO_BLOCK_SIZE 1024

/**
 * How long we are willing to wait for the last connections to go away
 * when the server is shutting down, in milliseconds.
 */
#define DRAIN_TIMEOUT_MS 2000


/**
 * The front page.  Its JavaScript opens the "/events" stream and adds
 * a row for every server-sent event as it arrives, so that the delay
 * between the steps is plainly visible.  The "ping" button fires a
 * request against "/fast" and reports the round trip time; it stays in
 * the low milliseconds even while several jobs are running, which is
 * the whole point of suspending instead of blocking.
 */
static const char *PAGE =
  "<!DOCTYPE html>\n"
  "<html lang='en'>\n"
  "<head>\n"
  "<meta charset='utf-8'>\n"
  "<title>libmicrohttpd: answering from another thread</title>\n"
  "<style>\n"
  "body { font-family: sans-serif; max-width: 40em; margin: 2em auto; }\n"
  "#bar { height: 1em; border: 1px solid #888; margin: 1em 0; }\n"
  "#fill { height: 100%; width: 0; background: #4a90d9; transition: width .2s; }\n"
  "#log { font-family: monospace; font-size: 90%; list-style: none; padding: 0; }\n"
  "#log li { border-bottom: 1px solid #eee; padding: 2px 0; }\n"
  "button { margin-right: .5em; }\n"
  "</style>\n"
  "</head>\n"
  "<body>\n"
  "<h1>Answering from another thread</h1>\n"
  "<p>The server runs a single external <code>select()</code> loop.  The job\n"
  "below is computed by a thread of its own, and the connection carrying it is\n"
  "suspended whenever that thread has nothing to say.  Nothing is buffered: each\n"
  "row appears the moment the worker produced it.</p>\n"
  "<button id='go'>Start a job</button>\n"
  "<button id='ping'>Ping /fast</button>\n"
  "<div id='bar'><div id='fill'></div></div>\n"
  "<p id='status'>idle</p>\n"
  "<ul id='log'></ul>\n"
  "<script>\n"
  "const $ = (id) => document.getElementById(id);\n"
  "let es = null;\n"
  "let t0 = 0;\n"
  "const stop = () => { if (es) { es.close(); es = null; } };\n"
  "$('go').onclick = () => {\n"
  "  stop ();\n"
  "  $('log').innerHTML = '';\n"
  "  $('fill').style.width = '0';\n"
  "  $('status').textContent = 'running';\n"
  "  t0 = performance.now ();\n"
  "  es = new EventSource ('/events');\n"
  "  es.addEventListener ('step', (e) => {\n"
  "    const d = JSON.parse (e.data);\n"
  "    const li = document.createElement ('li');\n"
  "    li.textContent = '+' + Math.round (performance.now () - t0) +\n"
  "                     ' ms   ' + d.label;\n"
  "    $('log').appendChild (li);\n"
  "    $('fill').style.width = (100 * d.n / d.total) + '%';\n"
  "  });\n"
  "  es.addEventListener ('done', () => {\n"
  "    stop ();\n"
  "    $('status').textContent = 'done after ' +\n"
  "      Math.round (performance.now () - t0) + ' ms';\n"
  "  });\n"
  "  es.onerror = () => { stop (); $('status').textContent = 'connection lost'; };\n"
  "};\n"
  "$('ping').onclick = async () => {\n"
  "  const t = performance.now ();\n"
  "  await fetch ('/fast', { cache: 'no-store' });\n"
  "  $('status').textContent = '/fast answered in ' +\n"
  "    Math.round (performance.now () - t) + ' ms';\n"
  "};\n"
  "</script>\n"
  "</body>\n"
  "</html>\n";


/**
 * State shared between the thread that runs libmicrohttpd and the
 * worker thread that produces the answer.  Everything below @e lock is
 * protected by it.
 *
 * The structure is reference counted, with one reference held by MHD
 * (dropped in #stream_done() or #request_completed()) and one held by
 * the worker (dropped when the worker function returns).  Reaching zero
 * does not free the job: only the main thread does that, in
 * #reap_jobs(), because it is also the thread that has to join the
 * worker.
 */
struct Job
{
  /**
   * Kept in a doubly linked list of all jobs, so that the shutdown
   * code can reach every worker.  The list is protected by
   * #jobs_lock, never by @e lock.
   */
  struct Job *next;

  /**
   * See @e next.
   */
  struct Job *prev;

  /**
   * Protects every field below, and---just as importantly---keeps the
   * connection alive across #MHD_resume_connection().
   */
  pthread_mutex_t lock;

  /**
   * Used to wake the worker out of its sleep when the client goes away
   * or the server is shutting down.
   */
  pthread_cond_t cond;

  /**
   * The worker thread.  Only touched by the main thread, under
   * #jobs_lock.
   */
  pthread_t tid;

  /**
   * The connection this job answers.  Set to NULL by the MHD side as
   * soon as MHD is done with the connection; the worker must not touch
   * it after that, which is why @e abandoned is checked under @e lock
   * before every #MHD_resume_connection().
   */
  struct MHD_Connection *connection;

  /**
   * Bytes produced by the worker that the content reader has not
   * picked up yet.
   */
  char payload[MAX_PAYLOAD];

  /**
   * Number of valid bytes in @e payload.
   */
  size_t fill;

  /**
   * Number of bytes of @e payload already handed to MHD.
   */
  size_t off;

  /**
   * Number of references, see the comment on the structure.
   */
  unsigned int rc;

  /**
   * Non-zero if the answer is streamed as it is produced ("/events"),
   * zero if the client only ever sees the finished result ("/slow").
   * A streaming job resumes the connection after every step, the other
   * kind only once, at the very end.
   */
  int stream;

  /**
   * Non-zero once the worker has produced everything it is going to
   * produce.
   */
  int finished;

  /**
   * Non-zero while the connection is suspended (or is just about to
   * be, which under @e lock is the same thing).
   */
  int suspended;

  /**
   * Non-zero once MHD is done with the connection.  The worker must
   * not call any MHD function on @e connection any more.
   */
  int abandoned;

  /**
   * Non-zero if the worker should give up early.
   */
  int stop;

  /**
   * Non-zero once the worker thread was started.  Main thread only.
   */
  int started;

  /**
   * Non-zero once the worker thread was joined.  Main thread only.
   */
  int joined;
};


/**
 * Head of the list of all jobs.
 */
static struct Job *jobs_head;

/**
 * Protects #jobs_head and the list links of every job.  Lock order is
 * #jobs_lock before any `struct Job`'s @e lock, never the other way
 * round.
 */
static pthread_mutex_t jobs_lock = PTHREAD_MUTEX_INITIALIZER;

/**
 * Set by the signal handler, read by the main loop.
 */
static volatile sig_atomic_t shutdown_requested;

/**
 * Written to by the signal handler so that a blocking select() returns
 * at once.  MHD's own wakeup goes through its inter-thread
 * communication channel, but our signal is our own business.
 */
static int wake_pipe[2] = { -1, -1 };

/**
 * Milliseconds the worker sleeps per step.
 */
static unsigned int step_ms = DEFAULT_STEP_MS;

/**
 * Number of steps that make up one job.
 */
static unsigned int total_steps = DEFAULT_STEPS;


/**
 * Signal handler for SIGINT and SIGTERM.  Does the two things that are
 * safe to do here: set a flag and poke a pipe.
 *
 * @param sig the signal that was received
 */
static void
signal_handler (int sig)
{
  static const char c = 'x';

  (void) sig;               /* Unused. Silent compiler warning. */
  shutdown_requested = 1;
  if (0 > write (wake_pipe[1],
                 &c,
                 1))
  {
    /* Nothing useful can be done about this here. */
  }
}


/**
 * Allocate a job and put it on the global list.
 *
 * @param connection the connection the job answers
 * @param stream non-zero to deliver the steps as they are produced
 * @return the new job with a reference count of two (one for MHD, one
 *         for the worker that the caller is about to start), NULL on
 *         error
 */
static struct Job *
job_create (struct MHD_Connection *connection,
            int stream)
{
  struct Job *job;

  job = malloc (sizeof (struct Job));
  if (NULL == job)
    return NULL;
  memset (job,
          0,
          sizeof (struct Job));
  if (0 != pthread_mutex_init (&job->lock,
                               NULL))
  {
    free (job);
    return NULL;
  }
  if (0 != pthread_cond_init (&job->cond,
                              NULL))
  {
    pthread_mutex_destroy (&job->lock);
    free (job);
    return NULL;
  }
  job->connection = connection;
  job->stream = stream;
  job->rc = 2;
  pthread_mutex_lock (&jobs_lock);
  job->next = jobs_head;
  if (NULL != jobs_head)
    jobs_head->prev = job;
  jobs_head = job;
  pthread_mutex_unlock (&jobs_lock);
  return job;
}


/**
 * Drop a reference.  Note that this never frees the job: the main
 * thread has to join the worker first, and only it may do that.  See
 * #reap_jobs().
 *
 * @param job the job to release
 */
static void
job_unref (struct Job *job)
{
  pthread_mutex_lock (&job->lock);
  job->rc--;
  pthread_mutex_unlock (&job->lock);
}


/**
 * Called by the MHD side once MHD is done with the connection.  After
 * this returns, the worker will not touch the connection again.
 *
 * @param job the job to detach from its connection
 */
static void
job_detach (struct Job *job)
{
  pthread_mutex_lock (&job->lock);
  job->abandoned = 1;
  job->connection = NULL;
  /* Wake the worker out of its sleep: if the client hung up in the
     middle of the transfer there is no point in producing the rest. */
  pthread_cond_signal (&job->cond);
  pthread_mutex_unlock (&job->lock);
  job_unref (job);
}


/**
 * Resume the connection of @a job if it is suspended.
 *
 * Must be called with @a job's lock held, and it deliberately calls
 * into MHD while holding it: the MHD thread has to take the very same
 * lock in #job_detach() before it can finish the connection, so as
 * long as we hold the lock the connection cannot go away underneath
 * us.  The reverse order never occurs---MHD invokes our callbacks
 * without holding any of its own locks that #MHD_resume_connection()
 * would need---so this cannot deadlock.
 *
 * @param job the job whose connection to resume
 */
static void
job_resume_locked (struct Job *job)
{
  if ( (0 == job->suspended) ||
       (0 != job->abandoned) )
    return;
  job->suspended = 0;
  MHD_resume_connection (job->connection);
}


/**
 * Sleep for one step, or until the job is woken up.
 *
 * @param job the job to sleep on
 * @return non-zero if the worker should stop early
 */
static int
job_sleep (struct Job *job)
{
  struct timespec ts;
  int stop;

  if (0 != clock_gettime (CLOCK_REALTIME,
                          &ts))
    return 1;
  ts.tv_sec += (time_t) (step_ms / 1000);
  ts.tv_nsec += (long) (step_ms % 1000) * 1000000L;
  if (1000000000L <= ts.tv_nsec)
  {
    ts.tv_nsec -= 1000000000L;
    ts.tv_sec++;
  }
  pthread_mutex_lock (&job->lock);
  while ( (0 == job->stop) &&
          (0 == job->abandoned) )
  {
    if (ETIMEDOUT == pthread_cond_timedwait (&job->cond,
                                             &job->lock,
                                             &ts))
      break;
  }
  stop = (0 != job->stop) || (0 != job->abandoned);
  pthread_mutex_unlock (&job->lock);
  return stop;
}


/**
 * Append @a len bytes from @a data to the job's payload buffer,
 * compacting the buffer first.  Must be called with @a job's lock
 * held.  A real application would need a policy for the case that the
 * client cannot keep up; here we simply drop the step, which cannot
 * happen with the sizes used in this example.
 *
 * @param job the job to append to
 * @param data the bytes to append
 * @param len the number of bytes to append
 */
static void
job_append_locked (struct Job *job,
                   const char *data,
                   size_t len)
{
  if (0 != job->off)
  {
    memmove (job->payload,
             &job->payload[job->off],
             job->fill - job->off);
    job->fill -= job->off;
    job->off = 0;
  }
  if (len > MAX_PAYLOAD - job->fill)
    return;
  memcpy (&job->payload[job->fill],
          data,
          len);
  job->fill += len;
}


/**
 * The worker.  This stands in for whatever expensive computation,
 * database cursor or remote query a real application would run: it
 * produces one server-sent event per step and resumes the connection
 * whenever it has something new to offer.
 *
 * Note that the only MHD function this thread ever calls is
 * #MHD_resume_connection().  Building and queueing the response is the
 * business of the thread that runs the daemon.
 *
 * @param cls the `struct Job` to work on
 * @return always NULL
 */
static void *
worker (void *cls)
{
  struct Job *job = cls;
  char event[256];
  unsigned int i;
  int len;

  for (i = 1; i <= total_steps; i++)
  {
    if (0 != job_sleep (job))
      break;
    if (0 != job->stream)
      len = snprintf (event,
                      sizeof (event),
                      "event: step\ndata: {\"n\":%u,\"total\":%u,"
                      "\"label\":\"step %u of %u done\"}\n\n",
                      i,
                      total_steps,
                      i,
                      total_steps);
    else
      len = snprintf (event,
                      sizeof (event),
                      "step %u of %u done\n",
                      i,
                      total_steps);
    if ( (0 >= len) ||
         (sizeof (event) <= (size_t) len) )
      break;
    pthread_mutex_lock (&job->lock);
    job_append_locked (job,
                       event,
                       (size_t) len);
    /* Only a streaming job has anything to show yet.  The other kind
       stays suspended until the very last step. */
    if (0 != job->stream)
      job_resume_locked (job);
    pthread_mutex_unlock (&job->lock);
  }
  if (0 != job->stream)
    len = snprintf (event,
                    sizeof (event),
                    "event: done\ndata: {\"n\":%u,\"total\":%u}\n\n",
                    total_steps,
                    total_steps);
  else
    len = snprintf (event,
                    sizeof (event),
                    "all %u steps done\n",
                    total_steps);
  pthread_mutex_lock (&job->lock);
  if ( (0 < len) &&
       (sizeof (event) > (size_t) len) )
    job_append_locked (job,
                       event,
                       (size_t) len);
  job->finished = 1;
  /* The last resume is not optional: if the connection were left
     suspended, nothing would ever wake it up again, and the daemon
     could not be stopped. */
  job_resume_locked (job);
  pthread_mutex_unlock (&job->lock);
  job_unref (job);
  return NULL;
}


/**
 * Start the worker thread of @a job.
 *
 * @param job the job whose worker to start
 * @return #MHD_YES on success
 */
static enum MHD_Result
job_start (struct Job *job)
{
  pthread_mutex_lock (&jobs_lock);
  if (0 != pthread_create (&job->tid,
                           NULL,
                           &worker,
                           job))
  {
    pthread_mutex_unlock (&jobs_lock);
    return MHD_NO;
  }
  job->started = 1;
  pthread_mutex_unlock (&jobs_lock);
  return MHD_YES;
}


/**
 * Content reader for the "/events" stream.  This is the interesting
 * one: when the worker has produced nothing since the last call we
 * suspend the connection and return zero, instead of returning zero on
 * its own---which would make MHD ask again immediately and burn a CPU
 * core for the whole duration of the transfer.
 *
 * @param cls our `struct Job`
 * @param pos number of bytes already returned for this response
 * @param buf where to copy the data
 * @param max maximum number of bytes to copy to @a buf
 * @return number of bytes written to @a buf, 0 if the connection was
 *         suspended, MHD_CONTENT_READER_END_OF_STREAM at the end
 */
static ssize_t
stream_reader (void *cls,
               uint64_t pos,
               char *buf,
               size_t max)
{
  struct Job *job = cls;
  size_t ready;

  (void) pos;               /* Unused. Silent compiler warning. */
  pthread_mutex_lock (&job->lock);
  if (job->off == job->fill)
  {
    job->off = 0;
    job->fill = 0;
    if (0 != job->finished)
    {
      pthread_mutex_unlock (&job->lock);
      return MHD_CONTENT_READER_END_OF_STREAM;
    }
    /* Nothing to send yet.  Take the connection out of the event loop;
       the worker will put it back in. */
    job->suspended = 1;
    MHD_suspend_connection (job->connection);
    pthread_mutex_unlock (&job->lock);
    return 0;
  }
  ready = job->fill - job->off;
  if (ready > max)
    ready = max;
  memcpy (buf,
          &job->payload[job->off],
          ready);
  job->off += ready;
  pthread_mutex_unlock (&job->lock);
  return (ssize_t) ready;
}


/**
 * Called by MHD when the response object of an "/events" request is
 * destroyed, which happens for a completed transfer just as well as
 * for a client that went away in the middle of one.  This is the MHD
 * side of the job's reference count.
 *
 * @param cls our `struct Job`
 */
static void
stream_done (void *cls)
{
  job_detach (cls);
}


/**
 * Handle "GET /events": queue a streaming response right away and let
 * the content reader deal with the fact that the data does not exist
 * yet.
 *
 * @param connection the connection to answer
 * @return #MHD_YES on success
 */
static enum MHD_Result
handle_events (struct MHD_Connection *connection)
{
  struct MHD_Response *response;
  struct Job *job;
  enum MHD_Result ret;

  job = job_create (connection,
                    1);
  if (NULL == job)
    return MHD_NO;
  response = MHD_create_response_from_callback (MHD_SIZE_UNKNOWN,
                                                IO_BLOCK_SIZE,
                                                &stream_reader,
                                                job,
                                                &stream_done);
  if (NULL == response)
  {
    /* No response object exists, so nobody will call stream_done() for
       us; drop both references by hand.  The worker was never
       started. */
    job_unref (job);
    job_unref (job);
    return MHD_NO;
  }
  if (MHD_NO == job_start (job))
  {
    MHD_destroy_response (response);
    job_unref (job);
    return MHD_NO;
  }
  (void) MHD_add_response_header (response,
                                  MHD_HTTP_HEADER_CONTENT_TYPE,
                                  "text/event-stream");
  (void) MHD_add_response_header (response,
                                  MHD_HTTP_HEADER_CACHE_CONTROL,
                                  "no-cache");
  ret = MHD_queue_response (connection,
                            MHD_HTTP_OK,
                            response);
  MHD_destroy_response (response);
  return ret;
}


/**
 * Handle "GET /slow": the answer is only useful as a whole, so instead
 * of streaming we suspend the connection until the worker is done.
 * MHD then calls this function again---on its own thread---and that is
 * where the response is queued.  #MHD_queue_response() is never called
 * from the worker.
 *
 * @param connection the connection to answer
 * @param req_cls the per-request pointer, holding our `struct Job`
 * @return #MHD_YES on success
 */
static enum MHD_Result
handle_slow (struct MHD_Connection *connection,
             void **req_cls)
{
  struct MHD_Response *response;
  struct Job *job = *req_cls;
  char answer[MAX_PAYLOAD];
  size_t len;
  enum MHD_Result ret;

  if (NULL == job)
  {
    /* First call for this request: start the work and ask MHD to come
       back to us. */
    job = job_create (connection,
                      0);
    if (NULL == job)
      return MHD_NO;
    if (MHD_NO == job_start (job))
    {
      job_unref (job);
      job_unref (job);
      return MHD_NO;
    }
    *req_cls = job;
    return MHD_YES;
  }
  pthread_mutex_lock (&job->lock);
  if (0 == job->finished)
  {
    /* Still working.  Park the connection; the worker resumes it when
       it is done, and MHD will then enter this function once more. */
    job->suspended = 1;
    MHD_suspend_connection (connection);
    pthread_mutex_unlock (&job->lock);
    return MHD_YES;
  }
  len = job->fill - job->off;
  if (len > sizeof (answer))
    len = sizeof (answer);
  memcpy (answer,
          &job->payload[job->off],
          len);
  pthread_mutex_unlock (&job->lock);

  response = MHD_create_response_from_buffer_copy (len,
                                                   answer);
  if (NULL == response)
    return MHD_NO;
  (void) MHD_add_response_header (response,
                                  MHD_HTTP_HEADER_CONTENT_TYPE,
                                  "text/plain");
  ret = MHD_queue_response (connection,
                            MHD_HTTP_OK,
                            response);
  MHD_destroy_response (response);
  return ret;
}


/**
 * Queue a complete response that is already sitting in memory.
 *
 * @param connection the connection to answer
 * @param status the HTTP status code to use
 * @param mime the value for the "Content-Type" header
 * @param body the body to send
 * @return #MHD_YES on success
 */
static enum MHD_Result
queue_static (struct MHD_Connection *connection,
              unsigned int status,
              const char *mime,
              const char *body)
{
  struct MHD_Response *response;
  enum MHD_Result ret;

  response = MHD_create_response_from_buffer_copy (strlen (body),
                                                   body);
  if (NULL == response)
    return MHD_NO;
  (void) MHD_add_response_header (response,
                                  MHD_HTTP_HEADER_CONTENT_TYPE,
                                  mime);
  (void) MHD_add_response_header (response,
                                  MHD_HTTP_HEADER_CACHE_CONTROL,
                                  "no-store");
  ret = MHD_queue_response (connection,
                            status,
                            response);
  MHD_destroy_response (response);
  return ret;
}


static enum MHD_Result
answer_to_connection (void *cls,
                      struct MHD_Connection *connection,
                      const char *url,
                      const char *method,
                      const char *version,
                      const char *upload_data,
                      size_t *upload_data_size,
                      void **req_cls)
{
  (void) cls;               /* Unused. Silent compiler warning. */
  (void) version;           /* Unused. Silent compiler warning. */
  (void) upload_data;       /* Unused. Silent compiler warning. */
  (void) upload_data_size;  /* Unused. Silent compiler warning. */

  if (0 != strcmp (method,
                   MHD_HTTP_METHOD_GET))
    return MHD_NO;
  if (0 == strcmp (url,
                   "/"))
    return queue_static (connection,
                         MHD_HTTP_OK,
                         "text/html",
                         PAGE);
  if (0 == strcmp (url,
                   "/fast"))
    return queue_static (connection,
                         MHD_HTTP_OK,
                         "text/plain",
                         "pong\n");
  if ( (0 == strcmp (url,
                     "/events")) ||
       (0 == strcmp (url,
                     "/slow")) )
  {
    if (0 != shutdown_requested)
      return queue_static (connection,
                           MHD_HTTP_SERVICE_UNAVAILABLE,
                           "text/plain",
                           "shutting down\n");
    if (0 == strcmp (url,
                     "/events"))
      return handle_events (connection);
    return handle_slow (connection,
                        req_cls);
  }
  return queue_static (connection,
                       MHD_HTTP_NOT_FOUND,
                       "text/plain",
                       "not found\n");
}


/**
 * Called by MHD when a request is done.  For "/slow" this is where the
 * MHD side of the reference count is dropped; the other handlers leave
 * @a req_cls alone, so there is nothing to do for them.
 *
 * @param cls closure, unused
 * @param connection the connection that finished
 * @param req_cls the per-request pointer
 * @param toe why the request ended
 */
static void
request_completed (void *cls,
                   struct MHD_Connection *connection,
                   void **req_cls,
                   enum MHD_RequestTerminationCode toe)
{
  struct Job *job = *req_cls;

  (void) cls;               /* Unused. Silent compiler warning. */
  (void) connection;        /* Unused. Silent compiler warning. */
  (void) toe;               /* Unused. Silent compiler warning. */
  if (NULL == job)
    return;
  *req_cls = NULL;
  job_detach (job);
}


/**
 * Free every job that nobody references any more, joining its worker
 * on the way.  Called from the main loop, and thus always from the
 * thread that also runs the daemon.
 */
static void
reap_jobs (void)
{
  struct Job *job;
  struct Job *next;
  unsigned int rc;

  pthread_mutex_lock (&jobs_lock);
  for (job = jobs_head; NULL != job; job = next)
  {
    next = job->next;
    pthread_mutex_lock (&job->lock);
    rc = job->rc;
    pthread_mutex_unlock (&job->lock);
    if (0 != rc)
      continue;
    if ( (0 != job->started) &&
         (0 == job->joined) )
    {
      pthread_join (job->tid,
                    NULL);
      job->joined = 1;
    }
    if (NULL != job->prev)
      job->prev->next = job->next;
    else
      jobs_head = job->next;
    if (NULL != job->next)
      job->next->prev = job->prev;
    pthread_cond_destroy (&job->cond);
    pthread_mutex_destroy (&job->lock);
    free (job);
  }
  pthread_mutex_unlock (&jobs_lock);
}


/**
 * Ask every worker to stop and wait until they all did.
 *
 * This has to happen before the daemon is stopped: a worker that is
 * still asleep may be holding the only promise to resume a suspended
 * connection, and stopping a daemon that has suspended connections is
 * an API violation.  Once every worker has returned, no connection can
 * be suspended any more, because the workers resume before they exit
 * and the content reader only ever suspends while a worker is running.
 */
static void
stop_all_jobs (void)
{
  struct Job *job;

  pthread_mutex_lock (&jobs_lock);
  for (job = jobs_head; NULL != job; job = job->next)
  {
    pthread_mutex_lock (&job->lock);
    job->stop = 1;
    pthread_cond_signal (&job->cond);
    pthread_mutex_unlock (&job->lock);
  }
  for (job = jobs_head; NULL != job; job = job->next)
  {
    if ( (0 != job->started) &&
         (0 == job->joined) )
    {
      pthread_join (job->tid,
                    NULL);
      job->joined = 1;
    }
  }
  pthread_mutex_unlock (&jobs_lock);
}


/**
 * Number of connections the daemon is currently handling.
 *
 * @param daemon the daemon to query
 * @return the number of connections, 0 if it cannot be determined
 */
static unsigned int
connection_count (struct MHD_Daemon *daemon)
{
  const union MHD_DaemonInfo *info;

  info = MHD_get_daemon_info (daemon,
                              MHD_DAEMON_INFO_CURRENT_CONNECTIONS);
  if (NULL == info)
    return 0;
  return info->num_connections;
}


int
main (int argc,
      char *const *argv)
{
  struct MHD_Daemon *daemon;
  const union MHD_DaemonInfo *info;
  struct sigaction sa;
  fd_set rs;
  fd_set ws;
  fd_set es;
  struct timeval tv;
  struct timeval *tvp;
  MHD_socket max;
  uint64_t mhd_timeout;
  unsigned long port = DEFAULT_PORT;
  unsigned int drained_ms = 0;
  char drain_buf[64];
  int draining = 0;
  int ret = 0;

  if (1 < argc)
    port = strtoul (argv[1],
                    NULL,
                    10);
  if (2 < argc)
    step_ms = (unsigned int) strtoul (argv[2],
                                      NULL,
                                      10);
  if (3 < argc)
    total_steps = (unsigned int) strtoul (argv[3],
                                          NULL,
                                          10);
  if ( (65535 < port) ||
       (0 == total_steps) )
  {
    fprintf (stderr,
             "Usage: %s [PORT [STEP_MS [STEPS]]]\n"
             "Pass 0 as PORT to let the system pick a free one.\n",
             argv[0]);
    return 1;
  }

  if (0 > pipe (wake_pipe))
  {
    fprintf (stderr,
             "Failed to create wakeup pipe: %s\n",
             strerror (errno));
    return 1;
  }
  memset (&sa,
          0,
          sizeof (sa));
  sa.sa_handler = &signal_handler;
  sigaction (SIGINT,
             &sa,
             NULL);
  sigaction (SIGTERM,
             &sa,
             NULL);
  sa.sa_handler = SIG_IGN;
  sigaction (SIGPIPE,
             &sa,
             NULL);

  /* No MHD_USE_INTERNAL_POLLING_THREAD: the loop below is ours.
     MHD_ALLOW_SUSPEND_RESUME implies MHD_USE_ITC, and that channel is
     what lets a worker thread break us out of the select() call. */
  daemon = MHD_start_daemon (MHD_ALLOW_SUSPEND_RESUME | MHD_USE_ERROR_LOG,
                             (uint16_t) port,
                             NULL, NULL,
                             &answer_to_connection, NULL,
                             MHD_OPTION_NOTIFY_COMPLETED,
                             &request_completed, NULL,
                             MHD_OPTION_END);
  if (NULL == daemon)
  {
    fprintf (stderr,
             "Failed to start daemon.\n");
    return 1;
  }
  info = MHD_get_daemon_info (daemon,
                              MHD_DAEMON_INFO_BIND_PORT);
  if ( (NULL == info) ||
       (0 == info->port) )
  {
    fprintf (stderr,
             "Failed to determine bound port.\n");
    MHD_stop_daemon (daemon);
    return 1;
  }
  printf ("Listening on port %u\n",
          (unsigned int) info->port);
  fflush (stdout);

  while (1)
  {
    if ( (0 != shutdown_requested) &&
         (0 == draining) )
    {
      /* Every worker has to be gone before the daemon may be stopped. */
      stop_all_jobs ();
      draining = 1;
    }
    if ( (0 != draining) &&
         ( (0 == connection_count (daemon)) ||
           (DRAIN_TIMEOUT_MS <= drained_ms) ) )
      break;

    FD_ZERO (&rs);
    FD_ZERO (&ws);
    FD_ZERO (&es);
    max = 0;
    if (MHD_YES != MHD_get_fdset (daemon,
                                  &rs,
                                  &ws,
                                  &es,
                                  &max))
    {
      fprintf (stderr,
               "Failed to obtain the file descriptor set.\n");
      ret = 1;
      break;
    }
    /* Our own descriptors go into the very same sets. */
    FD_SET (wake_pipe[0],
            &rs);
    if (max < wake_pipe[0])
      max = wake_pipe[0];

    if (0 != draining)
    {
      /* Look at the drain deadline regularly. */
      tv.tv_sec = 0;
      tv.tv_usec = 50 * 1000;
      tvp = &tv;
      drained_ms += 50;
    }
    else if (MHD_YES == MHD_get_timeout64 (daemon,
                                           &mhd_timeout))
    {
      tv.tv_sec = (time_t) (mhd_timeout / 1000);
      tv.tv_usec = ((long) (mhd_timeout % 1000)) * 1000;
      tvp = &tv;
    }
    else
    {
      /* MHD has nothing to wait for.  With every connection suspended
         this is the normal case, and the loop simply sleeps until a
         worker resumes one---which reaches us through MHD's ITC, as it
         is part of the read set above. */
      tvp = NULL;
    }

    if (-1 == select ((int) max + 1,
                      &rs,
                      &ws,
                      &es,
                      tvp))
    {
      if (EINTR == errno)
        continue;
      fprintf (stderr,
               "Aborting due to error during select: %s\n",
               strerror (errno));
      ret = 1;
      break;
    }
    if (FD_ISSET (wake_pipe[0],
                  &rs))
      (void) read (wake_pipe[0],
                   drain_buf,
                   sizeof (drain_buf));
    MHD_run_from_select (daemon,
                         &rs,
                         &ws,
                         &es);
    reap_jobs ();
  }

  stop_all_jobs ();
  reap_jobs ();
  MHD_stop_daemon (daemon);
  close (wake_pipe[0]);
  close (wake_pipe[1]);
  return ret;
}
