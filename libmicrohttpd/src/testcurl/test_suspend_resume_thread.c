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
 * @file test_suspend_resume_thread.c
 * @brief  Testcase for suspend/resume with a thread per connection
 *
 * The content reader suspends the connection and returns zero, which is
 * the pattern microhttpd.h prescribes for "no body data yet".  The
 * resume comes from a separate thread, as it would from an application
 * that is waiting on some other I/O.  Several clients run at once and
 * every response stalls repeatedly, so a single lost resume anywhere
 * hangs the connection it belongs to and the body arrives short.
 *
 * @author Christian Grothoff
 */
#include "mhd_options.h"
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <pthread.h>
#include <curl/curl.h>
#include <microhttpd.h>

/* Turn any MHD_PANIC() or failing mhd_assert() reached from this
   test into a marked, classifiable test error (TESTING.md, P5). */
#include "mhd_panic_tripwire.h"

#ifndef WINDOWS
#include <unistd.h>
#endif

/**
 * Number of clients to run against the daemon at the same time.
 */
#define NUM_CLIENTS 4

/**
 * Total size of the response body.
 */
#define BODY_SIZE 64

/**
 * Number of bytes the content reader hands out at a time.
 */
#define CHUNK_SIZE 8

/**
 * Number of times the content reader stalls before each chunk.
 */
#define NUM_STALLS 3

/**
 * The byte the response body is made of.
 */
#define BODY_FILL 'x'


struct ReaderData
{
  /**
   * Connection to suspend and resume.
   */
  struct MHD_Connection *connection;

  /**
   * Number of stalls left before the next chunk is handed out.
   */
  unsigned int stalls_left;
};


static uint16_t port;

static volatile unsigned int panicked;


_MHD_NORETURN static void
test_panic_cb (void *cls,
               const char *file,
               unsigned int line,
               const char *reason)
{
  (void) cls;
  fprintf (stderr,
           "PANIC: %s at %s:%u\n",
           (NULL != reason) ? reason : "",
           file,
           line);
  panicked = 1;
  exit (99);
}


static void *
resume_thread (void *cls)
{
  /* Give the connection's thread a chance to actually park itself,
     so that the resume has to travel between threads. */
  (void) usleep (1000);
  MHD_resume_connection (cls);
  return NULL;
}


static ssize_t
content_reader (void *cls,
                uint64_t pos,
                char *buf,
                size_t max)
{
  struct ReaderData *data = cls;
  pthread_t tid;

  if (pos >= BODY_SIZE)
    return MHD_CONTENT_READER_END_OF_STREAM;
  if (0 != data->stalls_left)
  {
    /* No data yet.  Park the connection and report that, as
       documented for #MHD_ContentReaderCallback. */
    data->stalls_left--;
    MHD_suspend_connection (data->connection);
    if (0 != pthread_create (&tid,
                             NULL,
                             &resume_thread,
                             data->connection))
      return MHD_CONTENT_READER_END_WITH_ERROR;
    (void) pthread_detach (tid);
    return 0;
  }
  data->stalls_left = NUM_STALLS;
  if (max > CHUNK_SIZE)
    max = CHUNK_SIZE;
  if (max > (size_t) (BODY_SIZE - pos))
    max = (size_t) (BODY_SIZE - pos);
  memset (buf,
          BODY_FILL,
          max);
  return (ssize_t) max;
}


static void
free_reader_data (void *cls)
{
  free (cls);
}


static enum MHD_Result
ahc_echo (void *cls,
          struct MHD_Connection *connection,
          const char *url,
          const char *method,
          const char *version,
          const char *upload_data,
          size_t *upload_data_size,
          void **req_cls)
{
  static int marker;
  struct MHD_Response *response;
  struct ReaderData *data;
  enum MHD_Result ret;
  (void) cls; (void) url; (void) method; (void) version;
  (void) upload_data; (void) upload_data_size;

  if (&marker != *req_cls)
  {
    *req_cls = &marker;
    return MHD_YES;
  }
  data = malloc (sizeof (struct ReaderData));
  if (NULL == data)
    return MHD_NO;
  data->connection = connection;
  data->stalls_left = NUM_STALLS;
  response = MHD_create_response_from_callback (BODY_SIZE,
                                                4096,
                                                &content_reader,
                                                data,
                                                &free_reader_data);
  if (NULL == response)
  {
    free (data);
    return MHD_NO;
  }
  ret = MHD_queue_response (connection,
                            MHD_HTTP_OK,
                            response);
  MHD_destroy_response (response);
  return ret;
}


struct Buffer
{
  size_t used;
  char data[2 * BODY_SIZE];
};


static size_t
copy_buffer (void *ptr,
             size_t size,
             size_t nmemb,
             void *cls)
{
  struct Buffer *buf = cls;

  if (0 == size * nmemb)
    return 0;
  if (buf->used + size * nmemb > sizeof (buf->data))
    return 0; /* overflow */
  memcpy (&buf->data[buf->used],
          ptr,
          size * nmemb);
  buf->used += size * nmemb;
  return size * nmemb;
}


/**
 * Fetch the response once.
 *
 * @param cls unused
 * @return NULL on success, non-NULL on failure
 */
static void *
client_thread (void *cls)
{
  static int failure = 1;
  char url[128];
  struct Buffer buf;
  CURL *c;
  CURLcode errornum;
  (void) cls;

  memset (&buf, 0, sizeof (buf));
  c = curl_easy_init ();
  if (NULL == c)
    return &failure;
  snprintf (url,
            sizeof (url),
            "http://127.0.0.1:%u/",
            (unsigned int) port);
  curl_easy_setopt (c, CURLOPT_URL, url);
  curl_easy_setopt (c, CURLOPT_WRITEFUNCTION, &copy_buffer);
  curl_easy_setopt (c, CURLOPT_WRITEDATA, &buf);
  curl_easy_setopt (c, CURLOPT_FAILONERROR, 1L);
  curl_easy_setopt (c, CURLOPT_TIMEOUT, 30L);
  curl_easy_setopt (c, CURLOPT_CONNECTTIMEOUT, 30L);
  curl_easy_setopt (c, CURLOPT_HTTP_VERSION, CURL_HTTP_VERSION_1_1);
  errornum = curl_easy_perform (c);
  curl_easy_cleanup (c);
  if (CURLE_OK != errornum)
  {
    fprintf (stderr,
             "curl_easy_perform() failed: `%s'\n",
             curl_easy_strerror (errornum));
    return &failure;
  }
  if (BODY_SIZE != buf.used)
  {
    fprintf (stderr,
             "Got %u bytes of body, expected %u.\n",
             (unsigned int) buf.used,
             (unsigned int) BODY_SIZE);
    return &failure;
  }
  if (BODY_SIZE != strspn (buf.data, "x"))
  {
    fprintf (stderr,
             "Body has unexpected content.\n");
    return &failure;
  }
  return NULL;
}


/**
 * Run all clients against a daemon started with the given flags.
 *
 * @param flags the flags to start the daemon with
 * @return 0 on success
 */
static unsigned int
test_daemon (unsigned int flags)
{
  pthread_t clients[NUM_CLIENTS];
  struct MHD_Daemon *d;
  const union MHD_DaemonInfo *dinfo;
  void *res;
  unsigned int i;
  unsigned int started;
  unsigned int failures;

  d = MHD_start_daemon (flags
                        | MHD_USE_THREAD_PER_CONNECTION
                        | MHD_USE_INTERNAL_POLLING_THREAD
                        | MHD_ALLOW_SUSPEND_RESUME
                        | MHD_USE_ERROR_LOG,
                        0,
                        NULL, NULL,
                        &ahc_echo, NULL,
                        MHD_OPTION_END);
  if (NULL == d)
  {
    fprintf (stderr,
             "Failed to start daemon with flags %x.\n",
             flags);
    return 1;
  }
  dinfo = MHD_get_daemon_info (d,
                               MHD_DAEMON_INFO_BIND_PORT);
  if ( (NULL == dinfo) ||
       (0 == dinfo->port) )
  {
    MHD_stop_daemon (d);
    fprintf (stderr,
             "Failed to get the port number.\n");
    return 1;
  }
  port = dinfo->port;

  failures = 0;
  for (started = 0; started < NUM_CLIENTS; started++)
  {
    if (0 != pthread_create (&clients[started],
                             NULL,
                             &client_thread,
                             NULL))
    {
      fprintf (stderr,
               "Failed to create a client thread.\n");
      failures++;
      break;
    }
  }
  for (i = 0; i < started; i++)
  {
    res = NULL;
    if (0 != pthread_join (clients[i],
                           &res))
    {
      fprintf (stderr,
               "Failed to join a client thread.\n");
      failures++;
    }
    else if (NULL != res)
      failures++;
  }
  MHD_stop_daemon (d);
  return failures;
}


int
main (int argc,
      char *const *argv)
{
  unsigned int failures = 0;
  (void) argc; (void) argv;

  MHD_set_panic_func (&test_panic_cb,
                      NULL);
  if (0 != curl_global_init (CURL_GLOBAL_WIN32))
    return 2;
  /* Without an ITC, and with one; both use select() internally. */
  failures += test_daemon (0);
  failures += test_daemon (MHD_USE_ITC);
  if (MHD_NO != MHD_is_feature_supported (MHD_FEATURE_POLL))
    failures += test_daemon (MHD_USE_POLL | MHD_USE_ITC);
  curl_global_cleanup ();
  if (0 != panicked)
    return 99;
  return (0 == failures) ? 0 : 1;
}
