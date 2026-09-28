/* Feel free to use this example code in any way
   you see fit (Public Domain) */

/**
 * @file callbackresponse.c
 * @brief   Example for generating a response on the fly with
 *          MHD_create_response_from_callback().  The body is not a
 *          file and is never assembled in memory as a whole; it is
 *          produced block by block into a single heap buffer that is
 *          refilled every time libmicrohttpd asks for more data.
 *          "GET /" streams the document with an unknown size (and thus
 *          with chunked transfer encoding), "GET /sized" streams the
 *          very same document with a "Content-Length" announced up
 *          front, and "GET /error" aborts the stream in the middle to
 *          show MHD_CONTENT_READER_END_WITH_ERROR.
 * @author  Christian Grothoff
 */

#include <sys/types.h>
#ifndef _WIN32
#include <sys/select.h>
#include <sys/socket.h>
#else
#include <winsock2.h>
#endif
#include <microhttpd.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define PORT 8888

/**
 * Length of one generated line, including the newline character.
 */
#define LINE_SIZE 64

/**
 * Size of the heap buffer that is refilled over and over again.  This
 * is the amount of data we produce in one go; it has nothing to do
 * with the block size we pass to MHD.
 */
#define BUFFER_SIZE (64 * LINE_SIZE)

/**
 * Number of times the buffer is refilled before the stream ends.  The
 * complete document is BLOCK_COUNT * BUFFER_SIZE bytes long.
 */
#define BLOCK_COUNT 64

/**
 * Block size we ask MHD to use when it queries our callback.  MHD
 * allocates a buffer of this size together with the response; it is an
 * advisory value and MHD may ask for less.
 */
#define IO_BLOCK_SIZE 1024

/**
 * For the "/error" URL: number of blocks to deliver before the stream
 * is aborted with MHD_CONTENT_READER_END_WITH_ERROR.
 */
#define ABORT_AFTER 3


/**
 * State we keep for one response that is being streamed.  One such
 * structure is allocated per request and released by the free callback
 * that we hand to MHD_create_response_from_callback().
 */
struct ResponseContext
{
  /**
   * Heap buffer holding the block that is currently being delivered.
   * Refilled by generate_block() whenever it has been drained.
   */
  char *buf;

  /**
   * Number of valid bytes in @e buf.
   */
  size_t fill;

  /**
   * Number of bytes of @e buf that were already handed to MHD.
   */
  size_t off;

  /**
   * Number of blocks generated so far, and thus the number of the
   * block that generate_block() will produce next.
   */
  unsigned int block;

  /**
   * Non-zero if this stream is supposed to fail in the middle.
   */
  int fail;
};


/**
 * Produce the next block of the document into @a ctx->buf.  This
 * stands in for whatever expensive computation, database query or
 * network fetch a real application would perform here.  Note that the
 * same buffer is reused for every block, so the memory needed by the
 * server does not grow with the size of the document.
 *
 * Every line is exactly LINE_SIZE bytes long, which is what allows us
 * to announce an exact "Content-Length" for the "/sized" URL.
 *
 * @param ctx the per-response state to refill
 */
static void
generate_block (struct ResponseContext *ctx)
{
  unsigned int i;
  char *line;
  char label[32];
  int len;

  for (i = 0; i < BUFFER_SIZE / LINE_SIZE; i++)
  {
    line = &ctx->buf[i * LINE_SIZE];
    memset (line, '.', LINE_SIZE);
    len = snprintf (label,
                    sizeof (label),
                    "block %3u line %3u ",
                    ctx->block,
                    i);
    if ((0 < len) && (LINE_SIZE > (size_t) len))
      memcpy (line, label, (size_t) len);
    line[LINE_SIZE - 1] = '\n';
  }
  ctx->fill = BUFFER_SIZE;
  ctx->off = 0;
  ctx->block++;
}


/**
 * Callback used by MHD to obtain the next piece of the response body.
 *
 * @param cls our `struct ResponseContext`
 * @param pos number of bytes already returned for this response
 * @param buf where to copy the data
 * @param max maximum number of bytes to copy to @a buf
 * @return number of bytes written to @a buf,
 *         MHD_CONTENT_READER_END_OF_STREAM for the regular end,
 *         MHD_CONTENT_READER_END_WITH_ERROR to abort the transfer
 */
static ssize_t
content_reader (void *cls,
                uint64_t pos,
                char *buf,
                size_t max)
{
  struct ResponseContext *ctx = cls;
  size_t ready;

  /* We generate a pure stream and never look back, so the position is
     of no interest to us.  MHD guarantees that it is the sum of all
     non-negative values we returned so far. */
  (void) pos;                   /* Unused. Silent compiler warning. */

  if (ctx->off == ctx->fill)
  {
    /* Everything we had was passed on, produce the next block. */
    if (BLOCK_COUNT == ctx->block)
      return MHD_CONTENT_READER_END_OF_STREAM;
    if ((0 != ctx->fail) && (ABORT_AFTER == ctx->block))
      return MHD_CONTENT_READER_END_WITH_ERROR;
    generate_block (ctx);
  }
  /* Hand over as much of the current block as MHD is willing to take;
     the rest follows on the next invocation. */
  ready = ctx->fill - ctx->off;
  if (ready > max)
    ready = max;
  memcpy (buf, &ctx->buf[ctx->off], ready);
  ctx->off += ready;
  return (ssize_t) ready;
}


/**
 * Release the resources of a `struct ResponseContext`.  MHD calls this
 * once the response is destroyed, which happens no matter whether the
 * body was transmitted completely or the client went away early.
 *
 * @param cls our `struct ResponseContext`
 */
static void
free_context (void *cls)
{
  struct ResponseContext *ctx = cls;

  free (ctx->buf);
  free (ctx);
}


static enum MHD_Result
answer_to_connection (void *cls, struct MHD_Connection *connection,
                      const char *url, const char *method,
                      const char *version, const char *upload_data,
                      size_t *upload_data_size, void **req_cls)
{
  struct ResponseContext *ctx;
  struct MHD_Response *response;
  enum MHD_Result ret;
  uint64_t size;
  (void) cls;               /* Unused. Silent compiler warning. */
  (void) version;           /* Unused. Silent compiler warning. */
  (void) upload_data;       /* Unused. Silent compiler warning. */
  (void) upload_data_size;  /* Unused. Silent compiler warning. */
  (void) req_cls;           /* Unused. Silent compiler warning. */

  if (0 != strcmp (method, MHD_HTTP_METHOD_GET))
    return MHD_NO;

  /* Allocate the state of this particular response before the response
     object exists; from now on the free callback owns it. */
  ctx = malloc (sizeof (struct ResponseContext));
  if (NULL == ctx)
    return MHD_NO;
  ctx->buf = malloc (BUFFER_SIZE);
  if (NULL == ctx->buf)
  {
    free (ctx);
    return MHD_NO;
  }
  ctx->fill = 0;
  ctx->off = 0;
  ctx->block = 0;
  ctx->fail = (0 == strcmp (url, "/error"));

  /* "/sized" announces the length in advance, everything else is sent
     with an unknown size and thus with chunked transfer encoding. */
  if (0 == strcmp (url, "/sized"))
    size = (uint64_t) BLOCK_COUNT * BUFFER_SIZE;
  else
    size = MHD_SIZE_UNKNOWN;

  response = MHD_create_response_from_callback (size,
                                                IO_BLOCK_SIZE,
                                                &content_reader,
                                                ctx,
                                                &free_context);
  if (NULL == response)
  {
    /* The response was never created, so nobody will call the free
       callback for us. */
    free_context (ctx);
    return MHD_NO;
  }
  (void) MHD_add_response_header (response,
                                  MHD_HTTP_HEADER_CONTENT_TYPE,
                                  "text/plain");
  ret = MHD_queue_response (connection, MHD_HTTP_OK, response);
  MHD_destroy_response (response);

  return ret;
}


int
main (void)
{
  struct MHD_Daemon *daemon;

  daemon = MHD_start_daemon (MHD_USE_AUTO | MHD_USE_INTERNAL_POLLING_THREAD,
                             PORT, NULL, NULL,
                             &answer_to_connection, NULL, MHD_OPTION_END);
  if (NULL == daemon)
    return 1;

  (void) getchar ();

  MHD_stop_daemon (daemon);
  return 0;
}
