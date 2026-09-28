/* Feel free to use this example code in any way
   you see fit (Public Domain) */

/**
 * @file upgrade.c
 * @brief   Minimal example for the HTTP "Upgrade" API of libmicrohttpd.
 *          A "GET /" carrying "Connection: Upgrade" and "Upgrade: echo"
 *          is answered with "101 Switching Protocols"; afterwards the
 *          raw socket speaks a trivial line-based echo protocol until
 *          the client sends the line "QUIT" or closes the connection.
 * @author  Christian Grothoff
 */

#include <sys/types.h>
#ifndef _WIN32
#include <sys/select.h>
#include <sys/socket.h>
#include <fcntl.h>
#else
#include <winsock2.h>
#endif
#include <microhttpd.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>

#define PORT 8888

/**
 * Name of the protocol we are willing to switch to.  Any name would
 * do; "echo" is not registered with IANA and is only used here to keep
 * the example self-contained.
 */
#define PROTOCOL "echo"

/**
 * Maximum length of a line of the echo protocol.  Longer lines are
 * truncated.
 */
#define LINE_SIZE 1024

#define PAGE_UPGRADE_REQUIRED \
  "This resource speaks the \"" PROTOCOL "\" protocol only.\n"

#define PAGE_NOT_FOUND \
  "Not found.\n"


/**
 * State of the line-based echo protocol for one connection.
 */
struct EchoState
{
  /**
   * Bytes of the line received so far (without the line terminator).
   */
  char line[LINE_SIZE];

  /**
   * Number of valid bytes in @e line.
   */
  size_t line_len;
};


/**
 * Compare the first @a len bytes of @a a and @a b, ignoring case.
 * Only ASCII letters are folded, which is all HTTP tokens may contain.
 *
 * @param a first string
 * @param b second string
 * @param len number of bytes to compare
 * @return 1 if the strings match, 0 if they do not
 */
static int
equal_caseless (const char *a,
                const char *b,
                size_t len)
{
  size_t i;

  for (i = 0; i < len; i++)
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
 * Check whether the comma-separated list @a value contains the token
 * @a token.  Both the "Connection:" and the "Upgrade:" request header
 * fields are lists, so a client may legitimately send
 * "Connection: keep-alive, Upgrade"; a plain string comparison against
 * the whole field value would reject such a request.
 *
 * @param value the header field value, may be NULL
 * @param token the token to look for, compared case-insensitively
 * @return 1 if @a token is one of the tokens in @a value, 0 if not
 */
static int
has_token (const char *value,
           const char *token)
{
  const size_t token_len = strlen (token);
  const char *pos = value;

  if (NULL == value)
    return 0;
  while ('\0' != *pos)
  {
    const char *end;
    size_t len;

    /* skip separators and optional whitespace before the token */
    while ((',' == *pos) || (' ' == *pos) || ('\t' == *pos))
      pos++;
    end = pos;
    while (('\0' != *end) && (',' != *end))
      end++;
    len = (size_t) (end - pos);
    /* strip optional whitespace after the token */
    while ((0 != len) &&
           ((' ' == pos[len - 1]) || ('\t' == pos[len - 1])))
      len--;
    if ((len == token_len) &&
        (equal_caseless (pos, token, token_len)))
      return 1;
    pos = end;
    if ('\0' != *pos)
      pos++;   /* skip the comma */
  }
  return 0;
}


/**
 * Send @a len bytes from @a buf over @a sock, retrying until either
 * everything was sent or the connection broke.
 *
 * @param sock the socket to write to
 * @param buf the data to send
 * @param len number of bytes in @a buf
 * @return 1 on success, 0 if the connection broke
 */
static int
send_all (MHD_socket sock,
          const char *buf,
          size_t len)
{
  ssize_t ret;
  size_t off;

  for (off = 0; off < len; off += (size_t) ret)
  {
    ret = send (sock,
                buf + off,
                (int) (len - off),
                0);
    if (0 > ret)
    {
      if (EINTR == errno)
      {
        ret = 0;
        continue;
      }
      return 0;
    }
    if (0 == ret)
      return 0;
  }
  return 1;
}


/**
 * Make @a sock blocking.  MHD hands out the socket in non-blocking
 * mode, see the tutorial chapter for the reason why.  This function
 * contains the only operating-system-dependent code of this example.
 *
 * @param sock the socket to modify
 */
static void
make_blocking (MHD_socket sock)
{
#ifndef _WIN32
  int flags;

  flags = fcntl (sock, F_GETFL);
  if (-1 == flags)
    abort ();
  if ((flags & ~O_NONBLOCK) != flags)
    if (-1 == fcntl (sock, F_SETFL, flags & ~O_NONBLOCK))
      abort ();
#else  /* _WIN32 */
  unsigned long flags = 0;

  if (0 != ioctlsocket (sock, (int) FIONBIO, &flags))
    abort ();
#endif /* _WIN32 */
}


/**
 * Feed @a size bytes of received data into the echo protocol state
 * machine, echoing back every complete line.
 *
 * @param sock the socket to echo to
 * @param es the protocol state of this connection
 * @param data the received bytes
 * @param size number of bytes in @a data
 * @return 1 if the client asked us to stop or the connection broke,
 *         0 if we should keep going
 */
static int
echo_feed (MHD_socket sock,
           struct EchoState *es,
           const char *data,
           size_t size)
{
  size_t i;

  for (i = 0; i < size; i++)
  {
    if ('\n' != data[i])
    {
      if (es->line_len < sizeof (es->line))
        es->line[es->line_len++] = data[i];
      /* else: line too long, drop the excess bytes */
      continue;
    }
    /* A complete line was received; drop the CR of a CRLF terminator */
    if ((0 != es->line_len) &&
        ('\r' == es->line[es->line_len - 1]))
      es->line_len--;
    if ((4 == es->line_len) &&
        (equal_caseless (es->line, "QUIT", 4)))
    {
      (void) send_all (sock, "BYE\r\n", 5);
      es->line_len = 0;
      return 1;
    }
    if ((! send_all (sock, es->line, es->line_len)) ||
        (! send_all (sock, "\r\n", 2)))
      return 1;
    es->line_len = 0;
  }
  return 0;
}


/**
 * Called by MHD once the "101 Switching Protocols" response was sent.
 * From here on MHD is out of the picture: @a sock is an ordinary
 * socket and we are free to speak whatever protocol we like on it.
 *
 * As the daemon runs with #MHD_USE_THREAD_PER_CONNECTION, this
 * function has a thread of its own and may block for as long as it
 * wants.
 *
 * @param cls closure given to #MHD_create_response_for_upgrade()
 * @param connection the original HTTP connection
 * @param req_cls last value of @a req_cls of the access handler
 * @param extra_in bytes the client sent after the request header and
 *                 which MHD read together with the header
 * @param extra_in_size number of bytes in @a extra_in
 * @param sock the socket to talk to the client on
 * @param urh handle to pass to #MHD_upgrade_action()
 */
static void
upgrade_handler (void *cls,
                 struct MHD_Connection *connection,
                 void *req_cls,
                 const char *extra_in,
                 size_t extra_in_size,
                 MHD_socket sock,
                 struct MHD_UpgradeResponseHandle *urh)
{
  struct EchoState es;
  char buf[256];
  ssize_t got;
  int done;

  (void) cls;         /* Unused. Silent compiler warning. */
  (void) connection;  /* Unused. Silent compiler warning. */
  (void) req_cls;     /* Unused. Silent compiler warning. */

  /* MHD hands out a non-blocking socket; this example wants to use
     plain blocking recv()/send() calls on it. */
  make_blocking (sock);

  es.line_len = 0;

  /* The client may have pipelined payload directly behind the request
     header, in which case MHD has read it already.  Those bytes are
     gone from the socket, so they must be processed first. */
  done = echo_feed (sock,
                    &es,
                    extra_in,
                    extra_in_size);

  while (0 == done)
  {
    got = recv (sock,
                buf,
                sizeof (buf),
                0);
    if (0 > got)
    {
      if (EINTR == errno)
        continue;
      break;            /* read error */
    }
    if (0 == got)
      break;            /* client closed the connection */
    done = echo_feed (sock,
                      &es,
                      buf,
                      (size_t) got);
  }

  /* Hand the socket back to MHD.  This is the only legal way to get
     rid of it; never call close() on it ourselves, and note that the
     connection is not cleaned up before this call happens. */
  MHD_upgrade_action (urh,
                      MHD_UPGRADE_ACTION_CLOSE);
}


/**
 * Answer an ordinary HTTP request from a static string.
 *
 * @param connection the connection to answer
 * @param status_code the HTTP status code to use
 * @param page the response body
 * @param offer_upgrade if true, advertise our protocol in an
 *                      "Upgrade:" header field
 * @return #MHD_YES on success, #MHD_NO on error
 */
static enum MHD_Result
answer_plain (struct MHD_Connection *connection,
              unsigned int status_code,
              const char *page,
              int offer_upgrade)
{
  struct MHD_Response *response;
  enum MHD_Result ret;

  response = MHD_create_response_from_buffer_static (strlen (page),
                                                     page);
  if (NULL == response)
    return MHD_NO;
  if (offer_upgrade)
    (void) MHD_add_response_header (response,
                                    MHD_HTTP_HEADER_UPGRADE,
                                    PROTOCOL);
  ret = MHD_queue_response (connection,
                            status_code,
                            response);
  MHD_destroy_response (response);
  return ret;
}


static enum MHD_Result
access_handler (void *cls,
                struct MHD_Connection *connection,
                const char *url,
                const char *method,
                const char *version,
                const char *upload_data,
                size_t *upload_data_size,
                void **req_cls)
{
  struct MHD_Response *response;
  enum MHD_Result ret;

  (void) cls;               /* Unused. Silent compiler warning. */
  (void) upload_data;       /* Unused. Silent compiler warning. */
  (void) upload_data_size;  /* Unused. Silent compiler warning. */
  (void) req_cls;           /* Unused. Silent compiler warning. */

  if (0 != strcmp (url, "/"))
    return answer_plain (connection,
                         MHD_HTTP_NOT_FOUND,
                         PAGE_NOT_FOUND,
                         0);
  /* Upgrading requires HTTP/1.1 and a request that actually asks for
     our protocol.  A client that does not ask gets a plain 426. */
  if ((0 != strcmp (method, MHD_HTTP_METHOD_GET)) ||
      (0 != strcmp (version, MHD_HTTP_VERSION_1_1)) ||
      (! has_token (MHD_lookup_connection_value (connection,
                                                 MHD_HEADER_KIND,
                                                 MHD_HTTP_HEADER_CONNECTION),
                    "Upgrade")) ||
      (! has_token (MHD_lookup_connection_value (connection,
                                                 MHD_HEADER_KIND,
                                                 MHD_HTTP_HEADER_UPGRADE),
                    PROTOCOL)))
    return answer_plain (connection,
                         MHD_HTTP_UPGRADE_REQUIRED,
                         PAGE_UPGRADE_REQUIRED,
                         1);

  /* The request is fine, switch protocols.  MHD already put
     "Connection: Upgrade" into the response for us, we only have to
     name the protocol we switch to. */
  response = MHD_create_response_for_upgrade (&upgrade_handler,
                                              NULL);
  if (NULL == response)
    return MHD_NO;
  if (MHD_YES !=
      MHD_add_response_header (response,
                               MHD_HTTP_HEADER_UPGRADE,
                               PROTOCOL))
  {
    MHD_destroy_response (response);
    return MHD_NO;
  }
  ret = MHD_queue_response (connection,
                            MHD_HTTP_SWITCHING_PROTOCOLS,
                            response);
  /* The response may be destroyed right away: MHD keeps its own
     reference until the upgrade handler has been called. */
  MHD_destroy_response (response);
  return ret;
}


int
main (void)
{
  struct MHD_Daemon *daemon;

  daemon = MHD_start_daemon (MHD_USE_THREAD_PER_CONNECTION
                             | MHD_USE_INTERNAL_POLLING_THREAD
                             | MHD_ALLOW_UPGRADE
                             | MHD_USE_ERROR_LOG,
                             PORT, NULL, NULL,
                             &access_handler, NULL,
                             MHD_OPTION_END);
  if (NULL == daemon)
    return 1;

  (void) getchar ();

  MHD_stop_daemon (daemon);
  return 0;
}
