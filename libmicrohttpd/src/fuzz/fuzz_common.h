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
 * @file fuzz/fuzz_common.h
 * @brief Shared, header-only fuzzing driver for the MHD in-process fuzzers.
 * @author Christian Grothoff
 *
 * Every harness in this directory is a single translation unit that
 * includes this header.  The header provides:
 *  - a deterministic, seeded PRNG (splitmix64 / xoshiro256**),
 *  - a generic byte-level mutator,
 *  - crash bookkeeping (the input of the currently running iteration is
 *    dumped to the crash directory whenever the process dies),
 *  - a standalone @c main() driver (generator + mutator loop, corpus
 *    replay, single-file replay) so that the harnesses are usable with
 *    a plain gcc + ASAN/UBSAN build, i.e. without clang/libFuzzer.
 *
 * The harness itself must provide:
 *  - @c LLVMFuzzerTestOneInput() (the actual fuzz target),
 *  - @c fuzz_generate() (a structure-aware input generator),
 *  - @c fuzz_seed_count() / @c fuzz_seed_get() (a built-in seed corpus).
 *
 * Define @c FUZZ_NO_MAIN when linking against libFuzzer or AFL++'s
 * driver, which supply their own @c main().
 */

#ifndef MHD_FUZZ_COMMON_H
#define MHD_FUZZ_COMMON_H 1

#include <stdint.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <signal.h>
#include <errno.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <dirent.h>

#ifndef FUZZ_HARNESS_NAME
#define FUZZ_HARNESS_NAME "fuzz"
#endif

/**
 * Not every harness uses every helper; silence -Wunused-function.
 */
#define FUZZ_UNUSED __attribute__ ((unused))

/**
 * Hard upper bound on the size of a single fuzz input.
 */
#ifndef FUZZ_MAX_INPUT
#define FUZZ_MAX_INPUT 32768
#endif

/**
 * Default number of iterations of the built-in driver.  Kept small so
 * that "make check" stays in the "couple of seconds" range; raise with
 * --iterations=N or the MHD_FUZZ_ITERATIONS environment variable.
 */
#ifndef FUZZ_DEFAULT_ITERATIONS
#define FUZZ_DEFAULT_ITERATIONS 3000
#endif

/**
 * Default per-iteration watchdog, in seconds.
 */
#ifndef FUZZ_DEFAULT_TIMEOUT
#define FUZZ_DEFAULT_TIMEOUT 20
#endif


/* ------------------------------------------------------------------ */
/* Interface to be implemented by each harness                        */
/* ------------------------------------------------------------------ */

/**
 * The fuzz target.  Signature is the libFuzzer one on purpose, so that
 * the very same harness can be linked with libFuzzer or AFL++ later.
 */
int
LLVMFuzzerTestOneInput (const uint8_t *data,
                        size_t size);

struct fuzz_rng;

/**
 * Structure-aware generator used by the built-in standalone driver.
 * Must write at most @a cap bytes to @a buf and return the number of
 * bytes written.  Purely random bytes almost never form a valid HTTP
 * request, so this is what actually makes the gcc-only driver useful.
 */
FUZZ_UNUSED static size_t
fuzz_generate (struct fuzz_rng *rng,
               uint8_t *buf,
               size_t cap);

/**
 * @return number of entries in the built-in seed corpus
 */
FUZZ_UNUSED static size_t
fuzz_seed_count (void);

/**
 * @param idx index of the seed to retrieve
 * @param[out] len set to the length of the seed
 * @return pointer to the seed bytes
 */
FUZZ_UNUSED static const uint8_t *
fuzz_seed_get (size_t idx,
               size_t *len);


/* ------------------------------------------------------------------ */
/* Deterministic PRNG                                                  */
/* ------------------------------------------------------------------ */

struct fuzz_rng
{
  uint64_t s[4];
};

FUZZ_UNUSED static uint64_t
fuzz_splitmix64 (uint64_t *x)
{
  uint64_t z;

  *x += UINT64_C (0x9E3779B97F4A7C15);
  z = *x;
  z = (z ^ (z >> 30)) * UINT64_C (0xBF58476D1CE4E5B9);
  z = (z ^ (z >> 27)) * UINT64_C (0x94D049BB133111EB);
  return z ^ (z >> 31);
}


FUZZ_UNUSED static void
fuzz_rng_seed (struct fuzz_rng *r,
               uint64_t seed)
{
  uint64_t x = seed;
  unsigned int i;

  for (i = 0; i < 4; i++)
    r->s[i] = fuzz_splitmix64 (&x);
}


FUZZ_UNUSED static uint64_t
fuzz_rot64 (uint64_t x,
            unsigned int k)
{
  return (x << k) | (x >> (64 - k));
}


/**
 * xoshiro256** -- small, fast, deterministic and identical on every
 * platform, which is what we need for reproducible fuzzing runs.
 */
FUZZ_UNUSED static uint64_t
fuzz_next (struct fuzz_rng *r)
{
  const uint64_t res = fuzz_rot64 (r->s[1] * 5, 7) * 9;
  const uint64_t t = r->s[1] << 17;

  r->s[2] ^= r->s[0];
  r->s[3] ^= r->s[1];
  r->s[1] ^= r->s[2];
  r->s[0] ^= r->s[3];
  r->s[2] ^= t;
  r->s[3] = fuzz_rot64 (r->s[3], 45);
  return res;
}


/**
 * @return uniformly distributed value in [0, n), 0 if @a n is 0
 */
FUZZ_UNUSED static uint32_t
fuzz_below (struct fuzz_rng *r,
            uint32_t n)
{
  if (0 == n)
    return 0;
  return (uint32_t) (fuzz_next (r) % n);
}


FUZZ_UNUSED static uint8_t
fuzz_byte (struct fuzz_rng *r)
{
  return (uint8_t) (fuzz_next (r) & 0xFF);
}


/**
 * @return true with a probability of 1/@a n
 */
FUZZ_UNUSED static int
fuzz_chance (struct fuzz_rng *r,
             uint32_t n)
{
  return 0 == fuzz_below (r, n);
}


/* ------------------------------------------------------------------ */
/* Global driver state                                                 */
/* ------------------------------------------------------------------ */

/**
 * Non-zero if the input of the current iteration comes from a trusted
 * source (the built-in generator, the built-in seed corpus, --file or
 * --corpus-dir) and has NOT been mutated afterwards.  Harnesses use
 * this to enable "ground truth" oracles, e.g. the expected decoded
 * request body that a generated chunked request declares.  Random
 * mutations invalidate such declarations, hence the flag.
 */
FUZZ_UNUSED static int fuzz_pristine;

/**
 * Non-zero to let the harness enable MHD's own error log.
 */
FUZZ_UNUSED static int fuzz_verbose;

/**
 * Non-zero to skip the replay of the built-in seed corpus at the start
 * of a run (useful when a seed is known to trigger an already-reported
 * finding and one wants to look for others).
 */
FUZZ_UNUSED static int fuzz_skip_seeds;

/* Only read by the built-in driver; under -DFUZZ_NO_MAIN (the libFuzzer
   and AFL++ builds, see contrib/oss-fuzz/build.sh) they are written but
   never read, which is not a defect. */
FUZZ_UNUSED static uint64_t fuzz_cur_seed;
FUZZ_UNUSED static uint64_t fuzz_cur_iter;
static const uint8_t *fuzz_cur_input;
static size_t fuzz_cur_input_len;
static const char *fuzz_crash_dir = "crashes";

/* Pre-rendered, so that the death/signal handlers stay
   async-signal-safe (no snprintf, no malloc). */
static char fuzz_crash_path[512];
static char fuzz_crash_msg[512];
static volatile sig_atomic_t fuzz_dumped;


FUZZ_UNUSED static void
fuzz_write_all (int fd,
                const void *buf,
                size_t len)
{
  const char *p = (const char *) buf;

  while (0 != len)
  {
    ssize_t w = write (fd, p, len);
    if (0 >= w)
      break;
    p += w;
    len -= (size_t) w;
  }
}


FUZZ_UNUSED static void
fuzz_msg (const char *s)
{
  fuzz_write_all (STDERR_FILENO, s, strlen (s));
}


/**
 * Dump the input of the currently running iteration so that the
 * failure can be replayed with --file=...  Async-signal-safe.
 */
FUZZ_UNUSED static void
fuzz_dump_current (void)
{
  int fd;

  if (fuzz_dumped)
    return;
  fuzz_dumped = 1;
  if ( (NULL == fuzz_cur_input) ||
       ('\0' == fuzz_crash_path[0]) )
    return;
  (void) mkdir (fuzz_crash_dir, 0755);
  fd = open (fuzz_crash_path,
             O_WRONLY | O_CREAT | O_TRUNC,
             0644);
  if (0 > fd)
  {
    fuzz_msg ("\n*** FUZZ: failed to write crash file ***\n");
    return;
  }
  fuzz_write_all (fd, fuzz_cur_input, fuzz_cur_input_len);
  (void) close (fd);
  fuzz_msg ("\n*** FUZZ: reproducer written to ");
  fuzz_msg (fuzz_crash_path);
  fuzz_msg (" ***\n*** FUZZ: ");
  fuzz_msg (fuzz_crash_msg);
  fuzz_msg (" ***\n");
}


FUZZ_UNUSED static void
fuzz_death_callback (void)
{
  fuzz_dump_current ();
}


FUZZ_UNUSED static void
fuzz_sig_handler (int sig)
{
  fuzz_dump_current ();
  if (SIGALRM == sig)
  {
    fuzz_msg ("*** FUZZ: HANG detected (watchdog fired) ***\n");
    _exit (99);
  }
  /* restore default handler and re-raise so that the usual
     ASAN/abort diagnostics are produced */
  signal (sig, SIG_DFL);
  raise (sig);
}


/**
 * Report a logical (non-memory-safety) finding: dump the reproducer
 * and abort so that the failure is impossible to overlook.
 */
FUZZ_UNUSED static void
fuzz_report_finding (const char *what)
{
  size_t l = strlen (what);

  if (l >= sizeof (fuzz_crash_msg))
    l = sizeof (fuzz_crash_msg) - 1;
  memcpy (fuzz_crash_msg, what, l);
  fuzz_crash_msg[l] = '\0';
  fuzz_msg ("\n*** FUZZ FINDING: ");
  fuzz_msg (fuzz_crash_msg);
  fuzz_msg (" ***\n");
  fuzz_dump_current ();
  abort ();
}


/* Weak declaration: resolved when built with ASAN (gcc or clang),
   NULL otherwise.  ASAN calls this right before it terminates the
   process, which is the only reliable hook when abort_on_error=0. */
extern void
__sanitizer_set_death_callback (void (*cb)(void)) __attribute__ ((weak));


/**
 * Ignore SIGPIPE.  Idempotent, so it is safe to call on every execution.
 *
 * This deliberately lives OUTSIDE the #ifndef FUZZ_NO_MAIN block below,
 * because it is needed by the fuzz *target*, not merely by the built-in
 * driver.  fuzz_request writes into an AF_UNIX socketpair whose peer end
 * MHD may already have closed (any input that makes the daemon drop the
 * connection early does this), and a write() to a socket with no reader
 * raises SIGPIPE.
 *
 * None of the external engines does this for us: libFuzzer intercepts
 * SEGV/BUS/ABRT/ILL/FPE/INT/TERM/XFSZ/USR1/USR2 and has no
 * -handle_sigpipe flag at all, and AFL++/honggfuzz likewise leave the
 * default disposition in place.  So without this call an OSS-Fuzz build
 * of fuzz_request is killed by SIGPIPE after a few dozen executions,
 * with no stack trace, no artifact and no report -- the target simply
 * stops fuzzing.  Measured here: dead after ~28 execs without it,
 * 540000 execs in 31 s with it.
 */
FUZZ_UNUSED static void
fuzz_ignore_sigpipe (void)
{
  static int sigpipe_ignored;

  if (sigpipe_ignored)
    return;
  sigpipe_ignored = 1;
  (void) signal (SIGPIPE, SIG_IGN);
}


#ifndef FUZZ_NO_MAIN

static void
fuzz_install_handlers (void)
{
  struct sigaction sa;

  if (NULL != __sanitizer_set_death_callback)
    __sanitizer_set_death_callback (&fuzz_death_callback);
  memset (&sa, 0, sizeof (sa));
  sa.sa_handler = &fuzz_sig_handler;
  sigemptyset (&sa.sa_mask);
  sa.sa_flags = 0;
  (void) sigaction (SIGABRT, &sa, NULL);
  (void) sigaction (SIGSEGV, &sa, NULL);
  (void) sigaction (SIGBUS, &sa, NULL);
  (void) sigaction (SIGILL, &sa, NULL);
  (void) sigaction (SIGFPE, &sa, NULL);
  (void) sigaction (SIGALRM, &sa, NULL);
  fuzz_ignore_sigpipe ();
}


/**
 * Remember which input we are about to feed to the target, and
 * pre-render the name of the file it would be dumped to.
 */
static void
fuzz_set_current (const uint8_t *data,
                  size_t size,
                  const char *tag)
{
  fuzz_cur_input = data;
  fuzz_cur_input_len = size;
  fuzz_dumped = 0;
  (void) snprintf (fuzz_crash_path,
                   sizeof (fuzz_crash_path),
                   "%s/crash-%s-seed%llu-iter%llu.bin",
                   fuzz_crash_dir,
                   FUZZ_HARNESS_NAME,
                   (unsigned long long) fuzz_cur_seed,
                   (unsigned long long) fuzz_cur_iter);
  (void) snprintf (fuzz_crash_msg,
                   sizeof (fuzz_crash_msg),
                   "harness=%s seed=%llu iteration=%llu source=%s",
                   FUZZ_HARNESS_NAME,
                   (unsigned long long) fuzz_cur_seed,
                   (unsigned long long) fuzz_cur_iter,
                   tag);
}


/* ------------------------------------------------------------------ */
/* Generic byte-level mutator                                          */
/* ------------------------------------------------------------------ */

static const uint8_t fuzz_interesting[] = {
  0x00, 0x01, 0x07, 0x09, 0x0A, 0x0D, 0x20, 0x22, 0x25, 0x26, 0x27,
  0x2C, 0x2D, 0x2E, 0x2F, 0x30, 0x31, 0x3A, 0x3B, 0x3D, 0x3F, 0x40,
  0x5C, 0x7B, 0x7D, 0x7F, 0x80, 0xC0, 0xFE, 0xFF
};

static const char *const fuzz_interesting_str[] = {
  "\r\n", "\r\n\r\n", "\n", "%", "%%NONCE%%", ";", "=", "\"", "\\",
  "chunked", "Transfer-Encoding: ", "Content-Length: ", "algorithm=",
  "userhash=true", "Authorization: Digest ", "Authorization: Basic ",
  "boundary=", "multipart/form-data", "0\r\n\r\n", "?", "&",
  "aaaaaaaaaaaaaaaa"
};


/**
 * Apply a single random mutation to @a buf.
 *
 * @param rng the PRNG state
 * @param[in,out] buf the buffer to mutate
 * @param len current length
 * @param cap capacity of @a buf
 * @return new length
 */
static size_t
fuzz_mutate_once (struct fuzz_rng *rng,
                  uint8_t *buf,
                  size_t len,
                  size_t cap)
{
  uint32_t op;

  if (0 == len)
  {
    buf[0] = fuzz_byte (rng);
    return 1;
  }
  op = fuzz_below (rng, 10);
  switch (op)
  {
  case 0:                      /* bit flip */
    {
      size_t p = fuzz_below (rng, (uint32_t) len);
      buf[p] = (uint8_t) (buf[p] ^ (1u << fuzz_below (rng, 8)));
      break;
    }
  case 1:                      /* random byte */
    buf[fuzz_below (rng, (uint32_t) len)] = fuzz_byte (rng);
    break;
  case 2:                      /* interesting byte */
    buf[fuzz_below (rng, (uint32_t) len)] =
      fuzz_interesting[fuzz_below (rng,
                                   (uint32_t) (sizeof (fuzz_interesting)))];
    break;
  case 3:                      /* add/sub small value */
    {
      size_t p = fuzz_below (rng, (uint32_t) len);
      buf[p] = (uint8_t) (buf[p] + (int) fuzz_below (rng, 17) - 8);
      break;
    }
  case 4:                      /* erase a run */
    {
      size_t p = fuzz_below (rng, (uint32_t) len);
      size_t n = 1 + fuzz_below (rng, (uint32_t) (len - p));
      memmove (buf + p, buf + p + n, len - p - n);
      len -= n;
      break;
    }
  case 5:                      /* insert repeated byte */
    {
      size_t p = fuzz_below (rng, (uint32_t) len + 1);
      size_t n = 1 + fuzz_below (rng, 32);
      uint8_t v = fuzz_byte (rng);
      if (len + n > cap)
        n = cap - len;
      if (0 == n)
        break;
      memmove (buf + p + n, buf + p, len - p);
      memset (buf + p, v, n);
      len += n;
      break;
    }
  case 6:                      /* duplicate a chunk */
    {
      size_t p = fuzz_below (rng, (uint32_t) len);
      size_t n = 1 + fuzz_below (rng, (uint32_t) (len - p));
      size_t d = fuzz_below (rng, (uint32_t) len + 1);
      if (len + n > cap)
        n = cap - len;
      if (0 == n)
        break;
      memmove (buf + d + n, buf + d, len - d);
      memmove (buf + d, buf + ((p >= d) ? (p + n) : p), n);
      len += n;
      break;
    }
  case 7:                      /* insert an interesting token */
    {
      const char *s =
        fuzz_interesting_str[fuzz_below (rng,
                                         (uint32_t)
                                         (sizeof (fuzz_interesting_str)
                                          / sizeof (fuzz_interesting_str[0])))];
      size_t n = strlen (s);
      size_t p = fuzz_below (rng, (uint32_t) len + 1);
      if (len + n > cap)
        break;
      memmove (buf + p + n, buf + p, len - p);
      memcpy (buf + p, s, n);
      len += n;
      break;
    }
  case 8:                      /* swap two bytes */
    {
      size_t a = fuzz_below (rng, (uint32_t) len);
      size_t b = fuzz_below (rng, (uint32_t) len);
      uint8_t t = buf[a];
      buf[a] = buf[b];
      buf[b] = t;
      break;
    }
  default:                     /* truncate */
    len = 1 + fuzz_below (rng, (uint32_t) len);
    break;
  }
  return len;
}


/* ------------------------------------------------------------------ */
/* Standalone driver                                                   */
/* ------------------------------------------------------------------ */

static int
fuzz_run_file (const char *path)
{
  FILE *f;
  uint8_t *buf;
  size_t n;

  f = fopen (path, "rb");
  if (NULL == f)
  {
    fprintf (stderr,
             "%s: cannot open '%s': %s\n",
             FUZZ_HARNESS_NAME,
             path,
             strerror (errno));
    return 1;
  }
  buf = (uint8_t *) malloc (FUZZ_MAX_INPUT);
  if (NULL == buf)
  {
    (void) fclose (f);
    return 1;
  }
  n = fread (buf, 1, FUZZ_MAX_INPUT, f);
  (void) fclose (f);
  fuzz_pristine = 1;
  fuzz_set_current (buf, n, path);
  alarm (FUZZ_DEFAULT_TIMEOUT);
  (void) LLVMFuzzerTestOneInput (buf, n);
  alarm (0);
  free (buf);
  return 0;
}


static int
fuzz_run_corpus_dir (const char *dir)
{
  DIR *d;
  struct dirent *de;
  char path[1024];
  int ret = 0;
  unsigned int cnt = 0;

  d = opendir (dir);
  if (NULL == d)
  {
    fprintf (stderr,
             "%s: cannot open corpus dir '%s': %s\n",
             FUZZ_HARNESS_NAME,
             dir,
             strerror (errno));
    return 1;
  }
  while (NULL != (de = readdir (d)))
  {
    struct stat sb;

    if ('.' == de->d_name[0])
      continue;
    (void) snprintf (path, sizeof (path), "%s/%s", dir, de->d_name);
    if ( (0 != stat (path, &sb)) ||
         (! S_ISREG (sb.st_mode)) )
      continue;
    fuzz_cur_iter = cnt++;
    ret |= fuzz_run_file (path);
  }
  (void) closedir (d);
  printf ("%s: replayed %u corpus file(s) from %s\n",
          FUZZ_HARNESS_NAME, cnt, dir);
  return ret;
}


static void
fuzz_usage (const char *argv0)
{
  printf (
    "Usage: %s [OPTIONS] [FILE...]\n"
    "\n"
    "In-process fuzzing harness '%s' for GNU libmicrohttpd.\n"
    "\n"
    "  --iterations=N    number of generate/mutate iterations (default %d)\n"
    "  --seed=N          PRNG seed; runs are fully reproducible (default 1)\n"
    "  --corpus-dir=DIR  replay every regular file in DIR and exit\n"
    "  --file=PATH       replay a single input and exit (crash reproduction)\n"
    "  --crash-dir=DIR   where to write reproducers (default 'crashes')\n"
    "  --timeout=SEC     per-iteration watchdog (default %d, 0 disables)\n"
    "  --write-corpus=DIR  write the built-in seed corpus to DIR and exit\n"
    "  --skip-seeds      do not replay the built-in seed corpus first\n"
    "  --verbose         enable MHD's error log inside the harness\n"
    "  --help            this text\n"
    "\n"
    "Environment: MHD_FUZZ_ITERATIONS, MHD_FUZZ_SEED, MHD_FUZZ_TIMEOUT,\n"
    "             MHD_FUZZ_CRASH_DIR, MHD_FUZZ_VERBOSE\n"
    "\n"
    "Bare FILE arguments are equivalent to --file=FILE (libFuzzer-style).\n",
    argv0, FUZZ_HARNESS_NAME,
    (int) FUZZ_DEFAULT_ITERATIONS, (int) FUZZ_DEFAULT_TIMEOUT);
}


static int
fuzz_write_corpus (const char *dir)
{
  size_t i;
  size_t n = fuzz_seed_count ();

  if ( (0 != mkdir (dir, 0755)) &&
       (EEXIST != errno) )
  {
    fprintf (stderr, "%s: mkdir '%s': %s\n",
             FUZZ_HARNESS_NAME, dir, strerror (errno));
    return 1;
  }
  for (i = 0; i < n; i++)
  {
    char path[1024];
    size_t len;
    const uint8_t *s = fuzz_seed_get (i, &len);
    FILE *f;

    (void) snprintf (path, sizeof (path), "%s/%s-%02u.bin",
                     dir, FUZZ_HARNESS_NAME, (unsigned int) i);
    f = fopen (path, "wb");
    if (NULL == f)
    {
      fprintf (stderr, "%s: fopen '%s': %s\n",
               FUZZ_HARNESS_NAME, path, strerror (errno));
      return 1;
    }
    if (len != fwrite (s, 1, len, f))
    {
      (void) fclose (f);
      return 1;
    }
    (void) fclose (f);
  }
  printf ("%s: wrote %u seed(s) to %s\n",
          FUZZ_HARNESS_NAME, (unsigned int) n, dir);
  return 0;
}


int
main (int argc, char *const *argv)
{
  uint64_t iterations = FUZZ_DEFAULT_ITERATIONS;
  uint64_t seed = 1;
  unsigned int timeout = FUZZ_DEFAULT_TIMEOUT;
  const char *corpus_dir = NULL;
  const char *single_file = NULL;
  const char *write_corpus = NULL;
  struct fuzz_rng rng;
  uint8_t *buf;
  uint64_t i;
  int j;
  const char *e;
  int ret = 0;

  e = getenv ("MHD_FUZZ_ITERATIONS");
  if (NULL != e)
    iterations = strtoull (e, NULL, 10);
  e = getenv ("MHD_FUZZ_SEED");
  if (NULL != e)
    seed = strtoull (e, NULL, 10);
  e = getenv ("MHD_FUZZ_TIMEOUT");
  if (NULL != e)
    timeout = (unsigned int) strtoul (e, NULL, 10);
  e = getenv ("MHD_FUZZ_CRASH_DIR");
  if (NULL != e)
    fuzz_crash_dir = e;
  e = getenv ("MHD_FUZZ_VERBOSE");
  if (NULL != e)
    fuzz_verbose = (0 != atoi (e));
  e = getenv ("MHD_FUZZ_SKIP_SEEDS");
  if (NULL != e)
    fuzz_skip_seeds = (0 != atoi (e));

  for (j = 1; j < argc; j++)
  {
    const char *a = argv[j];

    if (0 == strncmp (a, "--iterations=", 13))
      iterations = strtoull (a + 13, NULL, 10);
    else if (0 == strncmp (a, "--seed=", 7))
      seed = strtoull (a + 7, NULL, 10);
    else if (0 == strncmp (a, "--corpus-dir=", 13))
      corpus_dir = a + 13;
    else if (0 == strncmp (a, "--file=", 7))
      single_file = a + 7;
    else if (0 == strncmp (a, "--crash-dir=", 12))
      fuzz_crash_dir = a + 12;
    else if (0 == strncmp (a, "--timeout=", 10))
      timeout = (unsigned int) strtoul (a + 10, NULL, 10);
    else if (0 == strncmp (a, "--write-corpus=", 15))
      write_corpus = a + 15;
    else if (0 == strcmp (a, "--skip-seeds"))
      fuzz_skip_seeds = 1;
    else if (0 == strcmp (a, "--verbose"))
      fuzz_verbose = 1;
    else if ( (0 == strcmp (a, "--help")) ||
              (0 == strcmp (a, "-h")) )
    {
      fuzz_usage (argv[0]);
      return 0;
    }
    else if ('-' == a[0])
    {
      fprintf (stderr, "%s: unknown option '%s'\n", FUZZ_HARNESS_NAME, a);
      fuzz_usage (argv[0]);
      return 2;
    }
    else
      single_file = a;
  }

  fuzz_cur_seed = seed;
  fuzz_install_handlers ();

  if (NULL != write_corpus)
    return fuzz_write_corpus (write_corpus);

  if (NULL != single_file)
  {
    printf ("%s: replaying %s\n", FUZZ_HARNESS_NAME, single_file);
    ret = fuzz_run_file (single_file);
    printf ("%s: replay finished without a finding\n", FUZZ_HARNESS_NAME);
    return ret;
  }
  if (NULL != corpus_dir)
    return fuzz_run_corpus_dir (corpus_dir);

  buf = (uint8_t *) malloc (FUZZ_MAX_INPUT);
  if (NULL == buf)
    return 1;
  fuzz_rng_seed (&rng, seed);
  printf ("%s: seed=%llu iterations=%llu\n",
          FUZZ_HARNESS_NAME,
          (unsigned long long) seed,
          (unsigned long long) iterations);
  fflush (stdout);

  for (i = 0; i < iterations; i++)
  {
    size_t len;
    const char *tag;
    uint32_t mode;

    fuzz_cur_iter = i;
    if ( (! fuzz_skip_seeds) &&
         (i < fuzz_seed_count ()) )
    {
      size_t sl;
      const uint8_t *s = fuzz_seed_get ((size_t) i, &sl);

      if (sl > FUZZ_MAX_INPUT)
        sl = FUZZ_MAX_INPUT;
      memcpy (buf, s, sl);
      len = sl;
      fuzz_pristine = 1;
      tag = "builtin-seed";
    }
    else
    {
      mode = fuzz_below (&rng, 100);
      if (mode < 55)
      {
        fuzz_pristine = 1;
        len = fuzz_generate (&rng, buf, FUZZ_MAX_INPUT);
        tag = "generated";
      }
      else
      {
        unsigned int k;
        unsigned int nmut;

        if (mode < 85)
        {
          len = fuzz_generate (&rng, buf, FUZZ_MAX_INPUT);
          tag = "generated+mutated";
        }
        else
        {
          size_t sl;
          const uint8_t *s;

          if (0 == fuzz_seed_count ())
          {
            len = fuzz_generate (&rng, buf, FUZZ_MAX_INPUT);
          }
          else
          {
            s = fuzz_seed_get (fuzz_below (&rng,
                                           (uint32_t) fuzz_seed_count ()),
                               &sl);
            if (sl > FUZZ_MAX_INPUT)
              sl = FUZZ_MAX_INPUT;
            memcpy (buf, s, sl);
            len = sl;
          }
          tag = "seed+mutated";
        }
        fuzz_pristine = 0;
        nmut = 1 + fuzz_below (&rng, 8);
        for (k = 0; k < nmut; k++)
          len = fuzz_mutate_once (&rng, buf, len, FUZZ_MAX_INPUT);
      }
    }
    fuzz_set_current (buf, len, tag);
    if (0 != timeout)
      alarm (timeout);
    (void) LLVMFuzzerTestOneInput (buf, len);
    if (0 != timeout)
      alarm (0);
  }
  free (buf);
  printf ("%s: %llu iterations completed, no findings\n",
          FUZZ_HARNESS_NAME,
          (unsigned long long) iterations);
  return ret;
}


#endif /* ! FUZZ_NO_MAIN */

#endif /* MHD_FUZZ_COMMON_H */
