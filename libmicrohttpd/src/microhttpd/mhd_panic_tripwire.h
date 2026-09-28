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
 * @file microhttpd/mhd_panic_tripwire.h
 * @brief  Test-only tripwire that turns a fatal libmicrohttpd invariant
 *         failure into a loud, greppable, machine-classifiable test error.
 * @author Christian Grothoff
 *
 * Rationale (TESTING.md, proposal P5): no network input must ever be able to
 * reach #MHD_PANIC() or a failing mhd_assert().  When it does, the test suite
 * should say so in a way that a CI job or the option-matrix driver can pick
 * out mechanically, instead of leaving behind an anonymous SIGABRT that is
 * indistinguishable from an ordinary test failure.
 *
 * USAGE
 * -----
 * Add exactly one line to a test program:
 *
 *     #include "mhd_panic_tripwire.h"
 *
 * Nothing else is needed: on GCC/clang the header installs itself from a
 * `__attribute__((constructor))`, which runs after the libmicrohttpd shared
 * object has run its own initialiser (and therefore after MHD_init() has
 * installed the stock panic handler), so the tripwire wins.  On toolchains
 * without constructor support, call mhd_panic_tripwire_install() as the first
 * statement of main() instead.
 *
 * WHAT IS INTERCEPTED
 * -------------------
 * 1. #MHD_PANIC() - via the public MHD_set_panic_func() hook.  The reference
 *    to MHD_set_panic_func() is *weak*, so this header can also be included
 *    by the unit tests that compile a couple of library objects directly and
 *    do not link libmicrohttpd at all; there the hook is simply skipped.
 * 2. abort() - via a SIGABRT handler.  This matters because in this code base
 *    the overwhelming majority of "fatal invariant reached from network
 *    input" sites are mhd_assert(), which goes to assert(3)/abort(3) and
 *    never passes through mhd_panic().  Set MHD_TEST_PANIC_TRIPWIRE_ABRT=0
 *    to intercept #MHD_PANIC() only.
 *
 * WHY THE HANDLER MUST NOT RETURN, AND WHY IT DOES NOT longjmp()
 * --------------------------------------------------------------
 * #MHD_PANIC(msg) expands to `mhd_panic (...); BUILTIN_NOT_REACHED;`, i.e.
 * __builtin_unreachable().  A panic handler that returns therefore drops the
 * caller straight into undefined behaviour - the compiler has already been
 * told that the following code is dead and may have deleted it.  So the
 * handler has to terminate the process.
 *
 * longjmp() back into main() is not an option either: MHD_PANIC() is reached
 * from library code that may be running on a daemon worker thread or on a
 * thread-per-connection thread, and a longjmp() across threads is undefined.
 * Even on the right thread it would leave the daemon's mutexes locked and its
 * connection lists half-updated, so any "recording" done afterwards would run
 * in a process whose state is already corrupt.  We therefore report and
 * terminate rather than recover.
 *
 * TERMINATION STATUS
 * ------------------
 * The default is _exit(99).  The automake parallel test harness classifies
 * exit status 99 as a hard ERROR rather than an ordinary FAIL, which is
 * exactly the "this is not a normal test failure, a fatal invariant was
 * reached" signal wanted here.  Note that this also applies to tests listed
 * in XFAIL_TESTS - a test that is *expected* to trip an assertion (such as
 * src/microhttpd/test_known_bugs.c) must therefore NOT include this header.
 *
 * ENVIRONMENT VARIABLES
 * ---------------------
 * @c MHD_TEST_PANIC_TRIPWIRE
 *   - unset, or any unrecognised value: enabled, terminate with _exit(99).
 *   - @c 0 / @c off / @c no / @c disable: completely disabled; the stock
 *     libmicrohttpd behaviour (mhd_panic_std(), plain abort()) is left in
 *     place.  Use this when a debugger or an external tool wants the
 *     original behaviour.
 *   - @c abort: print the marker and the stack trace, then re-raise SIGABRT
 *     with the default disposition so that a core dump is produced.
 *   - @c exit:N (0 <= N <= 255): print the marker and the stack trace, then
 *     terminate with status N instead of 99.
 *
 * @c MHD_TEST_PANIC_TRIPWIRE_ABRT
 *   - @c 0 / @c off / @c no / @c disable: do not install the SIGABRT handler;
 *     only #MHD_PANIC() is intercepted.  Failing mhd_assert()s then abort as
 *     usual.
 *   - unset or anything else: the SIGABRT handler is installed.
 *
 * OUTPUT FORMAT
 * -------------
 * A single greppable marker line is written to stderr, followed (where
 * available) by a stack trace and a final status line:
 *
 *   MHD-PANIC-TRIPWIRE: kind=MHD_PANIC file=connection.c line=1234 \
 *     reason=Data offset exceeds limit.
 *   MHD-PANIC-TRIPWIRE-FRAME: ...
 *   MHD-PANIC-TRIPWIRE: terminating with exit status 99
 *
 * Grep for #MHD_PANIC_TRIPWIRE_MARKER ("MHD-PANIC-TRIPWIRE") to classify a
 * failure.  Everything is emitted with write(2) and without allocating, so
 * the same code path is usable from the SIGABRT handler.
 */

#ifndef MHD_PANIC_TRIPWIRE_H
#define MHD_PANIC_TRIPWIRE_H 1

#include <stdlib.h>
#include <string.h>
#include <signal.h>
#ifdef _WIN32
#include <io.h>
#else  /* ! _WIN32 */
#include <unistd.h>
#endif /* ! _WIN32 */

/**
 * The distinctive, greppable marker that prefixes every line printed by the
 * tripwire.
 */
#define MHD_PANIC_TRIPWIRE_MARKER "MHD-PANIC-TRIPWIRE"

/**
 * The exit status used by default.  The automake test harness reports this
 * as a hard ERROR instead of a FAIL.
 */
#define MHD_PANIC_TRIPWIRE_EXIT_STATUS 99

/* Detect a usable backtrace() implementation.  This must not depend on
   configure, because this header is also used from test directories that do
   not run any dedicated check for it.  Degrade silently when absent. */
#if ! defined(MHD_PANIC_TRIPWIRE_BACKTRACE_)
#  if defined(__has_include )
#    if __has_include (<execinfo.h>)
#      define MHD_PANIC_TRIPWIRE_BACKTRACE_ 1
#    endif /* __has_include(<execinfo.h>) */
#  elif defined(HAVE_EXECINFO_H) || defined(__GLIBC__)
#    define MHD_PANIC_TRIPWIRE_BACKTRACE_ 1
#  endif /* HAVE_EXECINFO_H || __GLIBC__ */
#endif /* ! MHD_PANIC_TRIPWIRE_BACKTRACE_ */
#ifdef MHD_PANIC_TRIPWIRE_BACKTRACE_
#include <execinfo.h>
#endif /* MHD_PANIC_TRIPWIRE_BACKTRACE_ */

/* Weak references let this header be included by the unit tests that do not
   link libmicrohttpd (test_str*, test_md5, test_sha*, test_auth_parse, ...).
   Without weak-symbol support the MHD_PANIC() hook is simply not installed
   and only the abort() hook remains. */
#if defined(__GNUC__) && defined(__ELF__) && ! defined(_WIN32)
#  define MHD_PANIC_TRIPWIRE_WEAK_ __attribute__ ((weak))
#endif /* __GNUC__ && __ELF__ && ! _WIN32 */

#ifdef MHD_PANIC_TRIPWIRE_WEAK_
/* Deliberately declared here instead of pulling in <microhttpd.h>: the
   signature is identical to MHD_PanicCallback, so this declaration is
   compatible with the one in <microhttpd.h> when that header is also
   included, and it keeps this file usable in translation units that never
   see the public header. */
extern MHD_PANIC_TRIPWIRE_WEAK_ void
MHD_set_panic_func (void (*cb)(void *cls,
                               const char *file,
                               unsigned int line,
                               const char *reason),
                    void *cls);

#endif /* MHD_PANIC_TRIPWIRE_WEAK_ */

#if defined(__GNUC__) || defined(__clang__)
#  define MHD_PANIC_TRIPWIRE_UNUSED_ __attribute__ ((unused))
#  define MHD_PANIC_TRIPWIRE_NORETURN_ __attribute__ ((noreturn))
#else  /* ! __GNUC__ */
#  define MHD_PANIC_TRIPWIRE_UNUSED_
#  define MHD_PANIC_TRIPWIRE_NORETURN_
#endif /* ! __GNUC__ */

/**
 * Selected action, resolved once by the installer so that the handlers
 * themselves never have to call getenv().
 * 0: terminate with #mhd_panic_tripwire_status_; 1: re-raise SIGABRT.
 */
static volatile sig_atomic_t mhd_panic_tripwire_reraise_ = 0;

/**
 * The exit status to use when #mhd_panic_tripwire_reraise_ is zero.
 */
static volatile sig_atomic_t mhd_panic_tripwire_status_ =
  MHD_PANIC_TRIPWIRE_EXIT_STATUS;

/**
 * Set once a report is in progress, so that a second thread tripping at the
 * same time does not interleave its output with the first one.
 */
static volatile sig_atomic_t mhd_panic_tripwire_busy_ = 0;


/**
 * Write a string literal to stderr.
 *
 * @param str a string literal
 */
#define MHD_PANIC_TRIPWIRE_WRS_(str) \
        mhd_panic_tripwire_wr_ (str, sizeof(str) - 1)


/**
 * Write a buffer to stderr.  Async-signal-safe: no locking, no allocation,
 * no stdio.
 *
 * @param buf the bytes to write
 * @param len the number of bytes to write
 */
static void
mhd_panic_tripwire_wr_ (const char *buf,
                        size_t len)
{
  size_t off = 0;

  while (off < len)
  {
#ifdef _WIN32
    int res = _write (2, buf + off, (unsigned int) (len - off));
#else  /* ! _WIN32 */
    ssize_t res = write (STDERR_FILENO, buf + off, len - off);
#endif /* ! _WIN32 */
    if (0 >= res)
      return; /* Give up rather than spin. */
    off += (size_t) res;
  }
}


/**
 * Write a NUL-terminated string to stderr, replacing every control character
 * by a space so that the marker always stays on a single line.
 *
 * @param str the string to write, may be NULL
 */
static void
mhd_panic_tripwire_wr_clean_ (const char *str)
{
  char chunk[256];
  size_t used = 0;

  if (NULL == str)
  {
    MHD_PANIC_TRIPWIRE_WRS_ ("(null)");
    return;
  }
  while (0 != *str)
  {
    const unsigned char chr = (unsigned char) *str++;

    chunk[used++] = (0x20 > chr) ? ' ' : (char) chr;
    if (sizeof(chunk) == used)
    {
      mhd_panic_tripwire_wr_ (chunk, used);
      used = 0;
    }
  }
  if (0 != used)
    mhd_panic_tripwire_wr_ (chunk, used);
}


/**
 * Write an unsigned number in decimal to stderr.
 *
 * @param val the value to print
 */
static void
mhd_panic_tripwire_wr_num_ (unsigned long val)
{
  char buf[24];
  size_t pos = sizeof(buf);

  do
  {
    buf[--pos] = (char) ('0' + (val % 10));
    val /= 10;
  } while (0 != val);
  mhd_panic_tripwire_wr_ (buf + pos, sizeof(buf) - pos);
}


/**
 * Print the stack trace of the calling thread, if the platform provides one.
 * Silently does nothing otherwise.
 */
static void
mhd_panic_tripwire_backtrace_ (void)
{
#ifdef MHD_PANIC_TRIPWIRE_BACKTRACE_
  void *frames[64];
  int num;

  num = backtrace (frames, (int) (sizeof(frames) / sizeof(frames[0])));
  if (0 >= num)
    return;
  MHD_PANIC_TRIPWIRE_WRS_ (MHD_PANIC_TRIPWIRE_MARKER "-FRAMES: ");
  mhd_panic_tripwire_wr_num_ ((unsigned long) num);
  MHD_PANIC_TRIPWIRE_WRS_ (" frames follow\n");
  /* backtrace_symbols_fd() does not allocate, unlike backtrace_symbols(). */
  backtrace_symbols_fd (frames, num, 2);
#endif /* MHD_PANIC_TRIPWIRE_BACKTRACE_ */
}


/**
 * Print the marker line and the stack trace, then terminate the process.
 * Never returns; see the file comment for why recovering is not an option.
 *
 * @param kind a short token naming what was intercepted
 * @param file the source file of the failure, may be NULL
 * @param line the source line of the failure
 * @param reason the human-readable reason, may be NULL
 */
MHD_PANIC_TRIPWIRE_NORETURN_ static void
mhd_panic_tripwire_report_ (const char *kind,
                            const char *file,
                            unsigned int line,
                            const char *reason)
{
  if (0 == mhd_panic_tripwire_busy_)
  {
    mhd_panic_tripwire_busy_ = 1;
    MHD_PANIC_TRIPWIRE_WRS_ ("\n" MHD_PANIC_TRIPWIRE_MARKER ": kind=");
    mhd_panic_tripwire_wr_clean_ (kind);
    MHD_PANIC_TRIPWIRE_WRS_ (" file=");
    mhd_panic_tripwire_wr_clean_ ((NULL != file) ? file : "(unknown)");
    MHD_PANIC_TRIPWIRE_WRS_ (" line=");
    mhd_panic_tripwire_wr_num_ ((unsigned long) line);
    MHD_PANIC_TRIPWIRE_WRS_ (" reason=");
    mhd_panic_tripwire_wr_clean_ ((NULL != reason) ? reason : "(none)");
    MHD_PANIC_TRIPWIRE_WRS_ ("\n");
    mhd_panic_tripwire_backtrace_ ();
    if (0 == mhd_panic_tripwire_reraise_)
    {
      MHD_PANIC_TRIPWIRE_WRS_ (MHD_PANIC_TRIPWIRE_MARKER
                               ": terminating with exit status ");
      mhd_panic_tripwire_wr_num_ ((unsigned long) mhd_panic_tripwire_status_);
      MHD_PANIC_TRIPWIRE_WRS_ ("\n");
    }
    else
      MHD_PANIC_TRIPWIRE_WRS_ (MHD_PANIC_TRIPWIRE_MARKER
                               ": re-raising SIGABRT for a core dump\n");
  }
  if (0 != mhd_panic_tripwire_reraise_)
  {
    signal (SIGABRT, SIG_DFL);
    raise (SIGABRT);
  }
  _exit ((int) mhd_panic_tripwire_status_);
}


/**
 * The #MHD_PanicCallback installed by the tripwire.
 *
 * @param cls unused
 * @param file the name of the file with the problem
 * @param line the line number with the problem
 * @param reason the error message with details
 */
static void
mhd_panic_tripwire_panic_cb_ (void *cls,
                              const char *file,
                              unsigned int line,
                              const char *reason)
{
  (void) cls; /* Mute compiler warning. */
  mhd_panic_tripwire_report_ ("MHD_PANIC",
                              file,
                              line,
                              reason);
}


/**
 * The SIGABRT handler installed by the tripwire.  Catches a failing
 * mhd_assert() (which goes through assert(3) and abort(3)) and any other
 * abort(), for example from the C library's own consistency checks.
 *
 * @param sig the signal number, always SIGABRT
 */
static void
mhd_panic_tripwire_abrt_cb_ (int sig)
{
  (void) sig; /* Mute compiler warning. */
  mhd_panic_tripwire_report_ ("abort",
                              NULL,
                              0,
                              "abort() reached; see the line above for the "
                              "failed assertion, if any");
}


/**
 * Test whether an environment variable value means "off".
 *
 * @param val the value to test, may be NULL
 * @return non-zero if @a val explicitly disables a feature
 */
static int
mhd_panic_tripwire_is_off_ (const char *val)
{
  if (NULL == val)
    return 0;
  return (0 == strcmp (val, "0")) ||
         (0 == strcmp (val, "off")) ||
         (0 == strcmp (val, "no")) ||
         (0 == strcmp (val, "disable"));
}


/**
 * Install the panic tripwire.  Called automatically from a constructor on
 * GCC-compatible toolchains; call it explicitly as the first statement of
 * main() on any other toolchain.  Idempotent.
 */
MHD_PANIC_TRIPWIRE_UNUSED_ static void
mhd_panic_tripwire_install (void)
{
  const char *mode = getenv ("MHD_TEST_PANIC_TRIPWIRE");

  if (mhd_panic_tripwire_is_off_ (mode))
    return; /* Leave the stock behaviour completely untouched. */
  if ((NULL != mode) && (0 == strcmp (mode, "abort")))
    mhd_panic_tripwire_reraise_ = 1;
  else if ((NULL != mode) && (0 == strncmp (mode, "exit:", 5)))
  {
    const long status = strtol (mode + 5, NULL, 10);

    if ((0 <= status) && (255 >= status))
      mhd_panic_tripwire_status_ = (sig_atomic_t) status;
  }
#ifdef MHD_PANIC_TRIPWIRE_WEAK_
  if (NULL != MHD_set_panic_func)
    MHD_set_panic_func (&mhd_panic_tripwire_panic_cb_,
                        NULL);
#else  /* ! MHD_PANIC_TRIPWIRE_WEAK_ */
  MHD_set_panic_func (&mhd_panic_tripwire_panic_cb_,
                      NULL);
#endif /* ! MHD_PANIC_TRIPWIRE_WEAK_ */
  if (! mhd_panic_tripwire_is_off_ (getenv ("MHD_TEST_PANIC_TRIPWIRE_ABRT")))
    signal (SIGABRT,
            &mhd_panic_tripwire_abrt_cb_);
}


#if defined(__GNUC__) || defined(__clang__)
/**
 * Self-installer, so that adding the tripwire to a test program is a single
 * #include line.  Runs after the libmicrohttpd initialiser (the library is a
 * dependency of the test executable and is therefore initialised first), so
 * MHD_init()'s call to MHD_set_panic_func(NULL, NULL) cannot undo this.
 */
__attribute__ ((constructor)) static void
mhd_panic_tripwire_ctor_ (void)
{
  mhd_panic_tripwire_install ();
}


#endif /* __GNUC__ || __clang__ */

#endif /* ! MHD_PANIC_TRIPWIRE_H */
