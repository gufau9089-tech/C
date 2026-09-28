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
 * @file microhttpd/mhd_opt_matrix.h
 * @brief  The environment-driven daemon option matrix shared by the tests
 * @author Christian Grothoff
 *
 * This header must be included *after* "platform.h" and <microhttpd.h>.
 *
 * ## What this is
 *
 * Almost every test in this directory starts its daemon with one hard-coded
 * set of options, so the whole test suite only ever exercises a single point
 * of a large configuration space.  This helper turns that space into a small
 * table of named *profiles* and lets the profile be selected from the
 * environment, so that an already built test binary can be re-run across the
 * whole matrix without recompiling anything (see contrib/run-option-matrix.sh).
 *
 * The dimensions of the matrix are:
 *
 * * #MHD_OPTION_CONNECTION_MEMORY_LIMIT in
 *   {64, 128, 256, 512, 1024, 2048, 3072, 4096, library default}.  64 is the
 *   smallest value MHD accepts (anything below is rounded up to 64, see
 *   daemon.c).  Everything up to 2048 keeps the read buffer below
 *   #MHD_BUF_INC_SIZE (1500) resp. small enough to unlock the read-buffer
 *   "shift back" path fixed by commit 29eaa56b, 3072 and 4096 do not, so both
 *   sides of that boundary are in the sweep;
 * * #MHD_OPTION_CLIENT_DISCIPLINE_LVL in {-3 ... 3};
 * * #MHD_OPTION_STRICT_FOR_CLIENT, the older two-valued form of the same
 *   knob, so that its translation code is covered as well.  Beware: that
 *   option maps *every* value of -1 or below to client discipline level -3,
 *   the most permissive one (daemon.c:7102-7106), so an application asking
 *   for "slightly lenient" in fact selects the most lenient mode;
 * * the threading mode: external polling, internal polling thread,
 *   thread-per-connection and thread pool;
 * * the polling backend: select(), poll() and epoll.  Profiles asking for a
 *   backend that this build does not provide are reported as unsupported by
 *   mhd_opt_matrix_profile_supported().
 *
 * #MHD_OPTION_SERVER_INSANITY is deliberately *not* a dimension: in this MHD
 * version `enum MHD_DisableSanityCheck` has exactly one member,
 * #MHD_DSC_SANE (zero), so the option cannot disable anything.
 *
 * ## Environment variables
 *
 * * #MHD_OPT_MATRIX_PROFILE_ENV ("MHD_TEST_PROFILE") - the profile to use,
 *   given either by name ("mem-512") or by index ("4").  The special value
 *   "list" is not handled here; contrib/run-option-matrix.sh knows the names.
 * * #MHD_OPT_MATRIX_MEM_ENV ("MHD_TEST_MEM_LIMIT") - override the connection
 *   memory limit of the selected profile.  "0" or "default" selects the
 *   library default.
 * * #MHD_OPT_MATRIX_DISCP_ENV ("MHD_TEST_DISCIPLINE") - override the client
 *   discipline level (-3 ... 3) and use #MHD_OPTION_CLIENT_DISCIPLINE_LVL.
 * * #MHD_OPT_MATRIX_STRICT_ENV ("MHD_TEST_STRICT_FOR_CLIENT") - override the
 *   same knob but use the deprecated #MHD_OPTION_STRICT_FOR_CLIENT instead.
 * * #MHD_OPT_MATRIX_THREADING_ENV ("MHD_TEST_THREADING") - one of
 *   "external", "internal", "per-connection", "pool".
 * * #MHD_OPT_MATRIX_POLL_ENV ("MHD_TEST_POLL") - one of "select", "poll",
 *   "epoll".
 *
 * If *none* of these variables is set, mhd_opt_matrix_from_env()
 * returns NULL and every test keeps its previous, hard-coded behaviour.  This
 * is what a stock "make check" does, so nothing regresses.
 */

#ifndef MHD_OPT_MATRIX_H
#define MHD_OPT_MATRIX_H 1

#include <stddef.h>
#include <microhttpd.h>

/**
 * The name of the environment variable selecting the profile.
 */
#define MHD_OPT_MATRIX_PROFILE_ENV "MHD_TEST_PROFILE"

/**
 * The name of the environment variable overriding the memory limit.
 */
#define MHD_OPT_MATRIX_MEM_ENV "MHD_TEST_MEM_LIMIT"

/**
 * The name of the environment variable overriding the discipline level.
 */
#define MHD_OPT_MATRIX_DISCP_ENV "MHD_TEST_DISCIPLINE"

/**
 * The name of the environment variable overriding the discipline level via
 * the deprecated #MHD_OPTION_STRICT_FOR_CLIENT option.
 */
#define MHD_OPT_MATRIX_STRICT_ENV "MHD_TEST_STRICT_FOR_CLIENT"

/**
 * The name of the environment variable overriding the threading mode.
 */
#define MHD_OPT_MATRIX_THREADING_ENV "MHD_TEST_THREADING"

/**
 * The name of the environment variable overriding the polling backend.
 */
#define MHD_OPT_MATRIX_POLL_ENV "MHD_TEST_POLL"

/**
 * The threading mode of a profile.
 */
enum MHD_OptMatrixThreading
{
  /**
   * External polling: the application drives the daemon with MHD_run().
   */
  MHD_OPT_MATRIX_THR_EXTERNAL = 0,

  /**
   * One internal polling thread for all connections.
   */
  MHD_OPT_MATRIX_THR_INTERNAL = 1,

  /**
   * One internal thread per connection.
   */
  MHD_OPT_MATRIX_THR_PER_CONNECTION = 2,

  /**
   * A pool of internal polling threads.
   */
  MHD_OPT_MATRIX_THR_POOL = 3
};


/**
 * The polling backend of a profile.
 */
enum MHD_OptMatrixPoll
{
  /**
   * Use select().
   */
  MHD_OPT_MATRIX_POLL_SELECT = 0,

  /**
   * Use poll(), needs #MHD_FEATURE_POLL.
   */
  MHD_OPT_MATRIX_POLL_POLL = 1,

  /**
   * Use epoll, needs #MHD_FEATURE_EPOLL.
   */
  MHD_OPT_MATRIX_POLL_EPOLL = 2
};


/**
 * One point of the daemon option matrix.
 *
 * A caller may copy the structure and modify the copy, e.g. with
 * mhd_opt_matrix_raise_mem_limit(); the tables returned by
 * mhd_opt_matrix_profile() must not be modified.
 */
struct MHD_OptMatrixProfile
{
  /**
   * Human readable name of the profile, used for logging and for
   * #MHD_OPT_MATRIX_PROFILE_ENV.
   */
  const char *name;

  /**
   * The value for #MHD_OPTION_CONNECTION_MEMORY_LIMIT.
   * Zero means "keep the MHD default".
   */
  size_t mem_limit;

  /**
   * The value for #MHD_OPTION_CLIENT_DISCIPLINE_LVL or, when
   * @a use_legacy_strict is set, for #MHD_OPTION_STRICT_FOR_CLIENT.
   * Zero means "keep the MHD default" and adds no option at all.
   */
  int discipline_lvl;

  /**
   * If non-zero, the deprecated #MHD_OPTION_STRICT_FOR_CLIENT option is used
   * instead of #MHD_OPTION_CLIENT_DISCIPLINE_LVL, so that the legacy option
   * translation code is exercised as well.
   */
  int use_legacy_strict;

  /**
   * The threading mode.
   */
  enum MHD_OptMatrixThreading threading;

  /**
   * The polling backend.
   */
  enum MHD_OptMatrixPoll poll_backend;

  /**
   * The number of worker threads, only used with
   * #MHD_OPT_MATRIX_THR_POOL.
   */
  unsigned int thread_pool_size;
};


/**
 * The number of built-in profiles.
 */
unsigned int
mhd_opt_matrix_num_profiles (void);


/**
 * Get the built-in profile number @a idx.
 *
 * Profile zero is the "default" profile: the library defaults for every
 * dimension plus one internal polling thread, i.e. the configuration the
 * tests of this directory used before the matrix was introduced.
 *
 * @param idx the index of the profile, wraps around
 * @return the profile, never NULL
 */
const struct MHD_OptMatrixProfile *
mhd_opt_matrix_profile (unsigned int idx);


/**
 * Look up a profile by name or by decimal index.
 *
 * @param name_or_idx the name ("mem-512") or the index ("4")
 * @return the profile, or NULL if @a name_or_idx matches nothing
 */
const struct MHD_OptMatrixProfile *
mhd_opt_matrix_lookup (const char *name_or_idx);


/**
 * Get the profile selected by the environment.
 *
 * @return NULL if the environment selects nothing, in which case the caller
 *         must keep its own, previous configuration; otherwise a pointer to
 *         a static profile that stays valid until the next call
 */
const struct MHD_OptMatrixProfile *
mhd_opt_matrix_from_env (void);


/**
 * Get the client discipline level that MHD will *really* use for @a prof.
 *
 * This is not always @a prof->discipline_lvl: #MHD_OPTION_STRICT_FOR_CLIENT
 * only has two settings, and daemon.c:7102-7106 maps every value of -1 or
 * below to level -3 (the most permissive one) and every value of 1 or above
 * to level 1.  A caller that decides what a request must do therefore has to
 * ask for the effective level, not for the configured one - a test that
 * believes it asked for "slightly lenient" in fact runs at -3.
 *
 * @param prof the profile to inspect, may be NULL (0 is returned then)
 * @return the client discipline level in effect
 */
int
mhd_opt_matrix_effective_discipline (const struct MHD_OptMatrixProfile *prof);


/**
 * Check whether @a prof can be used by this build at run time.
 *
 * @param prof the profile to check
 * @return non-zero if the profile is usable, zero if the required threading
 *         support or polling backend is missing
 */
int
mhd_opt_matrix_profile_supported (const struct MHD_OptMatrixProfile *prof);


/**
 * Render a one-line, human readable description of @a prof.
 *
 * @param prof the profile to describe
 * @param[out] buf the buffer to write to
 * @param buf_size the size of @a buf
 * @return @a buf
 */
const char *
mhd_opt_matrix_describe (const struct MHD_OptMatrixProfile *prof,
                         char *buf,
                         size_t buf_size);


/**
 * Fill @a ops with the options of @a prof.
 *
 * The array is terminated with an #MHD_OPTION_END element, so it can be
 * passed to MHD_start_daemon() as
 *
 *     MHD_start_daemon (flags, port, NULL, NULL, ahc, cls,
 *                       MHD_OPTION_ARRAY, ops,
 *                       ... other options ...,
 *                       MHD_OPTION_END);
 *
 * which works for a varargs call just as well as for a call that already
 * uses #MHD_OPTION_ARRAY.
 *
 * @param prof the profile to apply, may be NULL (only #MHD_OPTION_END is
 *             stored then)
 * @param[out] ops the array to fill
 * @param max_ops the number of elements of @a ops, at least 4
 * @return the number of elements used, including the terminating
 *         #MHD_OPTION_END; zero if @a ops is too small
 */
unsigned int
mhd_opt_matrix_fill_options (const struct MHD_OptMatrixProfile *prof,
                             struct MHD_OptionItem *ops,
                             unsigned int max_ops);


/**
 * Combine the daemon flags required by @a prof with @a base_flags.
 *
 * @param prof the profile to apply, may be NULL (@a base_flags is returned)
 * @param base_flags the flags the caller wants in any case, e.g.
 *                   #MHD_USE_ERROR_LOG
 * @param allow_external if zero, a profile that asks for external polling is
 *                       served with an internal polling thread instead; use
 *                       this in tests whose client cannot call MHD_run()
 * @return the flags for MHD_start_daemon()
 */
unsigned int
mhd_opt_matrix_daemon_flags (const struct MHD_OptMatrixProfile *prof,
                             unsigned int base_flags,
                             int allow_external);


/**
 * Check whether @a prof needs the application to drive MHD_run().
 *
 * @param prof the profile to check, may be NULL
 * @return non-zero if the daemon has no internal thread
 */
int
mhd_opt_matrix_is_external (const struct MHD_OptMatrixProfile *prof);


/**
 * Raise the connection memory limit of @a prof to at least @a min_limit.
 *
 * Tests that cannot work with a tiny connection pool (because the requests
 * they must send do not fit into it) use this to keep the other dimensions of
 * the matrix while staying functional.  The change must be reported in the
 * test output so that the log stays truthful.
 *
 * @param[in,out] prof the profile to adjust, must be a caller-owned copy
 * @param min_limit the smallest acceptable limit, zero does nothing
 * @return non-zero if the limit was actually raised
 */
int
mhd_opt_matrix_raise_mem_limit (struct MHD_OptMatrixProfile *prof,
                                size_t min_limit);


/**
 * Print the one-line notice naming the profile in use and, if a profile is
 * selected, the profile.
 *
 * @param test_name the name of the calling test, used as the line prefix
 */
void
mhd_opt_matrix_print_notice (const char *test_name);


#endif /* MHD_OPT_MATRIX_H */
