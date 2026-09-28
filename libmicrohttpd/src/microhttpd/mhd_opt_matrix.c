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
 * @file microhttpd/mhd_opt_matrix.c
 * @brief  The environment-driven daemon option matrix shared by the tests
 * @author Christian Grothoff
 */

#include "platform.h"
#include <microhttpd.h>
#include <stdlib.h>
#include <string.h>
#include <stdio.h>

#include "mhd_opt_matrix.h"


/**
 * The built-in matrix of daemon option profiles.
 *
 * Every value of every dimension listed in the header appears at least once:
 *
 * * memory limit: 0 (default), 64, 128, 256, 512, 1024, 2048, 3072, 4096;
 * * client discipline level: -3, -2, -1, 0, 1, 2, 3;
 * * #MHD_OPTION_STRICT_FOR_CLIENT with a positive and with a negative value;
 * * threading: external polling, one internal thread, thread-per-connection,
 *   thread pool;
 * * polling backend: select(), poll(), epoll.
 *
 * Profile zero is "neutral": it is exactly the configuration the tests of
 * this directory used before the matrix was introduced.
 *
 * The combination "thread-per-connection + epoll" is deliberately absent: MHD
 * rejects it (daemon.c:8680).  External polling is always paired with the
 * select()-style interface, as that is the only one the tests can drive.
 */
static const struct MHD_OptMatrixProfile opt_profiles[] = {
  /* name            mem  discp legacy threading
     poll                          pool */
  { "default",         0,   0, 0, MHD_OPT_MATRIX_THR_INTERNAL,
    MHD_OPT_MATRIX_POLL_SELECT, 0 },
  { "mem-64",         64,   0, 0, MHD_OPT_MATRIX_THR_INTERNAL,
    MHD_OPT_MATRIX_POLL_SELECT, 0 },
  { "mem-128",       128,   0, 0, MHD_OPT_MATRIX_THR_INTERNAL,
    MHD_OPT_MATRIX_POLL_POLL, 0 },
  { "mem-256",       256,   0, 0, MHD_OPT_MATRIX_THR_PER_CONNECTION,
    MHD_OPT_MATRIX_POLL_SELECT, 0 },
  { "mem-512",       512,   0, 0, MHD_OPT_MATRIX_THR_PER_CONNECTION,
    MHD_OPT_MATRIX_POLL_POLL, 0 },
  { "mem-1024",     1024,   0, 0, MHD_OPT_MATRIX_THR_INTERNAL,
    MHD_OPT_MATRIX_POLL_EPOLL, 0 },
  { "mem-2048",     2048,   0, 0, MHD_OPT_MATRIX_THR_POOL,
    MHD_OPT_MATRIX_POLL_SELECT, 4 },
  { "mem-3072",     3072,   0, 0, MHD_OPT_MATRIX_THR_EXTERNAL,
    MHD_OPT_MATRIX_POLL_SELECT, 0 },
  { "mem-4096",     4096,   0, 0, MHD_OPT_MATRIX_THR_POOL,
    MHD_OPT_MATRIX_POLL_EPOLL, 3 },
  { "strict-1",        0,   1, 0, MHD_OPT_MATRIX_THR_INTERNAL,
    MHD_OPT_MATRIX_POLL_SELECT, 0 },
  { "strict-2",     1024,   2, 0, MHD_OPT_MATRIX_THR_INTERNAL,
    MHD_OPT_MATRIX_POLL_POLL, 0 },
  { "strict-3",      512,   3, 0, MHD_OPT_MATRIX_THR_INTERNAL,
    MHD_OPT_MATRIX_POLL_EPOLL, 0 },
  { "lax-1",         512,  -1, 0, MHD_OPT_MATRIX_THR_INTERNAL,
    MHD_OPT_MATRIX_POLL_SELECT, 0 },
  { "lax-2",         256,  -2, 0, MHD_OPT_MATRIX_THR_PER_CONNECTION,
    MHD_OPT_MATRIX_POLL_SELECT, 0 },
  { "lax-3",        2048,  -3, 0, MHD_OPT_MATRIX_THR_POOL,
    MHD_OPT_MATRIX_POLL_SELECT, 4 },
  { "legacy-strict", 768,   1, 1, MHD_OPT_MATRIX_THR_INTERNAL,
    MHD_OPT_MATRIX_POLL_SELECT, 0 },
  { "legacy-lax",    768,  -1, 1, MHD_OPT_MATRIX_THR_EXTERNAL,
    MHD_OPT_MATRIX_POLL_SELECT, 0 }
};

/**
 * The number of built-in profiles.
 */
#define NUM_PROFILES \
        ((unsigned int) (sizeof(opt_profiles) / sizeof(opt_profiles[0])))


/**
 * Non-zero once the environment has been read into @a env_profile.
 */
static int env_parsed;

/**
 * Non-zero if the environment selects a profile at all.
 */
static int env_selected;

/**
 * The profile derived from the environment.
 */
static struct MHD_OptMatrixProfile env_profile;

/**
 * The name of @a env_profile.
 */
static char env_profile_name[64];


unsigned int
mhd_opt_matrix_num_profiles (void)
{
  return NUM_PROFILES;
}


const struct MHD_OptMatrixProfile *
mhd_opt_matrix_profile (unsigned int idx)
{
  return opt_profiles + (idx % NUM_PROFILES);
}


const struct MHD_OptMatrixProfile *
mhd_opt_matrix_lookup (const char *name_or_idx)
{
  unsigned int i;

  if ((NULL == name_or_idx) || (0 == name_or_idx[0]))
    return NULL;
  for (i = 0; i < NUM_PROFILES; ++i)
  {
    if (0 == strcmp (name_or_idx, opt_profiles[i].name))
      return opt_profiles + i;
  }
  if (('0' <= name_or_idx[0]) && ('9' >= name_or_idx[0]))
  {
    char *end;
    unsigned long v;

    v = strtoul (name_or_idx, &end, 10);
    if ((NULL != end) && (0 == *end) && (NUM_PROFILES > v))
      return opt_profiles + v;
  }
  return NULL;
}


/**
 * Parse the threading mode name.
 *
 * @param s the name
 * @param[out] out the parsed mode
 * @return non-zero on success
 */
static int
parse_threading (const char *s, enum MHD_OptMatrixThreading *out)
{
  if (0 == strcmp (s, "external"))
    *out = MHD_OPT_MATRIX_THR_EXTERNAL;
  else if (0 == strcmp (s, "internal"))
    *out = MHD_OPT_MATRIX_THR_INTERNAL;
  else if ((0 == strcmp (s, "per-connection")) ||
           (0 == strcmp (s, "tpc")))
    *out = MHD_OPT_MATRIX_THR_PER_CONNECTION;
  else if (0 == strcmp (s, "pool"))
    *out = MHD_OPT_MATRIX_THR_POOL;
  else
    return 0;
  return ! 0;
}


/**
 * Parse the polling backend name.
 *
 * @param s the name
 * @param[out] out the parsed backend
 * @return non-zero on success
 */
static int
parse_poll (const char *s, enum MHD_OptMatrixPoll *out)
{
  if (0 == strcmp (s, "select"))
    *out = MHD_OPT_MATRIX_POLL_SELECT;
  else if (0 == strcmp (s, "poll"))
    *out = MHD_OPT_MATRIX_POLL_POLL;
  else if (0 == strcmp (s, "epoll"))
    *out = MHD_OPT_MATRIX_POLL_EPOLL;
  else
    return 0;
  return ! 0;
}


/**
 * Report a broken environment variable and terminate: a typo in a driver
 * script must not silently produce a run with the default configuration.
 *
 * @param name the name of the variable
 * @param value the offending value
 */
_MHD_NORETURN static void
env_error (const char *name, const char *value)
{
  fprintf (stderr,
           "Invalid value '%s' for the environment variable %s.\n",
           (NULL != value) ? value : "(null)",
           name);
  fflush (stderr);
  exit (99);
}


const struct MHD_OptMatrixProfile *
mhd_opt_matrix_from_env (void)
{
  const char *prof_env;
  const char *mem_env;
  const char *discp_env;
  const char *strict_env;
  const char *thr_env;
  const char *poll_env;

  if (0 != env_parsed)
    return env_selected ? &env_profile : NULL;
  env_parsed = ! 0;

  prof_env = getenv (MHD_OPT_MATRIX_PROFILE_ENV);
  mem_env = getenv (MHD_OPT_MATRIX_MEM_ENV);
  discp_env = getenv (MHD_OPT_MATRIX_DISCP_ENV);
  strict_env = getenv (MHD_OPT_MATRIX_STRICT_ENV);
  thr_env = getenv (MHD_OPT_MATRIX_THREADING_ENV);
  poll_env = getenv (MHD_OPT_MATRIX_POLL_ENV);
  if ((NULL == prof_env) && (NULL == mem_env) && (NULL == discp_env) &&
      (NULL == strict_env) && (NULL == thr_env) && (NULL == poll_env))
    return NULL; /* Nothing selected: keep the previous behaviour */

  if (NULL != prof_env)
  {
    const struct MHD_OptMatrixProfile *base;

    base = mhd_opt_matrix_lookup (prof_env);
    if (NULL == base)
      env_error (MHD_OPT_MATRIX_PROFILE_ENV, prof_env);
    env_profile = *base;
  }
  else
    env_profile = opt_profiles[0];
  strncpy (env_profile_name, env_profile.name, sizeof(env_profile_name) - 1);
  env_profile_name[sizeof(env_profile_name) - 1] = 0;
  env_profile.name = env_profile_name;

  /* The explicit per-dimension overrides below are NOT clamped: they are an
     explicit request by the caller, see the header. */
  if (NULL != mem_env)
  {
    if (0 == strcmp (mem_env, "default"))
      env_profile.mem_limit = 0;
    else
    {
      char *end;
      unsigned long v;

      v = strtoul (mem_env, &end, 10);
      if ((NULL == end) || (0 != *end))
        env_error (MHD_OPT_MATRIX_MEM_ENV, mem_env);
      env_profile.mem_limit = (size_t) v;
    }
  }
  if (NULL != discp_env)
  {
    char *end;
    long v;

    v = strtol (discp_env, &end, 10);
    if ((NULL == end) || (0 != *end) || (-3 > v) || (3 < v))
      env_error (MHD_OPT_MATRIX_DISCP_ENV, discp_env);
    env_profile.discipline_lvl = (int) v;
    env_profile.use_legacy_strict = 0;
  }
  if (NULL != strict_env)
  {
    char *end;
    long v;

    v = strtol (strict_env, &end, 10);
    if ((NULL == end) || (0 != *end))
      env_error (MHD_OPT_MATRIX_STRICT_ENV, strict_env);
    env_profile.discipline_lvl = (int) v;
    env_profile.use_legacy_strict = ! 0;
  }
  if (NULL != thr_env)
  {
    if (! parse_threading (thr_env, &env_profile.threading))
      env_error (MHD_OPT_MATRIX_THREADING_ENV, thr_env);
    if ((MHD_OPT_MATRIX_THR_POOL == env_profile.threading) &&
        (2 > env_profile.thread_pool_size))
      env_profile.thread_pool_size = 4;
  }
  if (NULL != poll_env)
  {
    if (! parse_poll (poll_env, &env_profile.poll_backend))
      env_error (MHD_OPT_MATRIX_POLL_ENV, poll_env);
  }
  env_selected = ! 0;
  return &env_profile;
}


int
mhd_opt_matrix_effective_discipline (const struct MHD_OptMatrixProfile *prof)
{
  if (NULL == prof)
    return 0;
  if (! prof->use_legacy_strict)
    return prof->discipline_lvl;
  /* Mirror the mapping of daemon.c:7102-7106 exactly. */
  if (-1 >= prof->discipline_lvl)
    return -3;
  if (1 <= prof->discipline_lvl)
    return 1;
  return 0;
}


int
mhd_opt_matrix_profile_supported (const struct MHD_OptMatrixProfile *prof)
{
  if (NULL == prof)
    return ! 0;
  if ((MHD_OPT_MATRIX_THR_EXTERNAL != prof->threading) &&
      (MHD_YES != MHD_is_feature_supported (MHD_FEATURE_THREADS)))
    return 0;
  if (MHD_OPT_MATRIX_THR_EXTERNAL == prof->threading)
  {
    /* Only the select()-style external interface is driven by the tests. */
    return (MHD_OPT_MATRIX_POLL_SELECT == prof->poll_backend) ? ! 0 : 0;
  }
  if ((MHD_OPT_MATRIX_POLL_POLL == prof->poll_backend) &&
      (MHD_YES != MHD_is_feature_supported (MHD_FEATURE_POLL)))
    return 0;
  if (MHD_OPT_MATRIX_POLL_EPOLL == prof->poll_backend)
  {
    if (MHD_YES != MHD_is_feature_supported (MHD_FEATURE_EPOLL))
      return 0;
    /* MHD refuses to combine 'epoll' with a thread per connection. */
    if (MHD_OPT_MATRIX_THR_PER_CONNECTION == prof->threading)
      return 0;
  }
  return ! 0;
}


const char *
mhd_opt_matrix_describe (const struct MHD_OptMatrixProfile *prof,
                         char *buf,
                         size_t buf_size)
{
  static const char *const thr_names[] = {
    "external polling", "internal thread", "thread-per-connection",
    "thread pool"
  };
  static const char *const poll_names[] = { "select()", "poll()", "epoll" };
  char mem[32];
  char pool[32];
  char discp[64];

  if (NULL == prof)
  {
    snprintf (buf, buf_size, "(built-in defaults of the test)");
    return buf;
  }
  if (0 == prof->mem_limit)
    snprintf (mem, sizeof(mem), "default");
  else
    snprintf (mem, sizeof(mem), "%lu", (unsigned long) prof->mem_limit);
  if (MHD_OPT_MATRIX_THR_POOL == prof->threading)
    snprintf (pool, sizeof(pool), " x%u", prof->thread_pool_size);
  else
    pool[0] = 0;
  /* Always show the level that is really in effect: the deprecated option
     silently maps its value, see mhd_opt_matrix_effective_discipline(). */
  if (prof->use_legacy_strict)
    snprintf (discp, sizeof(discp), "strict_for_client=%d -> discipline_lvl=%d",
              prof->discipline_lvl,
              mhd_opt_matrix_effective_discipline (prof));
  else
    snprintf (discp, sizeof(discp), "discipline_lvl=%d", prof->discipline_lvl);
  snprintf (buf, buf_size,
            "'%s' (mem_limit=%s, %s, %s%s, %s)",
            prof->name,
            mem,
            discp,
            thr_names[(unsigned int) prof->threading],
            pool,
            poll_names[(unsigned int) prof->poll_backend]);
  return buf;
}


unsigned int
mhd_opt_matrix_fill_options (const struct MHD_OptMatrixProfile *prof,
                             struct MHD_OptionItem *ops,
                             unsigned int max_ops)
{
  unsigned int n = 0;

  if (4 > max_ops)
    return 0;
  if (NULL != prof)
  {
    if (0 != prof->mem_limit)
    {
      ops[n].option = MHD_OPTION_CONNECTION_MEMORY_LIMIT;
      ops[n].value = (intptr_t) prof->mem_limit;
      ops[n].ptr_value = NULL;
      ++n;
    }
    if (0 != prof->discipline_lvl)
    {
      ops[n].option = prof->use_legacy_strict ?
                      MHD_OPTION_STRICT_FOR_CLIENT :
                      MHD_OPTION_CLIENT_DISCIPLINE_LVL;
      ops[n].value = (intptr_t) prof->discipline_lvl;
      ops[n].ptr_value = NULL;
      ++n;
    }
    if ((MHD_OPT_MATRIX_THR_POOL == prof->threading) &&
        (1 < prof->thread_pool_size))
    {
      ops[n].option = MHD_OPTION_THREAD_POOL_SIZE;
      ops[n].value = (intptr_t) prof->thread_pool_size;
      ops[n].ptr_value = NULL;
      ++n;
    }
  }
  ops[n].option = MHD_OPTION_END;
  ops[n].value = 0;
  ops[n].ptr_value = NULL;
  ++n;
  return n;
}


unsigned int
mhd_opt_matrix_daemon_flags (const struct MHD_OptMatrixProfile *prof,
                             unsigned int base_flags,
                             int allow_external)
{
  unsigned int flags = base_flags;

  if (NULL == prof)
    return flags;
  switch (prof->threading)
  {
  case MHD_OPT_MATRIX_THR_EXTERNAL:
    if (allow_external)
      return flags; /* No internal thread, no polling backend flag */
    /* The caller cannot drive MHD_run(); fall back to an internal thread. */
    return flags | MHD_USE_INTERNAL_POLLING_THREAD;
  case MHD_OPT_MATRIX_THR_PER_CONNECTION:
    flags |= MHD_USE_INTERNAL_POLLING_THREAD | MHD_USE_THREAD_PER_CONNECTION;
    break;
  case MHD_OPT_MATRIX_THR_INTERNAL:
  case MHD_OPT_MATRIX_THR_POOL:
  default:
    flags |= MHD_USE_INTERNAL_POLLING_THREAD;
    break;
  }
  switch (prof->poll_backend)
  {
  case MHD_OPT_MATRIX_POLL_POLL:
    flags |= MHD_USE_POLL;
    break;
  case MHD_OPT_MATRIX_POLL_EPOLL:
    flags |= MHD_USE_EPOLL;
    break;
  case MHD_OPT_MATRIX_POLL_SELECT:
  default:
    break;
  }
  return flags;
}


int
mhd_opt_matrix_is_external (const struct MHD_OptMatrixProfile *prof)
{
  if (NULL == prof)
    return 0;
  return (MHD_OPT_MATRIX_THR_EXTERNAL == prof->threading) ? ! 0 : 0;
}


int
mhd_opt_matrix_raise_mem_limit (struct MHD_OptMatrixProfile *prof,
                                size_t min_limit)
{
  if ((NULL == prof) || (0 == min_limit) || (0 == prof->mem_limit))
    return 0;
  if (prof->mem_limit >= min_limit)
    return 0;
  prof->mem_limit = min_limit;
  return ! 0;
}


void
mhd_opt_matrix_print_notice (const char *test_name)
{
  const struct MHD_OptMatrixProfile *prof;
  const char *name = (NULL != test_name) ? test_name : "test";
  char desc[256];

  prof = mhd_opt_matrix_from_env ();
  printf ("%s: option matrix profile %s\n",
          name,
          mhd_opt_matrix_describe (prof, desc, sizeof(desc)));
  fflush (stdout);
}
