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
 * @file fuzz/fuzz_memorypool.c
 * @brief Direct in-process fuzzer for src/microhttpd/memorypool.c
 * @author Christian Grothoff
 *
 * memorypool.c is the per-connection allocator: a bump allocator that
 * hands out "normal" blocks from the start of the pool and small,
 * never-reallocated blocks from its end, plus an in-place resize and a
 * reset that moves one surviving block back to the beginning.  Every
 * request buffer, every header name and value of every connection lives
 * in it, so a single mis-computed offset here is a cross-request
 * information leak or a heap overflow -- and one that ASAN alone cannot
 * see, because the whole pool is one malloc()ed object.  (It does see it
 * in a build where MHD_ASAN_POISON_ACTIVE is defined, i.e. where
 * `sanitizer/asan_interface.h` was found and memorypool.c poisons the
 * unallocated parts of the pool itself.  The harness works either way
 * and knows the red zone size that mode adds between two blocks.)
 *
 * The harness therefore keeps its own model of the pool and checks it
 * against the allocator after every single operation:
 *
 *  - every returned pointer lies inside the pool, is aligned, and does
 *    not overlap any other live allocation;
 *  - every live allocation carries a position-dependent byte pattern
 *    that is re-verified later; the allocator moves data around in
 *    MHD_pool_reallocate() and MHD_pool_reset(), and the pattern is what
 *    proves the move was correct;
 *  - the sum of the live allocations plus MHD_pool_get_free() never
 *    exceeds the size of the pool, MHD_pool_get_free() never grows
 *    across an allocation and never shrinks across a deallocation;
 *  - the implications the rest of MHD relies on hold:
 *      * MHD_pool_allocate (pool, MHD_pool_get_free (pool), false) must
 *        succeed (response.c:2203 does exactly this), and more generally
 *        an allocation must not fail while get_free() reports room for
 *        its rounded-up size;
 *      * if MHD_pool_is_resizable_inplace() says yes, a reallocation
 *        that fits must succeed *and must not move the block*
 *        (connection.c:729/750/2082/2121 assert precisely that);
 *      * after freeing the number of bytes MHD_pool_try_alloc() asked
 *        for in @a required_bytes, the same call must succeed -- this is
 *        the whole point of that out parameter and the logic of
 *        MHD_connection_alloc_memory_().
 *
 * Documented preconditions are respected, since violating them would
 * only produce findings about the harness: blocks allocated "from the
 * end" are never passed to MHD_pool_reallocate(), MHD_pool_reset() is
 * never asked for more than the pool size nor for more copy_bytes than
 * the kept block holds, and a block is only ever deallocated with the
 * size it was allocated with.
 *
 * Two *open* defects of memorypool.c are reachable and would otherwise
 * make every run abort; each is gated behind an environment variable,
 * documented in full at full_dealloc_enabled and wrap_realloc_enabled
 * below and in README section 6.1, with a byte-exact reproducer in the
 * built-in seed corpus.  Nothing else is gated.
 *
 * Input format:
 *   byte 0    pool size selector (index into fz_pool_sizes[])
 *   byte 1    flags
 *               0x01  verify every live block after every operation
 *               0x02  prefer allocating "from the end"
 *               rest  unused
 *   byte 2..  a stream of 3-byte operation records
 *               [0] opcode          (see enum fz_op)
 *               [1] block selector / auxiliary nibbles
 *               [2] size selector   (see fz_size())
 */

#define FUZZ_HARNESS_NAME "fuzz_memorypool"
#include "fuzz_common.h"

/* internal.h pulls in MHD_config.h and <microhttpd.h> in the right
   order; including <microhttpd.h> first would redefine _MHD_EXTERN. */
#include "internal.h"
#include "memorypool.h"


/**
 * Alignment of every block the pool hands out; memorypool.c aligns to
 * two words "as GNU libc does".
 */
#define FZ_ALIGN_SIZE (2 * sizeof (void *))

/**
 * Size of the red zone memorypool.c keeps between two blocks.  It only
 * exists in a build with user memory poisoning, i.e. when the pool
 * itself is instrumented; without it the pool is packed tight.
 */
#ifdef MHD_ASAN_POISON_ACTIVE
#define FZ_RED_ZONE_SIZE FZ_ALIGN_SIZE
#else  /* ! MHD_ASAN_POISON_ACTIVE */
#define FZ_RED_ZONE_SIZE ((size_t) 0)
#endif /* ! MHD_ASAN_POISON_ACTIVE */

/**
 * Maximum number of live allocations the model tracks.  An operation
 * that would exceed this is skipped, so the model never loses a block.
 */
#define FZ_MAX_BLOCKS 24

/**
 * Maximum number of operations executed for one input.
 */
#define FZ_MAX_OPS 64

/**
 * Number of bytes of each allocation that carry the check pattern.
 * Bounding this keeps the harness fast; the interesting bugs of a bump
 * allocator are all at the start of a block or at its (ASAN-guarded)
 * end.
 */
#define FZ_PAT_MAX 96

/**
 * Pool sizes to choose from.  MHD uses 128..32768 in practice (the
 * default is 32768 and MHD_OPTION_CONNECTION_MEMORY_LIMIT can set
 * anything); everything at or below 32k is malloc()ed by
 * MHD_pool_create(), so the harness knows the exact usable size and
 * ASAN's redzone sits right behind the pool.  The last two entries are
 * larger than that on purpose: they take the mmap() path of
 * MHD_pool_create() and the munmap() path of MHD_pool_destroy().  Both
 * are powers of two and therefore a multiple of any page size, so the
 * resulting pool is exactly that large either way and the check below
 * stays exact.
 */
static const size_t fz_pool_sizes[] = {
  1, 15, 16, 17, 32, 48, 64, 96, 128, 129, 192, 256, 320, 384, 512,
  768, 1024, 1400, 1500, 2048, 4096, 8192, 16384, 32768, 65536, 131072
};

#define FZ_NUM_POOL_SIZES \
  (sizeof (fz_pool_sizes) / sizeof (fz_pool_sizes[0]))


enum fz_op
{
  FZ_OP_ALLOC = 0,       /**< MHD_pool_allocate() */
  FZ_OP_ALLOC_ALL,       /**< allocate exactly MHD_pool_get_free() bytes */
  FZ_OP_TRY_ALLOC,       /**< MHD_pool_try_alloc() */
  FZ_OP_SQUEEZE,         /**< try_alloc + shrink + retry */
  FZ_OP_REALLOC,         /**< MHD_pool_reallocate() of a live block */
  FZ_OP_REALLOC_NEW,     /**< MHD_pool_reallocate() with old == NULL */
  FZ_OP_DEALLOC,         /**< MHD_pool_deallocate() */
  FZ_OP_RESET,           /**< MHD_pool_reset() */
  FZ_OP_GET_FREE,        /**< MHD_pool_get_free() */
  FZ_OP_RESIZABLE,       /**< MHD_pool_is_resizable_inplace() */
  FZ_OP_VERIFY,          /**< re-check every live block */
  FZ_OP_RECREATE,        /**< MHD_pool_destroy() + MHD_pool_create() */
  FZ_OP_COUNT
};


/**
 * One live allocation.
 */
struct fz_block
{
  /**
   * Address returned by the pool.
   */
  uint8_t *ptr;

  /**
   * Current size of the block, i.e. the number of bytes the harness is
   * allowed to touch and the size it will pass to the pool again.
   */
  size_t size;

  /**
   * Seed of the check pattern of this block.
   */
  uint8_t tag;

  /**
   * True if the block was allocated "from the end" (MHD_pool_allocate()
   * with @a from_end, or MHD_pool_try_alloc()).  Such blocks must never
   * be passed to MHD_pool_reallocate().
   */
  bool from_end;
};


/**
 * The model of one pool.
 */
struct fz_pool
{
  struct MemoryPool *pool;

  /**
   * Address of the first byte of the pool, as returned by
   * MHD_pool_reset() for an empty pool -- that is a real MHD call site
   * (connection.c:3021 uses the result as the new read buffer).
   */
  uint8_t *base;

  /**
   * Total size of the pool in bytes.
   */
  size_t cap;

  struct fz_block blk[FZ_MAX_BLOCKS];

  unsigned int nblk;

  uint8_t next_tag;

  /**
   * Verify every live block after every operation.
   */
  bool paranoid;
};


/**
 * F1 -- MHD_pool_deallocate() of a "from the end" block of a pool that
 * is *exactly* full.  This is a live defect in memorypool.c and is
 * therefore off by default; set MHD_FUZZ_POOL_FULL_DEALLOC=1 to reach
 * it (seed fuzz_memorypool-15.bin is the byte-exact reproducer).
 *
 * MHD_pool_deallocate() decides whether a block came from the front or
 * from the end with
 *
 *     if (block_offset <= pool->pos)     memorypool.c:666
 *
 * which is ambiguous when pool->pos == pool->end, i.e. when the pool has
 * no free space left: a "from the end" block then starts exactly at
 * pool->pos and is treated as a front block.  With --enable-asserts
 *
 *     mhd_assert ((block_offset != pool->pos) || (block_size == 0));   :655
 *     mhd_assert (alg_end <= pool->pos);                               :671
 *
 * both fail, i.e. the process aborts; without them the block is simply
 * not returned to the pool (pool->end is left alone), so the memory is
 * lost until the pool is reset or destroyed.  Reproducer:
 *
 *     p = MHD_pool_create (128);
 *     e = MHD_pool_allocate (p, 16, true);
 *     (void) MHD_pool_allocate (p, MHD_pool_get_free (p), false);
 *     MHD_pool_deallocate (p, e, 16);      <- abort / 16 bytes lost
 *
 * Nothing in memorypool.h forbids this; MHD_pool_deallocate() documents
 * only that "the NULL is tolerated" and has an explicit branch for
 * blocks allocated from the end.  MHD's own call sites never hit it,
 * because the three MHD_pool_deallocate() calls in connection.c and
 * response.c all pass the read or the write buffer, which are front
 * allocations -- so this is a latent defect of a supported branch of the
 * API rather than something reachable from the network today.  A
 * dispatch on `block_offset < pool->end` would resolve the ambiguity.
 */
static int full_dealloc_enabled;

/**
 * F2 -- MHD_pool_reallocate() reports success for a @a new_size that
 * wrapped.  Also a live defect, off by default; set
 * MHD_FUZZ_POOL_WRAP_REALLOC=1 to reach it (seed
 * fuzz_memorypool-16.bin is the byte-exact reproducer).
 *
 * Every other entry point of memorypool.c detects a size that is too
 * close to SIZE_MAX explicitly:
 *
 *     asize = ROUND_TO_ALIGN_PLUS_RED_ZONE (size);
 *     if ( (0 == asize) && (0 != size) )
 *       return NULL;                 // "size too close to SIZE_MAX"
 *
 * -- MHD_pool_allocate(), MHD_pool_try_alloc() and the "need to
 * allocate a new block" tail of MHD_pool_reallocate() all do it.  The
 * in-place branch of MHD_pool_reallocate() instead relies on
 *
 *     const size_t new_apos =
 *       ROUND_TO_ALIGN_PLUS_RED_ZONE (old_offset + new_size);
 *     if ( (new_apos > pool->end) ||
 *          (new_apos < pool->pos) )  // "Value wrap"
 *       return NULL;
 *
 * which does not catch the wrap when the wrapped value happens to land
 * on pool->pos.  For a zero-length block sitting at the front boundary
 * (old_size == 0, old_offset == pool->pos, which is exactly what
 * MHD_pool_reset (pool, NULL, 0, 0) returns -- see connection.c:3021 --
 * or MHD_pool_allocate (pool, 0, false)) and any new_size in
 * [SIZE_MAX - 14, SIZE_MAX], old_offset + new_size wraps to
 * old_offset - 1 - k, which rounds back up to exactly old_offset, i.e.
 * to pool->pos: neither test fires, pool->pos is left alone and the
 * function returns @a old, i.e. it reports success.
 *
 *     p = MHD_pool_create (1024);
 *     b = MHD_pool_reset (p, NULL, 0, 0);
 *     r = MHD_pool_reallocate (p, b, 0, SIZE_MAX - 4);
 *     // r == b, not NULL: the caller now believes it owns
 *     // SIZE_MAX - 4 bytes at the start of a 1024 byte pool,
 *     // while MHD_pool_get_free() still reports the full 1024.
 *
 * The documented contract is "@return new address of the block, or NULL
 * if the pool cannot support @a new_size bytes", so this is a plain
 * contract violation, and one that hands the caller a buffer size the
 * allocation does not have.  No MHD call site can reach it today: every
 * new_size MHD passes is derived from the pool size (connection.c:1636,
 * 2031, 2082, 2121, 2170, 6935), so it is a latent defect rather than
 * something reachable from the network.  Checking the addition itself,
 * e.g. `if (new_size > pool->size - old_offset) return NULL;`, would
 * close it.
 */
static int wrap_realloc_enabled;

static int known_bugs_read;

/** Statistics, printed at exit with --verbose. */
static unsigned long stat_ops;
static unsigned long stat_alloc_ok;
static unsigned long stat_alloc_fail;
static unsigned long stat_realloc_moved;
static unsigned long stat_resets;


static void
print_stats (void)
{
  if (! fuzz_verbose)
    return;
  fprintf (stderr,
           "%s: ops=%lu allocations=%lu (failed %lu) "
           "moved reallocations=%lu resets=%lu\n",
           FUZZ_HARNESS_NAME,
           stat_ops, stat_alloc_ok, stat_alloc_fail,
           stat_realloc_moved, stat_resets);
}


/**
 * Report a finding, prefixed with the name of the operation that was
 * running.
 */
static void
fz_report (const char *op,
           const char *what)
{
  char msg[256];

  (void) snprintf (msg, sizeof (msg), "%s: %s", op, what);
  fuzz_report_finding (msg);
}


/**
 * The ROUND_TO_ALIGN() of memorypool.c, wrap-around included: a size
 * that is too close to SIZE_MAX rounds to 0, which is how the allocator
 * detects it.
 */
static size_t
fz_round (size_t n)
{
  return (n + (FZ_ALIGN_SIZE - 1)) / FZ_ALIGN_SIZE * FZ_ALIGN_SIZE;
}


/**
 * Byte @a idx of the check pattern of a block with seed @a tag.
 */
static uint8_t
fz_pat (uint8_t tag,
        size_t idx)
{
  return (uint8_t) ((((unsigned int) tag) * 131u)
                    + ((unsigned int) (idx * 17u))
                    + 0x5Au);
}


/**
 * Write the check pattern into @a ptr[from..to).
 */
static void
fz_fill (uint8_t *ptr,
         uint8_t tag,
         size_t from,
         size_t to)
{
  size_t i;

  if (to > FZ_PAT_MAX)
    to = FZ_PAT_MAX;
  for (i = from; i < to; i++)
    ptr[i] = fz_pat (tag, i);
}


/**
 * Verify that the first bytes of @a ptr still carry the pattern of
 * @a tag.  The expected bytes are built in an exactly sized malloc()ed
 * buffer, so that a comparison that runs off either end is caught by
 * ASAN rather than silently passing.
 */
static void
fz_verify (const uint8_t *ptr,
           size_t size,
           uint8_t tag,
           const char *op,
           const char *what)
{
  size_t n = (size < FZ_PAT_MAX) ? size : (size_t) FZ_PAT_MAX;
  uint8_t *expect;
  size_t i;

  if (0 == n)
    return;
  expect = (uint8_t *) malloc (n);
  if (NULL == expect)
    abort ();
  for (i = 0; i < n; i++)
    expect[i] = fz_pat (tag, i);
  if (0 != memcmp (expect, ptr, n))
    fz_report (op, what);
  free (expect);
}


/**
 * Verify every live block.
 */
static void
fz_verify_all (struct fz_pool *st,
               const char *op)
{
  unsigned int i;

  for (i = 0; i < st->nblk; i++)
    fz_verify (st->blk[i].ptr,
               st->blk[i].size,
               st->blk[i].tag,
               op,
               "the contents of a live allocation changed");
}


/**
 * Check a pointer the pool just returned: inside the pool, aligned, and
 * not overlapping any block that is still live.  The caller has already
 * removed the block being replaced (if any) from the model.
 */
static void
fz_check_ptr (struct fz_pool *st,
              void *p,
              size_t size,
              const char *op)
{
  const uint8_t *up = (const uint8_t *) p;
  size_t off;
  unsigned int i;

  if ( (up < st->base) ||
       (up > st->base + st->cap) )
  {
    fz_report (op, "returned a pointer outside of the pool");
    return;
  }
  off = (size_t) (up - st->base);
  if ( (size > st->cap) ||
       (off + size > st->cap) )
    fz_report (op, "returned a block that extends past the end of the pool");
  if (0 != (off % FZ_ALIGN_SIZE))
    fz_report (op, "returned a misaligned pointer");
  if (0 == size)
    return;
  for (i = 0; i < st->nblk; i++)
  {
    const uint8_t *q = st->blk[i].ptr;

    if (0 == st->blk[i].size)
      continue;
    if ( (up < q + st->blk[i].size) &&
         (q < up + size) )
    {
      fz_report (op, "returned a block overlapping another live allocation");
      return;
    }
  }
}


/**
 * Invariants that must hold after every single operation.
 */
static void
fz_check_invariants (struct fz_pool *st,
                     const char *op)
{
  size_t total = 0;
  size_t freem;
  unsigned int i;

  freem = MHD_pool_get_free (st->pool);
  if (freem > st->cap)
    fz_report (op, "MHD_pool_get_free() exceeds the size of the pool");
  for (i = 0; i < st->nblk; i++)
    total += st->blk[i].size;
  if (total > st->cap)
    fz_report (op, "the live allocations alone exceed the size of the pool");
  else if (total + freem > st->cap)
    fz_report (op,
               "the live allocations plus the free space exceed the size "
               "of the pool");
  if (st->paranoid)
    fz_verify_all (st, op);
}


static struct fz_block *
fz_add (struct fz_pool *st,
        void *ptr,
        size_t size,
        bool from_end)
{
  struct fz_block *b = &st->blk[st->nblk++];

  b->ptr = (uint8_t *) ptr;
  b->size = size;
  b->tag = st->next_tag++;
  b->from_end = from_end;
  fz_fill (b->ptr, b->tag, 0, size);
  return b;
}


static void
fz_del (struct fz_pool *st,
        struct fz_block *b)
{
  *b = st->blk[--st->nblk];
}


/**
 * Pick a live block.
 *
 * @param st the model
 * @param sel selector byte
 * @param front_only only consider blocks that may be reallocated
 * @return NULL if there is no such block
 */
static struct fz_block *
fz_pick (struct fz_pool *st,
         uint8_t sel,
         bool front_only)
{
  unsigned int i;
  unsigned int n = 0;
  unsigned int idx;

  for (i = 0; i < st->nblk; i++)
  {
    if ( (! front_only) ||
         (! st->blk[i].from_end) )
      n++;
  }
  if (0 == n)
    return NULL;
  idx = ((unsigned int) sel) % n;
  for (i = 0; i < st->nblk; i++)
  {
    if ( (front_only) &&
         (st->blk[i].from_end) )
      continue;
    if (0 == idx)
      return &st->blk[i];
    idx--;
  }
  return NULL; /* unreachable */
}


/**
 * Turn a selector byte into a size.  The four classes matter: tiny
 * sizes are what headers use, fractions of the pool are what the
 * request buffers use, sizes around the currently free amount are where
 * the off-by-one-block bugs live, and sizes close to SIZE_MAX exercise
 * the "value wrap" guards of the allocator.
 */
static size_t
fz_size (uint8_t sel,
         size_t cap,
         size_t freem)
{
  size_t d;

  switch (sel & 0x03)
  {
  case 0:
    return (size_t) (sel >> 2);              /* 0 .. 63 */
  case 1:
    return (((size_t) ((sel >> 2) + 1)) * cap) / 64u;
  case 2:
    d = (size_t) ((sel >> 2) & 0x07u);
    if (0 != (sel & 0x20))
      return freem + d;
    return (freem > d) ? (freem - d) : 0;
  default:
    return SIZE_MAX - (size_t) (sel >> 2);
  }
}


static void
fz_pool_close (struct fz_pool *st)
{
  MHD_pool_destroy (st->pool);
  st->pool = NULL;
  st->nblk = 0;
}


/**
 * Create a pool and learn its base address and its exact size.
 *
 * @return false if the pool could not be created
 */
static bool
fz_pool_open (struct fz_pool *st,
              uint8_t sel)
{
  size_t max = fz_pool_sizes[((size_t) sel) % FZ_NUM_POOL_SIZES];
  void *base;

  st->nblk = 0;
  st->pool = MHD_pool_create (max);
  if (NULL == st->pool)
    return false;
  st->cap = MHD_pool_get_free (st->pool) + FZ_RED_ZONE_SIZE;
  if (st->cap != fz_round (max))
    fz_report ("MHD_pool_create",
               "a fresh pool does not offer the requested size rounded "
               "up to the alignment");
  /* MHD_pool_reset() with nothing to keep returns the start of the
     pool; connection.c:3021 relies on exactly this call.  It is the
     only way to learn the base address through the public interface. */
  base = MHD_pool_reset (st->pool, NULL, 0, 0);
  if (NULL == base)
  {
    fz_report ("MHD_pool_reset", "returned NULL for an empty pool");
    fz_pool_close (st);
    return false;
  }
  st->base = (uint8_t *) base;
  return true;
}


/* ------------------------------------------------------------------ */
/* The individual operations                                           */
/* ------------------------------------------------------------------ */

/**
 * MHD_pool_allocate(), from the front or from the end.
 */
static void
fz_op_alloc (struct fz_pool *st,
             const uint8_t *op,
             bool prefer_end)
{
  static const char *const nm[2] = { "MHD_pool_allocate",
                                     "MHD_pool_allocate (from_end)" };
  const bool from_end = (0 != (op[1] & 0x01)) || prefer_end;
  const char *name = nm[from_end ? 1 : 0];
  size_t freem;
  size_t after;
  size_t size;
  void *p;

  if (st->nblk >= FZ_MAX_BLOCKS)
    return;
  freem = MHD_pool_get_free (st->pool);
  size = fz_size (op[2], st->cap, freem);
  p = MHD_pool_allocate (st->pool, size, from_end);
  after = MHD_pool_get_free (st->pool);
  if (NULL == p)
  {
    stat_alloc_fail++;
    if (after != freem)
      fz_report (name, "a failed allocation changed the amount of free space");
    if ( (0 != fz_round (size)) &&
         (fz_round (size) <= freem) )
      fz_report (name,
                 "allocation failed although MHD_pool_get_free() reported "
                 "room for it");
    return;
  }
  stat_alloc_ok++;
  if (after > freem)
    fz_report (name, "MHD_pool_get_free() increased across an allocation");
  else if (freem - after < size)
    fz_report (name,
               "MHD_pool_get_free() dropped by less than the allocated size");
  fz_check_ptr (st, p, size, name);
  (void) fz_add (st, p, size, from_end);
}


/**
 * Allocate exactly MHD_pool_get_free() bytes.  response.c:2203 does
 * this and dereferences the result without a NULL check, so it must
 * always succeed, and it must leave the pool without any free space.
 */
static void
fz_op_alloc_all (struct fz_pool *st,
                 const uint8_t *op)
{
  static const char name[] = "MHD_pool_allocate (all free)";
  const bool from_end = (0 != (op[1] & 0x01));
  size_t freem;
  void *p;

  if (st->nblk >= FZ_MAX_BLOCKS)
    return;
  freem = MHD_pool_get_free (st->pool);
  if (0 == freem)
    return;
  p = MHD_pool_allocate (st->pool, freem, from_end);
  if (NULL == p)
  {
    stat_alloc_fail++;
    fz_report (name,
               "allocating exactly MHD_pool_get_free() bytes failed");
    return;
  }
  stat_alloc_ok++;
  fz_check_ptr (st, p, freem, name);
  if (0 != MHD_pool_get_free (st->pool))
    fz_report (name,
               "the pool still reports free space after all of it was "
               "allocated");
  (void) fz_add (st, p, freem, from_end);
}


/**
 * MHD_pool_try_alloc().  Checks the contract of @a required_bytes.
 */
static void
fz_op_try_alloc (struct fz_pool *st,
                 const uint8_t *op)
{
  static const char name[] = "MHD_pool_try_alloc";
  size_t freem;
  size_t after;
  size_t size;
  size_t need;
  void *p;

  if (st->nblk >= FZ_MAX_BLOCKS)
    return;
  freem = MHD_pool_get_free (st->pool);
  size = fz_size (op[2], st->cap, freem);
  need = 0x5A5A5A5Au; /* poor man's "was it written at all" */
  p = MHD_pool_try_alloc (st->pool, size, &need);
  after = MHD_pool_get_free (st->pool);
  if (NULL == p)
  {
    stat_alloc_fail++;
    if (after != freem)
      fz_report (name, "a failed allocation changed the amount of free space");
    if (0 == need)
      fz_report (name,
                 "the allocation failed but no additional memory is "
                 "reported to be required");
    else if ( (SIZE_MAX != need) &&
              (need > st->cap) )
      fz_report (name,
                 "more memory is reported to be required than the pool "
                 "has in total");
    if ( (0 != fz_round (size)) &&
         (fz_round (size) <= freem) )
      fz_report (name,
                 "allocation failed although MHD_pool_get_free() reported "
                 "room for it");
    return;
  }
  stat_alloc_ok++;
  if (0 != need)
    fz_report (name,
               "the allocation succeeded but required_bytes was not "
               "cleared");
  if (after > freem)
    fz_report (name, "MHD_pool_get_free() increased across an allocation");
  else if (freem - after < size)
    fz_report (name,
               "MHD_pool_get_free() dropped by less than the allocated size");
  fz_check_ptr (st, p, size, name);
  /* try_alloc always allocates "from the end" */
  (void) fz_add (st, p, size, true);
}


/**
 * The logic of MHD_connection_alloc_memory_() (connection.c:706): when
 * MHD_pool_try_alloc() fails it names the number of bytes that have to
 * be freed in the relocatable area; freeing exactly that many bytes by
 * shrinking a block that is resizable in-place must make the very same
 * allocation succeed.  If it does not, MHD returns "out of memory" for
 * a request it has the memory for.
 */
static void
fz_op_squeeze (struct fz_pool *st,
               const uint8_t *op)
{
  static const char name[] = "MHD_pool_try_alloc (squeeze)";
  size_t size;
  size_t need = 0;
  size_t need2 = 0;
  void *p;
  unsigned int i;
  struct fz_block *victim = NULL;

  if (st->nblk >= FZ_MAX_BLOCKS)
    return;
  size = fz_size (op[2], st->cap, MHD_pool_get_free (st->pool));
  p = MHD_pool_try_alloc (st->pool, size, &need);
  if (NULL != p)
  {
    fz_check_ptr (st, p, size, name);
    (void) fz_add (st, p, size, true);
    return;
  }
  if ( (0 == need) ||
       (SIZE_MAX == need) )
    return;
  for (i = 0; i < st->nblk; i++)
  {
    if (st->blk[i].from_end)
      continue;
    if (st->blk[i].size < need)
      continue;
    if (! MHD_pool_is_resizable_inplace (st->pool,
                                         st->blk[i].ptr,
                                         st->blk[i].size))
      continue;
    victim = &st->blk[i];
    break;
  }
  if (NULL == victim)
    return;
  {
    const size_t new_size = victim->size - need;
    void *shrunk = MHD_pool_reallocate (st->pool,
                                        victim->ptr,
                                        victim->size,
                                        new_size);

    if (NULL == shrunk)
    {
      fz_report (name,
                 "shrinking a block that is resizable in-place failed");
      return;
    }
    if (shrunk != victim->ptr)
      fz_report (name,
                 "shrinking a block that is resizable in-place moved it");
    victim->ptr = (uint8_t *) shrunk;
    victim->size = new_size;
    fz_verify (victim->ptr, victim->size, victim->tag, name,
               "shrinking a block damaged its contents");
  }
  p = MHD_pool_try_alloc (st->pool, size, &need2);
  if (NULL == p)
  {
    fz_report (name,
               "the allocation still fails after freeing the number of "
               "bytes that required_bytes asked for");
    return;
  }
  fz_check_ptr (st, p, size, name);
  (void) fz_add (st, p, size, true);
}


/**
 * MHD_pool_reallocate() of a live block that was allocated from the
 * front.  Blocks allocated "from the end" are excluded: memorypool.c
 * documents ("Blocks 'from the end' must not be reallocated") and
 * asserts that.
 */
static void
fz_op_realloc (struct fz_pool *st,
               const uint8_t *op)
{
  static const char name[] = "MHD_pool_reallocate";
  struct fz_block *b = fz_pick (st, op[1], true);
  struct fz_block saved;
  size_t freem;
  size_t after;
  size_t new_size;
  bool inplace;
  void *p;

  if (NULL == b)
    return;
  freem = MHD_pool_get_free (st->pool);
  new_size = fz_size (op[2], st->cap, freem);
  if ( (0 == b->size) &&
       (new_size > SIZE_MAX - FZ_ALIGN_SIZE) &&
       (! wrap_realloc_enabled) )
    return; /* open finding F2, see above */
  inplace = MHD_pool_is_resizable_inplace (st->pool, b->ptr, b->size);
  saved = *b;
  p = MHD_pool_reallocate (st->pool, b->ptr, b->size, new_size);
  after = MHD_pool_get_free (st->pool);
  if (NULL == p)
  {
    /* "old continues to be valid for old_size" */
    if (after != freem)
      fz_report (name,
                 "a failed reallocation changed the amount of free space");
    fz_verify (saved.ptr, saved.size, saved.tag, name,
               "a failed reallocation damaged the old block");
    if ( (inplace) &&
         (new_size <= saved.size + freem) )
      fz_report (name,
                 "reallocation failed although the block is resizable "
                 "in-place and the pool has the required free space");
    return;
  }
  if ( (inplace) &&
       (p != saved.ptr) )
    fz_report (name,
               "a block that MHD_pool_is_resizable_inplace() accepted was "
               "moved");
  if ( (new_size >= saved.size) &&
       (after > freem) )
    fz_report (name,
               "MHD_pool_get_free() increased across a growing "
               "reallocation");
  /* the old location is gone as far as the model is concerned */
  fz_del (st, b);
  if (p != saved.ptr)
    stat_realloc_moved++;
  fz_check_ptr (st, p, new_size, name);
  fz_verify ((const uint8_t *) p,
             (new_size < saved.size) ? new_size : saved.size,
             saved.tag,
             name,
             "reallocation did not preserve the contents of the block");
  b = &st->blk[st->nblk++];
  b->ptr = (uint8_t *) p;
  b->size = new_size;
  b->tag = saved.tag;
  b->from_end = false;
  if (new_size > saved.size)
    fz_fill (b->ptr, b->tag, saved.size, new_size);
}


/**
 * MHD_pool_reallocate() with @a old == NULL, which is the documented
 * way to obtain a fresh relocatable block (connection.c:2121 uses it
 * for the very first write buffer).
 */
static void
fz_op_realloc_new (struct fz_pool *st,
                   const uint8_t *op)
{
  static const char name[] = "MHD_pool_reallocate (fresh)";
  size_t freem;
  size_t size;
  void *p;

  if (st->nblk >= FZ_MAX_BLOCKS)
    return;
  freem = MHD_pool_get_free (st->pool);
  size = fz_size (op[2], st->cap, freem);
  p = MHD_pool_reallocate (st->pool, NULL, 0, size);
  if (NULL == p)
  {
    stat_alloc_fail++;
    if ( (0 != fz_round (size)) &&
         (fz_round (size) <= freem) )
      fz_report (name,
                 "allocation failed although MHD_pool_get_free() reported "
                 "room for it");
    return;
  }
  stat_alloc_ok++;
  if (MHD_pool_get_free (st->pool) > freem)
    fz_report (name, "MHD_pool_get_free() increased across an allocation");
  fz_check_ptr (st, p, size, name);
  (void) fz_add (st, p, size, false);
}


/**
 * MHD_pool_deallocate() of a live block, or of NULL ("the NULL is
 * tolerated").  A block is always deallocated with the size it
 * currently has: memorypool.c asserts that the block lies inside the
 * allocated area, and splitting a block is explicitly disallowed.
 */
static void
fz_op_dealloc (struct fz_pool *st,
               const uint8_t *op)
{
  static const char name[] = "MHD_pool_deallocate";
  struct fz_block *b = fz_pick (st, op[1], false);
  size_t freem;
  size_t after;

  freem = MHD_pool_get_free (st->pool);
  if ( (NULL != b) &&
       (b->from_end) &&
       (0 != b->size) &&
       (0 == freem) &&
       (! full_dealloc_enabled) )
  {
    /* See the comment on full_dealloc_enabled: this is an open finding,
       not a precondition of MHD_pool_deallocate().  The lowest-addressed
       live "from the end" block of non-zero size starts exactly at
       pool->end, which for a full pool is also pool->pos -- the
       ambiguous case.  Any block above it is unaffected, so only that
       one block is spared.  Zero-sized blocks do not count: they consume
       nothing, so they can sit below pool->end once a later
       deallocation has moved pool->end back up past them. */
    unsigned int i;

    for (i = 0; i < st->nblk; i++)
    {
      if ( (st->blk[i].from_end) &&
           (0 != st->blk[i].size) &&
           (st->blk[i].ptr < b->ptr) )
        break;
    }
    if (i == st->nblk)
      return;
  }
  if (NULL == b)
  {
    MHD_pool_deallocate (st->pool, NULL, 0);
  }
  else
  {
    fz_verify (b->ptr, b->size, b->tag, name,
               "the contents of the block changed before it was freed");
    MHD_pool_deallocate (st->pool, b->ptr, b->size);
    fz_del (st, b);
  }
  after = MHD_pool_get_free (st->pool);
  if (after < freem)
    fz_report (name, "deallocation reduced the amount of free space");
}


/**
 * MHD_pool_reset().  Preconditions: copy_bytes <= new_size,
 * new_size <= size of the pool, and the kept block must really hold
 * copy_bytes bytes.
 */
static void
fz_op_reset (struct fz_pool *st,
             const uint8_t *op)
{
  static const char name[] = "MHD_pool_reset";
  struct fz_block *b = fz_pick (st, (uint8_t) (op[1] & 0x0F), false);
  size_t new_size;
  size_t copy;
  uint8_t tag = 0;
  void *p;

  new_size = fz_size (op[2], st->cap, MHD_pool_get_free (st->pool));
  if (new_size > st->cap)
    new_size = st->cap;
  copy = 0;
  if (NULL != b)
  {
    copy = (b->size * ((size_t) (op[1] >> 4))) / 15u;
    if (copy > b->size)
      copy = b->size;
    if (copy > new_size)
      copy = new_size;
    tag = b->tag;
    fz_verify (b->ptr, b->size, b->tag, name,
               "the contents of the kept block changed before the reset");
  }
  p = MHD_pool_reset (st->pool,
                      (NULL != b) ? b->ptr : NULL,
                      copy,
                      new_size);
  stat_resets++;
  /* every allocation is gone now */
  st->nblk = 0;
  if (NULL == p)
  {
    fz_report (name, "returned NULL");
    return;
  }
  fz_check_ptr (st, p, new_size, name);
  fz_verify ((const uint8_t *) p, copy, tag, name,
             "the kept bytes did not survive the reset");
  b = fz_add (st, p, new_size, false);
  /* fz_add() has just re-tagged and re-filled the whole block */
}


/**
 * MHD_pool_is_resizable_inplace() on a live block, or on NULL.
 */
static void
fz_op_resizable (struct fz_pool *st,
                 const uint8_t *op)
{
  static const char name[] = "MHD_pool_is_resizable_inplace";
  struct fz_block *b = fz_pick (st, op[1], false);
  bool r;

  if ( (NULL == b) ||
       (0 != (op[1] & 0x80)) )
  {
    if (MHD_pool_is_resizable_inplace (st->pool, NULL, 0))
      fz_report (name, "an unallocated block is reported as resizable");
    return;
  }
  r = MHD_pool_is_resizable_inplace (st->pool, b->ptr, b->size);
  if ( (r) &&
       (b->from_end) &&
       (0 != b->size) )
    fz_report (name,
               "a block allocated from the end is reported as resizable "
               "in-place");
  if (! r)
    return;
  /* A block that is resizable in-place must survive a resize to its own
     size without moving; connection.c asserts this after every such
     reallocation. */
  {
    void *p = MHD_pool_reallocate (st->pool, b->ptr, b->size, b->size);

    if (NULL == p)
      fz_report (name,
                 "reallocating a resizable block to its own size failed");
    else if (p != b->ptr)
      fz_report (name,
                 "reallocating a resizable block to its own size moved it");
  }
}


static void
fz_do_op (struct fz_pool *st,
          const uint8_t *op,
          bool prefer_end)
{
  const char *name = "operation";

  stat_ops++;
  switch ((enum fz_op) (op[0] % (uint8_t) FZ_OP_COUNT))
  {
  case FZ_OP_ALLOC:
    fz_op_alloc (st, op, prefer_end);
    break;
  case FZ_OP_ALLOC_ALL:
    fz_op_alloc_all (st, op);
    break;
  case FZ_OP_TRY_ALLOC:
    fz_op_try_alloc (st, op);
    break;
  case FZ_OP_SQUEEZE:
    fz_op_squeeze (st, op);
    break;
  case FZ_OP_REALLOC:
    fz_op_realloc (st, op);
    break;
  case FZ_OP_REALLOC_NEW:
    fz_op_realloc_new (st, op);
    break;
  case FZ_OP_DEALLOC:
    fz_op_dealloc (st, op);
    break;
  case FZ_OP_RESET:
    fz_op_reset (st, op);
    break;
  case FZ_OP_GET_FREE:
    name = "MHD_pool_get_free";
    break;
  case FZ_OP_RESIZABLE:
    fz_op_resizable (st, op);
    break;
  case FZ_OP_VERIFY:
    name = "verify";
    fz_verify_all (st, name);
    break;
  case FZ_OP_RECREATE:
    fz_pool_close (st);
    if (! fz_pool_open (st, op[1]))
      return;
    break;
  case FZ_OP_COUNT:
  default:
    break;
  }
  fz_check_invariants (st, name);
}


int
LLVMFuzzerTestOneInput (const uint8_t *data,
                        size_t size)
{
  static bool inited = false;
  struct fz_pool st;
  size_t nops;
  size_t i;

  if (size < 5)
    return 0;
  if (! inited)
  {
    inited = true;
    /* Sets the page size used by MHD_pool_create(); MHD does this once
       from MHD_start_daemon(). */
    MHD_init_mem_pools_ ();
    (void) atexit (&print_stats);
  }
  if (! known_bugs_read)
  {
    const char *e;

    known_bugs_read = 1;
    e = getenv ("MHD_FUZZ_POOL_FULL_DEALLOC");
    if (NULL != e)
      full_dealloc_enabled = (0 != atoi (e));
    e = getenv ("MHD_FUZZ_POOL_WRAP_REALLOC");
    if (NULL != e)
      wrap_realloc_enabled = (0 != atoi (e));
  }
  memset (&st, 0, sizeof (st));
  st.paranoid = (0 != (data[1] & 0x01));
  if (! fz_pool_open (&st, data[0]))
    return 0;
  nops = (size - 2) / 3;
  if (nops > FZ_MAX_OPS)
    nops = FZ_MAX_OPS;
  for (i = 0; i < nops; i++)
  {
    if (NULL == st.pool)
      break;
    fz_do_op (&st, data + 2 + 3 * i, (0 != (data[1] & 0x02)));
  }
  fz_verify_all (&st, "final");
  fz_pool_close (&st);  /* MHD_pool_destroy() tolerates a NULL pool */
  return 0;
}


/* ------------------------------------------------------------------ */
/* Generator                                                           */
/* ------------------------------------------------------------------ */

/**
 * Opcodes, weighted: the allocating operations and the reallocation are
 * what move the pool's internal offsets around, so they get most of the
 * probability mass, while the read-only queries and the destructive
 * reset and re-create are rarer.
 */
static const uint8_t gen_ops[] = {
  FZ_OP_ALLOC, FZ_OP_ALLOC, FZ_OP_ALLOC, FZ_OP_ALLOC,
  FZ_OP_ALLOC_ALL,
  FZ_OP_TRY_ALLOC, FZ_OP_TRY_ALLOC,
  FZ_OP_SQUEEZE, FZ_OP_SQUEEZE,
  FZ_OP_REALLOC, FZ_OP_REALLOC, FZ_OP_REALLOC, FZ_OP_REALLOC,
  FZ_OP_REALLOC_NEW,
  FZ_OP_DEALLOC, FZ_OP_DEALLOC, FZ_OP_DEALLOC,
  FZ_OP_RESET,
  FZ_OP_GET_FREE,
  FZ_OP_RESIZABLE, FZ_OP_RESIZABLE,
  FZ_OP_VERIFY,
  FZ_OP_RECREATE
};


/**
 * Size selector bytes that are worth trying often: the boundary cases
 * (exactly the free space, one alignment unit more or less) and the
 * value-wrap guards.
 */
static uint8_t
gen_size_sel (struct fuzz_rng *rng)
{
  const uint32_t k = fuzz_below (rng, 100);
  uint32_t d;
  uint32_t sign;

  if (k < 35)                                  /* tiny */
    return (uint8_t) ((fuzz_below (rng, 64) << 2) | 0u);
  if (k < 60)                                  /* fraction of the pool */
    return (uint8_t) ((fuzz_below (rng, 64) << 2) | 1u);
  if (k < 95)
  {                                            /* around the free space */
    /* Two statements, not one expression: the order in which the
       operands of '|' are evaluated is unspecified, and both calls
       advance the PRNG, so a single expression would make the generated
       stream compiler-dependent. */
    d = fuzz_below (rng, 8);
    sign = fuzz_below (rng, 2);
    return (uint8_t) ((d << 2) | (sign << 5) | 2u);
  }
  return (uint8_t) ((fuzz_below (rng, 64) << 2) | 3u);   /* value wrap */
}


static size_t
fuzz_generate (struct fuzz_rng *rng,
               uint8_t *buf,
               size_t cap)
{
  size_t len = 0;
  unsigned int nops;
  unsigned int i;
  unsigned int psel;
  uint8_t flags = 0;

  if (cap < 8)
    return 0;
  /* Small pools are where the interesting paths are, so bias towards
     them, but keep the whole table reachable. */
  if (fuzz_chance (rng, 3))
    psel = fuzz_below (rng, (uint32_t) FZ_NUM_POOL_SIZES);
  else
    psel = fuzz_below (rng, 16);
  buf[len++] = (uint8_t) psel;
  /* One PRNG call per statement, see gen_size_sel(). */
  if (fuzz_chance (rng, 4))
    flags |= 0x01;
  if (fuzz_chance (rng, 8))
    flags |= 0x02;
  buf[len++] = flags;
  nops = 1 + fuzz_below (rng, FZ_MAX_OPS);
  for (i = 0; i < nops; i++)
  {
    if (len + 3 > cap)
      break;
    buf[len++] = gen_ops[fuzz_below (rng, (uint32_t) (sizeof (gen_ops)))];
    buf[len++] = fuzz_byte (rng);
    buf[len++] = gen_size_sel (rng);
  }
  return len;
}


/* ------------------------------------------------------------------ */
/* Seed corpus                                                         */
/* ------------------------------------------------------------------ */

/* Size selectors, see fz_size() */
#define SZ_TINY(n)    ((uint8_t) ((((unsigned int) (n)) << 2) | 0u))
#define SZ_FRAC(k)    ((uint8_t) ((((unsigned int) (k)) << 2) | 1u))
#define SZ_FREE       ((uint8_t) 2u)
#define SZ_FREE_M(d)  ((uint8_t) ((((unsigned int) (d)) << 2) | 2u))
#define SZ_FREE_P(d)  ((uint8_t) ((((unsigned int) (d)) << 2) | 0x20u | 2u))
#define SZ_HUGE       ((uint8_t) 3u)

/* Pool size selectors, indices into fz_pool_sizes[] */
#define PS_1     0
#define PS_16    2
#define PS_32    4
#define PS_64    6
#define PS_128   8
#define PS_256   11
#define PS_512   14
#define PS_1024  16
#define PS_1500  18
#define PS_32768 23

#define OPR(o,b,s) ((uint8_t) (o)), ((uint8_t) (b)), (s)

static const uint8_t seed_grow_shrink[] = {
  PS_512, 0x01,
  OPR (FZ_OP_ALLOC, 0x00, SZ_TINY (32)),
  OPR (FZ_OP_REALLOC, 0x00, SZ_TINY (63)),
  OPR (FZ_OP_REALLOC, 0x00, SZ_TINY (8)),
  OPR (FZ_OP_REALLOC, 0x00, SZ_FRAC (32)),
  OPR (FZ_OP_VERIFY, 0x00, SZ_TINY (0)),
  OPR (FZ_OP_REALLOC, 0x00, SZ_TINY (1)),
  OPR (FZ_OP_DEALLOC, 0x00, SZ_TINY (0))
};

static const uint8_t seed_two_blocks_realloc[] = {
  PS_256, 0x01,
  OPR (FZ_OP_ALLOC, 0x00, SZ_TINY (17)),
  OPR (FZ_OP_ALLOC, 0x00, SZ_TINY (23)),
  /* the first block is no longer the last one: it has to move */
  OPR (FZ_OP_REALLOC, 0x00, SZ_TINY (60)),
  OPR (FZ_OP_VERIFY, 0x00, SZ_TINY (0)),
  OPR (FZ_OP_REALLOC, 0x01, SZ_TINY (40)),
  OPR (FZ_OP_VERIFY, 0x00, SZ_TINY (0))
};

static const uint8_t seed_from_end[] = {
  PS_128, 0x01,
  OPR (FZ_OP_ALLOC, 0x01, SZ_TINY (16)),
  OPR (FZ_OP_ALLOC, 0x01, SZ_TINY (1)),
  OPR (FZ_OP_ALLOC, 0x00, SZ_TINY (16)),
  OPR (FZ_OP_RESIZABLE, 0x00, SZ_TINY (0)),
  OPR (FZ_OP_DEALLOC, 0x00, SZ_TINY (0)),
  OPR (FZ_OP_ALLOC, 0x01, SZ_TINY (16))
};

static const uint8_t seed_fill_exactly[] = {
  PS_128, 0x01,
  OPR (FZ_OP_ALLOC, 0x01, SZ_TINY (16)),
  OPR (FZ_OP_ALLOC_ALL, 0x00, SZ_TINY (0)),
  OPR (FZ_OP_GET_FREE, 0x00, SZ_TINY (0)),
  OPR (FZ_OP_ALLOC, 0x00, SZ_TINY (1)),
  OPR (FZ_OP_TRY_ALLOC, 0x00, SZ_TINY (1))
};

static const uint8_t seed_squeeze[] = {
  PS_512, 0x01,
  OPR (FZ_OP_ALLOC, 0x00, SZ_FREE),
  OPR (FZ_OP_SQUEEZE, 0x00, SZ_TINY (40)),
  OPR (FZ_OP_SQUEEZE, 0x00, SZ_TINY (7)),
  OPR (FZ_OP_VERIFY, 0x00, SZ_TINY (0)),
  OPR (FZ_OP_SQUEEZE, 0x00, SZ_FRAC (8))
};

static const uint8_t seed_squeeze_small[] = {
  PS_128, 0x01,
  OPR (FZ_OP_REALLOC_NEW, 0x00, SZ_FREE_M (2)),
  OPR (FZ_OP_SQUEEZE, 0x00, SZ_TINY (17)),
  OPR (FZ_OP_SQUEEZE, 0x00, SZ_TINY (17)),
  OPR (FZ_OP_SQUEEZE, 0x00, SZ_TINY (17))
};

static const uint8_t seed_reset_keep[] = {
  PS_1500, 0x01,
  OPR (FZ_OP_ALLOC, 0x00, SZ_TINY (60)),
  OPR (FZ_OP_ALLOC, 0x01, SZ_TINY (12)),
  OPR (FZ_OP_RESET, 0xF0, SZ_FRAC (31)),
  OPR (FZ_OP_VERIFY, 0x00, SZ_TINY (0)),
  OPR (FZ_OP_RESET, 0xF0, SZ_TINY (4)),
  OPR (FZ_OP_RESET, 0x00, SZ_TINY (0))
};

static const uint8_t seed_reset_full[] = {
  PS_256, 0x01,
  OPR (FZ_OP_ALLOC, 0x00, SZ_FRAC (63)),
  OPR (FZ_OP_RESET, 0xF0, SZ_FRAC (63)),
  OPR (FZ_OP_RESET, 0xF0, SZ_FREE_P (1)),
  OPR (FZ_OP_VERIFY, 0x00, SZ_TINY (0))
};

static const uint8_t seed_boundary[] = {
  PS_64, 0x01,
  OPR (FZ_OP_ALLOC, 0x00, SZ_FREE_M (1)),
  OPR (FZ_OP_ALLOC, 0x00, SZ_FREE),
  OPR (FZ_OP_ALLOC, 0x01, SZ_FREE_P (1)),
  OPR (FZ_OP_TRY_ALLOC, 0x00, SZ_FREE),
  OPR (FZ_OP_DEALLOC, 0x00, SZ_TINY (0)),
  OPR (FZ_OP_ALLOC, 0x00, SZ_FREE)
};

static const uint8_t seed_wrap[] = {
  PS_256, 0x00,
  OPR (FZ_OP_ALLOC, 0x00, SZ_HUGE),
  OPR (FZ_OP_ALLOC, 0x01, SZ_HUGE),
  OPR (FZ_OP_TRY_ALLOC, 0x00, SZ_HUGE),
  OPR (FZ_OP_REALLOC_NEW, 0x00, SZ_HUGE),
  OPR (FZ_OP_ALLOC, 0x00, SZ_TINY (16)),
  OPR (FZ_OP_REALLOC, 0x00, SZ_HUGE),
  OPR (FZ_OP_VERIFY, 0x00, SZ_TINY (0))
};

static const uint8_t seed_tiny_pool[] = {
  PS_1, 0x01,
  OPR (FZ_OP_ALLOC, 0x00, SZ_TINY (1)),
  OPR (FZ_OP_ALLOC, 0x01, SZ_TINY (1)),
  OPR (FZ_OP_GET_FREE, 0x00, SZ_TINY (0)),
  OPR (FZ_OP_RESET, 0xF0, SZ_TINY (1)),
  OPR (FZ_OP_DEALLOC, 0x00, SZ_TINY (0))
};

static const uint8_t seed_zero_sizes[] = {
  PS_32, 0x01,
  OPR (FZ_OP_ALLOC, 0x00, SZ_TINY (0)),
  OPR (FZ_OP_ALLOC, 0x01, SZ_TINY (0)),
  OPR (FZ_OP_REALLOC, 0x00, SZ_TINY (0)),
  OPR (FZ_OP_REALLOC, 0x00, SZ_TINY (4)),
  OPR (FZ_OP_DEALLOC, 0x00, SZ_TINY (0)),
  OPR (FZ_OP_RESET, 0x00, SZ_TINY (0))
};

static const uint8_t seed_many_small[] = {
  PS_1500, 0x01,
  OPR (FZ_OP_ALLOC, 0x00, SZ_TINY (5)),
  OPR (FZ_OP_ALLOC, 0x01, SZ_TINY (5)),
  OPR (FZ_OP_ALLOC, 0x00, SZ_TINY (5)),
  OPR (FZ_OP_ALLOC, 0x01, SZ_TINY (5)),
  OPR (FZ_OP_ALLOC, 0x00, SZ_TINY (5)),
  OPR (FZ_OP_ALLOC, 0x01, SZ_TINY (5)),
  OPR (FZ_OP_REALLOC, 0x00, SZ_TINY (33)),
  OPR (FZ_OP_REALLOC, 0x01, SZ_TINY (33)),
  OPR (FZ_OP_DEALLOC, 0x02, SZ_TINY (0)),
  OPR (FZ_OP_VERIFY, 0x00, SZ_TINY (0)),
  OPR (FZ_OP_ALLOC, 0x00, SZ_TINY (5))
};

static const uint8_t seed_recreate[] = {
  PS_32768, 0x00,
  OPR (FZ_OP_ALLOC, 0x00, SZ_FRAC (60)),
  OPR (FZ_OP_RECREATE, PS_16, SZ_TINY (0)),
  OPR (FZ_OP_ALLOC, 0x00, SZ_FREE),
  OPR (FZ_OP_RECREATE, PS_512, SZ_TINY (0)),
  OPR (FZ_OP_ALLOC, 0x01, SZ_TINY (24)),
  OPR (FZ_OP_RESET, 0xF0, SZ_FRAC (2))
};

/* The read-buffer life cycle of a connection: allocate the read buffer,
   grow it to everything that is free, put the parsed headers "at the
   end", shrink the read buffer to what was actually received, then
   reset the pool keeping the received bytes -- connection.c does
   exactly this for every keep-alive request. */
static const uint8_t seed_connection_cycle[] = {
  PS_1500, 0x01,
  OPR (FZ_OP_REALLOC_NEW, 0x00, SZ_FRAC (31)),
  OPR (FZ_OP_REALLOC, 0x00, SZ_FREE),
  OPR (FZ_OP_TRY_ALLOC, 0x00, SZ_TINY (12)),
  OPR (FZ_OP_TRY_ALLOC, 0x00, SZ_TINY (20)),
  OPR (FZ_OP_SQUEEZE, 0x00, SZ_TINY (40)),
  OPR (FZ_OP_REALLOC, 0x00, SZ_TINY (60)),
  OPR (FZ_OP_VERIFY, 0x00, SZ_TINY (0)),
  OPR (FZ_OP_RESET, 0xF0, SZ_FRAC (31)),
  OPR (FZ_OP_REALLOC, 0x00, SZ_FREE),
  OPR (FZ_OP_VERIFY, 0x00, SZ_TINY (0))
};


/* The reproducer of the open finding described at full_dealloc_enabled:
   a 128 byte pool, one 16 byte block "from the end", the whole rest of
   the pool allocated from the front, then that first block released.
   Inert unless MHD_FUZZ_POOL_FULL_DEALLOC=1 is set. */
static const uint8_t seed_dealloc_end_full[] = {
  PS_128, 0x01,
  OPR (FZ_OP_ALLOC, 0x01, SZ_TINY (16)),
  OPR (FZ_OP_ALLOC_ALL, 0x00, SZ_TINY (0)),
  OPR (FZ_OP_DEALLOC, 0x00, SZ_TINY (0))
};


/* The reproducer of the open finding F2: MHD_pool_reset() with nothing
   to keep leaves a zero-length block at the front boundary, and
   reallocating that to SIZE_MAX wraps.  Inert unless
   MHD_FUZZ_POOL_WRAP_REALLOC=1 is set. */
static const uint8_t seed_realloc_wrap[] = {
  PS_1024, 0x01,
  OPR (FZ_OP_RESET, 0x00, SZ_TINY (0)),
  OPR (FZ_OP_REALLOC, 0x00, SZ_HUGE)
};


struct mp_seed
{
  const uint8_t *bytes;
  size_t len;
};

#define MSEED(a) { (a), sizeof (a) }

static const struct mp_seed mp_seeds[] = {
  MSEED (seed_grow_shrink),
  MSEED (seed_two_blocks_realloc),
  MSEED (seed_from_end),
  MSEED (seed_fill_exactly),
  MSEED (seed_squeeze),
  MSEED (seed_squeeze_small),
  MSEED (seed_reset_keep),
  MSEED (seed_reset_full),
  MSEED (seed_boundary),
  MSEED (seed_wrap),
  MSEED (seed_tiny_pool),
  MSEED (seed_zero_sizes),
  MSEED (seed_many_small),
  MSEED (seed_recreate),
  MSEED (seed_connection_cycle),
  MSEED (seed_dealloc_end_full),
  MSEED (seed_realloc_wrap)
};


static size_t
fuzz_seed_count (void)
{
  return sizeof (mp_seeds) / sizeof (mp_seeds[0]);
}


static const uint8_t *
fuzz_seed_get (size_t idx,
               size_t *len)
{
  *len = mp_seeds[idx].len;
  return mp_seeds[idx].bytes;
}
