/* mimalloc 3 as musl's allocator (--with-malloc=external): the whole of mimalloc in one
 * translation unit, and the entry points musl calls. Adapted from Chimera Linux's glue for
 * mimalloc 2 (https://github.com/chimera-linux/cports, main/musl/files/mimalloc.c). */

/* the C library build (patches/mimalloc-libc.patch) */
#define MI_LIBC_BUILD 1
#define MI_TLS_MODEL_LIBC 1
/* the libc malloc reads no environment variables */
#define MI_NO_GETENV 1
/* no constructor and no pthread_atfork: musl calls __malloc_init and __malloc_atfork */
#define MI_PRIM_HAS_PROCESS_ATTACH 1
#define MI_NO_PTHREAD_ATFORK 1
/* hardened: invalid and double free checks, guard pages around metadata, encoded free lists,
 * randomized allocation; without padding, which makes some programs a lot slower (as Chimera) */
#define MI_SECURE 4
#define MI_PADDING 0

#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wunused-function"

#include <features.h>
/* small workaround for musl includes */
#ifdef weak
#undef weak
#endif

#include "pthread_impl.h"

/* internal: direct system calls */
#include "syscall.h"
#define madvise __madvise
#define MADV_DONTNEED POSIX_MADV_DONTNEED

#include <stdatomic.h>
#if ATOMIC_LONG_LOCK_FREE != 2 || ATOMIC_CHAR_LOCK_FREE != 2 || ATOMIC_LLONG_LOCK_FREE != 2
#error words, bytes and 64-bit integers must be lock-free
#endif

/* The thread structure holds mimalloc's per-thread pointers (patches/0100-malloc-tls-extra.patch):
 * musl itself has no thread locals. */
#define MI_LIBC_TLS_theap_default    (__pthread_self()->malloc_tls)
#define MI_LIBC_TLS_theap_cached     (__pthread_self()->malloc_tls_extra[0])
#define MI_LIBC_TLS_mi_thread_locals (__pthread_self()->malloc_tls_extra[1])
#define MI_LIBC_TLS_mi_slot_fast     (__pthread_self()->malloc_tls_extra[2])

/* A thread's id: its thread pointer when it first allocates. Kept when the dynamic linker moves
 * the initial thread structure, and inherited by a forked child, so the pages it owns stay its
 * own; the kernel thread id has neither property. The low bits are clear (alignment). */
static inline size_t mi_libc_thread_id(void) {
    pthread_t self = __pthread_self();
    if (__builtin_expect(self->malloc_tls_extra[3] == NULL, 0))
        self->malloc_tls_extra[3] = (void *)self;
    return (size_t)self->malloc_tls_extra[3];
}
#define MI_PRIM_THREAD_ID() mi_libc_thread_id()

/* the whole mimalloc source */
#include "static.c"

/* entry points */

#define INTERFACE __attribute__((visibility("default")))

extern int __malloc_replaced;
extern int __aligned_alloc_replaced;

void * const __malloc_tls_default = (void *)&_mi_theap_empty;

void __malloc_init(pthread_t p) {
    (void)p;
    _mi_auto_process_init();
}

void __malloc_tls_teardown(pthread_t p) {
    /* if it never allocated, nothing to do */
    if (p->malloc_tls == __malloc_tls_default)
        return;
    _mi_thread_done(p->malloc_tls);
    p->malloc_tls = __malloc_tls_default;
}

/* The locks shared between threads. */
static size_t mi_fork_locks(mi_lock_t **locks) {
    size_t n = 0;
    mi_subproc_t *subproc = _mi_subproc_main();
    mi_heap_t *heap = mi_atomic_load_ptr_acquire(mi_heap_t, &subproc->heap_main);
    locks[n++] = &mi_subprocs_lock;
    locks[n++] = &subproc->heaps_lock;
    if (heap != NULL) {
        locks[n++] = &heap->theaps_lock;
        locks[n++] = &heap->os_abandoned_pages_lock;
        locks[n++] = &heap->arena_pages_lock;
    }
    locks[n++] = &subproc->theap_meta_lock;
    locks[n++] = &subproc->arena_reserve_lock;
    locks[n++] = &out_buf_lock;
    return n;
}

/* Takes all of `locks` without holding any while waiting for one: mimalloc nests some of them
 * (e.g. theap metadata, then arena pages), and this must not deadlock whatever the order. */
static void mi_fork_lock_all(mi_lock_t **locks, size_t n) {
    for (;;) {
        size_t i = 0;
        while (i < n && mi_lock_try_acquire(locks[i]))
            i++;
        if (i == n)
            return;
        while (i > 0)
            mi_lock_release(locks[--i]);
        __syscall(SYS_sched_yield);
    }
}

/* fork() of a multithreaded process: before (who < 0) no other thread may hold a lock the child
 * needs; after, the parent (0) releases them, and the child (1) reinitializes them (their owners
 * may not exist there) and abandons the pages of the threads it lost. */
void __malloc_atfork(int who) {
    mi_lock_t *locks[8];
    size_t n = mi_fork_locks(locks);
    if (who < 0) {
        mi_fork_lock_all(locks, n);
    } else if (who == 0) {
        for (size_t i = n; i > 0; i--)
            mi_lock_release(locks[i - 1]);
    } else {
        for (size_t i = 0; i < n; i++)
            mi_lock_init(locks[i]);
        _mi_fork_child();
    }
}

/* mimalloc has no use for memory donated by the dynamic linker */
void __malloc_donate(char *a, char *b) { (void)a; (void)b; }

void *__libc_calloc(size_t m, size_t n) {
    return mi_calloc(m, n);
}

void __libc_free(void *ptr) {
    mi_free(ptr);
}

void *__libc_malloc_impl(size_t len) {
    return mi_malloc(len);
}

void *__libc_realloc(void *ptr, size_t len) {
    return mi_realloc(ptr, len);
}

/* musl implements memalign and posix_memalign with aligned_alloc */
INTERFACE void *aligned_alloc(size_t align, size_t len) {
    if (mi_unlikely(__malloc_replaced && !__aligned_alloc_replaced)) {
        errno = ENOMEM;
        return NULL;
    }
    return mi_malloc_aligned(len, align);
}

INTERFACE size_t malloc_usable_size(void *p) {
    return mi_usable_size(p);
}

#pragma GCC diagnostic pop
