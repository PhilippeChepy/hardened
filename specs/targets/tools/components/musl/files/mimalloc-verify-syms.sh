#!/bin/sh
# Run by musl's Makefile on the mimalloc object (patches/0001-plumb-in-...): keeps only the
# allocator interface musl calls global, then checks that nothing else is. (After Chimera Linux's
# check, with llvm-objcopy localizing mimalloc's own symbols instead of patching them static.)
set -e
obj=$1
keep="__libc_calloc __libc_free __libc_malloc_impl __libc_realloc __malloc_init
__malloc_tls_teardown __malloc_atfork __malloc_donate __malloc_tls_default aligned_alloc
malloc_usable_size"
args=
for sym in $keep; do
    args="$args --keep-global-symbol=$sym"
done
${OBJCOPY:-objcopy} $args "$obj"
${NM:-nm} --defined-only --extern-only "$obj" | while read -r addr type name; do
    case " $(echo $keep) " in
        *" $name "*) ;;
        *)
            echo "unexpected global symbol $name ($type)"
            exit 1
            ;;
    esac
done
