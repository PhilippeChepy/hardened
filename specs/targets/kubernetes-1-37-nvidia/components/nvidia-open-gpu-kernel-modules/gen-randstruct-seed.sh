#!/bin/sh
# SPDX-License-Identifier: GPL-2.0
# The kernel's scripts/gen-randstruct-seed.sh, but with the seed of build/keys, which the recipe
# installs next to it, in place of a random one: the same keys give the same kernel.

SEED=$(cat "$(dirname "$0")/hardened-randstruct.seed")
echo "$SEED" > "$1"
HASH=$(echo -n "$SEED" | sha256sum | cut -d" " -f1)
echo "#define RANDSTRUCT_HASHED_SEED \"$HASH\"" > "$2"
