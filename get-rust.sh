#!/bin/bash
#
# This is a helper script for dev containters that do not already have rust
#

curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh

. "$HOME/.cargo/env"

rustup toolchain install stable
rustup component add clippy rustfmt

