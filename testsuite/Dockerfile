# syntax=docker/dockerfile:1.7

# Runtime-only image for the `pso-e2e` binary.
#
# The release binary is built by `psonet/pso-integration`'s CI
# (`.github/workflows/testsuite-image.yml`) on the runner — where
# git auth, the C++ toolchain, and the long noir/bb compile already
# work — and then COPYed into this image at build time. Doing the
# cargo work inside docker would require the runner's PAT, a full
# C++ toolchain, and ~10 minutes of repeated barretenberg-rs compile
# every time the image needs to be pushed. None of that buys
# anything when the binary already exists three steps earlier in the
# same workflow.
#
# The build context must contain a `pso-e2e` binary at the root
# (the workflow drops it there before invoking docker build).
#
# Manual / local build:
#
#   cargo build --release -p pso-e2e-testsuite --bin pso-e2e
#   cp target/release/pso-e2e ./pso-e2e
#   docker build -t pso-e2e:dev -f testsuite/Dockerfile .

FROM debian:bookworm-slim

# Runtime deps:
# - `libstdc++6`  -- GCC C++ stdlib used by some glue layers
# - `libc++1`     -- LLVM C++ stdlib that barretenberg-rs links
#                    against (`-lc++` at compile time -> .so.1 at run)
# - `ca-certificates` -- HTTPS to the L2 RPC endpoints
RUN apt-get update \
 && apt-get install -y --no-install-recommends \
        libstdc++6 \
        libc++1 \
        ca-certificates \
 && rm -rf /var/lib/apt/lists/*

# Drop in the prebuilt binary. Workflow places it at the context
# root; `chmod +x` is belt-and-braces since cargo already sets it.
COPY pso-e2e /usr/local/bin/pso-e2e
RUN chmod +x /usr/local/bin/pso-e2e

# Non-root user — the binary only needs network access.
RUN useradd -m -u 1001 pso
USER pso
WORKDIR /home/pso

ENTRYPOINT ["/usr/local/bin/pso-e2e"]
CMD ["--help"]
