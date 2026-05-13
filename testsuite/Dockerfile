# syntax=docker/dockerfile:1.7

# -----------------------------------------------------------------
# Builder stage
# -----------------------------------------------------------------
# Pinned to the same Rust toolchain the workspace develops against
# (1.94 — see `rustc --version` in pso-integration/README.md).
# bookworm base because the barretenberg-rs FFI (pulled in via
# `pso-l2-client`'s prover stack) requires a recent libstdc++ + cmake +
# clang. Anything older mis-links the bb 5.x C++ symbol set.
FROM rust:1.94-bookworm AS builder

# C++ toolchain + git for the noir_rs fork the workspace patches in.
# barretenberg-rs links against LLVM's libc++ (not GCC's libstdc++);
# both -dev packages are required so headers + shared objects
# resolve. Missing libc++-dev surfaces as "rust-lld: unable to find
# library -lc++" at the link step.
RUN apt-get update \
 && apt-get install -y --no-install-recommends \
        cmake \
        clang \
        libstdc++-12-dev \
        libc++-dev \
        libc++abi-dev \
        pkg-config \
        git \
        libssl-dev \
        ca-certificates \
 && rm -rf /var/lib/apt/lists/*

# Reproducible builds — strip debug info from the release binary in the
# runtime stage. We keep `debug = false` (workspace `[profile.release]`
# already pins this) plus an explicit `strip` after build below.
ENV CARGO_TERM_COLOR=always
ENV CARGO_INCREMENTAL=0

WORKDIR /build

# Copy the entire workspace. The Dockerfile lives at `testsuite/` but
# the build context is the workspace root (see the build instruction
# in the README: `docker build -f testsuite/Dockerfile .`). Copying
# the whole tree is the simplest path that handles all path
# dependencies (`pso-mobile-integration`, `pso-nft`, ...).
COPY . .

# Build the `pso-e2e` binary in release mode. cargo will pull
# git-tracked workspace dependencies (`pso-protocol`,
# `pso-zk-circuits`, `psonet/noir_rs`) over the network during this
# step — the build context does NOT include sibling repos.
#
# Authentication for private psonet/* repos goes through a BuildKit
# build-secret named `gh_token` (a fine-grained GitHub PAT with
# `Contents: Read` on the psonet org). The secret is mounted only for
# the duration of this RUN — it never lands in any image layer.
#
#   docker build \
#     --secret id=gh_token,env=GH_TOKEN \
#     -f testsuite/Dockerfile .
#
# `cargo` is told to use the system `git` binary
# (`CARGO_NET_GIT_FETCH_WITH_CLI=true`) so git's `url.insteadOf`
# rewrite is honoured.
# PAT issuer's GitHub login. Non-sensitive (just a username), but
# required: fine-grained PATs authenticate to git HTTP Basic Auth
# with the issuer's real login as the username. The caller workflow
# resolves this via api.github.com/user once and passes it in here
# so the build doesn't have to call the API itself.
ARG GH_LOGIN=""

RUN --mount=type=cache,target=/usr/local/cargo/registry \
    --mount=type=cache,target=/usr/local/cargo/git \
    --mount=type=cache,target=/build/target \
    --mount=type=secret,id=gh_token,target=/run/secrets/gh_token,required=false \
    bash -euo pipefail -c '\
      if [ -s /run/secrets/gh_token ] && [ -n "$GH_LOGIN" ]; then \
        token=$(cat /run/secrets/gh_token); \
        umask 077; \
        printf "https://%s:%s@github.com\n" "$GH_LOGIN" "$$token" > /root/.git-credentials; \
        git config --global credential.helper "store --file=/root/.git-credentials"; \
        git config --global url."https://github.com/".insteadOf "ssh://git@github.com/"; \
        echo "git auth configured for $GH_LOGIN"; \
      else \
        echo "no PAT mounted; private psonet/* deps will fail to resolve"; \
      fi; \
      export CARGO_NET_GIT_FETCH_WITH_CLI=true; \
      cargo build --release -p pso-e2e-testsuite --bin pso-e2e; \
      cp /build/target/release/pso-e2e /usr/local/bin/pso-e2e; \
      strip /usr/local/bin/pso-e2e'

# -----------------------------------------------------------------
# Runtime stage
# -----------------------------------------------------------------
# Slim debian + just enough shared libs to run the FFI'd prover.
FROM debian:bookworm-slim AS runtime

RUN apt-get update \
 && apt-get install -y --no-install-recommends \
        libstdc++6 \
        ca-certificates \
 && rm -rf /var/lib/apt/lists/*

COPY --from=builder /usr/local/bin/pso-e2e /usr/local/bin/pso-e2e

# Non-root user — the binary doesn't need privileges, only a TCP
# socket to the devnet RPC.
RUN useradd -m -u 1001 pso
USER pso
WORKDIR /home/pso

# Document the canonical CLI surface. The CLI itself has no env-var
# fallbacks for endpoints / keys; CI passes everything explicitly.
ENTRYPOINT ["/usr/local/bin/pso-e2e"]
CMD ["--help"]
