# syntax=docker/dockerfile:1.7
#
# Runtime image for the `pso-e2e` binary.
#
# Mirrors psonet/bank-data-provider's "build offline, package
# minimal" pattern: the binary is cross-compiled by the
# build-binaries composite action (cargo zigbuild against glibc
# 2.31) and dropped at `dist/pso-e2e` before `docker build`.
#
# Why distroless/cc rather than `FROM scratch`:
# barretenberg-rs links against LLVM's libc++ (`-lc++`) at build
# time and the resulting binary needs `libc++.so.1` at runtime —
# MUSL static-linking didn't pan out for our dep tree (aws-lc-sys
# / glibc-only symbols, see build-binaries action notes). With a
# glibc-targeted binary we need glibc available at runtime;
# distroless/cc-debian12 ships glibc 2.36 + libgcc + libstdc++.
# libc++ isn't included in distroless, so we copy it from a
# bookworm-slim stage.
#
# Build context must contain:
#   dist/pso-e2e          -- the binary (mode 0755)
#
# Manual / local build:
#
#   cargo zigbuild --release --target x86_64-unknown-linux-gnu.2.31 \
#       -p pso-e2e-testsuite --bin pso-e2e
#   mkdir -p dist && cp target/x86_64-unknown-linux-gnu/release/pso-e2e dist/
#   docker build -t pso-e2e:dev -f testsuite/Dockerfile .

# Stage 1: harvest the runtime bits distroless doesn't ship —
# libc++ + the CA bundle. `bookworm-slim` is enough; we only
# need the .so files, not the dev headers.
FROM debian:bookworm-slim AS runtime-libs
RUN apt-get update \
 && apt-get install -y --no-install-recommends \
        libc++1 \
        libc++abi1 \
        ca-certificates \
 && rm -rf /var/lib/apt/lists/*

# Stage 2: the actual image. distroless/cc-debian12 already
# carries glibc 2.36 + libgcc + libstdc++; layer libc++ on top.
FROM gcr.io/distroless/cc-debian12 AS runtime

COPY --from=runtime-libs /etc/ssl/certs/ca-certificates.crt \
                         /etc/ssl/certs/ca-certificates.crt
# libc++ + libc++abi: dynamic loader resolves the `.so.1` ELF
# DT_NEEDED entry recorded in the binary at link time.
COPY --from=runtime-libs /usr/lib/x86_64-linux-gnu/libc++.so.1 \
                         /usr/lib/x86_64-linux-gnu/libc++.so.1
COPY --from=runtime-libs /usr/lib/x86_64-linux-gnu/libc++abi.so.1 \
                         /usr/lib/x86_64-linux-gnu/libc++abi.so.1

# --chmod=0755 because actions/upload-artifact strips Unix exec
# bits; if a caller round-trips the binary through an artifact
# the file arrives at 0644 in the context. Force the bit back on
# at COPY time.
COPY --chmod=0755 dist/pso-e2e /usr/local/bin/pso-e2e

# distroless/cc declares a `nonroot` user; pin it explicitly.
USER nonroot

ENTRYPOINT ["/usr/local/bin/pso-e2e"]
CMD ["--help"]
