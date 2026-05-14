# syntax=docker/dockerfile:1.7
#
# Runtime image for the `pso-e2e` binary.
#
# Mirrors the pattern psonet/bank-data-provider uses: the binary is
# cross-compiled statically against MUSL by the build-binaries
# composite action and dropped at `dist/pso-e2e` before the
# `docker build` invocation. Because the binary is fully static, we
# can run it from `FROM scratch` — no glibc, no libstdc++, no
# debian/ubuntu base.
#
# Build context must contain:
#   dist/pso-e2e          -- the static MUSL binary (mode 0755)
#
# Manual / local build:
#
#   cargo zigbuild --release --target x86_64-unknown-linux-musl \
#       -p pso-e2e-testsuite --bin pso-e2e
#   mkdir -p dist && cp target/x86_64-unknown-linux-musl/release/pso-e2e dist/
#   docker build -t pso-e2e:dev -f testsuite/Dockerfile .

# Stage a CA bundle. The binary itself doesn't currently make TLS
# calls (devnet RPC is plaintext), but having the standard trust
# store available means a later flag like `--actor-rpc-url https://…`
# Just Works without rebuilding the image.
FROM alpine:3.21 AS certs
RUN apk add --no-cache ca-certificates

FROM scratch AS runtime

COPY --from=certs /etc/ssl/certs/ca-certificates.crt /etc/ssl/certs/ca-certificates.crt

# --chmod=0755 because actions/upload-artifact strips Unix exec
# bits; if a caller round-trips the binary through an artifact the
# file arrives at 0644 in the context. Force the bit back on at
# COPY time.
COPY --chmod=0755 dist/pso-e2e /usr/local/bin/pso-e2e

# Non-root nobody — no apt user provisioning available on
# `FROM scratch`, so re-use the well-known reserved uid that's
# guaranteed to exist nowhere on the host either.
USER 65534

ENTRYPOINT ["/usr/local/bin/pso-e2e"]
CMD ["--help"]
