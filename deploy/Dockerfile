# syntax=docker/dockerfile:1
#
# Two stages, one file out:
#   build  compile lacuna against musl (SQLite is compiled in; DoH trusts the bundled
#          Mozilla roots, so no certificate store is needed at runtime)
#   final  `scratch`: no OS, no shell, only /lacuna
#
# Build context is lacuna/ (see compose.yml).

FROM rust:1-alpine AS build
RUN apk add --no-cache musl-dev
WORKDIR /src
# Dependencies first, in their own layer: the manifests plus an empty main, built once.
# Docker reuses this layer until Cargo.toml or Cargo.lock changes, so editing lacuna's
# own code recompiles only lacuna.
COPY Cargo.toml Cargo.lock ./
RUN mkdir src && echo 'fn main() {}' > src/main.rs \
 && cargo build --release --locked \
 && rm -rf src
COPY src ./src
# COPY keeps the files' original timestamps, which are OLDER than the stub build above,
# so cargo would think the stub is current and ship it. Touching the real sources makes
# them newer. The size check fails the build if the stub got through.
RUN find src -name '*.rs' -exec touch {} + \
 && cargo build --release --locked && cp target/release/lacuna /lacuna \
 && test "$(stat -c %s /lacuna)" -gt 1000000

FROM scratch
COPY --from=build /lacuna /lacuna
USER 3070:3070
EXPOSE 5353/udp 5353/tcp 8053
ENTRYPOINT ["/lacuna", "serve", "/config/config.toml"]
