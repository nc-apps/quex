ARG RUST_VERSION=1.83

FROM rust:${RUST_VERSION} AS builder
# Create a new empty shell project to enable downloading dependencies before building for caching
RUN cargo new quex
WORKDIR /quex

# Copy over manifests
COPY ./Cargo.lock ./Cargo.lock
COPY ./Cargo.toml ./Cargo.toml

# Build to cache the dependencies
RUN cargo build --release

# Remove build artifacts that are not needed in next steps
RUN rm ./target/release/deps/quex*

# Don't remove source code as that breaks building from cargo workspace

# Build core rust wasm
FROM builder AS build

# Copy over the source code to build the library
RUN rm src/*.rs
COPY ./src ./src
COPY ./templates ./templates

# Build the application
RUN cargo build --release


# The final image can be specified with the target when building the docker image
# Final base image
FROM debian:bookworm-slim AS final
# Copy the build artifacts from the build stage
COPY --from=build ./quex/target/release/quex .

EXPOSE 3000
# Set the startup command to run the application
CMD ["./quex"]
