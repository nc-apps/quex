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



FROM node:lts-slim AS build-styles
# Updating corepack to not have signing keys out of date
RUN npm install --global corepack@latest
# Installs pnpm(?)
RUN corepack enable
#TODO use pnpm fetch to cache dependencies and only use pnpm install --offline to not refetch

COPY ./pnpm-lock.yaml ./pnpm-lock.yaml
RUN pnpm fetch

COPY . .

RUN pnpm install --offline --frozen-lockfile

RUN pnpm run build


# Build core rust wasm
FROM builder AS build

# Copy over the source code to build the library
RUN rm src/*.rs
COPY ./src ./src
COPY ./templates ./templates
COPY ./translations ./translations

# Build the application
RUN cargo build --release



# The final image can be specified with the target when building the docker image
# Final base image
FROM debian:bookworm-slim AS final

RUN apt-get update && apt-get install -y --no-install-recommends \
    # OpenSSL dependency for reqwest used by bitwarden
    libssl-dev \
    # Certificates needed to make HTTPS requests
    ca-certificates \
    && rm -rf /var/lib/apt/lists/*

# Copy the build artifacts from the build stage
COPY --from=build ./quex/target/release/quex .
COPY --from=build-styles ./public/styles.css ./public/styles.css

EXPOSE 3000
# Set the startup command to run the application
CMD ["./quex"]
