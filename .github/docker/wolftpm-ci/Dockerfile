# wolfTPM CI base image.
#
# Bakes the apt dependencies that wolfTPM CI jobs install on every run so
# the apt mirror is never contacted on the happy path (the source of the
# intermittent `apt-get update` timeouts). Mirrors the wolfBoot CI image
# model (ghcr.io/wolfssl/wolfboot-ci-*): jobs run inside this image via
# `container: image: ghcr.io/wolfssl/wolftpm-ci:<tag>` instead of calling
# `sudo apt-get install`.
#
# Built and pushed by .github/workflows/publish-ci-image.yml. Pin consumers
# to a version tag (e.g. :v1.0), never :latest, and bump the tag when this
# file changes.
FROM ubuntu:24.04

ENV DEBIAN_FRONTEND=noninteractive

RUN apt-get update && apt-get install --no-install-recommends -y \
    autoconf \
    automake \
    build-essential \
    ca-certificates \
    clang \
    clang-tools \
    cmake \
    git \
    iproute2 \
    libclang-rt-18-dev \
    libssl-dev \
    libtool \
    libtss2-tcti-mssim0 \
    openssl \
    pkg-config \
    sudo \
    tpm2-tools \
    valgrind \
    zip \
    && rm -rf /var/lib/apt/lists/*
