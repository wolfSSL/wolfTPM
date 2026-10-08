# Shared image for every wolfTPM Linux CI workload.
# Install system dependencies here, never in workflows or composite actions.
# Publish and verify the versioned image before updating its consumers.
FROM ubuntu:24.04

ENV DEBIAN_FRONTEND=noninteractive \
    WOLFTPM_CI_IMAGE=v1.1 \
    CARGO_HOME=/opt/cargo \
    RUSTUP_HOME=/opt/rustup

# Allow image builders to use another official Ubuntu mirror.
ARG UBUNTU_ARCHIVE_MIRROR=http://archive.ubuntu.com/ubuntu/
RUN sed -i "s|http://archive.ubuntu.com/ubuntu/|${UBUNTU_ARCHIVE_MIRROR}|g" \
        /etc/apt/sources.list.d/ubuntu.sources \
    && apt-get -o Acquire::Retries=3 -o Acquire::http::Timeout=30 -o APT::Update::Error-Mode=any update \
    && apt-get -o Acquire::Retries=3 -o Acquire::http::Timeout=30 install --no-install-recommends -y \
    autoconf automake bison build-essential ca-certificates ccache \
    clang clang-14 clang-15 clang-17 clang-tools cmake curl \
    device-tree-compiler dfu-util file flex g++-11 g++-12 g++-13 \
    g++-multilib gcc-11 gcc-12 gcc-13 gcc-arm-none-eabi gcc-multilib \
    git gperf iproute2 jq libcapstone-dev libclang-18-dev \
    libclang-rt-18-dev libdw-dev libmagic1 libnewlib-arm-none-eabi \
    libsdl2-dev libssl-dev libtool libtss2-tcti-mssim0 \
    mono-mcs mono-tools-devel ninja-build nunit nunit-console openssl \
    patch pkg-config procps psmisc python3 python3-dev python3-pip \
    python3-venv rsync sudo tpm2-tools unzip util-linux valgrind wget \
    xxd xz-utils zip \
    && rm -rf /var/lib/apt/lists/*

# Keep the Python tools away from Ubuntu's externally managed interpreter.
RUN python3 -m venv /opt/ci-python \
    && /opt/ci-python/bin/pip install --no-cache-dir \
        'semgrep==1.166.0' 'spdx-tools==0.8.*' 'codespell[toml]==2.4.3'

# Zephyr retains its existing release and SDK. Its Python dependencies are
# isolated from the scanners and SBOM validator.
RUN git clone --depth 1 --branch v3.4.0 \
        https://github.com/zephyrproject-rtos/zephyr.git /tmp/zephyr-deps \
    && python3 -m venv /opt/zephyr-python \
    && /opt/zephyr-python/bin/pip install --no-cache-dir \
        -r /tmp/zephyr-deps/scripts/requirements-base.txt \
        -r /tmp/zephyr-deps/scripts/requirements-build-test.txt \
    && rm -rf /tmp/zephyr-deps

RUN curl -fsSL --retry 3 \
        https://github.com/zephyrproject-rtos/sdk-ng/releases/download/v0.16.1/zephyr-sdk-0.16.1_linux-x86_64_minimal.tar.xz \
        -o /tmp/zephyr-sdk.tar.xz \
    && tar -xJf /tmp/zephyr-sdk.tar.xz -C /opt \
    && cd /opt/zephyr-sdk-0.16.1 \
    && ./setup.sh -h -c -t x86_64-zephyr-elf \
    && rm /tmp/zephyr-sdk.tar.xz

# rustup lives outside HOME, which GitHub overrides for container jobs.
RUN curl -fsSL --retry 3 https://sh.rustup.rs -o /tmp/rustup.sh \
    && sh /tmp/rustup.sh -y --no-modify-path --profile minimal \
        --default-toolchain stable --component clippy --component rustfmt \
    && rm /tmp/rustup.sh

ENV PATH=/opt/ci-python/bin:/opt/cargo/bin:${PATH}

# Include the STM32 emulator in this image rather than installing dependencies
# in a second CI container. Pin the source so image rebuilds are reproducible.
ARG M33MU_REF=7ff584479f8cb53c5016a5a429484e82b498b289
RUN git init -q /tmp/m33mu \
    && git -C /tmp/m33mu remote add origin https://github.com/danielinux/m33mu.git \
    && git -C /tmp/m33mu fetch --depth 1 origin "$M33MU_REF" \
    && git -C /tmp/m33mu checkout -q --detach FETCH_HEAD \
    && cmake -S /tmp/m33mu -B /tmp/m33mu/build \
        -DM33MU_BUILD_TESTS=OFF -DM33MU_ENABLE_WOLFSSL=OFF \
        -DM33MU_ENABLE_RUST_PLUGINS=OFF \
    && cmake --build /tmp/m33mu/build --target m33mu -j4 \
    && cmake --install /tmp/m33mu/build \
    && rm -rf /tmp/m33mu
