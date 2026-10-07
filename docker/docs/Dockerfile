FROM python:3.12-slim-bookworm

LABEL org.opencontainers.image.source="https://github.com/wolfSSL/wolfTPM"

RUN apt-get update \
    && apt-get install -y --no-install-recommends \
        bash git make patch perl librsvg2-bin \
        doxygen build-essential cmake \
        libfmt-dev nlohmann-json3-dev libspdlog-dev libcxxopts-dev \
        pandoc texlive-xetex texlive-latex-extra texlive-fonts-recommended \
        fonts-noto-core fonts-noto-mono fonts-noto-cjk lmodern \
    && rm -rf /var/lib/apt/lists/*

# doxybook2 (wolfSSL fork) turns the Doxygen XML into the API-reference markdown.
RUN git clone --depth 1 https://github.com/pantor/inja /tmp/inja \
    && cmake -S /tmp/inja -B /tmp/inja/build -DBUILD_TESTING=OFF -DINJA_BUILD_TESTS=OFF \
    && cmake --install /tmp/inja/build \
    && git clone --depth 1 https://github.com/dgarske/doxybook2 /tmp/doxybook2 \
    && cmake -S /tmp/doxybook2 -B /tmp/doxybook2/build \
    && cmake --build /tmp/doxybook2/build --target install \
    && rm -rf /tmp/inja /tmp/doxybook2

COPY requirements.txt /tmp/requirements-docs.txt
RUN python -m pip install --no-cache-dir -r /tmp/requirements-docs.txt

WORKDIR /work
