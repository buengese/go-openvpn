# syntax=docker/dockerfile:1
#
# Parameterised OpenVPN server image for the e2e test matrix.
#
# Everything is pinned: BASE_IMAGE carries a manifest digest and the OpenVPN
# release tarball is checked against OPENVPN_SHA256 before it is unpacked. See
# versions.env for the values and build.sh for the driver.
#
# OpenVPN is built from the upstream release tarball rather than installed from
# a distro package for two reasons: 2.4 packages have disappeared from current
# distros, and the PRF vector capture needs to patch src/openvpn/ssl.c and
# rebuild. The patch hook below exists for that — every *.patch in PATCH_DIR is
# applied here.
#
# PATCH_DIR selects which patch set is applied, and defaults to `patches/`,
# which is empty. The instrumented build passes PATCH_DIR=patches-prfdebug
# and a distinct image tag, so the normal matrix images stay stock — an
# instrumented server that answered to the plain `:2.4.12` tag would silently
# print key material into every later test's logs. See docker/PRF-VECTORS.md.

ARG BASE_IMAGE=debian:trixie-slim

# ---------------------------------------------------------------------------
# Build stage
# ---------------------------------------------------------------------------
FROM ${BASE_IMAGE} AS build

ARG OPENVPN_VERSION
ARG OPENVPN_SHA256
ARG SOURCE_URL_BASE=https://build.openvpn.net/downloads/releases
ARG CONFIGURE_FLAGS="--prefix=/usr --enable-lzo --enable-lz4 --disable-plugin-auth-pam"
ARG PATCH_DIR=patches
ARG OPENSSL_URL=
ARG OPENSSL_SHA256=

SHELL ["/bin/sh", "-eux", "-c"]

RUN export DEBIAN_FRONTEND=noninteractive; \
    apt-get update; \
    apt-get install -y --no-install-recommends \
        build-essential \
        ca-certificates \
        curl \
        iproute2 \
        libcap-ng-dev \
        liblz4-dev \
        liblzo2-dev \
        libssl-dev \
        patch \
        pkg-config; \
    rm -rf /var/lib/apt/lists/*

WORKDIR /usr/src

# With OPENSSL_URL set, OpenSSL is built from that tarball and linked
# statically, reading openssl-1.1.cnf rather than the distro's 3.x config.
COPY openssl-1.1.cnf /usr/src/
RUN [ -n "${OPENSSL_URL}" ] || exit 0; \
    curl -fsSL -o openssl.tar.gz "${OPENSSL_URL}"; \
    echo "${OPENSSL_SHA256}  openssl.tar.gz" | sha256sum -c -; \
    mkdir openssl; \
    tar -xzf openssl.tar.gz -C openssl --strip-components=1; \
    cd openssl; \
    ./config --prefix=/opt/openssl --openssldir=/usr/lib/ssl-1.1 no-shared no-tests; \
    make -j"$(nproc)"; \
    make install_sw; \
    install -D -m 0644 /usr/src/openssl-1.1.cnf /out/usr/lib/ssl-1.1/openssl.cnf; \
    cd ..; \
    rm -rf openssl openssl.tar.gz

RUN test -n "${OPENVPN_VERSION}"; \
    test -n "${OPENVPN_SHA256}"; \
    curl -fsSL -o openvpn.tar.gz "${SOURCE_URL_BASE}/openvpn-${OPENVPN_VERSION}.tar.gz"; \
    echo "${OPENVPN_SHA256}  openvpn.tar.gz" | sha256sum -c -; \
    tar -xzf openvpn.tar.gz; \
    mv "openvpn-${OPENVPN_VERSION}" openvpn; \
    rm openvpn.tar.gz

# Patch hook. The default set (patches/) is empty, so the matrix images are
# stock upstream builds; PATCH_DIR=patches-prfdebug selects the
# generate_key_expansion() instrumentation instead.
COPY ${PATCH_DIR}/ /patches/
RUN cd /usr/src/openvpn; \
    for p in /patches/*.patch; do \
        [ -e "$p" ] || continue; \
        echo "applying patch: $p"; \
        patch -p1 --batch --forward < "$p"; \
    done

RUN cd /usr/src/openvpn; \
    if [ -n "${OPENSSL_URL}" ]; then \
        export OPENSSL_CFLAGS="-I/opt/openssl/include" \
            OPENSSL_LIBS="-L/opt/openssl/lib -lssl -lcrypto -ldl -pthread"; \
    fi; \
    ./configure ${CONFIGURE_FLAGS}; \
    make -j"$(nproc)"; \
    make DESTDIR=/out install; \
    /out/usr/sbin/openvpn --version 2>&1 | head -1 || true

# ---------------------------------------------------------------------------
# Runtime stage
# ---------------------------------------------------------------------------
FROM ${BASE_IMAGE} AS runtime

ARG OPENVPN_VERSION

SHELL ["/bin/sh", "-eux", "-c"]

RUN export DEBIAN_FRONTEND=noninteractive; \
    apt-get update; \
    apt-get install -y --no-install-recommends \
        ca-certificates \
        iproute2 \
        iptables \
        libcap-ng0 \
        liblz4-1 \
        liblzo2-2 \
        openssl; \
    rm -rf /var/lib/apt/lists/*

COPY --from=build /out/ /
COPY entrypoint.sh /usr/local/bin/entrypoint.sh
RUN chmod 0755 /usr/local/bin/entrypoint.sh; \
    openvpn --version 2>&1 | head -1 || true

ENV OPENVPN_VERSION=${OPENVPN_VERSION}

LABEL org.opencontainers.image.title="go-openvpn openvpn matrix server" \
      org.opencontainers.image.description="Pinned OpenVPN server for the go-openvpn e2e test matrix" \
      net.bngs.goopenvpn.openvpn-version="${OPENVPN_VERSION}"

# The container needs --cap-add=NET_ADMIN and --device=/dev/net/tun to bring up
# a tun device; testenv.StartMatrix passes both.
EXPOSE 1194/udp 1194/tcp

ENTRYPOINT ["/usr/local/bin/entrypoint.sh"]
