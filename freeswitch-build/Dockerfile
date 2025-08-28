
# ARM64 FreeSWITCH Dockerfile - Build from Source (No Token Required)
FROM --platform=linux/arm64 debian:bookworm-slim

# Set environment variables
ENV DEBIAN_FRONTEND=noninteractive

# Install build dependencies (comprehensive FreeSWITCH dependencies)
RUN apt-get update && apt-get install -y \
    build-essential \
    cmake \
    automake \
    autoconf \
    libtool \
    libtool-bin \
    libltdl-dev \
    pkg-config \
    git \
    curl \
    wget \
    libssl-dev \
    zlib1g-dev \
    libdb-dev \
    unixodbc-dev \
    libncurses5-dev \
    libexpat1-dev \
    libgdbm-dev \
    bison \
    erlang-dev \
    libtpl-dev \
    libtiff5-dev \
    uuid-dev \
    libpcre3-dev \
    libedit-dev \
    libsqlite3-dev \
    libcurl4-openssl-dev \
    nasm \
    yasm \
    libogg-dev \
    libvorbis-dev \
    libflac-dev \
    libmpg123-dev \
    libmp3lame-dev \
    libpq-dev \
    libspeex-dev \
    libspeexdsp-dev \
    libldns-dev \
    libsndfile1-dev \
    libopus-dev \
    libyaml-dev \
    libpng-dev \
    libfreetype6-dev \
    libjpeg-dev \
    libavformat-dev \
    libavcodec-dev \
    libavutil-dev \
    libswscale-dev \
    libswresample-dev \
    libx264-dev \
    liblua5.2-dev \
    lua5.2 \
    && rm -rf /var/lib/apt/lists/*

# Build and install spandsp 3.0+ from source (required by FreeSWITCH)
WORKDIR /usr/src
# Shallow clone to reduce download time and size
RUN git clone --depth 1 https://github.com/freeswitch/spandsp.git \
    || git clone --depth 1 https://github.com/spandsp/spandsp.git
WORKDIR /usr/src/spandsp
# Check what we got
RUN echo "Current spandsp version info:" && \
    (cat configure.ac | grep -i version || echo "No version in configure.ac") && \
    (git log --oneline -1 || echo "No git log available")
RUN ./bootstrap.sh
RUN ./configure --prefix=/usr --disable-static
RUN make -j$(nproc) && make install
RUN ldconfig

# Build and install Sofia-SIP from source
WORKDIR /usr/src
RUN wget https://github.com/freeswitch/sofia-sip/archive/refs/tags/v1.13.17.tar.gz \
    && tar -xzf v1.13.17.tar.gz \
    && rm v1.13.17.tar.gz
WORKDIR /usr/src/sofia-sip-1.13.17
# Update config scripts for sofia-sip as well
RUN mkdir -p build-aux || true
RUN wget -O build-aux/config.guess 'http://git.savannah.gnu.org/gitweb/?p=config.git;a=blob_plain;f=config.guess;hb=HEAD' || \
    wget -O config.guess 'http://git.savannah.gnu.org/gitweb/?p=config.git;a=blob_plain;f=config.guess;hb=HEAD' || true
RUN wget -O build-aux/config.sub 'http://git.savannah.gnu.org/gitweb/?p=config.git;a=blob_plain;f=config.sub;hb=HEAD' || \
    wget -O config.sub 'http://git.savannah.gnu.org/gitweb/?p=config.git;a=blob_plain;f=config.sub;hb=HEAD' || true
RUN chmod +x build-aux/config.* config.* || true
RUN autoreconf -fiv
RUN ./configure --prefix=/usr --disable-static
RUN make -j$(nproc) && make install
RUN ldconfig

# Create freeswitch user
RUN groupadd -r freeswitch && useradd -r -g freeswitch freeswitch

# Create directories
RUN mkdir -p /usr/local/freeswitch \
    /var/log/freeswitch \
    /var/lib/freeswitch \
    /var/run/freeswitch \
    /etc/freeswitch

# Download and build FreeSWITCH (shallow clone to reduce size)
WORKDIR /usr/src
RUN git clone --depth 1 -b v1.10 https://github.com/signalwire/freeswitch.git freeswitch
WORKDIR /usr/src/freeswitch

# Configure git for rebases
RUN git config pull.rebase true

# Bootstrap and configure
RUN ./bootstrap.sh -j

# Disable modules that require unavailable dependencies
RUN echo "=== Checking modules.conf before modification ===" && \
    grep -E "(mod_verto|mod_signalwire)" modules.conf || echo "Modules not found in expected format" && \
    echo "=== Disabling problematic modules ===" && \
    sed -i 's/^endpoints\/mod_verto/#endpoints\/mod_verto/' modules.conf && \
    sed -i 's/^endpoints\/mod_signalwire/#endpoints\/mod_signalwire/' modules.conf && \
    sed -i 's/^.*mod_verto.*/#&/' modules.conf && \
    sed -i 's/^.*mod_signalwire.*/#&/' modules.conf && \
    echo "=== Checking modules.conf after modification ===" && \
    sed -i 's/^.*mod_spandsp.*/#&/' modules.conf && \
    grep -E "(mod_verto|mod_signalwire|mod_spandsp)" modules.conf || echo "Modules successfully disabled"

# Set PKG_CONFIG_PATH to ensure libraries are found
ENV PKG_CONFIG_PATH=/usr/lib/pkgconfig:/usr/share/pkgconfig:/usr/local/lib/pkgconfig:$PKG_CONFIG_PATH

# Debug library detection before configure
RUN echo "=== Debugging library detection ===" \
    && echo "PKG_CONFIG_PATH: $PKG_CONFIG_PATH" \
    && pkg-config --list-all | grep -E "(spandsp|sofia)" || echo "No spandsp/sofia pkg-config found" \
    && ldconfig -p | grep -E "(spandsp|sofia)" || echo "No spandsp/sofia in ldconfig" \
    && find /usr -name "*spandsp*" -o -name "*sofia*" 2>/dev/null | head -20 || echo "No spandsp/sofia files found" \
    && ls -la /usr/lib/pkgconfig/*span* /usr/lib/pkgconfig/*sofia* 2>/dev/null || echo "No pkg-config files found"

# Configure with minimal modules for MVP
RUN ./configure \
    --prefix=/usr/local/freeswitch \
    --sysconfdir=/etc/freeswitch \
    --localstatedir=/var \
    --with-rundir=/var/run/freeswitch \
    --enable-core-pgsql-support \
    --disable-debug \
    --disable-static

# Build and install (single-threaded for better error reporting)
# Build with better error handling
RUN make -j$(nproc) 2>&1 | tee build.log || \
    (echo "=== Parallel build failed, retrying with single thread ===" && \
     make clean && make -j1 V=1 2>&1 | tee build-single.log) || \
    (echo "=== Build failed completely ===" && tail -100 build-single.log && exit 1)

# Install FreeSWITCH
RUN make install

# Install default configuration
RUN make samples

# Set proper ownership and permissions
RUN chown -R freeswitch:freeswitch /usr/local/freeswitch \
    && chown -R freeswitch:freeswitch /etc/freeswitch \
    && chown -R freeswitch:freeswitch /var/lib/freeswitch \
    && chown -R freeswitch:freeswitch /var/log/freeswitch \
    && chown -R freeswitch:freeswitch /var/run/freeswitch \
    && chmod -R 755 /var/run/freeswitch \
    && chmod -R 755 /var/log/freeswitch \
    && chmod -R 755 /var/lib/freeswitch

# Create symlinks for easier access
RUN ln -sf /usr/local/freeswitch/bin/freeswitch /usr/bin/freeswitch
RUN ln -sf /usr/local/freeswitch/bin/fs_cli /usr/bin/fs_cli

# Clean up build dependencies to reduce image size
RUN apt-get remove -y \
    build-essential \
    cmake \
    automake \
    autoconf \
    libtool \
    libtool-bin \
    libltdl-dev \
    git \
    && apt-get autoremove -y \
    && rm -rf /var/lib/apt/lists/* \
    && rm -rf /usr/src/freeswitch \
    && rm -rf /usr/src/spandsp \
    && rm -rf /usr/src/sofia-sip-1.13.17

# Expose ports
EXPOSE 5060/udp 5060/tcp 5080/tcp 8021/tcp
EXPOSE 10000-10020/udp

# Set working directory
WORKDIR /etc/freeswitch

# Switch to freeswitch user
USER freeswitch

# Health check
HEALTHCHECK --interval=30s --timeout=10s --start-period=30s --retries=3 \
    CMD /usr/bin/fs_cli -x "status" || exit 1
# Add entrypoint script
COPY docker/entrypoint.sh /docker-entrypoint.sh

# Set the entrypoint
ENTRYPOINT ["/bin/bash", "/docker-entrypoint.sh"]
