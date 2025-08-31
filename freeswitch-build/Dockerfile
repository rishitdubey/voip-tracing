# FreeSWITCH Dockerfile with spandsp support
FROM debian:bookworm-slim

# Set environment variables
ENV DEBIAN_FRONTEND=noninteractive

# Install build dependencies
RUN apt-get update && \
    apt-get install -y build-essential git automake autoconf libtool-bin \
        pkg-config libssl-dev zlib1g-dev libncurses5-dev \
        uuid-dev libpcre3-dev libedit-dev libsqlite3-dev libcurl4-openssl-dev \
        libpq-dev libopus-dev libsndfile1-dev libtiff5-dev wget unzip \
        libspeex-dev libspeexdsp-dev procps net-tools && \
    rm -rf /var/lib/apt/lists/*

# Build and install spandsp from source (FS_1.10 compatible)
RUN cd /usr/src && \
    git clone https://github.com/freeswitch/spandsp.git && \
    cd spandsp && \
    git checkout 0d2e6ac65e0e8f53d652665a743015a88bf048d4 && \
    ./bootstrap.sh && \
    ./configure && \
    make -j$(nproc) && \
    make install && \
    ldconfig

# Build and install sofia-sip from source
RUN cd /usr/src && \
    git clone https://github.com/freeswitch/sofia-sip.git && \
    cd sofia-sip && \
    ./bootstrap.sh && \
    ./configure && \
    make -j$(nproc) && \
    make install && \
    ldconfig

# Modules configuration including spandsp
RUN echo "applications/mod_commands\n\
applications/mod_db\n\
applications/mod_dptools\n\
applications/mod_hash\n\
applications/mod_spandsp\n\
codecs/mod_g723_1\n\
codecs/mod_amr\n\
codecs/mod_g729\n\
codecs/mod_h26x\n\
dialplans/mod_dialplan_xml\n\
endpoints/mod_sofia\n\
event_handlers/mod_event_socket\n\
formats/mod_local_stream\n\
loggers/mod_console\n\
loggers/mod_logfile\n\
say/mod_say_en" > /usr/src/minimal-modules.conf

# Clone and build FreeSWITCH
RUN cd /usr/src && \
    git clone --depth 1 -b v1.10 https://github.com/signalwire/freeswitch.git freeswitch && \
    cd freeswitch && \
    ./bootstrap.sh -j && \
    cp /usr/src/minimal-modules.conf modules.conf && \
    ./configure --enable-portable-binary \
                --enable-core-pgsql-support \
                --enable-static=no \
                --enable-shared=yes \
                --with-spandsp \
                --enable-spandsp \
                --without-shout \
                --without-python \
                --without-erlang \
                --with-gnu-ld \
                --with-openssl \
                --enable-core-odbc-support=no \
                --enable-zrtp=no \
                --enable-srtp=no \
                --enable-libvpx=no \
                --without-libvpx \
                --without-ffmpeg && \
    make -j$(nproc) && \
    make install && \
    # make sounds-install && \
    # make moh-install && \
    ln -s /usr/local/freeswitch/bin/freeswitch /usr/bin/ && \
    ln -s /usr/local/freeswitch/bin/fs_cli /usr/bin/

# Cleanup after all builds are complete
RUN apt-mark manual libtiff5-dev libspeex-dev libspeexdsp-dev && \
    apt-get purge -y build-essential git automake autoconf libtool-bin pkg-config && \
    apt-get autoremove -y && \
    apt-get clean && \
    rm -rf /usr/src/* && \
    ldconfig

# Create freeswitch user and group, and necessary directories
RUN addgroup --system freeswitch && \
    adduser --system --quiet --home /opt/freeswitch --gecos "FreeSWITCH Voice Platform" --ingroup freeswitch freeswitch && \
    mkdir -p /etc/freeswitch/conf/autoload_configs \
            /var/run/freeswitch \
            /var/lib/freeswitch/db \
            /var/lib/freeswitch/storage \
            /var/lib/freeswitch/recordings \
            /var/lib/freeswitch/images && \
    touch /var/lib/freeswitch/db/core.db \
          /var/lib/freeswitch/db/call_limit.db \
          /var/lib/freeswitch/db/cdr.db && \
    # Create necessary configuration directories
    mkdir -p /usr/local/freeswitch/conf && \
    # Set permissions before changing ownership
    chmod -R 755 /var/run/freeswitch \
            /var/lib/freeswitch \
            /usr/local/freeswitch \
            /etc/freeswitch && \
    # Change ownership as root
    chown -R freeswitch:freeswitch /etc/freeswitch \
            /var/run/freeswitch \
            /var/lib/freeswitch \
            /usr/local/freeswitch

# Expose ports
EXPOSE 5060/udp 5060/tcp 5080/tcp 8021/tcp
EXPOSE 10000-10020/udp

# Set working directory
WORKDIR /etc/freeswitch

# Add entrypoint script
COPY docker/entrypoint.sh /docker-entrypoint.sh
RUN chmod +x /docker-entrypoint.sh

# Switch to freeswitch user
#USER freeswitch

ENTRYPOINT ["/docker-entrypoint.sh"]
CMD ["freeswitch", "-nonat", "-nf"]
