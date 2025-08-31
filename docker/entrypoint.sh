#!/bin/bash
set -e

# Create necessary directories with root privileges
mkdir -p /etc/freeswitch/conf/autoload_configs \
         /var/run/freeswitch \
         /var/log/freeswitch \
         /var/lib/freeswitch/db \
         /var/lib/freeswitch/storage \
         /var/lib/freeswitch/recordings \
         /var/lib/freeswitch/images \
         /etc/freeswitch/conf/sip_profiles \
         /etc/freeswitch/conf/directory/default

# Copy configuration files if they don't exist
if [ ! -f /etc/freeswitch/conf/freeswitch.xml ]; then
    cp -r /usr/local/freeswitch/conf/* /etc/freeswitch/conf/
fi

# Create necessary database files if they don't exist
touch /var/lib/freeswitch/db/core.db \
      /var/lib/freeswitch/db/call_limit.db \
      /var/lib/freeswitch/db/cdr.db

# Fix permissions
chown -R freeswitch:freeswitch /etc/freeswitch \
      /var/run/freeswitch \
      /var/log/freeswitch \
      /var/lib/freeswitch
chmod -R 755 /var/lib/freeswitch

# Start FreeSWITCH in foreground mode
exec /usr/local/freeswitch/bin/freeswitch -u freeswitch -g freeswitch -c
