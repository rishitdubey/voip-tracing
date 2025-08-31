#!/bin/bash
set -e

# Create required directories
mkdir -p /etc/freeswitch/conf/{autoload_configs,sip_profiles,directory/default}
mkdir -p /var/run/freeswitch /var/log/freeswitch /var/lib/freeswitch

# Copy configuration files
cp -r /etc/freeswitch/autoload_configs/* /etc/freeswitch/conf/autoload_configs/ || true
cp -r /etc/freeswitch/sip_profiles/* /etc/freeswitch/conf/sip_profiles/ || true
cp -r /etc/freeswitch/directory/default/* /etc/freeswitch/conf/directory/default/ || true
cp /etc/freeswitch/freeswitch.xml /etc/freeswitch/conf/ || true

# Set permissions
chown -R freeswitch:freeswitch /var/run/freeswitch /var/log/freeswitch /var/lib/freeswitch /etc/freeswitch

# Start FreeSWITCH
exec /usr/local/freeswitch/bin/freeswitch -u freeswitch -g freeswitch -c

