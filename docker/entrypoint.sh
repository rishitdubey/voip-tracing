#!/bin/bash

# Check if directories exist
echo "Checking directory structure..."
ls -la /etc/freeswitch
ls -la /var/log/freeswitch
ls -la /var/run/freeswitch
ls -la /var/lib/freeswitch

# Check FreeSWITCH version
echo "FreeSWITCH version:"
freeswitch -version

# Start FreeSWITCH in console mode
echo "Starting FreeSWITCH..."
exec /usr/bin/freeswitch -c
