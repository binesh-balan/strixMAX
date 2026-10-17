#!/bin/bash
# PID 1 runs unprivileged as `pentester` and only keeps the container alive.
# All privileged setup (host UID mapping, the per-container CA, the egress
# firewall and starting Caido) happens in /usr/local/sbin/strix-init, which the
# Strix host runs as root through the Docker API once the container is up.
set -e

cd /workspace
exec "$@"
