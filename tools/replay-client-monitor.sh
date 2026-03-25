#!/usr/bin/env bash
#
# Gather replay diagnostics on a verifier-client host until interrupted.
#
# Copyright 2026, Verizon Media
# SPDX-License-Identifier: Apache-2.0
#

set -euo pipefail

process_name=verifier-client
role=client
interval_seconds=${INTERVAL_SECONDS:-1}
timestamp=$(date +%Y%m%dT%H%M%S)
output_dir=${1:-"${PWD}/replay-${role}-monitor-${timestamp}"}

mkdir -p "${output_dir}"

cleanup()
{
  echo
  echo "Stopped ${role} monitor. Logs are in ${output_dir}"
}

extract_monitored_peer_ports()
{
  local pid=$1
  ps -p "${pid}" -o args= | python3 - <<'PY'
import shlex
import sys

args = shlex.split(sys.stdin.read().strip())
ports = []
for index, arg in enumerate(args):
    if arg in ("--connect-http", "--connect-https") and index + 1 < len(args):
        endpoints = args[index + 1]
    elif arg.startswith("--connect-http="):
        endpoints = arg.split("=", 1)[1]
    elif arg.startswith("--connect-https="):
        endpoints = arg.split("=", 1)[1]
    else:
        continue
    for endpoint in endpoints.split(","):
        endpoint = endpoint.strip()
        if not endpoint or ":" not in endpoint:
            continue
        port = endpoint.rsplit(":", 1)[1]
        if port.isdigit():
            ports.append(port)
print(" ".join(ports))
PY
}

capture_process_snapshot()
{
  local pid=$1
  {
    echo "=== $(date -Is) pid=${pid} ==="
    ps -p "${pid}" -o pid,ppid,etimes,%cpu,%mem,nlwp,rss,cmd || true
    echo
    ps -Lp "${pid}" -o pid,tid,psr,%cpu,%mem,stat,comm --sort=-%cpu | head -n 15 || true
    echo
  } >> "${output_dir}/process.log"
}

capture_pidstat_snapshot()
{
  local pid=$1
  if command -v pidstat >/dev/null 2>&1; then
    {
      echo "=== $(date -Is) pid=${pid} ==="
      pidstat -durh -p "${pid}" "${interval_seconds}" 1 || true
      echo
    } >> "${output_dir}/pidstat.log"
  else
    sleep "${interval_seconds}"
  fi
}

socket_summary_from_ss_pid()
{
  local pid=$1
  ss -tanp 2>/dev/null | python3 - "${pid}" <<'PY'
import collections
import sys

pid = sys.argv[1]
matches = 0
peer_ports = collections.Counter()
states = collections.Counter()

def endpoint_port(endpoint: str) -> str:
    endpoint = endpoint.strip()
    if ":" not in endpoint:
        return ""
    return endpoint.rsplit(":", 1)[1].strip("[]")

for line in sys.stdin:
    if f"pid={pid}," not in line:
        continue
    parts = line.split()
    if len(parts) < 5:
        continue
    matches += 1
    states[parts[0]] += 1
    peer_port = endpoint_port(parts[4])
    if peer_port:
        peer_ports[peer_port] += 1

print("source ss-pid")
print("matching-connections", matches)
for state in sorted(states):
    print("state", state, states[state])
for port in sorted(peer_ports, key=lambda value: int(value)):
    print("peer-port", port, peer_ports[port])
sys.exit(0 if matches > 0 else 1)
PY
}

socket_summary_from_lsof()
{
  local pid=$1
  command -v lsof >/dev/null 2>&1 || return 1
  lsof -Pan -p "${pid}" -iTCP -n 2>/dev/null | python3 - <<'PY'
import collections
import re
import sys

matches = 0
peer_ports = collections.Counter()
states = collections.Counter()

def endpoint_port(endpoint: str) -> str:
    endpoint = endpoint.strip()
    if ":" not in endpoint:
        return ""
    return endpoint.rsplit(":", 1)[1].strip("[]")

for line in sys.stdin:
    if " TCP " not in line:
        continue
    name = line.split(" TCP ", 1)[1].strip()
    state = "UNKNOWN"
    state_match = re.search(r" \(([^)]+)\)$", name)
    if state_match:
        state = state_match.group(1)
        name = name[:state_match.start()]
    local_endpoint, peer_endpoint = name, ""
    if "->" in name:
        local_endpoint, peer_endpoint = name.split("->", 1)
    matches += 1
    states[state] += 1
    peer_port = endpoint_port(peer_endpoint)
    if peer_port:
        peer_ports[peer_port] += 1

print("source lsof-pid")
print("matching-connections", matches)
for state in sorted(states):
    print("state", state, states[state])
for port in sorted(peer_ports, key=lambda value: int(value)):
    print("peer-port", port, peer_ports[port])
sys.exit(0 if matches > 0 else 1)
PY
}

socket_summary_from_port_filter()
{
  local monitored_peer_ports=$1
  MONITORED_PEER_PORTS="${monitored_peer_ports}" ss -tanH 2>/dev/null | python3 - <<'PY'
import collections
import os
import sys

configured_ports = {
    port for port in os.environ.get("MONITORED_PEER_PORTS", "").split() if port
}
matches = 0
peer_ports = collections.Counter()
states = collections.Counter()

def endpoint_port(endpoint: str) -> str:
    endpoint = endpoint.strip()
    if ":" not in endpoint:
        return ""
    return endpoint.rsplit(":", 1)[1].strip("[]")

for line in sys.stdin:
    parts = line.split()
    if len(parts) < 4:
        continue
    state = parts[0]
    peer_endpoint = parts[4] if len(parts) > 4 else ""
    peer_port = endpoint_port(peer_endpoint)
    if peer_port not in configured_ports:
        continue
    matches += 1
    states[state] += 1
    peer_ports[peer_port] += 1

print("source ss-port-filter")
print("configured-peer-ports", len(configured_ports))
print("matching-connections", matches)
for state in sorted(states):
    print("state", state, states[state])
for port in sorted(peer_ports, key=lambda value: int(value)):
    print("peer-port", port, peer_ports[port])
PY
}

capture_socket_snapshot()
{
  local pid=$1
  local monitored_peer_ports
  monitored_peer_ports=$(extract_monitored_peer_ports "${pid}")
  {
    echo "=== $(date -Is) pid=${pid} ==="
    if ! socket_summary_from_ss_pid "${pid}"; then
      if ! socket_summary_from_lsof "${pid}"; then
        socket_summary_from_port_filter "${monitored_peer_ports}"
      fi
    fi
    echo
  } >> "${output_dir}/sockets.log"
}

trap cleanup INT TERM

{
  echo "role=${role}"
  echo "process=${process_name}"
  echo "interval_seconds=${interval_seconds}"
  echo "hostname=$(hostname)"
  echo "uname=$(uname -a)"
  echo "started_at=$(date -Is)"
} > "${output_dir}/metadata.txt"

echo "Writing ${role} diagnostics to ${output_dir}"

while true
do
  pid=$(pgrep -n "${process_name}" || true)
  timestamp_now=$(date -Is)
  if [ -z "${pid}" ]; then
    echo "${timestamp_now} pid=none process=${process_name} not running" \
      | tee -a "${output_dir}/events.log"
    sleep "${interval_seconds}"
    continue
  fi

  echo "${timestamp_now} pid=${pid}" >> "${output_dir}/events.log"
  capture_process_snapshot "${pid}"
  capture_socket_snapshot "${pid}"
  capture_pidstat_snapshot "${pid}"
done
