#!/usr/bin/env bash
#
# Gather replay diagnostics on a verifier-server host until interrupted.
#
# Copyright 2026, Verizon Media
# SPDX-License-Identifier: Apache-2.0
#

set -euo pipefail

process_name=verifier-server
role=server
interval_seconds=${INTERVAL_SECONDS:-1}
timestamp=$(date +%Y%m%dT%H%M%S)
output_dir=${1:-"${PWD}/replay-${role}-monitor-${timestamp}"}

mkdir -p "${output_dir}"

cleanup()
{
  echo
  echo "Stopped ${role} monitor. Logs are in ${output_dir}"
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

capture_socket_snapshot()
{
  local pid=$1
  {
    echo "=== $(date -Is) pid=${pid} ==="
    ss -tanp | awk -v pid="${pid}" '
      $0 ~ ("pid=" pid ",") {
        matches++
        split($4, local_ep, ":")
        local_port = local_ep[length(local_ep)]
        local_ports[local_port]++
        split($5, peer_ep, ":")
        peer_port = peer_ep[length(peer_ep)]
        peer_ports[peer_port]++
        states[$1]++
      }
      END {
        print "matching-connections", matches + 0
        for (state in states) {
          print "state", state, states[state]
        }
        for (port in local_ports) {
          print "local-port", port, local_ports[port]
        }
        for (port in peer_ports) {
          print "peer-port", port, peer_ports[port]
        }
      }' | sort -V
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
