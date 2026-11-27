#!/bin/bash
# Create the synthetic journal file test.journal used by the journal tests.
#
# The entries are written in the journal export format and converted into a
# binary journal file with systemd-journal-remote (package
# systemd-journal-remote). All timestamps, boot IDs and machine IDs are fixed,
# so the content is deterministic and contains no data of a real host.
#
# Layout of the generated journal (all times UTC):
#   boot 1 (BOOT1), 2026-01-01 10:00:00 .. 10:00:50
#     10:00:00  systemd        init.scope       "Started systemd-journald.service."
#     10:00:10  sshd           sshd.service     "Server listening on 0.0.0.0 port 22."
#     10:00:20  cron           cron.service     "(root) CMD (run-parts /etc/cron.hourly)"
#     10:00:30  sshd           sshd.service     "Accepted publickey for tux from 192.0.2.10 port 50000 ssh2"
#     10:00:40  myapp          user unit app.service "user application started"
#     10:00:50  kernel         -                "usb 1-1: new high-speed USB device"
#   boot 2 (BOOT2), 2026-01-02 08:00:00 .. 08:00:30
#     08:00:00  systemd        init.scope       "Started systemd-journald.service."
#     08:00:10  sshd           sshd.service     "Server listening on 0.0.0.0 port 22."
#     08:00:20  cron           cron.service     "(root) CMD (run-parts /etc/cron.daily)"
#     08:00:30  sshd           sshd.service     "error: kex_exchange_identification: Connection closed by remote host"
#
# Usage: ./make-test-journal.sh [output.journal]
set -euo pipefail

cd "$(dirname "$0")"
OUT="${1:-test.journal}"
REMOTE="${SYSTEMD_JOURNAL_REMOTE:-/usr/lib/systemd/systemd-journal-remote}"

if [ ! -x "$REMOTE" ]; then
	echo "systemd-journal-remote not found at $REMOTE, install the package systemd-journal-remote" >&2
	exit 1
fi

MACHINE=0123456789abcdef0123456789abcdef
BOOT1=11111111111111111111111111111111
BOOT2=22222222222222222222222222222222
HOST=testhost
# 2026-01-01T10:00:00Z and 2026-01-02T08:00:00Z in seconds since the epoch
BOOT1_START=1767261600
BOOT2_START=1767340800

# entry <boot-id> <boot-start> <offset-seconds> <identifier> <unit> <user-unit> <exe> <priority> <message>
# writes one entry in export format, an empty unit / user-unit / exe omits the field
entry() {
	local boot=$1 start=$2 off=$3 ident=$4 unit=$5 uunit=$6 exe=$7 prio=$8 msg=$9
	local realtime=$(((start + off) * 1000000))
	# monotonic time: pretend every boot started 5 seconds before its first entry
	local monotonic=$(((off + 5) * 1000000))
	echo "__REALTIME_TIMESTAMP=$realtime"
	echo "__MONOTONIC_TIMESTAMP=$monotonic"
	echo "_BOOT_ID=$boot"
	echo "_MACHINE_ID=$MACHINE"
	echo "_HOSTNAME=$HOST"
	echo "PRIORITY=$prio"
	echo "SYSLOG_IDENTIFIER=$ident"
	if [ "$ident" = kernel ]; then
		echo "_TRANSPORT=kernel"
	else
		echo "_TRANSPORT=syslog"
	fi
	[ -n "$unit" ] && echo "_SYSTEMD_UNIT=$unit"
	[ -n "$uunit" ] && echo "_SYSTEMD_USER_UNIT=$uunit"
	[ -n "$exe" ] && echo "_EXE=$exe"
	echo "MESSAGE=$msg"
	echo
}

TMP=$(mktemp -d)
trap 'rm -rf "$TMP"' EXIT

{
	entry $BOOT1 $BOOT1_START 0 systemd init.scope "" /usr/lib/systemd/systemd 6 \
		"Started systemd-journald.service."
	entry $BOOT1 $BOOT1_START 10 sshd sshd.service "" /usr/sbin/sshd 6 \
		"Server listening on 0.0.0.0 port 22."
	entry $BOOT1 $BOOT1_START 20 cron cron.service "" /usr/sbin/cron 6 \
		"(root) CMD (run-parts /etc/cron.hourly)"
	entry $BOOT1 $BOOT1_START 30 sshd sshd.service "" /usr/sbin/sshd 6 \
		"Accepted publickey for tux from 192.0.2.10 port 50000 ssh2"
	entry $BOOT1 $BOOT1_START 40 myapp user@1000.service app.service /usr/bin/myapp 6 \
		"user application started"
	entry $BOOT1 $BOOT1_START 50 kernel "" "" "" 6 \
		"usb 1-1: new high-speed USB device"
	entry $BOOT2 $BOOT2_START 0 systemd init.scope "" /usr/lib/systemd/systemd 6 \
		"Started systemd-journald.service."
	entry $BOOT2 $BOOT2_START 10 sshd sshd.service "" /usr/sbin/sshd 6 \
		"Server listening on 0.0.0.0 port 22."
	entry $BOOT2 $BOOT2_START 20 cron cron.service "" /usr/sbin/cron 6 \
		"(root) CMD (run-parts /etc/cron.daily)"
	entry $BOOT2 $BOOT2_START 30 sshd sshd.service "" /usr/sbin/sshd 3 \
		"error: kex_exchange_identification: Connection closed by remote host"
} >"$TMP/test.export"

# systemd-journal-remote appends to an existing file, so always start fresh.
# Compact mode (systemd >= 252) and keyed hashes (systemd >= 246) are disabled
# so that older libsystemd versions can read the file as well.
rm -f "$OUT"
SYSTEMD_JOURNAL_COMPACT=0 SYSTEMD_JOURNAL_KEYED_HASH=0 \
	"$REMOTE" --output="$TMP/out.journal" "$TMP/test.export"
mv "$TMP/out.journal" "$OUT"
echo "created $OUT ($(stat -c %s "$OUT") bytes)"
