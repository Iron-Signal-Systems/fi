#!/bin/sh
# Operator-governed C220 recovery: exact interrupted signed 22A generation,
# then sustained READY for 22A/22B only after canonical acceptance.
# No automatic replay on failure. No fresh receiver custody modifications.
set -eu
umask 077
die(){ echo "C1 RECOVERY STOP: $*" >&2; exit 1; }
[ "$#" -eq 1 ] && [ "$1" = "--recover-and-drain" ] ||
  die "usage: sh script --recover-and-drain"
[ "$(uname -s)" = FreeBSD ] && [ "$(hostname -s)" = c220 ] &&
  [ "$(id -u)" -eq 0 ] || die "run as C220 root"

code_commit=cbab8b4419b7976195bdee2b1fd6e857d4232d18
source=iss-fs-22a.iss.local
generation=20261030T000032.061323100Z-3e38b2210771462c
sor_binary=/fast/jails/roots/fi-sor/usr/local/sbin/fi-c1-sor-worker
sor_conf=/fast/jails/roots/fi-sor/etc/rc.conf.d/fi_c1_sor
ingest_conf=/fast/jails/roots/fi-ingest/etc/rc.conf.d/fi_c1_ingest
backup=/root/fi-c1-sor-worker.pre-$code_commit
replay_backup=
logdir=
started=0
modified=0
sql(){
  jexec -U postgres fi-sor psql -X -w -At -v ON_ERROR_STOP=1 \
    -h /var/db/fi/sor/run -p 5432 -d fi -c "$1"
}
postmortem(){
  echo "===== EXACT SOR SQL REJECTIONS ====="
  jexec fi-sor /bin/sh -c '
    for f in /var/log/daemon.log /var/log/messages; do
      [ -f "$f" ] || continue
      grep -F "FI C1 SOR SQL HANDOFF REJECTED" "$f" | tail -12 || :
    done
  ' || :
  echo "===== CURRENT PENDING SQL ====="
  sql "SELECT source_id||'|'||generation_id||'|'||state||'|'||
    record_count FROM fi_c1_pending.generation_control" || :
  sql "SELECT count(*) FROM fi_c1_pending.source_record" || :
}
cleanup(){
  rc=$?
  trap - EXIT HUP INT TERM
  if [ "$started" -eq 1 ]; then
    jexec fi-sor service fi_c1_sor onestop ||
      { echo "WARNING: SoR stop failed" >&2; rc=1; }
  fi
  if [ "$modified" -eq 1 ]; then
    install -o root -g 4100 -m 0640 "$replay_backup" "$sor_conf" ||
      { echo "WARNING: replay NO restore failed" >&2; rc=1; }
  fi
  if [ "$rc" -ne 0 ]; then
    postmortem
    echo "RECOVERY_LOGDIR=$logdir"
    echo "No automatic retries; keep Pending/READY/original custody" >&2
  fi
  exit "$rc"
}
trap cleanup EXIT
trap 'exit 130' HUP INT TERM

echo "===== VERIFY EXACT INTERRUPTED C1 STATE ====="
grep -qx 'fi_c1_sor_enable="NO"' "$sor_conf" || die "SoR rc enabled"
grep -qx 'fi_c1_ingest_enable="NO"' "$ingest_conf" || die "ingest rc enabled"
grep -qx 'fi_c1_sor_reconcile_private_replay="NO"' "$sor_conf" ||
  die "replay not disabled before starting"
[ ! -e "$backup" ] || die "pre-install binary backup already exists"
if jexec fi-sor service fi_c1_sor onestatus >/dev/null 2>&1 ||
   jexec fi-ingest service fi_c1_ingest onestatus >/dev/null 2>&1 ||
   jexec fi-ingest service fi_ingest_worker onestatus >/dev/null 2>&1; then
   die "another FI ingestion process already running"
fi
pending=$(sql "SELECT source_id||'|'||generation_id||'|'||state||'|'||
  record_count||'|'||batch_count FROM fi_c1_pending.generation_control")
[ "$pending" = "$source|$generation|Pending|15140785|8399" ] ||
  die "original signed Pending generation differs"
[ "$(sql "SELECT count(*) FROM fi_c1_pending.source_record")" = 334323 ] ||
  die "committed Pending prefix changed; read-only audit required"
[ "$(sql "SELECT count(*) FROM fi.recorded_generation
  WHERE source_id='$source' AND generation_id='$generation'")" = 0 ] ||
  die "generation already canonically published"
[ "$(sql "SELECT has_database_privilege(
  'fi_c1_publisher','fi','TEMPORARY')")" = t ] ||
  die "publisher TEMP SQL right not available"

echo "===== BUILD EXACT CI-PASSED FI-SOR DIAGNOSTIC WORKER ====="
repo=
for path in /home/jwood/fi-c1-two-process-2a449f1a \
            /home/jwood/fi-w512-c220-stage; do
  if jexec -U jwood fi-dev git -C "$path" rev-parse \
      --is-inside-work-tree >/dev/null 2>&1; then
    repo=$path;break
  fi
done
[ -n "$repo" ] || die "fi-dev repository checkout unavailable"
jexec -U jwood fi-dev git -C "$repo" fetch origin \
  refs/heads/dev/c1-two-process-20261120:refs/remotes/origin/dev/c1-two-process-20261120
jexec -U jwood fi-dev git -C "$repo" cat-file \
  -e "$code_commit^{commit}" ||
  die "the tested diagnostic commit was not fetched"
[ -n "$repo" ] || die "pinned diagnostic commit absent in fi-dev Git checkout"
build=$(jexec -U jwood fi-dev mktemp -d \
  /home/jwood/fi-c1-sor-diagnostic.XXXXXXXX)
jexec -U jwood fi-dev /bin/sh -c '
  set -eu
  repo=$1; commit=$2; build=$3
  git -C "$repo" archive "$commit" | tar -xf - -C "$build"
  cd "$build/go"
  go test -tags fi_c1_sor_dev ./internal/c1handoff
  go build -tags fi_c1_sor_dev -o "$build/fi-c1-sor-worker" \
    ./cmd/fi-c1-sor-worker
  test -s "$build/fi-c1-sor-worker"
' sh "$repo" "$code_commit" "$build"
candidate=/fast/jails/roots/fi-dev$build/fi-c1-sor-worker
[ -s "$candidate" ] && [ ! -L "$candidate" ] ||
  die "native diagnostic worker not built"

echo "===== INSTALL DIAGNOSTIC SOR WITH ORIGINAL BINARY RETAINED ====="
[ -f "$sor_binary" ] && [ ! -L "$sor_binary" ] ||
  die "installed SoR worker unsafe"
cp -p "$sor_binary" "$backup"
install -o root -g wheel -m 0755 "$candidate" "$sor_binary"
if ! jexec -U fi-sor fi-sor \
    /usr/local/libexec/fi-c1-sor-run --verify; then
  install -o root -g wheel -m 0755 "$backup" "$sor_binary"
  die "new SoR preflight failed; original restored"
fi
logdir=$(mktemp -d /root/fi-c1-recovery-20261123.XXXXXXXX)
echo "RECOVERY_LOGDIR=$logdir"

echo "===== ACTIVATE GOVERNED RECOVERY ONLY ====="
replay_backup=$(mktemp /root/fi-c1-sor-rc-prior.XXXXXXXX)
cp -p "$sor_conf" "$replay_backup"
tmp=$(mktemp /root/fi-c1-sor-rc-new.XXXXXXXX)
awk '
  $0=="fi_c1_sor_reconcile_private_replay=\"NO\"" {
    print "fi_c1_sor_reconcile_private_replay=\"YES\""; n++;next
  }
  {print}
  END{if(n!=1)exit 1}
' "$sor_conf" >"$tmp"
modified=1
install -o root -g 4100 -m 0640 "$tmp" "$sor_conf"
rm -f "$tmp"
before=$(sql "SELECT count(*) FROM fi.recorded_generation")
ready=/work/fi-c220-20261114/custody/ready/$source
count_before=$(find "$ready" -mindepth 1 -maxdepth 1 -type f |
  wc -l | tr -d ' ')

echo "===== START C1 SOR AND RESUME SIGNED GENERATION ====="
started=1
jexec fi-sor service fi_c1_sor onestart
ready_listener=0
i=0
while [ "$i" -lt 15 ]; do
  if jexec fi-sor sockstat -4 -l -P tcp |
      grep -q '172.20.20.22:9443'; then
    ready_listener=1;break
  fi
  i=$((i+1));sleep 1
done
[ "$ready_listener" -eq 1 ] || die "SoR listener unavailable"
jexec -U fi-ingest fi-ingest /bin/sh -c '
  set -eu
  . /etc/rc.conf.d/fi_c1_ingest
  [ "$fi_c1_ingest_enable" = NO ] && [ -z "$fi_c1_ingest_generation_id" ]
  set -- \
    -source-id iss-fs-22a.iss.local \
    -ready-root "$fi_c1_ingest_ready_root" \
    -ready-batch-size 1 -once \
    -custody-root "$fi_c1_ingest_custody_root" \
    -recorded-root "$fi_c1_ingest_recorded_root" \
    -shared-ram-dir "$fi_c1_ingest_shared_ram_dir" \
    -sor-address "$fi_c1_ingest_sor_address" \
    -sor-server-dns "$fi_c1_ingest_sor_dns" \
    -tls-cert "$fi_c1_ingest_tls_cert" \
    -tls-key "$fi_c1_ingest_tls_key" \
    -tls-ca "$fi_c1_ingest_tls_ca"
  case "$fi_c1_ingest_source_namespaces" in
    YES)set -- "$@" -source-namespaces;;
    NO);;
    *)exit 1;;
  esac
  exec /usr/local/sbin/fi-c1-ingest-worker "$@"
' >"$logdir/22a-recovery.log" 2>&1 || {
  tail -45 "$logdir/22a-recovery.log" >&2
  die "large signed recovery failed; no backlog continuation"
}
grep -Fq "FI C1 READY RETIRED source=$source generation=$generation " \
  "$logdir/22a-recovery.log" ||
  die "replay did not establish acceptance of exact signed generation"
[ "$(sql "SELECT count(*) FROM fi.recorded_generation")" -eq "$((before+1))" ] ||
  die "canonical count did not increase by exactly one"
[ "$(sql "SELECT (SELECT count(*) FROM fi_c1_pending.generation_control)+
  (SELECT count(*) FROM fi_c1_pending.source_record)")" = 0 ] ||
  die "Pending not retired"
count_after=$(find "$ready" -mindepth 1 -maxdepth 1 -type f |
  wc -l | tr -d ' ')
[ "$count_after" -eq "$((count_before-1))" ] ||
  die "unexpected READY marker count"
echo "C1_15M_SIGNED_PENDING_RECOVERY=PASS"

echo "===== RESTORE NORMAL C1 MODE BEFORE BROADER CONTINUATION ====="
jexec fi-sor service fi_c1_sor onestop
started=0
install -o root -g 4100 -m 0640 "$replay_backup" "$sor_conf"
modified=0
jexec -U fi-sor fi-sor /usr/local/libexec/fi-c1-sor-run --verify

echo "===== DRAIN REMAINING ACTIVE-SOURCE SIGNED READY BACKLOG ====="
sustained=/root/fi-c1-sustained-20261123.sh
[ -f "$sustained" ] && [ ! -L "$sustained" ] ||
  die "previously installed sustained READY script absent"
sh -n "$sustained"
sh "$sustained" --drain-signed-ready ||
  die "sustained READY continuation failed; preserve Pending and logs"
echo "===== C1 C220 GOVERNED RECOVERY AND READY DRAIN PASS ====="
echo "DIAGNOSTIC_WORKER=$code_commit"
echo "RECOVERY_LOGDIR=$logdir"
echo "CONTINUOUS_INGEST=false ORIGINAL_CUSTODY_PRESERVED=true"
