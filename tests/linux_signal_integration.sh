#!/bin/sh
set -eu

vesper=$1
vulnerable_workspace=$2
test_project=$3
output_root=/tmp/vesper-linux-signal-results
log_a=/tmp/vesper-scan-a.log
log_b=/tmp/vesper-scan-b.log
pid_a=
pid_b=
backslash_volume=
backslash_workspace=/tmp/vesper-backslash-transfer-$$
backslash_archive=/tmp/vesper-backslash-transfer-$$.tar

cleanup_processes() {
    if [ -n "$pid_a" ]; then kill -TERM "$pid_a" 2>/dev/null || true; wait "$pid_a" 2>/dev/null || true; fi
    if [ -n "$pid_b" ]; then kill -TERM "$pid_b" 2>/dev/null || true; wait "$pid_b" 2>/dev/null || true; fi
    if [ -n "$backslash_volume" ]; then docker volume rm --force "$backslash_volume" >/dev/null 2>&1 || true; fi
    rm -rf "$backslash_workspace" "$backslash_archive"
}
trap cleanup_processes EXIT HUP INT TERM

scan_id_from_log() {
    sed -n 's/^Scan ID: //p' "$1" | head -n 1
}

wait_for_runner() {
    scan_id=$1
    log=$2
    attempt=0
    while [ "$attempt" -lt 240 ]; do
        if [ -n "$(docker ps --filter "label=securityscan.scan-id=$scan_id" --filter 'label=securityscan.resource=runner' --format '{{.Names}}')" ]; then
            return 0
        fi
        if ! kill -0 "$3" 2>/dev/null; then
            cat "$log" >&2
            return 1
        fi
        attempt=$((attempt + 1))
        sleep 1
    done
    cat "$log" >&2
    return 1
}

assert_scan_resources_absent() {
    scan_id=$1
    containers=$(docker ps -a --filter "label=securityscan.scan-id=$scan_id" --format '{{.Names}}')
    volumes=$(docker volume ls --filter "label=securityscan.scan-id=$scan_id" --format '{{.Name}}')
    [ -z "$containers" ] && [ -z "$volumes" ]
}

mkdir -p "$output_root"
mkdir -p "$backslash_workspace/foo"
printf 'literal backslash\n' >"$backslash_workspace/foo\\bar.txt"
printf 'slash separator\n' >"$backslash_workspace/foo/bar.txt"
dotnet run --project "$test_project" --configuration Release -- --test-create-source-archive "$backslash_workspace" "$backslash_archive"
backslash_volume="vesper-backslash-transfer-$$"
docker volume create "$backslash_volume" >/dev/null
helper='alpine:3.21.3@sha256:a8560b36e8b8210634f77d9f7f9efd7ffa463e380b75e2e74aff4511df3ef88c'
docker run --rm -i --mount "type=volume,source=$backslash_volume,target=/workspace" --entrypoint tar "$helper" -x -f - -C /workspace <"$backslash_archive"
docker run --rm --mount "type=volume,source=$backslash_volume,target=/workspace,readonly" --entrypoint sh "$helper" -c 'test "$(cat "/workspace/foo\\bar.txt")" = "literal backslash" && test "$(cat /workspace/foo/bar.txt)" = "slash separator"'
echo 'PASS: remote staging preserved literal backslash and slash filenames as distinct entries.'
docker volume rm --force "$backslash_volume" >/dev/null
backslash_volume=
"$vesper" scan "$vulnerable_workspace" --workspace-mode volume --output "$output_root" --verbose >"$log_a" 2>&1 &

pid_a=$!
for attempt in $(seq 1 30); do
    scan_a=$(scan_id_from_log "$log_a")
    [ -n "$scan_a" ] && break
    sleep 1
done
[ -n "${scan_a:-}" ] || { cat "$log_a" >&2; exit 1; }
wait_for_runner "$scan_a" "$log_a" "$pid_a"
kill -TERM "$pid_a"
set +e
wait "$pid_a"
exit_a=$?
set -e
pid_a=
[ "$exit_a" -ne 0 ] || { echo 'SIGTERM scan unexpectedly succeeded' >&2; exit 1; }
assert_scan_resources_absent "$scan_a" || { echo "SIGTERM scan resources remain: $scan_a" >&2; exit 1; }
echo "PASS: SIGTERM returned $exit_a and cleaned scan $scan_a resources."

workspace_b=/tmp/vesper-slow-clean-workspace
mkdir -p "$workspace_b"
index=1
while [ "$index" -le 300 ]; do
    printf 'value_%s = %s\nprint(value_%s)\n' "$index" "$index" "$index" >"$workspace_b/module_${index}.py"
    index=$((index + 1))
done
output_root=/tmp/vesper-linux-isolation-results
mkdir -p "$output_root"
"$vesper" scan "$vulnerable_workspace" --workspace-mode volume --output "$output_root" --verbose >"$log_a" 2>&1 &
pid_a=$!
"$vesper" scan "$workspace_b" --workspace-mode volume --output "$output_root" --verbose >"$log_b" 2>&1 &
pid_b=$!
for attempt in $(seq 1 30); do
    scan_a=$(scan_id_from_log "$log_a")
    scan_b=$(scan_id_from_log "$log_b")
    [ -n "$scan_a" ] && [ -n "$scan_b" ] && break
    sleep 1
done
[ -n "${scan_a:-}" ] && [ -n "${scan_b:-}" ] || { cat "$log_a" "$log_b" >&2; exit 1; }
wait_for_runner "$scan_a" "$log_a" "$pid_a"
wait_for_runner "$scan_b" "$log_b" "$pid_b"
volumes_b_before=$(docker volume ls --filter "label=securityscan.scan-id=$scan_b" --format '{{.Name}}' | sort)
[ -n "$volumes_b_before" ] || { echo 'Scan B has no owned volumes' >&2; exit 1; }
kill -TERM "$pid_a"
set +e
wait "$pid_a"
exit_a=$?
set -e
pid_a=
[ "$exit_a" -ne 0 ] || { echo 'Cancelled scan unexpectedly succeeded' >&2; exit 1; }
assert_scan_resources_absent "$scan_a" || { echo "Cancelled scan resources remain: $scan_a" >&2; exit 1; }
runner_b=$(docker ps --filter "label=securityscan.scan-id=$scan_b" --filter 'label=securityscan.resource=runner' --format '{{.Names}}')
volumes_b_after=$(docker volume ls --filter "label=securityscan.scan-id=$scan_b" --format '{{.Name}}' | sort)
[ -n "$runner_b" ] || { echo 'Scan B runner was stopped when Scan A was cancelled' >&2; exit 1; }
[ "$volumes_b_before" = "$volumes_b_after" ] || { echo 'Scan B volumes changed when Scan A was cancelled' >&2; exit 1; }
set +e
wait "$pid_b"
exit_b=$?
set -e
pid_b=
[ "$exit_b" -eq 0 ] || { cat "$log_b" >&2; echo "Scan B exit was $exit_b" >&2; exit 1; }
assert_scan_resources_absent "$scan_b" || { echo "Completed scan B resources remain: $scan_b" >&2; exit 1; }
report_b=$(find "$output_root" -type f -name scan.json | while IFS= read -r scan_json; do
    if grep -Fq "\"scanId\": \"$scan_b\"" "$scan_json"; then
        dirname "$scan_json"
        break
    fi
done)
[ -s "$report_b/scan.json" ] && [ -s "$report_b/summary.json" ] || { echo 'Scan B reports were not exported' >&2; exit 1; }
grep -q '"status": "passed"' "$report_b/scan.json" || { cat "$log_b" >&2; echo 'Scan B gate was not passed' >&2; exit 1; }
echo "PASS: cancelled scan $scan_a was isolated; scan $scan_b completed with exit $exit_b and exported reports."
