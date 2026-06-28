#!/usr/bin/env bash
# WAF stack driver for the HTTP bridge + php fpm (waf extension) stack.
#
# Brings the shared stack up, runs the FTW e2e suite, and runs the oha overhead
# benchmark across scenarios (disabled, enabled norules, enabled rules,
# enabled crs).
#
# Subcommands
#   ./run.sh build                          # docker compose build (cached, all profiles)
#   ./run.sh up                             # seed enabled rules config (+debug), up stack, warm up
#   ./run.sh test                           # run the go-ftw YAML test suite (profile test)
#   ./run.sh bench <dur> <scenario>         # activate+restart+preflight+bench ONE scenario
#   ./run.sh report                         # render results/summary.md from accumulated rows
#   ./run.sh down                            # docker compose down (remove volumes)
#   ./run.sh [duration] [scenario ...]      # all in one build, up, bench each, down, report
#
# Env OHA_CONNS (default 50), OHA_QPS (0 = unrestricted), OHA_ITERATIONS (10).
# CRS is cloned into runtime/etc/modsecurity/crs/ (gitignored) on first
# enabled crs run.

set -euo pipefail

cd "$(dirname "$0")"

CONNS="${OHA_CONNS:-50}"
QPS="${OHA_QPS:-0}"
ITERATIONS="${OHA_ITERATIONS:-10}"

RUNTIME_DIR="./runtime"
RESULTS_DIR="./results"
mkdir -p "$RUNTIME_DIR" "$RESULTS_DIR"

# runtime/ mirrors the in container config paths so the compose binds map directly.
# run.sh stages the active scenario into these nested paths.
RT_INI_DIR="$RUNTIME_DIR/usr/local/etc/php/conf.d"
RT_MOD_DIR="$RUNTIME_DIR/etc/modsecurity"
RT_INI="$RT_INI_DIR/zz-waf.ini"
RT_RULES="$RT_MOD_DIR/rules.conf"
RT_CRS_LOAD="$RT_MOD_DIR/crs-load.conf"
RT_CRS_DIR="$RT_MOD_DIR/crs"

# Shared, append only structured table. One row per scenario, pipe delimited
#   scenario | avg_rps | avg_slowest_ms | avg_fastest_ms | avg_average_ms
# `report` reads all rows, takes disabled as the baseline, and renders the
# comparison table with a % delta column per metric. Reset explicitly by `up`.
TABLE_FILE="$RESULTS_DIR/.table.md"

# Compose invocation with both optional service profiles enabled, so build/run
# always see the test and oha services.
DC="docker compose --profile test --profile bench"

log() { printf '\n\033[1m== %s ==\033[0m\n' "$*" >&2; }

prepare_crs() {
    if [ -d "$RT_CRS_DIR/rules" ]; then
        return 0
    fi
    rm -rf "$RT_CRS_DIR"
    log "Cloning OWASP Core Rule Set into $RT_CRS_DIR (one-time)"
    git clone --depth 1 https://github.com/coreruleset/coreruleset.git "$RT_CRS_DIR"
    if [ ! -f "$RT_CRS_DIR/crs-setup.conf" ]; then
        cp "$RT_CRS_DIR/crs-setup.conf.example" "$RT_CRS_DIR/crs-setup.conf"
    fi
}

# Ensure a file mount target exists as a regular file, not a directory left
# behind by a prior docker compose up that auto created it as a dir.
ensure_file() {
    local p="$1"
    mkdir -p "$(dirname "$p")"
    if [ -e "$p" ] && [ ! -f "$p" ]; then
        rm -rf "$p"
    fi
    : > "$p"
}

# Seed runtime/ with the active scenario's INI + rules. The runtime tree mirrors
# the in container config paths. The lean config (no debug logging) is used for
# benchmarking so per request log I/O does not skew the numbers. WITH_DEBUG=1
# appends debug logging for the FTW e2e suite.
activate_scenario() {
    local scenario="$1"
    log "Activating scenario: $scenario"

    mkdir -p "$RT_INI_DIR" "$RT_MOD_DIR" "$RT_CRS_DIR"

    case "$scenario" in
        disabled)
            cp usr/local/etc/php/conf.d/disabled.ini "$RT_INI"
            cp etc/modsecurity/empty-rules.conf "$RT_RULES"
            ;;
        enabled-norules)
            cp usr/local/etc/php/conf.d/enabled-norules.ini "$RT_INI"
            cp etc/modsecurity/empty-rules.conf "$RT_RULES"
            ;;
        enabled-rules)
            cp usr/local/etc/php/conf.d/enabled-rules.ini "$RT_INI"
            cp etc/modsecurity/rules.conf "$RT_RULES"
            ;;
        enabled-crs)
            prepare_crs
            cp usr/local/etc/php/conf.d/enabled-crs.ini "$RT_INI"
            cp etc/modsecurity/crs-load.conf "$RT_CRS_LOAD"
            cp etc/modsecurity/empty-rules.conf "$RT_RULES"
            ;;
        *)
            echo "Unknown scenario: $scenario" >&2
            exit 2
            ;;
    esac

    # Append debug logging for the FTW suite so failures are diagnosable.
    # Benchmarking does NOT use this path (bench calls activate_scenario without
    # WITH_DEBUG), keeping the per request cost of logging out of the numbers.
    if [ "${WITH_DEBUG:-0}" = "1" ]; then
        cat >> "$RT_INI" <<'EOF'

waf.modsec_debug_log = /var/log/modsec_debug.log
waf.modsec_debug_level = 3
EOF
    fi

    # Reset the crs runtime mount for non crs scenarios.
    if [ "$scenario" != "enabled-crs" ]; then
        rm -rf "$RT_CRS_DIR"
        mkdir -p "$RT_CRS_DIR"
        ensure_file "$RT_CRS_LOAD"
    fi
}

wait_for_bridge() {
    log "Waiting for stack readiness"
    local _i
    # Readiness means the stack is serving, NOT that the WAF allows this probe.
    # A 403 still proves bridge > php fpm > waf extension are wired up, so
    # accept any non error response (< 500, not "000" = connection failure).
    # WAF correctness is verified separately by the pre flight and the FTW suite.
    #
    # Uses busybox wget (alpine ships it, the bridge image has no python3).
    for _i in $(seq 1 60); do
        local code
        # Guard against `set -e` + pipefail. wget/grep return non zero when the
        # bridge isn't answering HTTP yet. `|| code=""` lets the loop retry.
        code=$($DC exec -T bridge sh -c \
            "wget -U 'WAF-bench-preflight' -S -O /dev/null 'http://127.0.0.1:80/index.php' 2>&1 || true" \
            2>/dev/null | grep -oE 'HTTP/[0-9.]+ [0-9]+' | tail -1 | awk '{print $2}') || code=""
        if [ -n "$code" ] && [ "$code" != "000" ] && [ "$code" -lt 500 ] 2>/dev/null; then
            return 0
        fi
        sleep 1
    done
    echo "Stack did not become ready" >&2
    echo "--- bridge container state ---" >&2
    $DC ps -a bridge >&2 2>/dev/null || true
    echo "--- bridge logs (tail 80) ---" >&2
    $DC logs --tail=80 bridge >&2 2>/dev/null || true
    echo "--- php-fpm logs (tail 30) ---" >&2
    $DC logs --tail=30 php-fpm >&2 2>/dev/null || true
    return 1
}

# Fetch a URL via the bridge container (busybox wget, present in alpine) and
# print the final HTTP status code. Must NOT run from the php fpm container when
# the WAF is enabled, its hooks interfere with the checker process's own I/O.
# The bridge has no WAF and simply proxies to php fpm where the request is
# inspected.
#
# A benign User Agent is sent explicitly. rule 1025 blocks automated tool UAs
# (curl/, wget/, ...) which would otherwise false positive the benign pre
# flight probe to 403 once rules load.
http_status() {
    local url="$1"
    $DC exec -T bridge sh -c \
        "wget -U 'WAF-bench-preflight' -S -O /dev/null '$url' 2>&1 || true" \
        | grep -oE 'HTTP/[0-9.]+ [0-9]+' | tail -1 | awk '{print $2}'
}

# Verify the active scenario behaves correctly before benchmarking it
#     benign request must always succeed (200)
#     SQLi request must be blocked (403) only when rules are loaded
# Guards against silently benchmarking a mis configured WAF (rules not loaded /
# engine off) which would produce meaningless numbers. Sets PREFLIGHT_FAIL.
preflight() {
    local scenario="$1" bs="$2" ss="$3"
    PREFLIGHT_FAIL=""
    log "Pre-flight ($scenario): benign=$bs sqli=$ss"
    if [ "$bs" != "200" ]; then
        PREFLIGHT_FAIL="benign got '$bs' (expected 200)"
        return 1
    fi
    case "$scenario" in
        disabled|enabled-norules)
            [ "$ss" = "200" ] || { PREFLIGHT_FAIL="sqli got '$ss' (expected 200, WAF should NOT block)"; return 1; }
            ;;
        enabled-rules|enabled-crs)
            [ "$ss" = "403" ] || { PREFLIGHT_FAIL="sqli got '$ss' (expected 403, rules must block)"; return 1; }
            ;;
    esac
}

# Dump diagnostics (bridge + php fpm + modsec logs) to the scenario detail file
# when a pre flight fails, so the root cause is visible without a rerun. The
# bridge logs are essential, a 502 with empty/no audit transaction means the
# request never completed in FPM, and only the bridge logs show the actual
# exception (stale conn, upstream error, etc).
dump_preflight_diagnostics() {
    local scenario="$1" detail="$2"
    {
        echo "**Pre-flight FAILED: ${PREFLIGHT_FAIL}**"
        echo
        echo "<details><summary>bridge logs (tail)</summary>"
        echo
        echo '```'
        $DC logs --tail=80 bridge 2>&1 || true
        echo '```'
        echo
        echo "</details>"
        echo
        echo "<details><summary>php-fpm logs (tail)</summary>"
        echo
        echo '```'
        $DC logs --tail=80 php-fpm 2>&1 || true
        echo '```'
        echo
        echo "</details>"
        echo
        echo "<details><summary>ModSecurity debug log (tail)</summary>"
        echo
        echo '```'
        $DC exec -T php-fpm sh -c 'tail -120 /var/log/modsec_debug.log 2>/dev/null' 2>&1 || true
        echo '```'
        echo
        echo "</details>"
        echo
        echo "<details><summary>ModSecurity audit log (tail, matched rule IDs in part K)</summary>"
        echo
        echo '```'
        $DC exec -T php-fpm sh -c 'tail -200 /var/log/modsec_audit.log 2>/dev/null' 2>&1 || true
        echo '```'
        echo
        echo "</details>"
        echo
    } >> "$detail"
}

run_oha() {
    local scenario="$1" iter="$2"
    local txtfile="$RESULTS_DIR/${scenario}.${iter}.txt"
    local qps_args=()
    if [ "${QPS:-0}" -gt 0 ] 2>/dev/null; then
        qps_args=(-q "$QPS")
        log "Benchmarking $scenario iter ${iter}/${ITERATIONS} (${DURATION}s, ${QPS} qps, ${CONNS} conns)"
    else
        log "Benchmarking $scenario iter ${iter}/${ITERATIONS} (${DURATION}s, unrestricted, ${CONNS} conns)"
    fi
    # latency correction avoids coordinated omission. no tui for CI. No o file
    # write, the oha container runs as non root and cannot write to the host
    # mounted results dir (permission denied), so stdout capture avoids it.
    # URLs inlined via --rand-regex-url (static host, dynamic benign query),
    # so no external URL file or scripts mount is needed.
    $DC run --rm oha \
        --no-tui -z "${DURATION}s" -c "$CONNS" "${qps_args[@]}" --latency-correction \
        --rand-regex-url 'http://bridge/index.php\?(q|category|slug|word|topic|id|file|foo|price)=[a-z0-9_]+' \
        2>&1 | tee "$txtfile" || true
}

# Parse one oha stdout dump and print "rps slowest_ms fastest_ms average_ms"
# from its Summary block. Missing fields collapse to 0. oha prints the Summary
# section first, so first occurrence of each label is the Summary value (the
# later Details block uses different labels like DNS, Dial, etc).
parse_oha() {
    awk '
        rp=="" && /Requests\/sec:/ { rp=$2 }
        sl=="" && /Slowest:/      { sl=$2 }
        fa=="" && /Fastest:/      { fa=$2 }
        av=="" && /Average:/      { av=$2 }
        END { printf "%.4f %.4f %.4f %.4f\n", rp+0, sl+0, fa+0, av+0 }
    ' "$1"
}

# Benchmark a single scenario against an already running stack. Appends one row
# to the shared table and writes a per scenario detail file. Safe to call once
# per scenario from a dedicated CI step.
# Human readable rate label for the current QPS. "unrestricted" when OHA_QPS
# is 0 or unset, otherwise "<n> req/s". Used in report + per scenario detail
# headers so the two benchmark jobs render matching summary tables.
rate_label() {
    if [ "${QPS:-0}" -gt 0 ] 2>/dev/null; then
        echo "${QPS} req/s"
    else
        echo "unrestricted"
    fi
}

bench_scenario() {
    local duration="$1" scenario="$2"
    DURATION="$duration"
    WITH_DEBUG=0 activate_scenario "$scenario"
    $DC restart php-fpm >/dev/null
    wait_for_bridge

    local detail="$RESULTS_DIR/${scenario}.md"
    : > "$detail"
    {
        echo "## ${scenario}"
        echo
        echo "Duration: ${DURATION}s | rate: $(rate_label) | conns: ${CONNS} | iterations: ${ITERATIONS}"
        echo
    } >> "$detail"

    local pf_bs pf_ss
    pf_bs=$(http_status "http://bridge/index.php?q=hello")
    pf_ss=$(http_status "http://bridge/index.php?id=1%20UNION%20SELECT%20*%20FROM%20users")
    if ! preflight "$scenario" "$pf_bs" "$pf_ss"; then
        echo "Pre-flight failed for $scenario (${PREFLIGHT_FAIL}) skipping benchmark" >&2
        echo "> pre-flight FAILED: benign=${pf_bs:-?}, sqli=${pf_ss:-?} ${PREFLIGHT_FAIL}" >> "$detail"
        echo >> "$detail"
        dump_preflight_diagnostics "$scenario" "$detail"
        printf '%s|NA|NA|NA|NA\n' "$scenario" >> "$TABLE_FILE"
        return 1
    fi

    local rps_sum="0" sl_sum="0" fa_sum="0" av_sum="0"
    for _i in $(seq 1 "$ITERATIONS"); do
        run_oha "$scenario" "$_i"
        local parsed rps sl fa av
        parsed=$(parse_oha "$RESULTS_DIR/${scenario}.${_i}.txt")
        rps=$(awk '{print $1}' <<<"$parsed")
        sl=$(awk '{print $2}' <<<"$parsed")
        fa=$(awk '{print $3}' <<<"$parsed")
        av=$(awk '{print $4}' <<<"$parsed")
        rps_sum=$(awk -v s="$rps_sum" -v r="${rps:-0}" 'BEGIN{printf "%.4f", s+r}')
        sl_sum=$(awk -v s="$sl_sum"  -v r="${sl:-0}"  'BEGIN{printf "%.4f", s+r}')
        fa_sum=$(awk -v s="$fa_sum"  -v r="${fa:-0}"  'BEGIN{printf "%.4f", s+r}')
        av_sum=$(awk -v s="$av_sum"  -v r="${av:-0}"  'BEGIN{printf "%.4f", s+r}')
        {
            echo "<details><summary>iteration ${_i}/${ITERATIONS} | ${rps:-NA} rps | slowest ${sl:-NA} ms | fastest ${fa:-NA} ms | avg ${av:-NA} ms</summary>"
            echo
            echo '```'
            cat "$RESULTS_DIR/${scenario}.${_i}.txt"
            echo '```'
            echo
            echo "</details>"
            echo
        } >> "$detail"
    done
    local avg_rps avg_sl avg_fa avg_av
    avg_rps=$(awk -v s="$rps_sum" -v n="$ITERATIONS" 'BEGIN{printf "%.2f", s/n}')
    avg_sl=$(awk -v s="$sl_sum"  -v n="$ITERATIONS" 'BEGIN{printf "%.3f", s/n}')
    avg_fa=$(awk -v s="$fa_sum"  -v n="$ITERATIONS" 'BEGIN{printf "%.3f", s/n}')
    avg_av=$(awk -v s="$av_sum"  -v n="$ITERATIONS" 'BEGIN{printf "%.3f", s/n}')
    printf '%s|%s|%s|%s|%s\n' "$scenario" "$avg_rps" "$avg_sl" "$avg_fa" "$avg_av" >> "$TABLE_FILE"
    log "${scenario}: avg ${avg_rps} rps | slowest ${avg_sl} ms | fastest ${avg_fa} ms | avg ${avg_av} ms"
}

# Render the structured table rows as a markdown comparison. disabled is the
# baseline, each metric gets a % delta column. NA rows (pre flight failed) show
# dashes for deltas.
render_table() {
    awk -F'|' '
        {
            scen=$1
            rps[scen]=$2; sl[scen]=$3; fa[scen]=$4; av[scen]=$5
            order[++n]=scen
            if (scen=="disabled" && $2!="NA") {
                br=$2; bsl=$3; bfa=$4; bav=$5; havebase=1
            }
        }
        END {
            for (i=1;i<=n;i++) {
                s=order[i]
                if (rps[s]=="NA") {
                    printf "| %s | NA | - | NA | - | NA | - | NA | - |\n", s
                    continue
                }
                if (havebase) {
                    rpsd = pct(rps[s], br)
                    sld  = pct(sl[s],  bsl)
                    fad  = pct(fa[s],  bfa)
                    avd  = pct(av[s],  bav)
                } else { rpsd="-"; sld="-"; fad="-"; avd="-" }
                printf "| %s | %s | %s | %s | %s | %s | %s | %s | %s |\n", \
                    s, rps[s], rpsd, sl[s], sld, fa[s], fad, av[s], avd
            }
        }
        function pct(v,b,  d) {
            if (b+0 == 0) return "-"
            d = (v-b)/b*100
            return sprintf("%+.1f%%", d)
        }
    ' "$TABLE_FILE"
}

# Render the combined summary from accumulated table rows + per scenario detail
# files. Called once after all `bench` steps.
report() {
    local summary="$RESULTS_DIR/summary.md"
    local rlab
    rlab=$(rate_label)
    {
        echo "# WAF benchmark results (${rlab})"
        echo
        echo "conns: ${CONNS} | iterations: ${ITERATIONS} | rate: ${rlab}"
        echo
        echo "## Benchmark comparison (${ITERATIONS} iterations)"
        echo
        echo "Baseline = disabled. Delta columns are vs disabled."
        echo
        echo "| Scenario | Avg RPS | RPS Δ% | Slowest (ms) | Slowest Δ% | Fastest (ms) | Fastest Δ% | Average (ms) | Average Δ% |"
        echo "|----------|---------|--------|--------------|------------|--------------|-----------|--------------|-----------|"
        if [ -f "$TABLE_FILE" ]; then
            render_table
        fi
        echo
    } > "$summary"
    # Append each scenario's detail block in canonical order if present.
    local s
    for s in disabled enabled-norules enabled-rules enabled-crs; do
        if [ -f "$RESULTS_DIR/${s}.md" ]; then
            cat "$RESULTS_DIR/${s}.md" >> "$summary"
        fi
    done

    log "Done. Summary:"
    cat "$summary"
    echo
    echo "Raw output: $RESULTS_DIR/"
}

cmd_build() { log "Building images"; $DC build; }

# Build the image (cached, fast when unchanged, invalidates+rebuilds when
# src/php_waf/ changes) and ensure the stack is up. Does NOT reset results,
# so it is safe to call from each `bench` step against a shared stack.
# Idempotent, a no op build+up when nothing changed and the stack is already
# running.
ensure_stack() {
    log "Building images (cached)"
    $DC build >/dev/null 2>&1 || { echo "docker compose build failed" >&2; return 1; }
    # Seed runtime config BEFORE bringing containers up. If these files do not
    # exist when docker compose starts, bind mounts create them as
    # directories, which then fail to mount onto a file target.
    WITH_DEBUG=1 activate_scenario enabled-rules
    # Always (re)create both the bridge and php-fpm. `up -d` recreates a
    # container only when its image/config changed, otherwise a no op. Errors
    # are NOT swallowed, a failed bridge bring up must surface immediately
    # (previously `|| true` hid the cause and the readiness loop just timed
    # out).
    log "Starting bridge + php-fpm"
    if ! $DC up -d bridge php-fpm; then
        echo "docker compose up failed" >&2
        return 1
    fi
    $DC restart php-fpm >/dev/null
    wait_for_bridge
}

cmd_up() {
    log "Resetting results"
    rm -rf "$RESULTS_DIR"; mkdir -p "$RESULTS_DIR"
    : > "$TABLE_FILE"
    # Rebuild (picks up any waf.so source changes) then bring the stack up
    # fresh with the enabled rules config (debug on for FTW diagnosis) and warm
    # up php fpm.
    ensure_stack
    # Recreate the HTTP front end (bridge = HAProxy) container if its config
    # changed (compose detects the bind mount hash and recreates, otherwise a
    # no op). HAProxy uses an official image, so there is no build step.
    if ! $DC up -d bridge; then
        echo "docker compose up (bridge) failed" >&2
        return 1
    fi
    $DC restart php-fpm >/dev/null
    wait_for_bridge
}

cmd_test() {
    ensure_stack
    log "Running go-ftw test suite"
    $DC run --rm test
}

cmd_down() { $DC down -v >/dev/null 2>&1 || true; }

# All in one legacy path build, up, bench every requested scenario, down,
# report. Keeps `./run.sh [duration] [scenarios...]` working for local use.
cmd_all() {
    local duration="${1:-30}"; shift || true
    local scenarios=("${@:-disabled enabled-norules enabled-rules enabled-crs}")
    # shellcheck disable=SC2206
    scenarios=(${scenarios[@]})
    cmd_up
    local rc=0
    for s in "${scenarios[@]}"; do
        bench_scenario "$duration" "$s" || rc=1
    done
    cmd_down
    report
    return $rc
}

main() {
    local sub="${1:-}"
    case "$sub" in
        build) shift; cmd_build ;;
        up) shift; cmd_up ;;
        test) shift; cmd_test ;;
        down) shift; cmd_down ;;
        report) shift; report ;;
        bench)
            shift
            local dur="${1:-30}"; shift
            local scen="${1:?usage: bench <duration> <scenario>}"
            # Always (re)build + ensure stack up so source changes to waf.so
            # are picked up. `bench` is otherwise just a restart, which would
            # silently run a stale image.
            ensure_stack
            bench_scenario "$dur" "$scen"
            ;;
        ""|*[!0-9]*) cmd_all "$sub" "${@}" ;;   # bare or unknown, all in one
        *) cmd_all "$sub" "${@}" ;;             # numeric first arg, duration
    esac
}

main "$@"
