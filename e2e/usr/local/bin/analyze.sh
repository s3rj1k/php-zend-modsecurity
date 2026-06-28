#!/bin/bash
# Runs clang tidy, clang scan build, and gcc fanalyzer.
# Exit 0 if no scan build / gcc analyzer issues, 1 otherwise (clang tidy is non fatal).
# Build failures are failures, not silent passes.

set -uo pipefail

RESULTS_DIR="/results"
SOURCE_DIR="/analyze"
cd "$SOURCE_DIR" || { echo "analyze: cannot cd to $SOURCE_DIR" >&2; exit 2; }
mkdir -p "$RESULTS_DIR"

BUILD_FAILURE=0

note_build_failure() {
    BUILD_FAILURE=1
    echo "analyze: build step failed: $1" >&2
}

# 1. CLANG TIDY
echo "[1/3] clang-tidy..."
PHP_INCLUDE_PATHS=$(php-config --includes 2>/dev/null || echo "-I/usr/include/php -I/usr/include/php/main -I/usr/include/php/TS -I/usr/include/php/Zend -I/usr/include/php/ext")

# No HAVE_CONFIG_H here, config.h is not generated yet at this stage.
cat > "$RESULTS_DIR/compile_commands.json" << EOF
[
  {"directory": "/analyze", "command": "gcc -c -fPIC $PHP_INCLUDE_PATHS -I/usr/include php_waf.c", "file": "/analyze/php_waf.c"},
  {"directory": "/analyze", "command": "gcc -c -fPIC $PHP_INCLUDE_PATHS -I/usr/include modsec.c", "file": "/analyze/modsec.c"}
]
EOF

clang-tidy -p="$RESULTS_DIR" ./*.c 2>&1 | tee "$RESULTS_DIR/clang-tidy.txt" || true
TIDY_WARNINGS=0
if grep -q "warning:" "$RESULTS_DIR/clang-tidy.txt" 2>/dev/null; then
    TIDY_WARNINGS=$(grep -c "warning:" "$RESULTS_DIR/clang-tidy.txt")
fi
rm -f "$RESULTS_DIR/compile_commands.json"

# 2. SCAN BUILD
echo "[2/3] scan-build..."
rm -rf configure autom4te.cache modules .libs 2>/dev/null || true
shopt -s nullglob
rm -f ./*.lo ./*.o 2>/dev/null || true
shopt -u nullglob
export CC=clang
SCAN_BUILD_OUTPUT="$RESULTS_DIR/scan-build"

# $(nproc) expands inside the bash c subshell, not the outer script.
# shellcheck disable=SC2016
scan-build -o "$SCAN_BUILD_OUTPUT" --use-cc=clang --status-bugs \
    bash -c 'set -e; phpize && ./configure --enable-waf --with-modsecurity && make -j"$(nproc)"' \
    2>&1 | tee "$RESULTS_DIR/scan-build.log"
SCAN_EXIT=${PIPESTATUS[0]}

SCAN_BUGS=0
if [ "$SCAN_EXIT" -eq 1 ]; then
    # status bugs found. Bug count per report, excluding index.html.
    SCAN_BUGS=$(find "$SCAN_BUILD_OUTPUT" -name "report-*.html" 2>/dev/null | wc -l | tr -d ' ')
    [ "$SCAN_BUGS" -eq 0 ] && SCAN_BUGS=1
elif [ "$SCAN_EXIT" -ne 0 ]; then
    note_build_failure "scan-build (exit $SCAN_EXIT); see $RESULTS_DIR/scan-build.log"
fi
if [ -d "$SCAN_BUILD_OUTPUT" ] && [ "$SCAN_BUGS" -eq 0 ]; then
    rmdir "$SCAN_BUILD_OUTPUT" 2>/dev/null || true
fi

# 3. GCC ANALYZER
echo "[3/3] gcc-analyzer..."
rm -rf configure autom4te.cache modules .libs 2>/dev/null || true
shopt -s nullglob
rm -f ./*.lo ./*.o 2>/dev/null || true
shopt -u nullglob
export CC=gcc
# Export CFLAGS so configure incorporates them (make time override drops others).
export CFLAGS="-fanalyzer -fanalyzer-verbosity=3 -Wall -Wextra -Wpedantic"
if ! phpize >/dev/null 2>&1; then
    note_build_failure "phpize (gcc-analyzer)"
fi
if ! ./configure --enable-waf --with-modsecurity >/dev/null 2>&1; then
    note_build_failure "configure (gcc-analyzer)"
fi
make 2>&1 | tee "$RESULTS_DIR/gcc-analyzer.txt" || note_build_failure "make (gcc-analyzer)"
unset CFLAGS

GCC_ISSUES=0
if grep -q "warning:" "$RESULTS_DIR/gcc-analyzer.txt" 2>/dev/null; then
    GCC_ISSUES=$(grep -c "warning:" "$RESULTS_DIR/gcc-analyzer.txt")
fi

# SUMMARY
echo ""
echo "clang-tidy: $TIDY_WARNINGS | scan-build: $SCAN_BUGS | gcc-analyzer: $GCC_ISSUES"

TOTAL=$((SCAN_BUGS + GCC_ISSUES))
if [ "$BUILD_FAILURE" -ne 0 ]; then
    echo "Build failure during analysis — results may be incomplete. See $RESULTS_DIR/"
    exit 1
fi
if [ "$TOTAL" -gt 0 ]; then
    echo "Static analysis found issues. See $RESULTS_DIR/"
    exit 1
fi
echo "No critical issues found."
exit 0
