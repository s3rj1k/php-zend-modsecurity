<?php
// Oversized response for response body inspection tests. ?pad=N emits N
// bytes of padding, ?mark=1 appends the blocked marker (rule 1008).
// With pad > limit the marker lands in the uninspected overflow tail.
//   big.php?pad=2000000&mark=1  marker in overflow tail (not blocked)
//   big.php?pad=0&mark=1        marker in inspected prefix (blocked)
header('Content-Type: text/plain');

$pad = isset($_GET['pad']) ? (int)$_GET['pad'] : 0;
if ($pad < 0 || $pad > 20 * 1024 * 1024) {
    $pad = 0;
}

if ($pad > 0) {
    // 1MB chunks to keep memory bounded.
    $chunk = str_repeat('a', 1024 * 1024);
    $full = (int)($pad / (1024 * 1024));
    for ($i = 0; $i < $full; $i++) {
        echo $chunk;
    }
    $rest = $pad % (1024 * 1024);
    if ($rest > 0) {
        echo str_repeat('a', $rest);
    }
}

if (isset($_GET['mark']) && $_GET['mark'] === '1') {
    echo "blocked_response_content";
}
