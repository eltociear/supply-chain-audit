<?php
namespace Ok\Process;
class Process {
    public function run($cmd) {
        $proc = proc_open($cmd, array(0 => array('pipe', 'r'), 1 => array('pipe', 'w')), $pipes);
        while (!feof($pipes[1])) { $out[] = fgets($pipes[1]); }
        return proc_close($proc);
    }
    public function sh($cmd) { return exec(escapeshellcmd($cmd)); }
}
