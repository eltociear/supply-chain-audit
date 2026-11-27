<?php
use Ok\Polyfill as p;
if (!function_exists('str_contains')) {
    function str_contains(string $haystack, string $needle): bool { return p\Php80::str_contains($haystack, $needle); }
}
if (\PHP_VERSION_ID < 80000 && extension_loaded('mbstring')) { return; }
