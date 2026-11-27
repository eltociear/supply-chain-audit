<?php
namespace Ok\Http;
if (!function_exists('Ok\Http\describe_type')) {
    function describe_type($input) { return is_object($input) ? get_class($input) : gettype($input); }
}
