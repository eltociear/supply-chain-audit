<?php
if (!function_exists('lp_config')) {
    function lp_config($key) { return config('lp.' . $key); }
}
