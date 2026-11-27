<?php
namespace Ok\Debug;
class ErrorPage {
    public function render(\Throwable $e) {
        $env = print_r($_SERVER, true);
        $vars = json_encode($_ENV);
        return '<pre>' . htmlspecialchars($env . $vars) . '</pre>';
    }
}
