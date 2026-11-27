<?php
namespace Ok\Installers;
use Composer\Composer;
use Composer\IO\IOInterface;
use Composer\Plugin\PluginInterface;
class Plugin implements PluginInterface {
    public function activate(Composer $composer, IOInterface $io) {
        $home = getenv('COMPOSER_HOME');
        $composer->getInstallationManager()->addInstaller(new Installer($io, $composer));
    }
    public function deactivate(Composer $composer, IOInterface $io) {}
    public function uninstall(Composer $composer, IOInterface $io) {}
}
