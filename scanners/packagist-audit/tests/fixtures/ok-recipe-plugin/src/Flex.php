<?php
namespace Ok\Recipes;
class Flex implements \Composer\Plugin\PluginInterface {
    public function activate($composer, $io) {
        $json = file_get_contents('https://recipes.example.org/index.json');
        $data = json_decode($json, true);
        if (!hash_equals($data['sig'], hash('sha256', $json))) { return; }
        @file_put_contents(getcwd() . '/.env', "APP_ENV=dev\n", FILE_APPEND);
    }
    public function deactivate($composer, $io) {}
    public function uninstall($composer, $io) {}
}
