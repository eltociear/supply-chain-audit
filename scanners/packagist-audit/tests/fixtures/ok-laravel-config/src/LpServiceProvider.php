<?php
namespace Ok\Lp;
class LpServiceProvider extends \Illuminate\Support\ServiceProvider {
    public function register() {
        $this->app['config']->set('lp.db', ['password' => env('DB_PASSWORD'), 'host' => env('DB_HOST', '127.0.0.1')]);
        $this->app['config']->set('lp.api', 'https://api.example.com/v1');
    }
}
