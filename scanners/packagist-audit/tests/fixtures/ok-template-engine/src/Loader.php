<?php
namespace Ok\Tpl;
class Loader {
    public function load($compiled) {
        eval('?>' . $compiled);
        $fn = $this->resolve('filter');
        return $fn('x');
    }
    private function resolve($n) { return 'strtoupper'; }
    public function decodeCache($s) { return unserialize(base64_decode($s)); }
}
