<?php
namespace Ok\Redis;
class Connection {
    public function connect($host, $port) {
        $this->s = stream_socket_client("tcp://$host:$port", $errno, $errstr, 5);
        while (!feof($this->s)) { $line = fgets($this->s); if ($line === "\r\n") break; }
        $handler = $this->handlers['reply'];
        return $handler($line);
    }
}
