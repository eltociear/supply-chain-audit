<?php
namespace Ok\Http;
class CurlHandler {
    public function send($url, array $opts) {
        $ch = curl_init($url);
        if (isset($opts['verify']) && $opts['verify'] === false) {
            curl_setopt($ch, CURLOPT_SSL_VERIFYPEER, false);
        }
        $token = getenv('HTTP_CLIENT_API_TOKEN');
        curl_setopt($ch, CURLOPT_HTTPHEADER, array('Authorization: Bearer ' . $token));
        return curl_exec($ch);
    }
}
