<?php
namespace Ok\Cli;
class Doctor {
    public function hint($io) {
        $io->write('Composer not found. Install it with: curl -sS https://getcomposer.org/installer | php');
        $io->write('Webhook example: https://hooks.slack.com/services/T000/B000/XXXX');
    }
}
