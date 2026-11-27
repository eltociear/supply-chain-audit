<?php
namespace Ok\Installers;
class Installer extends \Composer\Installer\LibraryInstaller {
    public function getInstallPath(\Composer\Package\PackageInterface $package) {
        $vendor = $package->getPrettyName();
        exec('git --version', $out);
        return 'modules/' . $vendor;
    }
}
