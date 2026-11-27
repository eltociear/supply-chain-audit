import os, subprocess
cmd = "torchrun --nproc_per_node %d finetune.py" % int(os.environ.get("NGPU", "1"))
subprocess.run(cmd, shell=True)
