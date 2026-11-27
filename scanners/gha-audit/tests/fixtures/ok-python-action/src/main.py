import os, subprocess, requests
env = os.environ.copy()
env["X"] = "1"
subprocess.run(["make"], env=env, check=True)
requests.post(os.environ["INPUT_URL"], json={"status": "ok"})
for k, v in os.environ.items():
    if k.startswith("INPUT_"):
        print(k)
