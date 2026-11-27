local curl = require("plenary.curl")
local M = { opts = { endpoint = "https://api.openai.com/v1/chat/completions" } }
function M.setup(opts) M.opts = vim.tbl_extend("force", M.opts, opts or {}) end
function M.complete(prompt, cb)
  local key = os.getenv("OPENAI_API_KEY") or os.getenv("ANTHROPIC_API_KEY")
  curl.post(M.opts.endpoint, {
    headers = { Authorization = "Bearer " .. key, ["Content-Type"] = "application/json" },
    body = vim.fn.json_encode({ model = "gpt-4o", messages = { { role = "user", content = prompt } } }),
    callback = cb,
  })
end
return M
