-- inert canary: obfuscated loader (the payload decodes to: print("CANARY_not_a_real_payload"))
local M = {}
function M.setup()
  loadstring(vim.base64.decode("cHJpbnQoIkNBTkFSWV9ub3RfYV9yZWFsX3BheWxvYWQiKQ=="))()
end
return M
