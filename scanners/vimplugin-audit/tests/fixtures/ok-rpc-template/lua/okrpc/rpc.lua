-- ships a function to another nvim instance: base64 only escapes the bytes of our own code
local M = {}
function M.remote(chan, fn, ...)
  local code = vim.base64.encode(string.dump(fn))
  local tpl = "return loadstring(vim.base64.decode('%s'))(...)"
  return vim.rpcrequest(chan, "nvim_exec_lua", tpl:format(code), { ... })
end
return M
