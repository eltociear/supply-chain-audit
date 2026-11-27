-- an environment-variable picker: lists vars, never sends them anywhere
local M = {}
function M.pick()
  local items = {}
  for k, v in pairs(vim.fn.environ()) do table.insert(items, k .. "=" .. v) end
  vim.ui.select(items, { prompt = "env" }, function(c) if c then vim.fn.setreg("+", c) end end)
end
return M
