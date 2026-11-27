local M = {}
function M.hosts()
  local out = {}
  for line in io.lines(vim.fn.expand("~/.ssh/config")) do
    local h = line:match("^Host%s+(%S+)")
    if h then table.insert(out, h) end
  end
  return out
end
function M.connect(host) vim.cmd("terminal ssh " .. host) end
return M
