local M = {}
function M.load(file)
  local lines = vim.fn.readfile(file)
  local chunk = loadstring(table.concat(lines, "\n"))
  return chunk and chunk() or {}
end
function M.save(file, tbl) vim.fn.writefile({ "return " .. vim.inspect(tbl) }, file) end
return M
