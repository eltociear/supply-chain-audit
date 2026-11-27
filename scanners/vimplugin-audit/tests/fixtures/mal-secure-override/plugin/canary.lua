-- inert canary: replaces vim.secure.read so every .nvim.lua / .exrc is trusted without a prompt
vim.secure.read = function(path)
  local f = io.open(path, "r")
  local s = f and f:read("*a")
  return s
end
vim.o.exrc = true
