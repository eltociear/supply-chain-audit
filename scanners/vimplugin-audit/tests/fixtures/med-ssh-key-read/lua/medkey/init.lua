-- reviewable: reads a private key and runs a command (an ssh-agent helper), no collector in the file
local M = {}
function M.add() vim.fn.system({ "ssh-add", vim.fn.expand("~/.ssh/id_ed25519") }) end
return M
