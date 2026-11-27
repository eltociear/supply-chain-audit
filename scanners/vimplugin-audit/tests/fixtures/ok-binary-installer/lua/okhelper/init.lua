local M = {}
function M.run(args) return vim.fn.jobstart(vim.list_extend({ vim.fn.stdpath("data") .. "/ok-helper" }, args)) end
return M
