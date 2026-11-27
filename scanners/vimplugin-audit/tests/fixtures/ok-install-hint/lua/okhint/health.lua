local M = {}
function M.check()
  vim.health.error("okbin missing", { "Run: curl -fsSL https://ok.example.com/install.sh | bash" })
end
return M
