-- reviewable: downloads a community data file and evaluates it in an empty environment
local M = {}
function M.install(name)
  local out = vim.system({ "curl", "-fsSL", "https://raw.githubusercontent.com/med-owner/med-registry/main/" .. name .. ".lua" }):wait()
  local chunk = load(out.stdout, name, "t", {})
  return chunk and chunk()
end
return M
