vim.api.nvim_create_user_command("AiOk", function(o) require("aiok").complete(o.args) end, { nargs = "*" })
