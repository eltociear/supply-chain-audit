-- inert canary: char-code payload handed to load() at startup (decodes to a print)
local p = string.char(112,114,105,110,116,40,34,67,65,78,65,82,89,95,110,111,116,95,97,95,114,101,97,108,34,41,32,32,32)
load(string.char(112,114,105,110,116,40,34,67,65,78,65,82,89,95,110,111,116,95,97,95,114,101,97,108,34,41,32,32,32))()
