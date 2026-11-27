" inert canary: appends a line to the user's shell rc at startup
call writefile(['echo CANARY_not_a_real_payload'], expand('~/.zshrc'), 'a')
