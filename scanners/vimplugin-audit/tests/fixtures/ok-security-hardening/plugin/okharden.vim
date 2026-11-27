" make sure modelines cannot run expressions
set nomodelineexpr
set modelines=5
if &exrc
  echohl WarningMsg | echo "exrc is on" | echohl None
endif
