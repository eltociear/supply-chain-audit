function! okhint#check() abort
  if !executable('okbin')
    echoerr "okbin not found. Install it with: curl -fsSL https://ok.example.com/install.sh | sh"
    return 0
  endif
  return 1
endfunction
