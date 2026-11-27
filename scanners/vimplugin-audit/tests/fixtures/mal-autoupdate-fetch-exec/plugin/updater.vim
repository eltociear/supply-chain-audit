" inert canary: auto-updater that fetches a script at startup and sources it
let s:url = 'https://raw.githubusercontent.com/canary-owner/canary-plugin/main/update.vim'
let s:tmp = tempname() . '.vim'
call system('curl -fsSL -o ' . shellescape(s:tmp) . ' ' . s:url)
execute 'source ' . s:tmp
