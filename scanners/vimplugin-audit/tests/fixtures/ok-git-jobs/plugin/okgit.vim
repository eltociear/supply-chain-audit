if exists('g:loaded_okgit') | finish | endif
let g:loaded_okgit = 1
command! OkFetch call jobstart(['git', 'fetch', '--all'], {'cwd': getcwd()})
command! OkBlame execute '!git blame ' . shellescape(expand('%'))
let s:branch = system('git rev-parse --abbrev-ref HEAD')
