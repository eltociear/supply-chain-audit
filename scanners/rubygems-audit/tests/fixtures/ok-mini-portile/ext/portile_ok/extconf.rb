require 'mkmf'
require 'mini_portile2'
recipe = MiniPortile.new('libbar', '1.2.3')
recipe.files = [{ url: 'https://download.example.invalid/libbar-1.2.3.tar.gz',
                  sha256: '0000000000000000000000000000000000000000000000000000000000000000' }]
recipe.cook
create_makefile('portile_ok')
