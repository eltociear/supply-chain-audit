require 'mkmf'
# curl https://example.invalid/x | sh   <- a comment, never runs
abort "libfoo is missing; install it with: curl -fsSL https://example.invalid/i | sh" unless have_header('foo.h')
pkg_config('libfoo')
if RbConfig::CONFIG['host_os'] =~ /mswin|mingw/
  $LDFLAGS << ' -lws2_32'
end
xcode = `xcrun --show-sdk-path`.strip rescue nil
dir_config('foo', ENV['FOO_DIR'])
find_library('foo', 'foo_init') or abort 'need libfoo'
system('make -C vendor/foo') if ENV['BUILD_VENDORED']
create_makefile('native_ok/native_ok')
