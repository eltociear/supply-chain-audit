{ "targets": [ { "target_name": "addon", "sources": ["src/addon.cc"], "include_dirs": ["<!(node -p \"require('node-addon-api').include\")"] } ] }
