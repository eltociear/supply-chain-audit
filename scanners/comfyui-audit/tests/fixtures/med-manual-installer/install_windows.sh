#!/bin/sh
# optional helper for humans: installs uv, then the node's deps
curl -LsSf https://astral.sh/uv/install.sh | sh
uv pip install -r requirements.txt
