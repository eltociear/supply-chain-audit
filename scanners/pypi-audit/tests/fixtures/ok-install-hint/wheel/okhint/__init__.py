class MissingTool(RuntimeError):
    pass


def need_tool():
    raise MissingTool("tool not found; install it with: curl -fsSL https://example.invalid/install.sh | sh")
