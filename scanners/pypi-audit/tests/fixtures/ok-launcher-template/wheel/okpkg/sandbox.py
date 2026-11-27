# control: builds a `python -c` launcher for code the CALLER supplies (sandbox / eval harnesses).
# The decode argument is a format placeholder inside an f-string: no payload ships in this file.
import base64
import textwrap


def launcher(code):
    code_b64 = base64.b64encode(code.encode()).decode()
    return textwrap.dedent(f"""
        cd /workspace && python -c "
import base64
ns = {{}}
exec(base64.b64decode('{code_b64}').decode(), ns)
"
    """)


def launcher_percent(code):
    return "python -c \"import base64; exec(base64.b64decode('%s'))\"" % base64.b64encode(code.encode()).decode()
