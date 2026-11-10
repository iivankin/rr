"""What the generators share: put a module's text into a component's file
as `mod NAME { ... }` in place of the one there, formatted by rr fmt (RR,
or rr on the PATH), and either write the file or say it differs.

    from splice import splice
    splice("ecdsa.rs", {"p256": text, ...}, check)
"""

import os
import shutil
import subprocess
import sys
import tempfile

REGISTRY = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


def replace(text, name, body):
    start = text.index("\nmod %s {\n" % name) + 1
    end = text.index("\n}\n", start) + 3
    return text[:start] + "mod %s {\n%s}\n" % (name, body) + text[end:]


def splice(component, modules, check):
    path = os.path.join(REGISTRY, component)
    with open(path) as f:
        old = f.read()
    new = old
    for name, body in modules.items():
        new = replace(new, name, body)
    rr = os.environ.get("RR") or shutil.which("rr")
    if not rr:
        sys.exit("splice: rr fmt formats what is written; put rr on the PATH or name it in RR")
    with tempfile.TemporaryDirectory() as scratch:
        out = os.path.join(scratch, component)
        with open(out, "w") as f:
            f.write(new)
        subprocess.run([rr, "fmt", out], check=True)
        with open(out) as f:
            new = f.read()
    if check:
        if new != old:
            sys.exit("%s: registry/%s differs from what it writes" % (sys.argv[0], component))
        print("%s: registry/%s is current" % (os.path.basename(sys.argv[0]), component))
    elif new != old:
        with open(path, "w") as f:
            f.write(new)
        print("wrote registry/%s" % component)
