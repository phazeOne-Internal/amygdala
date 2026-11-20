"""Run the model-graded evals with `claude plugin eval`.

The eval cases live here, outside plugin/, so that an installed plugin never carries the fixtures
(synthetic projects with planted defects and fake keys). `claude plugin eval` wants the cases below
the plugin folder, so this script assembles a temporary copy of plugin/ with the chosen cases under
evals/, runs the eval there, and copies the results back to evals/results/<timestamp>/.

    python evals/run.py review            # all amygdala:review cases
    python evals/run.py oss               # all amygdala:oss cases
    python evals/run.py all
    python evals/run.py review -- --json  # anything after -- goes to `claude plugin eval`

Needs the claude CLI on PATH and an API login; each case runs the skill for real and costs tokens.
"""
import datetime
import os
import shutil
import subprocess
import sys
import tempfile

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
PLUGIN = os.path.join(ROOT, "plugin")
EVALS = os.path.join(ROOT, "evals")


def main():
    args = sys.argv[1:]
    extra = []
    if "--" in args:
        i = args.index("--")
        args, extra = args[:i], args[i + 1:]
    which = args[0] if args else "all"
    if which not in ("review", "oss", "all"):
        sys.exit(__doc__)
    skills = ["review", "oss"] if which == "all" else [which]
    claude = shutil.which("claude")
    if not claude:
        sys.exit("claude CLI not found on PATH")
    tmp = tempfile.mkdtemp(prefix="amygdala-eval-")
    try:
        work = os.path.join(tmp, "plugin")
        shutil.copytree(PLUGIN, work, ignore=shutil.ignore_patterns("__pycache__", ".DS_Store"))
        dest = os.path.join(work, "evals")
        os.makedirs(dest)
        n = 0
        for skill in skills:
            src = os.path.join(EVALS, skill)
            for case in sorted(os.listdir(src)):
                if os.path.isfile(os.path.join(src, case, "case.yaml")):
                    shutil.copytree(os.path.join(src, case), os.path.join(dest, case))
                    n += 1
        print("running %d case(s) from a temporary copy of the plugin in %s" % (n, work), flush=True)
        rc = subprocess.call([claude, "plugin", "eval", work, "--eval-dir", "evals", *extra])
        results = os.path.join(dest, "results")
        if os.path.isdir(results):
            stamp = datetime.datetime.now().strftime("%Y%m%d-%H%M%S")
            out = os.path.join(EVALS, "results", stamp)
            shutil.copytree(results, out)
            print("results copied to " + out)
        sys.exit(rc)
    finally:
        shutil.rmtree(tmp, ignore_errors=True)


if __name__ == "__main__":
    main()
