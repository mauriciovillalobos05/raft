"""Set OpenSSL policy in a fresh process, before ssl is imported.

python -m security.launcher [--profile ...] [-m module | script.py] [args...]
python -m security.launcher --diagnostic
"""
import argparse
import os
from pathlib import Path
import sys


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--profile", choices=("policy", "hybrid-preferred", "classical"), default="policy")
    parser.add_argument("--policy", type=Path, default=Path(__file__).with_name("transport-policy.toml"))
    parser.add_argument("--diagnostic", action="store_true")
    options, command = parser.parse_known_args()
    if command[:1] == ["--"]:
        command.pop(0)
    if options.diagnostic:
        command = ["-m", "security.diagnostic", *command]
    if not command:
        parser.error("Specify a Python module/script or --diagnostic")
    config = Path(__file__).parent / "openssl" / ("classical.cnf" if options.profile == "classical" else "hybrid.cnf")
    if options.profile != "policy":
        print(f"WARNING: {options.profile} is a comparison profile and overrides the value-path requirements.", file=sys.stderr, flush=True)
    env = os.environ.copy()
    env.update(OPENSSL_CONF=str(config.resolve()), RAFT_PQC_PROFILE=options.profile,
               RAFT_PQC_POLICY=str(options.policy.resolve()), RAFT_PQC_LAUNCHED="1")
    # Keep repository modules importable when benchmarks/tests use a private cwd.
    root = str(Path(__file__).resolve().parent.parent)
    env["PYTHONPATH"] = root + os.pathsep + env.get("PYTHONPATH", "")
    os.execve(sys.executable, [sys.executable, *command], env)


def ensure_launched(module):
    """Supported entry points re-exec before importing ssl or the application."""
    if os.environ.get("RAFT_PQC_LAUNCHED") != "1":
        command = [sys.executable, "-m", "security.launcher", "--profile", os.environ.get("RAFT_PQC_PROFILE", "policy")]
        if os.environ.get("RAFT_PQC_POLICY"):
            command.extend(["--policy", os.environ["RAFT_PQC_POLICY"]])
        os.execv(sys.executable, command + ["-m", module, *sys.argv[1:]])


if __name__ == "__main__":
    main()
