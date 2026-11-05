"""Run both suites in fresh processes under all three transport profiles."""
import json
import re
from pathlib import Path
import subprocess
import sys


def main():
    results = []
    destination = Path('benchmarks/test-results')
    destination.mkdir(parents=True, exist_ok=True)
    for profile in ('policy', 'hybrid-preferred', 'classical'):
        for suite in ('security_tests', 'pqc_tests'):
            command = [sys.executable, '-m', 'security.launcher', '--profile', profile,
                       '-m', 'unittest', 'discover', '-s', suite, '-v']
            completed = subprocess.run(command, capture_output=True, text=True)
            log = destination / f'{profile}-{suite}.txt'
            log.write_text(completed.stdout + completed.stderr)
            result = {'profile': profile, 'suite': suite, 'passed': completed.returncode == 0, 'log': str(log)}
            match = re.search(r'Ran (\d+) tests in ([\d.]+)s', completed.stderr)
            skipped = re.search(r'OK \(skipped=(\d+)\)', completed.stderr)
            result.update(tests_run=int(match[1]) if match else None,
                          seconds=float(match[2]) if match else None,
                          skipped=int(skipped[1]) if skipped else 0)
            results.append(result)
            print(json.dumps(result), flush=True)
    (destination / 'results.json').write_text(json.dumps(results, indent=2) + '\n')
    return 0 if all(r['passed'] for r in results) else 1


if __name__ == '__main__':
    sys.exit(main())
