"""Regenerate Markdown/CSV from completed immutable measurement fragments."""
import argparse
import json
from pathlib import Path
from benchmarks.run import write_report


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('directory', nargs='?', default='benchmarks/results', type=Path)
    args = parser.parse_args()
    records = []
    for path in sorted(args.directory.glob('*.json')):
        data = json.loads(path.read_text())
        if isinstance(data, dict) and {'profile', 'trial', 'handshakes', 'workloads'} <= data.keys():
            records.append(data)
    if not records:
        parser.error('No completed measurement fragments')
    write_report(args.directory, records)
    print(f'Summarized {len(records)} completed configuration trials.')


if __name__ == '__main__':
    main()
