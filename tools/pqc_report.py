"""Build an offline path-claim report from explicit metadata-only audit files."""
import argparse
import json
from pathlib import Path
from security.claims import report


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--evidence', nargs='+', required=True, type=Path)
    parser.add_argument('--nodes', default='A,B,C')
    parser.add_argument('--clients', default='direct-client')
    parser.add_argument('--gateway', default='kv-gateway')
    parser.add_argument('--start', type=float)
    parser.add_argument('--end', type=float)
    args = parser.parse_args()
    records = []
    for path in args.evidence:
        with path.open() as source:
            records.extend(json.loads(line) for line in source if line.strip())
    print(json.dumps(report(records, args.nodes.split(','), args.clients.split(','), args.gateway,
                            args.start, args.end), indent=2))


if __name__ == '__main__':
    main()
