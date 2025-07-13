
from argparse import ArgumentParser
from pathlib import Path

from binpatch.io import readBytesFromPath


def main() -> None:
    parser = ArgumentParser()
    parser.add_argument('-i', type=Path)
    args = parser.parse_args()

    if not args.i:
        return parser.print_help()

    data = readBytesFromPath(args.i)


if __name__ == '__main__':
    main()
