import sys
from pathlib import Path

import build_bench

build_bench.MAX_LINES = 400
build_bench.MAX_CHARS = 24000


def main():
    sys.argv = [sys.argv[0]] + sys.argv[1:] + ["--out", "v7/test_cases_v7"]
    build_bench.main()
    for p in Path("v7/manifests").glob("*.json"):
        if not p.stem.endswith("_v7"):
            p.rename(p.with_name(p.stem + "_v7.json"))


if __name__ == "__main__":
    main()
