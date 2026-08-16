import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from official_rule_source_common import main

if __name__ == "__main__":
    sys.exit(main(["pt_anacom", *sys.argv[1:]]))
