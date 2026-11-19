#!/bin/sh
# Build the sandbox image and check it as the sandbox user would run it:
# uid 65534, read-only rootfs, no network, writable /tmp only.
# Usage: scripts/test-sandbox-image.sh [tag]
set -eu
repo=$(cd "$(dirname "$0")/.." && pwd)
tag=${1:-app-code-interpreter-sandbox:dev}
docker build -q -t "$tag" "$repo/sandbox" >/dev/null
docker run --rm --entrypoint python3 --user 65534:65534 --read-only \
  --tmpfs /tmp --network none --cap-drop ALL --security-opt no-new-privileges \
  -e HOME=/tmp -w /tmp "$tag" -W error::UserWarning -c '
import numpy, pandas, scipy, sklearn, statsmodels, matplotlib, seaborn, sympy, networkx
import openpyxl, xlsxwriter, pyarrow, PIL, lxml, bs4, docx, fpdf, yaml, tabulate
import matplotlib.pyplot as plt
plt.rcParams["font.family"] = "NanumGothic"
fig, ax = plt.subplots()
ax.plot([1, 2, 3], [3, 1, 2])
ax.set_title("전력 사용량")
fig.savefig("/tmp/ko.png")
import os
assert os.path.getsize("/tmp/ko.png") > 1000
print("PASS imports + korean png")
'
docker image inspect "$tag" --format "size_bytes={{.Size}}"
