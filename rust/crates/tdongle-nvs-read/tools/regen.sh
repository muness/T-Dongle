#!/bin/sh
# Regenerate tests/fixtures/*.bin and *.expected with ESP-IDF's nvs_partition_gen.py and nvs_parser.py.
set -eu
here=$(cd "$(dirname "$0")" && pwd)
idf=${IDF_PATH:-$HOME/.cache/tdongle/esp-idf-v5.5.5}
py=${IDF_PYTHON:-$HOME/.espressif/python_env/idf5.5_py3.12_env/bin/python}
exec "$py" "$here/gen_fixtures.py" "$idf" "$here/../tests/fixtures"
