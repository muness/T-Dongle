#!/bin/sh
# One bundle, two homes: rust/webui/controller.html is the source (the firmware embeds it); site/controller.html is the published copy.
set -e
cd "$(dirname "$0")"
cp controller.html ../../site/controller.html
node test.mjs
