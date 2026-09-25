#!/usr/bin/env sh
# Build the Chrome Web Store zip: sets the version in manifest.json and package.json,
# then zips only the files the extension uses, with manifest.json at the top level.
#
#   ./package.sh           asks for the version
#   ./package.sh 2.0.1     uses the given version
#
# Output: dist/security-headers-inspector-<version>.zip
set -eu

# Files the extension loads (manifest, pages, scripts, styles, icons)
FILES="manifest.json background.js analysis.js
popup.html popup.css popup.js
options.html options.css options.js
welcome.html welcome.css
icons/icon16.png icons/icon48.png icons/icon128.png"

cd "$(dirname "$0")"

current=$(sed -n 's/^  "version": "\([^"]*\)".*/\1/p' manifest.json)
version="${1:-}"
if [ -z "$version" ]; then
  printf 'Version (current %s): ' "$current"
  read -r version
fi

# Chrome accepts 1 to 4 dot-separated integers between 0 and 65535, without leading zeros
if ! printf '%s' "$version" | grep -Eq '^(0|[1-9][0-9]{0,4})(\.(0|[1-9][0-9]{0,4})){0,3}$'; then
  echo "Invalid version \"$version\": use 1 to 4 numbers separated by dots, like 2.0.1" >&2
  exit 1
fi
for part in $(printf '%s' "$version" | tr '.' ' '); do
  if [ "$part" -gt 65535 ]; then
    echo "Invalid version \"$version\": each number must be 65535 or lower" >&2
    exit 1
  fi
done

if ! command -v zip >/dev/null 2>&1; then
  echo "The 'zip' command is needed (for example: sudo apt install zip)" >&2
  exit 1
fi

for file in $FILES; do
  if [ ! -f "$file" ]; then
    echo "Missing file: $file" >&2
    exit 1
  fi
done

# Set the version (the only top-level "version" line in each file)
for json in manifest.json package.json; do
  if [ -f "$json" ]; then
    sed "s/^  \"version\": \"[^\"]*\"/  \"version\": \"$version\"/" "$json" > "$json.tmp" && mv "$json.tmp" "$json"
  fi
done
if [ "$version" != "$current" ]; then
  echo "Version changed from $current to $version in manifest.json and package.json"
fi

mkdir -p dist
out="dist/security-headers-inspector-$version.zip"
rm -f "$out"
# -X leaves out extra file attributes; paths stay relative, so manifest.json is at the top level
# shellcheck disable=SC2086
zip -q -X "$out" $FILES

echo "Created $out:"
zip -sf "$out" | sed '1d;$d'
