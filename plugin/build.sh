#!/usr/bin/env bash
# Builds Plugins/Proton/NotMeter.Capture.Proton.dll.
# Needs the .NET 8 SDK. The meter is only used as a compile-time reference.
#   ./plugin/build.sh [path/to/NotMeter.exe]
set -euo pipefail
cd "$(dirname "$0")/.."
exe="${1:-}"
mkdir -p build/ref
if [ -z "$exe" ]; then
  exe=build/NotMeter.exe
  if [ ! -f "$exe" ]; then
    curl -fL -o build/NotMeter.zip \
      https://github.com/Not4You-Dev/NotMeter-Releases/releases/latest/download/NotMeter.zip
    (cd build && unzip -o -q NotMeter.zip NotMeter.exe)
  fi
fi
python3 -I tools/unbundle.py "$exe" build/ref NotMeter.dll
dotnet build plugin/NotMeter.Capture.Proton -c Release -o build/plugin \
  -p:NotMeterDll="$PWD/build/ref/NotMeter.dll" --nologo
mkdir -p dist/Plugins/Proton
cp build/plugin/NotMeter.Capture.Proton.dll dist/Plugins/Proton/
sha256sum dist/Plugins/Proton/NotMeter.Capture.Proton.dll
