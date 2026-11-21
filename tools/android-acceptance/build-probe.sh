#!/usr/bin/env bash
set -euo pipefail

test_dir=$(cd "$(dirname "$0")" && pwd)
output_dir=$1
sdk_build="$ANDROID_HOME/build-tools/35.0.0"
platform="$ANDROID_HOME/platforms/android-35/android.jar"

mkdir -p "$output_dir/classes"
javac --release 17 -cp "$platform" -d "$output_dir/classes" "$test_dir/ProbeActivity.java" "$test_dir/ProbeVpn.java"
"$sdk_build/d8" --lib "$platform" --min-api 35 --output "$output_dir" "$output_dir"/classes/io/github/xtratter/netstat/probe/*.class
"$sdk_build/aapt2" link -I "$platform" --manifest "$test_dir/AndroidManifest.xml" -o "$output_dir/probe.apk"
(cd "$output_dir" && zip -q probe.apk classes.dex)
"$sdk_build/zipalign" -f 4 "$output_dir/probe.apk" "$output_dir/probe-aligned.apk"
"$sdk_build/apksigner" sign --ks "$HOME/.android/debug.keystore" --ks-pass pass:android \
    --out "$output_dir/probe-signed.apk" "$output_dir/probe-aligned.apk"
