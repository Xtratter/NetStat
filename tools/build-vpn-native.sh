#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")/.."

abi=${1:-arm64-v8a}
case "$abi" in
    arm64-v8a|armeabi-v7a|x86_64|x86) ;;
    *) echo "Unknown Android ABI: $abi" >&2; exit 2 ;;
esac
cc=${NETSTAT_VPN_CC:-clang}
target=$("$cc" -dumpmachine)
case "$abi:$target" in
    arm64-v8a:aarch64*android*|armeabi-v7a:arm*android*|x86_64:x86_64*android*|x86:i?86*android*) ;;
    *) echo "Compiler target $target does not match Android ABI $abi" >&2; exit 2 ;;
esac
src=app/src/main/cpp
out=app/src/main/jniLibs/$abi
mkdir -p "$out"
common=(-shared -fPIC -O2 -DANDROID -D_LITTLE_ENDIAN -DNO_DEBUG -Wl,-z,max-page-size=16384 -Wl,-s)
"$cc" "${common[@]}" -Wl,-soname,libzdtun.so -o "$out/libzdtun.so" "$src/zdtun/zdtun.c" "$src/zdtun/utils.c" -llog
"$cc" "${common[@]}" -Wl,-soname,libnetstatvpn.so -o "$out/libnetstatvpn.so" "$src/vpn_bridge.c" -L"$out" -lzdtun
