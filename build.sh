#!/usr/bin/env bash
#
# build.sh — 编译微信防撤回 dylib
#
# 刻意不使用 Theos：Theos 的 tweak 模板默认会链接 libsubstrate，
# 而非越狱设备上并没有 substrate，加载时就会直接崩。
# 这里只用 Xcode 自带的 clang 交叉编译，产出一个零外部依赖的 dylib。
#
# 用法：
#   ./build.sh                 # 默认 arm64
#   ARCHS="arm64 arm64e" ./build.sh
#   MIN_IOS=15.0 ./build.sh
#
set -euo pipefail

SRC_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
SRC="$SRC_DIR/tweak/AntiRevoke.m"
OUT_DIR="${OUT_DIR:-$SRC_DIR/build}"
NAME="${NAME:-wxantirevoke}"
MIN_IOS="${MIN_IOS:-15.0}"
ARCHS="${ARCHS:-arm64}"

command -v xcrun >/dev/null 2>&1 || {
  echo "错误：找不到 xcrun，这个脚本必须在 macOS 上运行。" >&2
  exit 1
}

SDK="$(xcrun --sdk iphoneos --show-sdk-path)"
echo "==> iOS SDK : $SDK"
echo "==> 架构    : $ARCHS"
echo "==> 最低版本: iOS $MIN_IOS"

mkdir -p "$OUT_DIR"

COMMON_FLAGS=(
  -isysroot "$SDK"
  -miphoneos-version-min="$MIN_IOS"
  -fobjc-arc
  -fmodules
  -O2
  -Wall
  -Wno-unused-function
  -Wno-deprecated-declarations
)

SLICES=()
for ARCH in $ARCHS; do
  echo "==> 编译 $ARCH"
  OUT_SLICE="$OUT_DIR/${NAME}-${ARCH}.dylib"
  # 显式给出 target 三元组：只给 -arch 时，clang 有时会推断成 macOS 目标
  xcrun -sdk iphoneos clang \
    -target "${ARCH}-apple-ios${MIN_IOS}" \
    "${COMMON_FLAGS[@]}" \
    -dynamiclib \
    -install_name "@executable_path/${NAME}.dylib" \
    -framework Foundation \
    -framework UIKit \
    -o "$OUT_SLICE" \
    "$SRC"
  SLICES+=("$OUT_SLICE")
done

FINAL="$OUT_DIR/${NAME}.dylib"
if [ "${#SLICES[@]}" -eq 1 ]; then
  cp "${SLICES[0]}" "$FINAL"
else
  xcrun lipo -create -output "$FINAL" "${SLICES[@]}"
fi

echo
echo "==> 产物: $FINAL"
xcrun lipo -info "$FINAL"
ls -lh "$FINAL"

echo
echo "==> 依赖检查（应当只有系统框架，没有 substrate）"
otool -L "$FINAL" || true

echo
if command -v shasum >/dev/null 2>&1; then
  echo "==> SHA256: $(shasum -a 256 "$FINAL" | awk '{print $1}')"
fi

echo
echo "完成。用轻松签把 $FINAL 注入微信 IPA 即可。"
