#!/usr/bin/env bash
# Builds dist/EML-Reader-<version>-x86_64.AppImage and its .sha256 file.
#
# The binary links only against glibc; OpenGL, X11/Wayland and xkbcommon are
# loaded at runtime from the host system, as with any desktop application.
#
# Requirements: Rust toolchain (cargo), curl (only if appimagetool is not cached).
# Optional: cargo-zigbuild + zig to build for an older glibc (ZIGBUILD=1, GLIBC=2.31), as in CI.
# Usage:  packaging/build-appimage.sh      (APPIMAGETOOL=/path/to/tool to skip the download)
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
DIST="$ROOT/dist"
WORK="$ROOT/target/appimage"
APPDIR="$WORK/AppDir"
VERSION="$(sed -n 's/^version = "\(.*\)"/\1/p' "$ROOT/Cargo.toml" | head -1)"
CARGO="${CARGO:-$(command -v cargo || echo "$HOME/.cargo/bin/cargo")}"

echo "==> EML Reader $VERSION"
if [ "${ZIGBUILD:-0}" = "1" ]; then
    GLIBC="${GLIBC:-2.31}"
    "$CARGO" zigbuild --release --target "x86_64-unknown-linux-gnu.$GLIBC" --manifest-path "$ROOT/Cargo.toml"
    BIN="$ROOT/target/x86_64-unknown-linux-gnu/release/eml-reader"
else
    "$CARGO" build --release --manifest-path "$ROOT/Cargo.toml"
    BIN="$ROOT/target/release/eml-reader"
fi

rm -rf "$APPDIR"
mkdir -p "$APPDIR/usr/bin" "$APPDIR/usr/share/applications" \
         "$APPDIR/usr/share/icons/hicolor/256x256/apps" "$APPDIR/usr/share/icons/hicolor/scalable/apps" "$DIST"
install -m 755 "$BIN" "$APPDIR/usr/bin/"
install -m 755 "$ROOT/packaging/AppRun" "$APPDIR/AppRun"
cp "$ROOT/packaging/eml-reader.desktop" "$APPDIR/"
cp "$ROOT/packaging/eml-reader.desktop" "$APPDIR/usr/share/applications/"
cp "$ROOT/packaging/eml-reader.png" "$APPDIR/"
cp "$ROOT/packaging/eml-reader.png" "$APPDIR/usr/share/icons/hicolor/256x256/apps/"
cp "$ROOT/packaging/eml-reader.svg" "$APPDIR/usr/share/icons/hicolor/scalable/apps/"
ln -sf eml-reader.png "$APPDIR/.DirIcon"

TOOL="${APPIMAGETOOL:-$WORK/appimagetool-x86_64.AppImage}"
if [ ! -x "$TOOL" ]; then
    echo "==> Downloading appimagetool"
    curl -fsSL -o "$TOOL" \
        https://github.com/AppImage/appimagetool/releases/download/continuous/appimagetool-x86_64.AppImage
    chmod +x "$TOOL"
fi

OUT="$DIST/EML-Reader-$VERSION-x86_64.AppImage"
# Build next to the target and rename, so a running copy does not block the build.
ARCH=x86_64 APPIMAGE_EXTRACT_AND_RUN=1 "$TOOL" --no-appstream "$APPDIR" "$OUT.new"
chmod +x "$OUT.new"
mv -f "$OUT.new" "$OUT"
# Checksum for the built-in updater (uploaded with the AppImage as a release asset).
(cd "$DIST" && sha256sum "$(basename "$OUT")" > "$(basename "$OUT").sha256")
echo "==> Done: $OUT"
