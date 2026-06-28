from pathlib import Path
import json
import shutil
import subprocess
from PIL import Image


ROOT = Path(__file__).resolve().parents[1]
SOURCE = ROOT / "assets" / "app-icon-source.png"
PACK = ROOT / "outputs" / "app-icon-pack"


def square_source() -> Image.Image:
    img = Image.open(SOURCE).convert("RGBA")
    width, height = img.size
    side = min(width, height)
    left = (width - side) // 2
    top = (height - side) // 2
    return img.crop((left, top, left + side, top + side))


def save_png(base: Image.Image, path: Path, size: int) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    base.resize((size, size), Image.Resampling.LANCZOS).save(path, "PNG", optimize=True)


def build_pack() -> None:
    base = square_source()

    save_png(base, PACK / "master" / "icon-1024.png", 1024)
    save_png(base, PACK / "master" / "icon-512.png", 512)

    android_sizes = {
        "mipmap-mdpi": 48,
        "mipmap-hdpi": 72,
        "mipmap-xhdpi": 96,
        "mipmap-xxhdpi": 144,
        "mipmap-xxxhdpi": 192,
    }
    for folder, size in android_sizes.items():
        save_png(base, PACK / "android" / "res" / folder / "ic_launcher.png", size)
        save_png(base, PACK / "android" / "res" / folder / "ic_launcher_round.png", size)
    save_png(base, PACK / "android" / "play-store-icon.png", 512)

    ico_sizes = [16, 24, 32, 48, 64, 128, 256]
    windows_dir = PACK / "windows"
    windows_dir.mkdir(parents=True, exist_ok=True)
    ico_images = [base.resize((size, size), Image.Resampling.LANCZOS) for size in ico_sizes]
    ico_images[-1].save(windows_dir / "app_icon.ico", sizes=[(size, size) for size in ico_sizes])
    for size in ico_sizes:
        save_png(base, windows_dir / f"app_icon_{size}.png", size)

    for size in [16, 32, 48, 180, 192, 256, 512]:
        save_png(base, PACK / "web" / f"icon-{size}.png", size)
    shutil.copyfile(windows_dir / "app_icon.ico", PACK / "web" / "favicon.ico")
    (PACK / "web" / "manifest-icons.json").write_text(
        json.dumps(
            {
                "icons": [
                    {"src": "icon-192.png", "sizes": "192x192", "type": "image/png"},
                    {"src": "icon-512.png", "sizes": "512x512", "type": "image/png"},
                ]
            },
            indent=2,
        ),
        encoding="utf-8",
    )

    ios_dir = PACK / "ios" / "AppIcon.appiconset"
    ios_specs = [
        ("Icon-App-20x20@2x.png", 40, "20x20", "2x", "iphone"),
        ("Icon-App-20x20@3x.png", 60, "20x20", "3x", "iphone"),
        ("Icon-App-29x29@2x.png", 58, "29x29", "2x", "iphone"),
        ("Icon-App-29x29@3x.png", 87, "29x29", "3x", "iphone"),
        ("Icon-App-40x40@2x.png", 80, "40x40", "2x", "iphone"),
        ("Icon-App-40x40@3x.png", 120, "40x40", "3x", "iphone"),
        ("Icon-App-60x60@2x.png", 120, "60x60", "2x", "iphone"),
        ("Icon-App-60x60@3x.png", 180, "60x60", "3x", "iphone"),
        ("Icon-App-76x76@1x.png", 76, "76x76", "1x", "ipad"),
        ("Icon-App-76x76@2x.png", 152, "76x76", "2x", "ipad"),
        ("Icon-App-83.5x83.5@2x.png", 167, "83.5x83.5", "2x", "ipad"),
        ("Icon-App-1024x1024@1x.png", 1024, "1024x1024", "1x", "ios-marketing"),
    ]
    images = []
    for filename, pixels, point_size, scale, idiom in ios_specs:
        save_png(base, ios_dir / filename, pixels)
        images.append({"filename": filename, "idiom": idiom, "scale": scale, "size": point_size})
    (ios_dir / "Contents.json").write_text(
        json.dumps({"images": images, "info": {"author": "xcode", "version": 1}}, indent=2),
        encoding="utf-8",
    )

    mac_dir = PACK / "macos" / "AppIcon.iconset"
    for filename, size in [
        ("icon_16x16.png", 16),
        ("icon_16x16@2x.png", 32),
        ("icon_32x32.png", 32),
        ("icon_32x32@2x.png", 64),
        ("icon_128x128.png", 128),
        ("icon_128x128@2x.png", 256),
        ("icon_256x256.png", 256),
        ("icon_256x256@2x.png", 512),
        ("icon_512x512.png", 512),
        ("icon_512x512@2x.png", 1024),
    ]:
        save_png(base, mac_dir / filename, size)


def copy_tree_contents(source: Path, destination: Path) -> None:
    if not destination.exists():
        return
    for item in source.rglob("*"):
        if item.is_file():
            target = destination / item.relative_to(source)
            target.parent.mkdir(parents=True, exist_ok=True)
            shutil.copyfile(item, target)


def sync_existing_platforms() -> None:
    copy_tree_contents(PACK / "android" / "res", ROOT / "android" / "app" / "src" / "main" / "res")
    android_logo = ROOT / "android" / "app" / "src" / "main" / "res" / "drawable-nodpi" / "whitedns_logo.png"
    if android_logo.parent.exists():
        shutil.copyfile(PACK / "master" / "icon-512.png", android_logo)

    copy_tree_contents(PACK / "ios" / "AppIcon.appiconset", ROOT / "ios" / "Runner" / "Assets.xcassets" / "AppIcon.appiconset")
    copy_tree_contents(PACK / "macos" / "AppIcon.iconset", ROOT / "macos" / "Runner" / "Assets.xcassets" / "AppIcon.appiconset")

    windows_icon_targets = [
        ROOT / "windows" / "runner" / "resources" / "app_icon.ico",
        ROOT / "src-tauri" / "icons" / "icon.ico",
        ROOT / "build" / "icon.ico",
        ROOT / "cmd" / "whitedns" / "winres" / "app_icon.ico",
    ]
    for target in windows_icon_targets:
        if target.parent.exists():
            shutil.copyfile(PACK / "windows" / "app_icon.ico", target)

    winres_png = ROOT / "cmd" / "whitedns" / "winres" / "whitedns-icon-256.png"
    if winres_png.parent.exists():
        shutil.copyfile(PACK / "windows" / "app_icon_256.png", winres_png)

    web_targets = [
        (PACK / "web" / "favicon.ico", ROOT / "web" / "favicon.ico"),
        (PACK / "web" / "icon-192.png", ROOT / "web" / "icons" / "Icon-192.png"),
        (PACK / "web" / "icon-512.png", ROOT / "web" / "icons" / "Icon-512.png"),
        (PACK / "web" / "icon-192.png", ROOT / "public" / "icon-192.png"),
        (PACK / "web" / "icon-512.png", ROOT / "public" / "icon-512.png"),
        (PACK / "web" / "favicon.ico", ROOT / "public" / "favicon.ico"),
    ]
    for source, target in web_targets:
        if target.parent.exists():
            shutil.copyfile(source, target)


def maybe_convert_macos_icns() -> None:
    iconset = ROOT / "macos" / "Runner" / "Assets.xcassets" / "AppIcon.appiconset"
    if not iconset.exists():
        return
    if shutil.which("iconutil"):
        subprocess.run(["iconutil", "-c", "icns", str(PACK / "macos" / "AppIcon.iconset")], check=False)


def main() -> None:
    if not SOURCE.exists():
        raise SystemExit(f"Missing source icon: {SOURCE}")
    build_pack()
    sync_existing_platforms()
    maybe_convert_macos_icns()
    print(f"Icon assets generated from {SOURCE}")


if __name__ == "__main__":
    main()
