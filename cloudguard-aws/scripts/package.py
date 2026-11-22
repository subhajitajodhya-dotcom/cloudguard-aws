"""Build build/lambda.zip (app code + PyJWT for Linux). Works on Windows, Mac and Linux.

    python scripts/package.py
"""
import pathlib
import shutil
import subprocess
import sys
import zipfile

ROOT = pathlib.Path(__file__).resolve().parent.parent
BUILD = ROOT / "build"
PKG = BUILD / "package"


def main() -> None:
    shutil.rmtree(BUILD, ignore_errors=True)
    PKG.mkdir(parents=True)
    # Download Linux builds of the libraries, even when you run this on Windows.
    subprocess.run(  # noqa: S603 - fixed arguments, no user input
        [sys.executable, "-m", "pip", "install", "-r", str(ROOT / "requirements-lambda.txt"),
         "--target", str(PKG), "--platform", "manylinux2014_x86_64", "--implementation", "cp",
         "--python-version", "3.12", "--only-binary=:all:", "--upgrade", "--quiet"],
        check=True,
    )
    out = BUILD / "lambda.zip"
    with zipfile.ZipFile(out, "w", zipfile.ZIP_DEFLATED) as z:
        for f in PKG.rglob("*"):
            if f.is_file() and "__pycache__" not in f.parts:
                z.write(f, f.relative_to(PKG))
        for f in (ROOT / "app").rglob("*.py"):
            if "tests" not in f.parts and "__pycache__" not in f.parts:
                z.write(f, f.relative_to(ROOT))
    print(f"Built {out} ({out.stat().st_size / 1_000_000:.1f} MB)")


if __name__ == "__main__":
    main()
