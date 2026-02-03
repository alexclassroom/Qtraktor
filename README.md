# Traktor

Cross-platform desktop application for extracting WordPress `.wpress` backup files created by [All-in-One WP Migration](https://wordpress.org/plugins/all-in-one-wp-migration/). Built with C++11 and Qt Widgets.

Supports plain, compressed (zlib/bzip2), and encrypted (AES-256-CBC) archives.

## Prerequisites

### macOS

```bash
brew install qt@5 openssl pkg-config
export PATH="/opt/homebrew/opt/qt@5/bin:$PATH"
```

### Linux (Debian/Ubuntu)

```bash
sudo apt install qt5-qmake qtbase5-dev libssl-dev zlib1g-dev pkg-config
```

### Windows (MSVC)

- Qt 5.x or 6.x with MSVC kit
- OpenSSL (install via `choco install openssl` or download from [slproweb.com](https://slproweb.com/products/Win32OpenSSL.html))
- Set environment variable: `OPENSSL_DIR=C:\Program Files\OpenSSL-Win64`

### Windows (MinGW)

- Qt 5.x or 6.x with MinGW kit
- OpenSSL for MinGW
- Set environment variable: `OPENSSL_DIR=C:\path\to\openssl`

## Build

```bash
qmake Qtraktor.pro
make -j$(nproc)        # Linux
make -j$(sysctl -n hw.ncpu)  # macOS
```

On Windows with MSVC:

```powershell
qmake.exe Qtraktor.pro
jom -f Makefile.Release
# or: nmake -f Makefile.Release
```

On Windows with MinGW:

```powershell
qmake.exe Qtraktor.pro
mingw32-make
```

## Run

- **macOS**: `open Traktor.app`
- **Linux**: `./Traktor`
- **Windows**: `release\Traktor.exe`

## Clean Rebuild

```bash
make clean && qmake Qtraktor.pro && make -j$(nproc)
```

## Creating Installers

Requires [Qt Installer Framework](https://doc.qt.io/qtinstallerframework/).

### macOS

```bash
macdeployqt Traktor.app
mkdir -p packages/com.servmask.traktor/data
cp -r Traktor.app packages/com.servmask.traktor/data
binarycreator -c config/config.xml -p packages Traktor
```

### Windows

```powershell
windeployqt release\Traktor.exe
mkdir packages\com.servmask.traktor\data
Copy-Item release\* -Destination packages\com.servmask.traktor\data -Recurse
binarycreator.exe -c config\config.xml -p packages Traktor.exe
```

## Project Structure

```
Qtraktor.pro          # qmake project file
main.cpp              # Entry point
mainwindow.h/cpp/ui   # Main application window (open, validate, extract)
backupfile.h/cpp       # .wpress file format parser and extractor
cryptoutils.h/cpp      # Decompression (zlib, bzip2) and AES decryption
passworddialog.h/cpp   # Password prompt for encrypted archives
vendor/bzip2-1.0.8/    # Vendored bzip2 library (built as part of the project)
config/                # Qt Installer Framework config
packages/              # Qt Installer Framework package metadata
icons/                 # Application icons (.ico, .icns)
```

## License

GPLv3 - see [LICENSE](LICENSE).
