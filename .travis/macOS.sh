#!/bin/bash

set -eu -o pipefail

brew update > /dev/null

brew install qt5 openssl pkg-config

brew tap yani-/homebrew-qtifw
brew install qt-ifw

export PATH="$(brew --prefix qt5)/bin:$(brew --prefix qt-ifw)/bin:$PATH"
export PKG_CONFIG_PATH="$(brew --prefix openssl)/lib/pkgconfig:${PKG_CONFIG_PATH:-}"
export LDFLAGS="-L$(brew --prefix qt5)/lib"
export CPPFLAGS="-I$(brew --prefix qt5)/include"

cd $TRAVIS_BUILD_DIR

qmake Qtraktor.pro
make -j$(sysctl -n hw.ncpu)

# add dependencies
macdeployqt Traktor.app

mkdir packages/com.servmask.traktor/data

cp -r Traktor.app packages/com.servmask.traktor/data

sed -i '' s/develop/$(git describe)/ config/config.xml
sed -i '' s/develop/$(git describe)/ packages/com.servmask.traktor/meta/package.xml
sed -i '' s/release-date/$(date "+%Y-%m-%d")/ packages/com.servmask.traktor/meta/package.xml

binarycreator -c config/config.xml -p packages Traktor
