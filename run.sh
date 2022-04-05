#!/bin/sh

set -e

PATH_TO_SWAN_BIN="/Users/tiganov/Documents/research/swan/lib"

ROOT_DIR=$(pwd)

# SYNTHETIC TEST PROJECT
echo "📁 Running CryptoSwiftTests..."
cd CryptoSwiftTests
echo "ℹ️ Running swan-xcodebuild"
"$PATH_TO_SWAN_BIN"/swan-xcodebuild -- -project CryptoSwiftTests.xcodeproj -scheme CryptoSwiftTests
echo "ℹ️ Replacing SIL"
cp "$ROOT_DIR/replace/CryptoSwift.CryptoSwift.sil" swan-dir/
echo "ℹ️ Running SWAN"
java -jar "$PATH_TO_SWAN_BIN"/driver.jar --crypto swan-dir/
echo "ℹ️ Checking violations against annotations"
java -jar "$PATH_TO_SWAN_BIN"/annotation.jar swan-dir/
echo "  SUCCESS ✅"
echo ""

# REAL APPS
cd "$ROOT_DIR/apps"

echo "📁 Running RxCommonKit..."
cd RxCommonKit/Example
pod install
echo "ℹ️ Running swan-xcodebuild"
swan-xcodebuild -- -workspace RxCommonKit.xcworkspace/ -scheme "RxCommonKit"
echo "ℹ️ Replacing SIL"
cp "$ROOT_DIR/replace/CryptoSwift.CryptoSwift.sil" swan-dir/
echo "ℹ️ Removing unncessary SIL"
cd swan-dir
rm Alamofire* BFKit* GRDB* Handy* Moya* Result* RxCocoa* RxRelay* RxSwift* Star* SwiftDate*
cd ..
echo "ℹ️ Running SWAN"
java -jar "$PATH_TO_SWAN_BIN"/driver.jar --crypto swan-dir/ --module .*RxCommonKit.*
echo "ℹ️ Injecting annotations"
cp "$ROOT_DIR/replace/RxCryptoKit.swift" "$ROOT_DIR/apps/RxCommonKit/RxCommonKit/Classes/RxTools/RxCryptoKit.swift"
echo "ℹ️ Checking violations against annotations"
java -jar "$PATH_TO_SWAN_BIN"/annotation.jar swan-dir/ --src-dir "$ROOT_DIR/apps/RxCommonKit/RxCommonKit/Classes/RxTools/"
echo "  SUCCESS ✅"
echo ""

cd "$ROOT_DIR"

echo " ALL TESTS PASSED! ✅🟢✅"