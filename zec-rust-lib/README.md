# Separate library with all cpp and Rust code of Z-address transaction building

## How to install
You may need to install Boost(c++) library.

MacOS:
- brew install boost
- check if path to boost is valid in `rust-lib/src/main/CMakeLists.txt`
- check version of boost in `CMakeLists.txt:26`

To build .aar file of the library:
./gradlew assembleRelease

Build for testnet will need next changes:
In the file rust-lib/src/main/zec-rust-lib/src/lib.rs
line 1140 - constant HRP_SAPLING_EXTENDED_SPENDING_KEY_TEST expected
line 1269 - constant HRP_SAPLING_PAYMENT_ADDRESS_TEST expected

Build:
./gradlew clean assembleRelease

Add generated .aar file as module.
rust-lib/build/outputs/aar/rust-lib-release.aar

Using ZecLibRustApi methods:
ZecLibRustApi must be initialized by method
ZecLibRustApi.init(getApplicationContext());

Issues:
1.

> Task :zec-rust-lib:externalNativeBuildCleanDebug FAILED
Clean native-lib-canopy armeabi-v7a
ninja: Entering directory `/Users/samosudovd/StudioProjects/shielded-android-ndk-api-copy/zec-rust-lib/.cxx/cmake/debug/armeabi-v7a'
ninja: fatal: chdir to '/Users/samosudovd/StudioProjects/shielded-android-ndk-api-copy/zec-rust-lib/.cxx/cmake/debug/armeabi-v7a' - No such file or directory

FAILURE: Build failed with an exception.

Remove shielded-android-ndk-api-canopy/zec-rust-lib/.cxx folder

2. To prevent java.lang.UnsatisfiedLinkError:
Keep at least one call Rust's method from C++ code
(file src/main/cpp/main.cpp and header file src/main/include/zec_rust_lib.h)


