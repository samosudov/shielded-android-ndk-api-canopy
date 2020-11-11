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
In the file rust-lib/src/main/zapling-lib/src/lib.rs
line 1140 - constant HRP_SAPLING_EXTENDED_SPENDING_KEY_TEST expected
line 1269 - constant HRP_SAPLING_PAYMENT_ADDRESS_TEST expected