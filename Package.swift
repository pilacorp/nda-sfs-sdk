// swift-tools-version: 6.2

import PackageDescription

let package = Package(
    name: "nda-sfs-sdk",
    platforms: [
        .iOS(.v13),
        .macOS(.v12),
    ],
    products: [
        .library(name: "DIDEncrypt", targets: ["DIDEncrypt"]),
    ],
    dependencies: [
        .package(url: "https://github.com/attaswift/BigInt.git", from: "5.4.0"),
        .package(url: "https://github.com/krzyzanowskim/CryptoSwift.git", from: "1.8.0"),
        .package(url: "https://github.com/GigaBitcoin/secp256k1.swift.git", from: "0.23.0"),
        .package(url: "https://github.com/swiftlang/swift-testing.git", revision: "c9d57c8"),
    ],
    targets: [
        .target(
            name: "DIDEncrypt",
            dependencies: [
                .product(name: "BigInt", package: "BigInt"),
                .product(name: "CryptoSwift", package: "CryptoSwift"),
                .product(name: "libsecp256k1", package: "secp256k1.swift"),
            ],
            path: "did-encryption-swift/Sources/DIDEncrypt"
        ),
        .testTarget(
            name: "DIDEncryptTests",
            dependencies: [
                "DIDEncrypt",
                .product(name: "Testing", package: "swift-testing"),
            ],
            path: "did-encryption-swift/Tests/DIDEncryptTests"
        ),
    ]
)
