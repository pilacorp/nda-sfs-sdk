// swift-tools-version: 6.2
// The swift-tools-version declares the minimum version of Swift required to build this package.

import PackageDescription

let package = Package(
    name: "did-encryption-swift",
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
            ]
        ),
        .testTarget(
            name: "DIDEncryptTests",
            dependencies: [
                "DIDEncrypt",
                .product(name: "Testing", package: "swift-testing"),
            ]
        ),
    ]
)
