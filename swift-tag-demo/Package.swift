// swift-tools-version: 6.2

import PackageDescription

let package = Package(
    name: "swift-tag-demo",
    platforms: [
        .macOS(.v12),
    ],
    dependencies: [
        .package(url: "https://github.com/pilacorp/nda-sfs-sdk.git", revision: "917b5ac82e0094562750611945d580cded346734"),
    ],
    targets: [
        .executableTarget(
            name: "swift-tag-demo",
            dependencies: [
                .product(name: "DIDEncrypt", package: "nda-sfs-sdk"),
            ]
        ),
    ]
)
