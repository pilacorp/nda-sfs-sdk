// swift-tools-version: 6.2

import PackageDescription

let package = Package(
    name: "swift-tag-demo",
    platforms: [
        .macOS(.v12),
    ],
    dependencies: [
        .package(url: "https://github.com/pilacorp/nda-sfs-sdk.git", revision: "68409381cbb5f258e6b58dae88126f5356be1cc7"),
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
