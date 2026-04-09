# NDA Secure File System

This repository is a monorepo for multiple SDKs and applications.

## Release Tags

Use one root tag for the Swift package and subdirectory-prefixed tags for the
Go packages and app modules:

- `v1.0.0` for the Swift root package
- `did-auth/v1.0.0` for the `did-auth` module
- `did-encryption/v1.0.0` for the `did-encryption` module
- `file-application/v1.0.0` for the file application

## Swift Consumption

The Swift SDK is exposed from the repository root `Package.swift`, so client
projects can consume it directly from the git tag:

```swift
.package(url: "https://github.com/pilacorp/nda-sfs-sdk.git", from: "1.0.0")
```

Then depend on:

```swift
.product(name: "DIDEncrypt", package: "nda-sfs-sdk")
```
