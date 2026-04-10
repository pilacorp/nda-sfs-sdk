# Swift Tag Demo

Tiny SwiftPM app to exercise the `DIDEncrypt` SDK from this monorepo.

## Run remote

This demo consumes the SDK from the remote GitHub repo using the commit behind
the `did-encryption-swift/v1.0.0` release tag.

```bash
cd swift-tag-demo
swift run
```

## What it tests

- Generates Alice/Bob keys
- Encrypts a small payload
- Creates a re-capsule
- Decrypts with Bob's private key

## Note on tags

SwiftPM can fetch the remote SDK by commit revision immediately. To use a
versioned release instead, you still need a root semver tag like `v1.0.0`.
