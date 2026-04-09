# Swift Tag Demo

Tiny SwiftPM app to exercise the `DIDEncrypt` SDK from this monorepo.

## Run remote

This demo consumes the SDK from the remote GitHub repo, pinned to the commit
behind the `did-encryption-swift/test0.1` tag.

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

SwiftPM cannot consume `did-encryption-swift/test0.1` as a version tag. For
remote package resolution you should either:

- pin a commit revision, as this demo does, or
- publish a repo-root semver tag like `v0.1.0` / `v1.0.0`.
