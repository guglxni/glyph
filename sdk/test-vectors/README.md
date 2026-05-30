# GLYPH Cross-Language Canonicalization Test Vectors

These vectors pin the byte-level behavior of `glyph_common::canonical_signing_payload`,
`canonical_target_instruction_bytes`, and `canonical_serialize_policy` so that the
Rust SDK, the TEE worker, and the TypeScript SDK all produce identical bytes for
identical inputs.

Layout:

```
intents/
  1.input.json            human-authored CanonicalIntent
  1.canonical.bytes       hex-encoded output of canonical_signing_payload(...)
  1.signed.json           {"sha256": "..."} of the canonical bytes
policies/
  1.input.json            human-authored Policy
  1.canonical.bytes       hex-encoded output of canonical_serialize_policy(...)
  1.signed.json           {"sha256": "..."} of the canonical bytes
```

The `*.bytes` and `*.signed.json` files are produced by
`scripts/gen-test-vectors.sh`. The `*.input.json` files are authored by hand and
checked in. The `gen-test-vectors.sh` script and the integration test
`common/tests/canonical_test.rs` are the contracts: any change in canonical
encoding must be a deliberate version bump that updates both the inputs and the
generated outputs.
