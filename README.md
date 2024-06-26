# cesride

[![cesride](https://github.com/WebOfTrust/cesride/actions/workflows/test.yml/badge.svg)](https://github.com/WebOfTrust/cesride/actions/workflows/test.yml)
[![codecov](https://codecov.io/gh/WebOfTrust/cesride/branch/main/graph/badge.svg?token=L8K7H1XXQS)](https://codecov.io/gh/WebOfTrust/cesride)

Cryptographic primitives for use with Composable Event Streaming Representation (CESR).

This library is **currently under construction**. If you want to help build, see [contributing](#contributing) below.

## Important Reference Material
- trustoverip/[tswg-cesr-specification](https://github.com/trustoverip/tswg-cesr-specification) repository - [ToIP draft specification](https://trustoverip.github.io/tswg-cesr-specification/) for CESR
- Design Assumptions, Use Cases, and ToDo list - [HackMD link](https://hackmd.io/W2Z39cuSSTmD2TovVLvAPg?view)
- Introductory articles:
    - [#1 CESR Proof Signatures](https://medium.com/happy-blockchains/cesr-proof-signatures-are-the-segwit-of-authentic-data-in-keri-e891c83e070a)
    - [#2 CESR Overview](https://medium.com/happy-blockchains/cesr-one-of-sam-smiths-inventions-is-as-controversial-as-genius-d757f36b88f8)

## Contributing

If you want to contribute, check out the [issues](https://github.com/WebOfTrust/cesride/issues).
Tags provide some guidance.

When starting a new issue, ensure there are no others working on the same thing to avoid duplicated
effort (although alternative implementations are always welcome and considered):
- check that there is no open pull request
- make sure no one has assigned themselves
- look for comments on the issue
- look for development integrations ('linked an issue that may be closed by this pull request')

When you find an issue you want to take on:
- make yourself an assignee, if possible
- open a [Pull Request](https://docs.github.com/en/pull-requests/collaborating-with-pull-requests/proposing-changes-to-your-work-with-pull-requests/about-pull-requests) against a branch you created against your fork - even if empty
- paste a link to the PR in a comment on the issue you are working on for visibility

For better coordination, join the `#cesr-dev` slack channel using the link at the bottom of
this document.

## Development

Install dependencies:
```shell
cargo install cargo-audit
cargo install cargo-tarpaulin
```

Change some code and then fix it automatically:
```shell
make fix
```

Commit your changes locally, and run these automated tests:
```shell
make clean preflight
```

You are now ready to open a pull request!

## Terminology

`cesride` is built from cryptographic primitives that are named clearly and concisely. That said,
those unfamiliar with the naming strategy but familiar with cryptography may find themselves a bit
lost when first working with `cesride`. Implementation was ported from [KERIpy](https://github.com/WebOfTrust/keripy)
and terminology was carried along with the code. The basics:

- `Diger` - a primitive that represents a **digest**. It has the ability to verify that an input hashes to its raw value.
- `Verfer` - a primitive that represents a **public key**. It has the ability to verify signatures on data.
- `Signer` - a primitive that represents a **private key**. It has the ability to create `Sigers` and `Cigars` (signatures).
- `Siger` - an **_indexed_ signature**. This is used within KERI when there are multiple current keys associated with an identifier.
- `Cigar` - an **_unindexed_ signature**.
- `Salter` - a primitive that represents a **seed**. It has the ability to generate new `Signers`.
 
Each primitive will have methods attached to it that permit one to generate and parse the qualified
base2 or base64 representation. Common methods you'll find:

- `.qb64()` - qualified base-64 representation of cryptographic material as a string
- `.qb64b()` - qualified base-64 representation of cryptographic material as octets (bytes)
- `.qb2()` - qualified base-2 representation of cryptographic material as octets (bytes)
- `.code()` - qualifying code (describes the type of cryptographic material)
- `.raw()` - raw cryptographic material (unqualified) as octets (bytes)

### Qualification

Q: What do you mean, qualified cryptographic material?

A: There are [tables of codes](https://github.com/WebOfTrust/cesride/blob/main/src/core/matter/tables.rs#L92)
similar to a [TLV](https://en.wikipedia.org/wiki/Type%E2%80%93length%E2%80%93value) table but omitting
the length field for almost all cases (as the primitives are fixed in size). The type or _code_, in
CESR vernacular, conveys enough information to allow the application to parse data with qualified
cryptographic material embedded in it.

Here is what we mean:

`DKxy2sgzfplyr-tgwIxS19f2OchFHtLwPWD3v4oYimBx` - this is prefixed with a `D`. If we look that code
up in the table linked in the answer above, we find this is a transferable (rotatable) Ed25519
public key.

`ELEjyRTtmfyp4VpTBTkv_b6KONMS1V8-EW-aGJ5P_QMo` - this is prefixed with an `E`. Again, consulting the
table, we learn this is a Blake3 256 digest.

Each primitive can be represented in Base64 or binary, and can be processed from either format.

### Examples

```rust
use cesride::{common::Tierage, Salter};
// in this example we sign some data and ensure the signature verifies

let authentic = b"abcdefg";
let forgery = b"abcdefgh";
let mut sigers: Vec<Siger> = vec![];

// delay creating sensitive material until the last moment so it is resident in memory for shorter
let salter = Salter::new_with_defaults(Some(Tierage::med))?;

// generate a set of 3 signing keys. the fourth argument here is the code, and when we specify
// none we'll be given an Ed25519 key. the path here (third argument) will be input during key
// stretching so that the same seed can be used for a number of keys with differing paths
let signers = salter.signers(Some(3), None, Some("my-key"), None, None, None, None)?;

// sign some data
for i in 0..signers.len() {
    sigers.push(signers[i].sign_indexed(authentic, false, i as u32, None)?);
}

// verify the signatures
for i in 0..signers.len() {
    // check that verification works if the data and signature match
    assert!(signers[i].verfer().verify(&sigers[i].raw(), authentic)?);
    // verification fails if the data (or signature) does not match
    assert!(!signers[i].verfer().verify(&sigers[i].raw(), forgery)?);
}
```

```rust
use cesride::{Signer, Indexer, Matter};
// here we verify that a cigar primitive and a siger primitive have the same underlying
// cryptographic material

let data = b"abcdefg";

// defaults to Ed25519
let signer = Signer::new_with_defaults(None, None)?;

// create our signatures
let cigar = signer.sign_unindexed(data)?;
let siger = signer.sign_indexed(data, false, 0, None)?;

// compare the raw signatures
assert_eq!(cigar.raw(), siger.raw());
```

```rust
use cesride::{Diger, Matter, matter};
// here we simply print a qualified digest in base64 to stdout after hashing serialized data
// hash digests underpin core concepts of the KERI ecosystem

let data = b"abcdefg";

// derive the digest, opting this time to specify the algorithm
let diger = Diger::new_with_ser(data, Some(matter::Codex::SHA3_512))?;

// output the digest
println!("Blake3 256 digest: #{d}", d=diger.qb64()?);
```

For more implementation details at this time, see [KERIpy](https://github.com/WebOfTrust/keripy).

### Entropy

We use two `OsRng` implementations to obtain our random data. Our private keys are
sometimes generated from stock methods in the underlying libraries, which is why we currently
include both implementations (the two signing modules depend on traits that are incompatible).

When using `Salter`, one can produce many deterministic and reproducible results (such as keys) from
the same seed material, or use random seed material. In the latter case, we use the more recent of 
the `OsRng` implementations directly to fill buffers.

### External Dependencies (crates)

#### Key Stretching

- Argon2 ([argon2](https://docs.rs/argon2)) - `Salter` uses argon2id to stretch seeds into keying
material. These are our security tiers and param choices, which maintain compatiblity with the
reference python implementation ([KERIpy](https://github.com/WebOfTrust/keripy)):
    - `min`: unavailable outside the `cesride` context except when passing the `temp` param directly
    to `stretch()` to perform manual stretching. **NEVER** use this security tier in production.
    argon2id params:
        - m: 8
        - t: 1
        - p: 1
    - `low`: the default tier, suitable for low-risk online interactions
        - m: 65536
        - t: 2
        - p: 1
    - `med`: suitable for high-risk online interactions
        - m: 262144
        - t: 3
        - p: 1
    - `high`: resitant to offline attacks (use this for backups)
        - m: 1048576
        - t: 4
        - p: 1

We use 16 bytes of entropy from `OsRng` in `rand_core` to seed argon2. For more details on selecting
appropriate argon2 parameters, consult [this document](https://argon2-cffi.readthedocs.io/en/stable/parameters.html).

#### Hashing

`cesride` supports the following hash algorithms:
- Blake3 256 ([blake3](https://docs.rs/blake3))
- Blake3 512 ([blake3](https://docs.rs/blake3))
- Blake2b 256 ([blake2](https://docs.rs/blake2))
- Blake2b 512 ([blake2](https://docs.rs/blake2))
- Blake2s 256 ([blake2](https://docs.rs/blake2))
- SHA3 256 ([sha3](https://docs.rs/sha3))
- SHA3 512 ([sha3](https://docs.rs/sha3))
- SHA2 256 ([sha2](https://docs.rs/sha2))
- SHA2 512 ([sha2](https://docs.rs/sha2))

Blake3 is recommended for most applications since it outperforms the other algorithms.

#### Signing

`cesride` supports the following signing algorithms:
- Ed25519 ([ed25519-dalek](https://docs.rs/ed25519-dalek))
- Secp256k1 ([k256](https://docs.rs/k256))
- Secp256r1 ([p256](https://docs.rs/p256))

We have planned support for Ed448.

The ECDSA curves (Secp256k1 and Secp256r1) use randomized signatures. Ed25519 is always deterministic.
This means that if you need to avoid correlation and want to use Ed25519, you'll need to salt your data
for every use case that you do not want correlated. ACDC, for example, takes this into account, allowing for
configurable use of Ed25519 by injecting salty nonces in the data to be signed where privacy is a concern.

## Community

### Bi-weekly Meeting
[Information here](https://github.com/WebOfTrust/keri#meetings)

### Discord
- [Discord Invite](https://discord.gg/edGDD632tP)https://discord.gg/edGDD632tP)
    - `#cesr` channel.
