# cesride

[![cesride](https://github.com/WebOfTrust/cesride/actions/workflows/test.yml/badge.svg)](https://github.com/WebOfTrust/cesride/actions/workflows/test.yml)
[![codecov](https://codecov.io/gh/WebOfTrust/cesride/branch/main/graph/badge.svg?token=L8K7H1XXQS)](https://codecov.io/gh/WebOfTrust/cesride)

Cryptographic primitives for use with Composable Event Streaming Representation (CESR).

This library is **currently under construction**. If you want to help build, see [contributing](#contributing) below.

## Important Reference Material
- WebOfTrust/[ietf-cesr](https://github.com/WebOfTrust/ietf-cesr) repository - IETF draft specification for CESR
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

## Foreign language bindings

This implementation is not complete. Feel free to add.

We use [uniffi](https://github.com/mozilla/uniffi-rs) to provide foreign language bindings. This
provides bindings in Swift, Kotlin, Python and Ruby.

### Generating bindings

To build bindings for all four languages, simply run `make bindings`.

```sh
make bindings
```

To build for a specific language, use the name of that language as the make target (first argument).
For example, to build only kotlin bindings, run:

```sh
make kotlin
```

and to build Python and Swift bindings, run:

```sh
make python swift
```

The generated code will be dropped in `uniffi/generated`. Consult `uniffi` documentation on how to
use the library with the bindings of your choice.

### Python example - Verifying a signature with `cesride`

The Makefile contains a target that will launch a Python shell within a context that has access to
`cesride` primitives. Read the Makefile to see the commands required to do this yourself, or consult
`uniffi` documentation. The process differs from language to language and likely platform to
platform, and is out of scope of this project.

```
make python-shell
```

Inside the python shell:
```python
from cesride import Verfer
import pysodium

seed = pysodium.randombytes(32)
verkey, sigkey = pysodium.crypto_sign_seed_keypair(seed)

verfer = Verfer(raw=verkey, code="B")

# create something to sign and verify
ser = b'abcdefghijklmnopqrstuvwxyz0123456789'
sig = pysodium.crypto_sign_detached(ser, sigkey)

verfer.verify(sig, ser)
```

Let's try.

```
❯ make python-shell
    Finished release [optimized] target(s) in 0.13s
    Finished release [optimized] target(s) in 0.12s
     Running `target/release/cesride-bindgen generate src/cesride.udl --out-dir generated --language python`
Python 3.10.10 (main, Feb  8 2023, 05:40:53) [Clang 14.0.0 (clang-1400.0.29.202)] on darwin
Type "help", "copyright", "credits" or "license" for more information.
>>> from cesride import Verfer
>>> import pysodium
>>> 
>>> seed = pysodium.randombytes(32)
>>> verkey, sigkey = pysodium.crypto_sign_seed_keypair(seed)
>>> 
>>> verfer = Verfer(raw=verkey, code="B")
>>> 
>>> # create something to sign and verify
>>> ser = b'abcdefghijklmnopqrstuvwxyz0123456789'
>>> sig = pysodium.crypto_sign_detached(ser, sigkey)
>>> 
>>> verfer.verify(sig, ser)
True
>>> 
```

For good measure, lets tamper both the signature and input data:

```
>>> verfer.verify(b'x' + sig[1:], ser)
False
>>> verfer.verify(sig, b'x' + ser[1:])
False
```

Success!

### Formatting

If you want to make the generated code readable, you will need to install formatters for each language you
intend to build bindings for. If you don't do this, things will probably work with a few warnings.
One reason not to do this is the number of dependencies that seem to be installed for some of the
formatters.

Swift: `swiftformat`
Kotlin: `ktlint`
Ruby: `rubocop`
Python `yapf`

On `macOS`, one can use `brew` and the stock `ruby` installation to prep the system:

```shell
brew install swiftformat ktlint yapf
sudo gem install rubocop
```

## Community

### Bi-weekly Meeting
- [Zoom Link](https://us06web.zoom.us/j/88102305873?pwd=Wm01TEJKUWc0aE51a0QzZ2hNbTV2Zz09)
- [Agenda and Minutes Link](https://hackmd.io/UQaEI0w8Thy_xRF7oYX03Q?view)

### Slack
- [Slack Invite](https://join.slack.com/t/keriworld/shared_invite/zt-14326yxue-p7P~GEmAZ65luGSZvbgFAQ)
    - `#cesr` channel.
