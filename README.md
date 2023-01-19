# cesride

[![cesride](https://github.com/WebOfTrust/cesride/actions/workflows/test.yml/badge.svg)](https://github.com/WebOfTrust/cesride/actions/workflows/test.yml)
[![codecov](https://codecov.io/gh/WebOfTrust/cesride/branch/main/graph/badge.svg?token=L8K7H1XXQS)](https://codecov.io/gh/WebOfTrust/cesride)

Cryptographic primitives for use with Composable Event Streaming Representation (CESR).

#### Running tests on an M1

```shell
cargo +nightly test --target=aarch64-apple-darwin --package cesride --lib core::matter::matter_codex_tests::test_matter_new -- --exact --nocapture
```

## Community
## Bi-weekly Meeting
- [Zoom Link](https://us06web.zoom.us/j/88102305873?pwd=Wm01TEJKUWc0aE51a0QzZ2hNbTV2Zz09)
- [HackMD Link](https://hackmd.io/UQaEI0w8Thy_xRF7oYX03Q?view) Bi-Weekly Meeting Agenda and Minutes
- Slack https://join.slack.com/t/keriworld/shared_invite/zt-14326yxue-p7P~GEmAZ65luGSZvbgFAQ
    - `#cesr` channel.

# Important Reference Material
- WebOfTrust/[ietf-cesr](https://github.com/WebOfTrust/ietf-cesr) repository - IETF draft specification for CESR
- Design Assumptions, Use Cases, and ToDo list - [HackMD link](https://hackmd.io/W2Z39cuSSTmD2TovVLvAPg?view)
- Introductory articles:
    - [#1 CESR Proof Signatures](https://medium.com/happy-blockchains/cesr-proof-signatures-are-the-segwit-of-authentic-data-in-keri-e891c83e070a)
    - [#2 CESR Overview](https://medium.com/happy-blockchains/cesr-one-of-sam-smiths-inventions-is-as-controversial-as-genius-d757f36b88f8)