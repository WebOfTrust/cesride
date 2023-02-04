# cesride

[![cesride](https://github.com/WebOfTrust/cesride/actions/workflows/test.yml/badge.svg)](https://github.com/WebOfTrust/cesride/actions/workflows/test.yml)
[![codecov](https://codecov.io/gh/WebOfTrust/cesride/branch/main/graph/badge.svg?token=L8K7H1XXQS)](https://codecov.io/gh/WebOfTrust/cesride)

Cryptographic primitives for use with Composable Event Streaming Representation (CESR).

## Important Reference Material
- WebOfTrust/[ietf-cesr](https://github.com/WebOfTrust/ietf-cesr) repository - IETF draft specification for CESR
- Design Assumptions, Use Cases, and ToDo list - [HackMD link](https://hackmd.io/W2Z39cuSSTmD2TovVLvAPg?view)
- Introductory articles:
    - [#1 CESR Proof Signatures](https://medium.com/happy-blockchains/cesr-proof-signatures-are-the-segwit-of-authentic-data-in-keri-e891c83e070a)
    - [#2 CESR Overview](https://medium.com/happy-blockchains/cesr-one-of-sam-smiths-inventions-is-as-controversial-as-genius-d757f36b88f8)

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

If you've modified the python code, either add some python tests (you'll need to do that yourself,
none have been added) or run this code (and additionally exercising the changes you made):
```shell
make python python-shell

# in python shell
from cesride import Matter
m = Matter(qb64="BGlOiUdp5sMmfotHfCWQKEzWR91C72AH0lT84c0um-Qj")
qb2 = m.qb2()
print(qb2)
m2 = Matter(qb2=bytes(qb2))
m2.qb64()
```
and expect to see the initial `qb64` input as the output.

You are now ready to open a pull request!

## Community

### Bi-weekly Meeting
- [Zoom Link](https://us06web.zoom.us/j/88102305873?pwd=Wm01TEJKUWc0aE51a0QzZ2hNbTV2Zz09)
- [Agenda and Minutes Link](https://hackmd.io/UQaEI0w8Thy_xRF7oYX03Q?view)

### Slack
- [Slack Invite](https://join.slack.com/t/keriworld/shared_invite/zt-14326yxue-p7P~GEmAZ65luGSZvbgFAQ)
    - `#cesr` channel.
