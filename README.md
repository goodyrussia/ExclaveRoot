# Exclave Root

Exclave **0.17.53** fork: **root TPROXY only** (no VpnService).

| | |
|--|--|
| Display | Exclave Root |
| applicationId | `io.nekohasekai.sagernet.tproxy` |
| Base | ExclaveNetwork/Exclave `0.17.53` + exclave-core 5.50.x |
| Capture | hev-socks5-tproxy (root) → SOCKS 127.0.0.1:2080 → core |
| Needs | Magisk / KernelSU `su` |

Sideload next to stock Exclave (different package). CI builds arm64 APK.
