# fragnesia-go

> One SA. One byte at a time. No race.

Go port of [fragnesia](https://github.com/v12-security/pocs/tree/main/fragnesia) (CVE-2026-46300). Member of the [Dirty Frag](https://github.com/V4bel/dirtyfrag) vulnerability class - separate bug, same surface, own patch.

## How it works (tl;dr)

The bug is in the Linux XFRM ESP-in-TCP subsystem. When `TCP_ULP espintcp` is installed on a socket after data has already been `splice()`d from a file into the TCP receive queue, the kernel treats the queued data as an ESP ciphertext record and decrypts it in-place. The source of that data is a page-cache page. The decryption XORs the AES-GCM keystream directly into it.

The result is a controlled single-byte write into the page cache of any readable file.

**Keystream table**

AES-GCM (RFC 4106) counter block at position 2 is `[salt(4) || IV(8) || 0x00000002]`. Encrypting it under the session key gives a 16-byte keystream block. Byte 0 of that block is what gets XORed into the target byte. By varying the lower 32 bits of the IV nonce, all 256 possible keystream byte values are reachable within the first 65536 nonces. The exploit builds this lookup table once at startup via `AF_ALG` AES-ECB.

**Byte-flip loop**

For each byte of the payload:
1. Read the current value from the file (page cache).
2. Compute `needed_keystream = current XOR desired`.
3. Look up the nonce for that keystream byte.
4. Set the IV, fire a TCP trigger pair (sender splices the file page into the socket, receiver delays `TCP_ULP` install until the data is queued).
5. Result: `current XOR keystream = current XOR (current XOR desired) = desired`.

One SA. 192 triggers maximum. Deterministic.

## Usage

```bash
go build -o fragnesia-go .
./fragnesia-go
```

On success it drops into a root shell via a fresh PTY. The on-disk binary is untouched - page cache only.

### Cleanup

```bash
echo 1 | tee /proc/sys/vm/drop_caches
```

## Requirements

- Linux - unpatched kernel (see below)
- No external tools - pure Go, single static binary
- Kernel module: `esp6` (transport mode, IPv6 loopback)

## Affected kernels

All kernels before the patch: https://lists.openwall.net/netdev/2026/05/13/79

Same range as dirtyfrag.

## Mitigation

Same as dirtyfrag:

```bash
rmmod esp4 esp6
printf 'install esp4 /bin/false\ninstall esp6 /bin/false\n' \
  > /etc/modprobe.d/fragnesia.conf
```

## Compared to dirtyfrag-go

| | dirtyfrag-go | **fragnesia-go** |
|---|---|---|
| CVEs | CVE-2026-43284 / CVE-2026-43500 | CVE-2026-46300 |
| Transport | ESP-in-UDP + RxRPC | ESP-in-TCP (ULP) |
| Write granularity | 4 bytes per trigger | 1 byte per trigger |
| XFRM SAs | 48 | 1 |
| Crypto | HMAC-SHA256 + CBC-AES | AES-128-GCM |
| IP family | IPv4 | IPv6 |

## References

- [v12-security/pocs - fragnesia](https://github.com/v12-security/pocs/tree/main/fragnesia) - original C PoC
- [CVE-2026-46300 - Red Hat](https://access.redhat.com/security/cve/cve-2026-46300)
- [Kernel patch](https://lists.openwall.net/netdev/2026/05/13/79)

## Credits

- **William Bowling / V12 team** - vulnerability discovery and original PoC
