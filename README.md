# iOSNFCFCardEmulation

[日本語](README.ja.md)

iOSNFCFCardEmulation provides NFC-F Type 3 Tag emulation for a rootless jailbroken iPhone. It runs inside `nfcd`, configures Device Host routing, handles supported NFC-F commands, and restores the previous routing state when stopped.

It does not include a UI or any card-reading code. A client application supplies the emulation profile and calls `iosnfcfctl`.

## Tested environment

| | |
|---|---|
| Device | iPhone 8 (`iPhone10,1`) |
| iOS | 16.0.2 (`20A380`) |
| Jailbreak | rootless |
| Dependency | ElleKit 1.1.3 or later |

Other devices and iOS versions have not been tested and are not guaranteed to work.

## Protocol support

A profile contains the System Code, Service Code, IDm, the six trailing PMm bytes, and one to four 16-byte blocks.

The current responder implements one read-only service and handles:

- Request Response
- Read Without Encryption
- two-byte and three-byte block list elements

Multiple services, writes, encrypted services, and mutual authentication are not implemented. The lower NFC stack supplies `FE FE` as the first two PMm bytes.

## Profile interface

The client writes a 99-byte profile record to:

```text
/var/mobile/Library/Caches/org.hoshitsugi.iosnfcfcardemulation/profile.record
```

See [docs/profile-record.md](docs/profile-record.md) for the binary format.

```sh
iosnfcfctl profile apply
iosnfcfctl profile show
iosnfcfctl start
iosnfcfctl status
iosnfcfctl recover
iosnfcfctl stop
iosnfcfctl profile clear
iosnfcfctl logs
```

`start` is transactional: if routing setup fails, completed steps are rolled back in reverse order. Commands also emit one machine-readable line prefixed with `NFCF_JSON:`.

## Build and test

The build requires Theos, `ldid`, and an iPhoneOS SDK. It can be run from WSL2.

```sh
bash scripts/test.sh
THEOS="$HOME/theos" bash scripts/build.sh
```

The package is written to `dist/org.hoshitsugi.iosnfcfcardemulation_0.1.0_iphoneos-arm64.deb`.

## License

[Apache License 2.0](LICENSE)
