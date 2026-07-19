# NFC-F profile record

`profile.record`は99バイトの固定長データです。C/C++構造体のメモリ表現は使わず、複数バイトの整数はlittle-endianで保存します。

| Offset | Size | Field |
|---:|---:|---|
| 0 | 8 | Magic: `NFCFPROF` |
| 8 | 4 | Format version: `1` |
| 12 | 2 | System Code |
| 14 | 2 | Service Code |
| 16 | 8 | IDm |
| 24 | 6 | PMm timing bytes |
| 30 | 1 | Block count (`1`〜`4`) |
| 31 | 64 | Four 16-byte block slots |
| 95 | 4 | FNV-1a checksum of bytes 0〜94 |

未使用のblock slotは0で埋めます。System Codeはハードウェア設定時にon-airのバイト順へ変換されます。Service CodeはRead Without Encryptionのservice code listと照合します。

checksumは転送中の破損を検出するためのもので、署名や認証ではありません。ファイルは所有者だけが読み書きできる状態ディレクトリへ、mode `0600`で配置してください。
