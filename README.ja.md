# iOSNFCFCardEmulation

[English](README.md)

iOSNFCFCardEmulationは、rootless脱獄済みiPhoneでNFC-F Type 3 Tagエミュレーションを行うためのバックエンドです。`nfcd`内で動作し、Device Host routingの設定、対応コマンドへの応答、停止時のrouting復元を行います。

UIやカード読み取り機能はありません。利用側のアプリがプロファイルを書き、`iosnfcfctl`を呼び出します。

## 検証済み環境

| | |
|---|---|
| 端末 | iPhone 8 (`iPhone10,1`) |
| iOS | 16.0.2 (`20A380`) |
| 脱獄 | rootless |
| 依存 | ElleKit 1.1.3以降 |

これ以外の端末とiOSバージョンでの動作は未検証であり、保証しません。

## プロトコル

プロファイルにはSystem Code、Service Code、IDm、PMmの末尾6バイト、1〜4個の16バイトブロックを格納します。

現在は読み取り専用の1サービス構成で、次のコマンドに対応します。

- Request Response
- Read Without Encryption
- 2バイト形式と3バイト形式のblock list element

複数サービス、書き込み、暗号化サービス、相互認証には対応していません。PMmの先頭2バイトは下位スタック側で`FE FE`になります。

## プロファイルの受け渡し

利用側は99バイトのプロファイルを次の場所へ書きます。

```text
/var/mobile/Library/Caches/org.hoshitsugi.iosnfcfcardemulation/profile.record
```

バイナリ形式は[docs/profile-record.md](docs/profile-record.md)を参照してください。

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

`start`の途中で失敗した場合は、それまでに行ったrouting変更を逆順に戻します。各コマンドは`NFCF_JSON:`から始まる機械可読の結果も返します。

## ビルドとテスト

Theos、`ldid`、iPhoneOS SDKが必要です。WSL2からも実行できます。

```sh
bash scripts/test.sh
THEOS="$HOME/theos" bash scripts/build.sh
```

生成物は`dist/org.hoshitsugi.iosnfcfcardemulation_0.1.0_iphoneos-arm64.deb`です。

## ライセンス

[Apache License 2.0](LICENSE)
