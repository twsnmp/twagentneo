# twagentneo

[English README](./README.md) | [ドキュメント (GitHub Pages)](https://twsnmp.github.io/twagentneo/index_ja.html)

TWSNMP NEO 向け Pure Go クロスプラットフォーム監視 & AI セキュリティエージェント（内蔵 Sigma ルール & ローカル LLM トリアージ `tensai` 搭載）。

## 主な特徴

- **Pure Go シングルバイナリ (`CGO_ENABLED=0`)**: 外部 C ライブラリ依存ゼロ。Linux、macOS、Windows ですぐに稼働可能（MQTT クライアント脆弱性 CVE-2025-10543 対処済みなど依存パッケージの安全性を確保）。
- **内蔵 Sigma 評価エンジン**: 厳選されたセキュリティルールをバイナリ内蔵（`embed.FS`）。外部ルール管理の手間なく即座に利用可能。
- **ローカル AI トリアージ**: 組み込み LLM エンジン `tensai` によるローカル判定（LLM-as-a-Judge）。誤検知の抑制と実践的な対処アドバイザリを付与。
- **セキュリティ設定監査 (SCA)**: Pure Go による CIS ベンチマーク準拠のローカル設定・権限監査（World-Writable、秘密鍵/.env 権限、残存バックアップファイル、平文シークレット漏洩、sshd/sysctl 設定）を起動時ベースラインおよび FIM 連動リアルタイムで自動実行。
- **Windows サービス & Linux systemd 対応**: `twagentneo service install/start/stop/restart/status/remove` コマンドで OS ネイティブのバックグラウンド常駐・自動起動を一元管理。
- **ネットワークトラフィック & システム監視**: ネットワーク帯域レート（Bytes/Packets In/Out レート）、ARP テーブル、TCP 接続先追跡、スマート除外・重複排除付き CPU/メモリ/ディスク監視。
- **自己アップデート対応**: 内蔵 CLI アップデーター（`twagentneo update`）。Homebrew やコンテナ環境を自動識別。
- **マルチプロトコル連携**: MQTT、Syslog、SNMP TRAP で TWSNMP NEO にリアルタイム送信。

---

## ドキュメント

GitHub Pages にて詳細なマニュアルおよびアーキテクチャ解説を公開しています：
- 📖 [はじめての twagentneo (日本語マニュアル)](https://twsnmp.github.io/twagentneo/index_ja.html)
- 📖 [Getting Started with twagentneo (English)](https://twsnmp.github.io/twagentneo/)

---

## インストール手順

### macOS (Homebrew)

```bash
brew install twsnmp/tap/twagentneo
```

### Linux / macOS (ワンライナー)

```bash
curl -fsSL https://raw.githubusercontent.com/twsnmp/twagentneo/main/install/install.sh | sh
```

### 手動ダウンロード

[GitHub Releases](https://github.com/twsnmp/twagentneo/releases) から、お使いの環境に応じたバイナリアーカイブを直接ダウンロードしてください。

---

## ソースコードからのビルド

[`mise`](https://mise.jdx.dev/) を使用する場合：

```bash
mise run build
```

または `make` を使用する場合：

```bash
make build
```

---

## 基本操作・運用コマンド

### エージェントの起動

```bash
# 通常起動
twagentneo -config config.yaml

# デバッグログをコンソールに出力して起動 (-debug または -d)
twagentneo -config config.yaml -debug
```

### バージョン確認

```bash
twagentneo -version
# twagentneo v0.3.0 (commit: abc1234, built: 2026-10-27T05:00:00Z, darwin/arm64)
```

### セルフアップデート

```bash
# 更新確認のみ
twagentneo update -check

# 更新を適用
twagentneo update
```

### サービス管理 (Windows サービス & Linux systemd)

TWSNMP NEO (`twsnmpneo`) と同様に、バックグラウンドサービスとして登録・管理することができます。

#### Windows サービス常駐
管理者権限の PowerShell / コマンドプロンプトで実行します：

```powershell
# Windows サービスとして登録（OS起動時に自動起動）
.\twagentneo.exe service install -service-auto -config C:\twagentneo\config.yaml

# サービスの開始
.\twagentneo.exe service start

# サービスの再起動
.\twagentneo.exe service restart

# 状態確認
.\twagentneo.exe service status

# サービスの停止
.\twagentneo.exe service stop

# サービスの削除
.\twagentneo.exe service remove
```

#### Linux systemd サービス常駐
root 権限 (sudo) で実行します：

```bash
# systemd サービスとして登録（OS起動時に自動起動）
sudo /usr/local/bin/twagentneo service install -auto -config /etc/twagentneo/config.yaml

# サービスの開始
sudo /usr/local/bin/twagentneo service start

# サービスの再起動
sudo /usr/local/bin/twagentneo service restart

# 状態確認
sudo /usr/local/bin/twagentneo service status

# サービスの停止
sudo /usr/local/bin/twagentneo service stop

# サービスの削除
sudo /usr/local/bin/twagentneo service remove
```

---

## テストと動作検証

管理者権限を持たない一般ユーザー環境で **Sigma ルール** や **ファイル整合性監視 (FIM)** のアラートを検証する手順については、[TESTING.md](TESTING.md) をご覧ください。
