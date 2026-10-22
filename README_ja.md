# twagentneo

[English README](./README.md) | [ドキュメント (GitHub Pages)](https://twsnmp.github.io/twagentneo/index_ja.html)

TWSNMP NEO 向け Pure Go クロスプラットフォーム監視 & AI セキュリティエージェント（内蔵 Sigma ルール & ローカル LLM トリアージ `tensai` 搭載）。

## 主な特徴

- **Pure Go シングルバイナリ (`CGO_ENABLED=0`)**: 外部 C ライブラリ依存ゼロ。Linux、macOS、Windows ですぐに稼働可能。
- **内蔵 Sigma 評価エンジン**: 厳選されたセキュリティルールをバイナリ内蔵（`embed.FS`）。外部ルール管理の手間なく即座に利用可能。
- **ローカル AI トリアージ**: 組み込み LLM エンジン `tensai` によるローカル判定（LLM-as-a-Judge）。誤検知の抑制と実践的な対処アドバイザリを付与。
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
twagentneo -config config.yaml
```

### バージョン確認

```bash
twagentneo -version
# twagentneo v0.1.0 (commit: abc1234, built: 2026-10-22T08:00:00Z, darwin/arm64)
```

### セルフアップデート

```bash
# 更新確認のみ
twagentneo update -check

# 更新を適用
twagentneo update
```

---

## テストと動作検証

管理者権限を持たない一般ユーザー環境で **Sigma ルール** や **ファイル整合性監視 (FIM)** のアラートを検証する手順については、[TESTING.md](TESTING.md) をご覧ください。
