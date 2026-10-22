---
title: はじめての twagentneo
layout: default
---

[English (英語版はこちら)](./index.html)

# はじめての twagentneo
次世代 Pure Go クロスプラットフォーム監視 & AI セキュリティエージェント

![](./images/appicon.png){: width="200"}

---

## 1. はじめに

**twagentneo** は、Windows、Linux、macOS で軽快に動作する **TWSNMP NEO** 向けの次世代クロスプラットフォーム監視 & AI セキュリティエージェントです。

ホストリソース（CPU、メモリ、ディスク、ロードアベレージ）やネットワーク状態（ネットワークインターフェース、ARPテーブル、TCP接続宛先）の定期監視に加え、ファイル整合性監視（FIM）および OS セキュリティログの収集・監査を自律的に行います。

ログの監査には、TWSLA で実績のある **Sigma 評価エンジン** を Pure Go で内蔵。さらに検知された疑わしいイベントに対しては、Go 製の組み込みローカル LLM パッケージ **`tensai`** を活用した **LLM-as-a-Judge によるインテリジェントトリアージ** を端末ローカルで自律実行します。

### 主な特徴
- **Pure Go シングルバイナリ (`CGO_ENABLED=0`)**: 外部 C ライブラリへの依存が一切なく、1 つのバイナリを配置するだけで即座に稼働。
- **2段階ハイブリッド脅威監査 (Sigma × tensai)**:
  - **第1層 (超高速・超低負荷)**: 内蔵の厳選 Sigma ルールにより、毎秒数千行のログから疑わしいイベントのみをミリ秒単位で高速抽出。
  - **第2層 (インテリジェントローカル判定)**: 抽出されたイベントに対し、端末ローカルで動作する `tensai` が前後コンテキストを踏まえて誤検知排除・脅威スコアリング・日本語での推奨対処手順（アドバイザリ）を付与。
- **ゼロコンフィグ運用**: OS（Linux、macOS、Windows）に応じた主要 Sigma ルールをバイナリ内蔵（`embed.FS`）。外部ルールファイルを用意することなく起動直後から脅威監視を開始。
- **OS 自動判定による極小リソースフットプリント**: 起動時に実行環境の OS を自動認識し、必要なルールのみをインデックス化。アイドル時 CPU 1% 未満、常駐メモリ 30〜50MB 程度の極めて軽量な動作を実現。
- **マルチプロトコル送信**: 収集したメトリクスや高度に構造化されたアラートを、**MQTT**（リアルタイムストリーム）、**Syslog**（RFC 5424/3164）、**SNMP TRAP**（専用 MIB 定義）で TWSNMP NEO（および FC/FK）へ送信。
- **内蔵 CLI アップデーター**: `twagentneo update` コマンドにより、GitHub Releases や Homebrew と連動して安全に自己アップデート可能。

---

## 2. システムアーキテクチャ

twagentneo は、軽量なコレクター層、高速なイベントバス、2段階の監査エンジン、そして柔軟なエクスポーター層で構成されています。

```text
+-------------------------------------------------------------------------+
|                              twagentneo                                 |
|                                                                         |
|  +-------------------------------------------------------------------+  |
|  |                 コレクター層 (Pure Go / Native OS)                |  |
|  |  [Host Resource]   [ARP / Interface]   [TCP Connections]          |  |
|  |  [FIM (fsnotify)]  [Log Tailer (auth, secure, install, EventLog)] |  |
|  +-------------------------------------------------------------------+  |
|                                  |                                      |
|                                  v (Raw Logs / Events)                  |
|  +-------------------------------------------------------------------+  |
|  |             第1層: OS適応型 内蔵 Sigma 評価エンジン               |  |
|  |  - バイナリ内蔵 Curated Rules (Linux / Windows / macOS)           |  |
|  |  - 起動時 OS 自動インデックス化（高速文字列照合）                 |  |
|  |  - High / Critical 候補イベントのミリ秒フィルタリング             |  |
|  +-------------------------------------------------------------------+  |
|                                  | (Suspicious Candidate Events)        |
|                                  v                                      |
|  +-------------------------------------------------------------------+  |
|  |             第2層: ローカル LLM Judge (tensai パッケージ)         |  |
|  |  - 前後ログスライディングウィンドウによる文脈解析                 |  |
|  |  - 誤検知（False Positive）判定・脅威スコア算出 (0〜100)          |  |
|  |  - MITRE ATT&CK マッピング & 日本語推奨対処アドバイザリ生成       |  |
|  +-------------------------------------------------------------------+  |
|                                  | (Enriched Alerts & Metrics)          |
|                                  v                                      |
|  +-------------------------------------------------------------------+  |
|  |                  内部非同期イベントバス (Pipeline Bus)            |  |
|  +-------------------------------------------------------------------+  |
|                                  |                                      |
|                                  v                                      |
|  +-------------------------------------------------------------------+  |
|  |                 マルチプロトコル・エクスポーター                  |  |
|  |   [MQTT Exporter]      [Syslog Exporter]    [SNMP Trap Exporter]  |  |
|  +-------------------------------------------------------------------+  |
+-------------------------------------------------------------------------+
           |                         |                    |
           v                         v                    v
      TWSNMP NEO                 SIEM / Syslog       TWSNMP NEO /
    (MQTT Broker)                  Receiver          Trap Receiver
```

---

## 3. インストールと起動

twagentneo は、Linux、macOS、Windows の各プラットフォームに対応したクロスプラットフォーム設計です。

### 3.1 macOS (Homebrew)

公式の Homebrew Tap からワンステップでインストールできます：

```bash
brew install twsnmp/tap/twagentneo
```

### 3.2 Linux / macOS (ワンライナーインストーラー)

シェルスクリプトを用いて、アーキテクチャ（amd64 / arm64）に応じた最新バイナリを自動取得・配置します：

```bash
curl -fsSL https://raw.githubusercontent.com/twsnmp/twagentneo/main/install/install.sh | sh
```

### 3.3 GitHub Releases からの直接ダウンロード

[GitHub Releases](https://github.com/twsnmp/twagentneo/releases) から、環境に応じたアーカイブ（`.tar.gz` または `.zip`）をダウンロードして展開してください。

| OS | アーキテクチャ | ファイル名例 |
|:---|:---|:---|
| Linux | amd64 / x86_64 | `twagentneo_linux_amd64.tar.gz` |
| Linux | arm64 / aarch64 | `twagentneo_linux_arm64.tar.gz` |
| macOS | Apple Silicon (arm64) | `twagentneo_darwin_arm64.tar.gz` |
| macOS | Intel (amd64) | `twagentneo_darwin_amd64.tar.gz` |
| Windows | 64-bit (x64) | `twagentneo_windows_amd64.zip` |
| Windows | ARM64 | `twagentneo_windows_arm64.zip` |

### 3.4 ソースコードからのビルド

[`mise`](https://mise.jdx.dev/) または `make` を使用して簡単にビルドできます：

```bash
# mise を使用する場合
mise run build

# make を使用する場合
make build
```

---

## 4. 設定ガイド (`config.yaml`)

エージェントの動作は単一の YAML ファイルで設定します。デフォルトでは `./config.yaml` が読み込まれます。

```yaml
agent:
  id: "twagentneo-server-01"    # エージェント識別子（MQTTトピックやTRAPで使用）
  name: "Web-App-Host-01"       # 表示用ホスト名
  log_level: "info"             # debug | info | warn | error

collectors:
  resource:
    enabled: true
    interval: 60s               # リソース収集間隔
    cpu_threshold: 90.0         # CPUアラート閾値 (%)
    mem_threshold: 85.0         # メモリアラート閾値 (%)
    disk_threshold: 90.0        # ディスクアラート閾値 (%)
    load_threshold: 10.0        # 1分間ロードアベレージ閾値
  network:
    enabled: true
    interval: 180s              # ネットワーク状態収集間隔
    arp_watch: true             # ARPテーブル収集
    tcp_watch: true             # TCP接続先監視（アウトバウンド通信追跡）
  fim:
    enabled: true
    paths:                      # 整合性監視対象ディレクトリ（再帰監視）
      - /etc
      - /usr/bin
      - /usr/sbin
  logs:
    enabled: true
    paths:                      # 追加のカスタム監視ログパス（空時はOS標準ログを監視）
      # - /var/log/my-app.log

# 2段階監査エンジン設定
audit:
  sigma:
    enabled: true              # 内蔵Sigmaルール自動実行
  ai_judge:
    enabled: true              # tensai パッケージによるローカルLLMトリアージ
    model_path: ""             # カスタムモデルパス（空文字時はtensaiデフォルトモデル）
    timeout: 5s                # 判定推論タイムアウト

# 送信先（エクスポーター）設定
exporters:
  mqtt:
    enabled: true
    broker: "tls://twsnmp-neo-server:8883"
    client_id: "twagentneo-01"
    topic_prefix: "twsnmpneo/agent"
    username: "twagentneo"
    password: "${MQTT_PASSWORD}"

  syslog:
    enabled: false
    endpoint: "udp://twsnmp-neo-server:514"
    format: "rfc5424"          # rfc5424 または rfc3164

  snmp_trap:
    enabled: true
    target: "twsnmp-neo-server:162"
    version: "v3"              # v2c または v3
    community: "public"
    v3:
      user: "twsnmpUser"
      auth_protocol: "SHA256"
      auth_password: "${TRAP_AUTH_PASS}"
      priv_protocol: "AES128"
      priv_password: "${TRAP_PRIV_PASS}"
```

> **環境変数の展開**: パスワードなどの秘匿情報は `${ENV_NAME}` 形式で指定でき、起動時に環境変数から安全に展開されます。

---

## 5. 収集機能 & モニタリング詳細

### 5.1 ホストリソース監視 (`resource`)
Pure Go のシステムコールおよび `/proc`・OS API 経由でホストリソースを取得します：
- **CPU 使用率**: 全体およびコアごとの使用状況
- **メモリ**: トータル、使用中、空き容量、使用率 (%)
- **ディスク**: ルートおよびマウントポイントごとの使用率 (%)
- **ロードアベレージ**: 1分、5分、15分の負荷平均
- **しきい値アラート**: 設定値を超過した場合、即座にリソースアラートイベントを発行。

### 5.2 ネットワーク監視 (`network`)
- **インターフェース情報**: MAC アドレス、IP アドレス、MTU、インターフェースの UP/DOWN 状態。
- **ARP テーブル (`arp_watch`)**: 近隣 IP アドレスと物理 MAC アドレスの対応関係を収集。IP なりすましや未知のデバイス接続を検知。
- **TCP 接続監視 (`tcp_watch`)**: 確立中（ESTABLISHED）の外部宛先 IP・ポート番号を追跡。C2 サーバーや不審なアウトバウンド通信を捕捉。

### 5.3 ファイル整合性監視 (`fim`)
指定されたディレクトリを `fsnotify` および OS ネイティブの通知機構で再帰的に監視します：
- **ファイル作成 (CREATE)** / **変更 (WRITE)** / **削除 (REMOVE)** / **リネーム (RENAME)** をリアルタイム追跡。
- ファイル変更時には SHA-256 ハッシュ値を自動計算し、改ざん内容を記録。
- 重要システムファイル（`/etc/passwd`, `/etc/shadow`, Windows `System32` 等）の不正改ざんを即座にアラート化。

### 5.4 OS ログ監視 (`logs`)
OS 標準のセキュリティイベントログを自動識別して末尾追跡（Tail）します：
- **Linux**: `/var/log/auth.log`, `/var/log/secure`, `/var/log/syslog`
- **macOS**: `/var/log/install.log`, `/var/log/system.log`
- **Windows**: Windows Security Event Log（Syscall 経由）
- 独自アプリケーションログも `paths` 設定で任意に追加可能。

---

## 6. 内蔵 Sigma ルール & ローカル LLM トリアージ

### 6.1 内蔵 Sigma ルール (Tier-1 高速フィルタ)
twagentneo は、バイナリ内に厳選された Sigma ルールセットを組み込んでいます。外部ファイル不要で、起動時に OS に適したルールのみがインデックス化されます。

| 対象 OS | 検知カテゴリ | 主な検知内容 |
|:---|:---|:---|
| **Linux** | 認証・特権昇格・不審操作 | sudo パスワード総当たり、cron タブ不正追加、シェル履歴消去、不審バイナリ実行 |
| **macOS** | 権限昇格・永続化・改ざん | sudo 乱用、LaunchDaemon 不正登録、Gatekeeper 回避、SIP 改ざん |
| **Windows** | 攻撃ツール・認証侵害 | Mimikatz パターン、PowerShell ダウンロードクレードル、不正アカウント作成、不審サービス登録 |

### 6.2 ローカル LLM トリアージ (Tier-2: `tensai` AI Judge)

Sigma ルールで検知された候補イベントに対し、組み込み LLM エンジン `tensai` が端末ローカルで文脈判断を実行します：

1. **文脈スライディングウィンドウ**:
   検知イベントの前後に発生した直近最大 20 行のログ履歴を自動抽出し、AI 判定エンジンへ提供。
2. **誤検知（False Positive）判定**:
   定期メンテナンス作業や正常な管理者の操作であるかを判断し、不要な警告によるアラート疲れ（Alert Fatigue）を低減。
3. **脅威スコア (0〜100)**:
   事象の危険度を定量スコア化。
4. **MITRE ATT&CK マッピング & 日本語推奨対策**:
   どの攻撃戦術（Tactic/Technique）に該当するかをマッピングし、システム管理者が次に取るべき初動対応手順（プロセスキル、アカウント一時停止、FW遮断等）をわかりやすい日本語で生成。

---

## 7. 送信プロトコルと TWSNMP NEO 連携

### 7.1 MQTT トピック設計
MQTT エクスポーターは、TWSNMP NEO のイベントパイプラインに最適化されたトピック構成で送信します：

```text
{topic_prefix}/{agent_id}/metrics     # CPU, メモリ, ディスクメトリクス [エイリアス: resource]
{topic_prefix}/{agent_id}/interface   # ネットワークインターフェース状態 [エイリアス: network]
{topic_prefix}/{agent_id}/arp         # ARP テーブル一覧
{topic_prefix}/{agent_id}/tcp         # アクティブ TCP 接続宛先リスト
{topic_prefix}/{agent_id}/alert       # Sigma + AI Judge セキュリティアラート [エイリアス: fim]
{topic_prefix}/{agent_id}/status      # エージェント死活・ステータス (LWT) [エイリアス: heartbeat]
```

### 7.2 Syslog (RFC 5424 / RFC 3164)
既存の SIEM や TWSNMP NEO の Syslog レシーバーに対して、構造化データ付きの標準 Syslog メッセージを UDP / TCP で転送します。

### 7.3 SNMP TRAP (`TWAGENT-NEO-MIB.txt`)
エンタープライズ MIB（OID: `.1.3.6.1.4.1.17862.3`）に基づき、SNMPv2c および SNMPv3（SHA256 認証 / AES128 暗号化）でトラップを発行します：

- `twagentNeoAlertTrap` (OID: `.1.3.6.1.4.1.17862.3.2.1`): セキュリティアラート発生時
- `twagentNeoResourceTrap` (OID: `.1.3.6.1.4.1.17862.3.2.2`): リソース超過アラート発生時
- `twagentNeoFimTrap` (OID: `.1.3.6.1.4.1.17862.3.2.3`): ファイル改ざん検知時

---

## 8. 運用管理 & 自動更新

### 8.1 バージョン情報確認

```bash
twagentneo -version
# 出力例:
# twagentneo v0.1.0 (commit: 068f493, built: 2026-10-22T15:35:00Z, darwin/arm64)
```

### 8.2 セルフアップデートコマンド

`update` サブコマンドで最新版への更新を安全に実行できます：

```bash
# 更新があるか確認のみ実行
twagentneo update -check

# 対話形式で更新を適用
twagentneo update

# 確認プロンプトをスキップして即座に更新
twagentneo update -y

# 特定のバージョンを指定して更新
twagentneo update -version v0.2.0
```

> **環境認識機能**: Homebrew 経由でインストールされている場合は `brew upgrade` を促し、コンテナ環境ではイメージ再取得を案内するなど、実行環境に応じた最適な更新方法を提示します。

---

## 9. 動作検証とテスト手順

管理者権限を持たない一般ユーザー環境でも、安全に Sigma ルール検知と FIM アラートを検証できます。

### 9.1 FIM（ファイル整合性）テスト
一時ディレクトリでファイル作成・書き換えを行います：

```bash
mkdir -p /tmp/fim_test
# config.yaml の fim.paths に /tmp/fim_test を追加して起動

echo "test data" > /tmp/fim_test/sample.txt
echo "modified content" >> /tmp/fim_test/sample.txt
rm /tmp/fim_test/sample.txt
```
ログに `[bus] published FIM event: CREATE / MODIFY / DELETE` が記録されます。

### 9.2 Sigma × AI Judge ログ監査テスト
カスタムログファイルを指定して、疑似攻撃ログを追記します：

```bash
touch /tmp/test_audit.log
# config.yaml の collectors.logs.paths に /tmp/test_audit.log を指定

# Linux: sudo パスワード失敗イベントをシミュレート
echo "Oct 22 10:00:00 server sudo[1234]: pam_unix(sudo:auth): authentication failure; logname=test uid=1000 euid=0 tty=/dev/pts/0 ruser=test rhost= user=root" >> /tmp/test_audit.log
```
内蔵 Sigma ルールがマッチし、`tensai` による日本語トリアージ結果と脅威スコアが付与されたアラートが発行されます。

---

## 10. まとめ

twagentneo は、CGO 不要の軽量な Go 単一バイナリでありながら、**Sigma ルールの高速フィルタリング** と **ローカル LLM（`tensai`）のインテリジェント判定** を組み合わせた全く新しいセキュリティエージェントです。

TWSNMP NEO と組み合わせることで、ネットワーク機器からサーバー内部の脅威までを一元的に可視化・自律監視する環境が完成します。

ぜひお試しください！
