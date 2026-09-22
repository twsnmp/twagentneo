# SPEC.md: twagentneo

## 1. プロジェクト概要

### 1.1 目的
Windows、Linux、macOSで動作する、次世代クロスプラットフォーム監視・AIセキュリティエージェント `twagentneo` をGo言語で実装する。
ホストリソースやARPテーブルなどのネットワーク状態、Wazuh相当のセキュリティイベント・ログを収集する。ログの一次監査にはTWSLA等で実績のあるSigma評価エンジンを移植して内蔵し、さらに検知した疑わしいイベントに対しては **`tensai` パッケージを活用したローカルLLMによるインテリジェントトリアージ（LLM-as-a-Judge）** を実行する。脅威レベルやコンプライアンス違反の判定、推奨対策を付与した構造化データを、TWSNMP NEO（およびFC/FK）に対してMQTT、syslog、SNMP TRAP（新規定義MIB）で送信する。

### 1.2 コア設計思想
- **Pure Go（CGO_ENABLED=0）**: 外部Cライブラリへの依存を排除し、完全静的リンクシングルバイナリとしてビルド可能にする。
- **2段階ハイブリッド監査（Sigma × tensai）**:
  1. **第1層（超高速・超低負荷）**: 内蔵Sigmaルールにより、毎秒大量に発生するログから疑わしいイベントのみをミリ秒単位でフィルタリング。
  2. **第2層（インテリジェント判定）**: 抽出されたイベントに対し、Go製ローカルLLMエンジン `tensai` を介して端末ローカルで脅威判定・コンプライアンス監査・日本語解説生成を実施。
- **ゼロコンフィグ運用**: 外部ルールファイルや複雑な設定ファイル管理を排除。主要ルールをバイナリ内（`embed.FS`）に組み込み、配置するだけで即座に稼働する。
- **OS自動判定によるメモリ極小化**: 起動時に `runtime.GOOS` を判定し、実行中OSに対応するルールセットのみを展開。不要なメモリ消費を抑制する。

---

## 2. システムアーキテクチャ

```text
+-------------------------------------------------------------------------+
|                              twagentneo                                 |
|                                                                         |
|  +-------------------------------------------------------------------+  |
|  |                 Collectors (Pure Go / Native OS)                  |  |
|  |  [Host Resource]   [ARP / Interface]   [FIM (Syscall/fsnotify)]   |  |
|  |  [Process State]   [Log Stream / Event Collector]                 |  |
|  +-------------------------------------------------------------------+  |
|                                  |                                      |
|                                  v (Raw Logs / Events)                  |
|  +-------------------------------------------------------------------+  |
|  |                 Tier-1: OS-Adaptive Sigma Engine                  |  |
|  |             (Ported from TWSLA / Pure Go Sigma)                   |  |
|  |  - Built-in Curated Rules (Sigma Primary + Wazuh Mapped)          |  |
|  |  - OS Selective Load on Boot (Linux / Windows / macOS)           |  |
|  |  - High / Critical Suspicious Event Filter                        |  |
|  +-------------------------------------------------------------------+  |
|                                  | (Suspicious Candidate Events)        |
|                                  v                                      |
|  +-------------------------------------------------------------------+  |
|  |             Tier-2: Local LLM Judge (via tensai pkg)              |  |
|  |  - Threat Assessment & False Positive Reduction                  |  |
|  |  - Compliance Violation Evaluation (Privilege, Data Leak, etc.)   |  |
|  |  - Japanese Summary & Remediation Advisory Generation            |  |
|  +-------------------------------------------------------------------+  |
|                                  | (Enriched Alerts & Metrics)          |
|                                  v                                      |
|  +-------------------------------------------------------------------+  |
|  |                     Internal Event Bus                            |  |
|  |            (Buffered Channels / Non-blocking Queue)               |  |
|  +-------------------------------------------------------------------+  |
|                                  |                                      |
|                                  v                                      |
|  +-------------------------------------------------------------------+  |
|  |                    Exporters (Multi-Protocol)                     |  |
|  |   [MQTT Exporter]      [Syslog Exporter]    [SNMP Trap Exporter]  |  |
|  +-------------------------------------------------------------------+  |
+-------------------------------------------------------------------------+
           |                         |                    |
           v (MQTT/TLS)              v (UDP/TCP/TLS)      v (SNMPv2c/v3 Trap)
+-------------------------------------------------------------------------+
|                           TWSNMP NEO / FC / FK                          |
+-------------------------------------------------------------------------+
```

---

## 3. 収集機能仕様 (Collectors)

CGOを一切使用せず、OSネイティブのSyscallおよびGo標準パッケージで実装する。

### 3.1 ホストリソース (`collector/resource`)
- **Linux**: `/proc/stat`, `/proc/meminfo`, `/proc/diskstats`, `/proc/net/dev`, `syscall.Statfs`
- **Windows**: `golang.org/x/sys/windows` 経由の Win32 API (`GetSystemTimes`, `GlobalMemoryStatusEx`, `GetDiskFreeSpaceExW`)
- **macOS**: `golang.org/x/sys/unix` 経由の `sysctl` および `syscall.Statfs`
- **収集メトリクス**:
  - CPU使用率（全体/コア別）、ロードアベレージ
  - メモリ（総量、使用量、空き容量、スワップ使用量）
  - ディスク（マウントポイント別使用率、I/Oレート）
  - ネットワークトラフィック（IF別 送受信バイト数、パケット数、エラー数）

### 3.2 ネットワーク・ARPテーブル (`collector/network`)
- **ARP/近隣キャッシュ取得**:
  - **Linux**: `/proc/net/arp` のパース、またはNetlinkソケットによる近隣キャッシュ（RTM_GETNEIGH）取得
  - **Windows**: `iphlpapi.dll` の `GetIpNetTable2` を `syscall` で直接呼び出し
  - **macOS**: ルーティングソケット（`sysctl` の `NET_RT_FLAGS` + `RTF_LLINFO`）のパース
- **ネットワーク状態**:
  - `net.Interfaces()` によるリンク状態、IP/MACアドレス、MTUの取得
  - リスニングポートおよびソケット一覧（`/proc/net/tcp`, `/proc/net/udp`、Windows API `GetExtendedTcpTable` 等）

### 3.3 セキュリティ・整合性監視 (`collector/security`)
#### A. ファイル整合性監視 (FIM)
- 主要システムファイル・設定ディレクトリの改ざん検知（新規作成、更新、削除、属性変更）。
- 監視方式: OSネイティブイベント（Linux: `inotify`, Windows: `ReadDirectoryChangesW`, macOS: `kqueue`）。
- ハッシュアルゴリズム: `crypto/sha256`。

#### B. ログストリーム収集 (Log Tailer)
- OS標準のセキュリティログを追従読み込み（ローテーション自動追従）。
  - **Linux**: `/var/log/auth.log`, `/var/log/secure`, `/var/log/syslog`
  - **Windows**: Windows Event Log API (`EvtSubscribe` / `EvtQuery`)
  - **macOS**: `/var/log/system.log` または Apple Unified Log (OSLog) 連携

---

## 4. 監査・AI判定エンジン仕様 (`engine/audit`)

### 4.1 第1層：Sigmaルール評価 (TWSLA移植)
- **TWSLAのPure Go実装を移植**: 高速パースおよび正規表現・ワイルドカード評価。
- **厳選ルールの内蔵（embed.FS）**:
  - Sigma公式およびWazuh公開ルールから、重大なインシデント（認証突破、特権昇格、不正実行）に直結するルールを内蔵。
- **OS適応ロード**:
  - 起動時に `runtime.GOOS` を判定し、自OS用のルールのみをメモリ上に展開。

### 4.2 第2層：ローカルLLM Judge (`tensai` パッケージ連携)
Sigmaで検知された「疑わしいイベント」に対して、Go製ローカルLLMパッケージ `tensai` を呼び出し、コンテキストを考慮した評価を行う。

- **評価プロセス**:
  1. 対象イベントのログ、前後コンテキスト、関連プロセス、ユーザー情報を構造化プロンプトとして成形。
  2. `tensai` パッケージの推論APIに渡し、以下の観点をローカル判定させる。
     - **脅威判定（Threat Assessment）**: 管理操作や定期ジョブなどの誤検知（False Positive）でないか。
     - **コンプライアンス違反（Compliance Check）**: 特権昇格手順、データ持ち出しリスク、内部統制ポリシー違反の有無。
     - **日本語要約 & 推奨アクション**: 運用者が即座に把握・対処できる1〜2文のアドバイス生成。
- **フォールバック**:
  - `tensai` によるローカル推論がタイムアウト、またはハードウェア制約で利用不可の場合は、第1層のSigma検知結果をそのまま通知。

### 4.3 アラートデータモデル
```go
type SecurityAlert struct {
    Timestamp   time.Time              `json:"timestamp"`
    RuleID      string                 `json:"rule_id"`
    RuleTitle   string                 `json:"rule_title"`
    Level       string                 `json:"level"` // low, medium, high, critical
    Category    string                 `json:"category"`
    SourceLog   string                 `json:"source_log"`
    MatchedData map[string]interface{} `json:"matched_data"`
    
    // tensai パッケージによるローカルLLM判定結果
    AIJudge *AIJudgeResult             `json:"ai_judge,omitempty"`
}

type AIJudgeResult struct {
    IsThreat           bool     `json:"is_threat"`
    ComplianceViolated bool     `json:"compliance_violated"`
    ComplianceTypes    []string `json:"compliance_types"`    // e.g. ["Privilege_Abuse", "Unauthorized_Access"]
    Confidence         float64  `json:"confidence"`          // 0.0 - 1.0
    SummaryJa          string   `json:"summary_ja"`          // 日本語要約
    ActionJa           string   `json:"action_ja"`           // 推奨対処法
}
```

---

## 5. TWSNMP NEO / Twise MIB仕様 (`twise` MIBツリー)

Twise Labo Enterprise OID (`.1.3.6.1.4.1.17862`) 直下の `twagentNeo(3)` に定義。

### 5.1 OIDツリー構造
```text
iso(1).org(3).dod(6).internet(1).private(4).enterprises(1).twise(17862)
 └── twagentNeo(3)
      ├── twagentNeoObjects(1)
      │    ├── twagentNeoInfo(1)
      │    │    ├── twagentNeoVersion(1)       : DisplayString
      │    │    ├── twagentNeoHostname(2)      : DisplayString
      │    │    └── twagentNeoOS(3)            : DisplayString
      │    └── twagentNeoTrapObjects(2)
      │         ├── twagentNeoTrapSeverity(1)  : INTEGER { info(1), warn(2), high(3), critical(4) }
      │         ├── twagentNeoTrapCategory(2)  : DisplayString
      │         ├── twagentNeoTrapRuleTitle(3) : DisplayString
      │         ├── twagentNeoTrapAIJudge(4)   : DisplayString (e.g. "Threat:YES, CompViolation:YES")
      │         ├── twagentNeoTrapAISummary(5) : DisplayString (日本語要約)
      │         └── twagentNeoTrapAIAction(6)  : DisplayString (推奨対処)
      └── twagentNeoTraps(2)
           ├── twagentNeoTrapsPrefix(0)
           │    ├── twagentNeoResourceAlert(1) : リソース閾値超過アラート
           │    ├── twagentNeoSecurityAlert(2) : Sigma+tensai AI判定セキュリティアラート
           │    ├── twagentNeoFIMAlert(3)      : ファイル改ざんアラート
           │    └── twagentNeoHeartbeat(4)     : 定期キープアライブ
```

### 5.2 SNMP Trap 送信時のVarbinds構成 (`twagentNeoSecurityAlert`)
1. `sysUpTimeInstance` (`.1.3.6.1.2.1.1.3.0`)
2. `snmpTrapOID.0` (`.1.3.6.1.6.3.1.1.4.1.0`) = `.1.3.6.1.4.1.17862.3.2.0.2`
3. `twagentNeoHostname` (`.1.3.6.1.4.1.17862.3.1.1.2`)
4. `twagentNeoTrapSeverity` (`.1.3.6.1.4.1.17862.3.1.2.1`)
5. `twagentNeoTrapCategory` (`.1.3.6.1.4.1.17862.3.1.2.2`)
6. `twagentNeoTrapRuleTitle` (`.1.3.6.1.4.1.17862.3.1.2.3`)
7. `twagentNeoTrapAIJudge` (`.1.3.6.1.4.1.17862.3.1.2.4`)
8. `twagentNeoTrapAISummary` (`.1.3.6.1.4.1.17862.3.1.2.5`)
9. `twagentNeoTrapAIAction` (`.1.3.6.1.4.1.17862.3.1.2.6`)

---

## 6. 送信プロトコル仕様 (Exporters)

### 6.1 MQTT (`exporter/mqtt`)
- Pure Go MQTTライブラリ使用。
- トピック設計:
  - メトリクス: `twsnmpneo/agent/{agent_id}/metrics`
  - ARP/ネットワーク: `twsnmpneo/agent/{agent_id}/network`
  - セキュリティアラート: `twsnmpneo/agent/{agent_id}/alert`
  - 死活ステータス (LWT): `twsnmpneo/agent/{agent_id}/status`
- セキュリティアラートのPayloadには `ai_judge` フィールドが完全な形で埋め込まれる。

### 6.2 Syslog (`exporter/syslog`)
- Pure Go (`net` パッケージ) による UDP / TCP / TLS 送信。
- RFC 5424 形式。Structured Dataに `[twsnmpneo@17862 rule="..." threat="..." comp="..."]` を付与。

### 6.3 SNMP TRAP (`exporter/snmp_trap`)
- Pure Go SNMPライブラリ（`gosnmp`）使用。
- SNMPv2c / SNMPv3 (AuthPriv: SHA256/AES128) 対応。
- 第5章の `twagentNeo` MIB体系に基づいて送信。

---

## 7. ディレクトリ構成

```text
twagentneo/
├── cmd/
│   └── twagentneo/
│       └── main.go                  # エントリポイント・サービス管理
├── embed/
│   ├── rules/
│   │   ├── linux/                   # Linux向け厳選主要ルール (YAML)
│   │   ├── windows/                 # Windows向け厳選主要ルール (YAML)
│   │   └── darwin/                  # macOS向け厳選主要ルール (YAML)
│   └── mibs/
│       └── TWAGENT-NEO-MIB.txt      # 新規定義MIBファイル
├── internal/
│   ├── collector/                   # OS別コレクター (Pure Go)
│   │   ├── resource/
│   │   ├── network/
│   │   ├── fim/
│   │   └── logtail/
│   ├── audit/                       # 2段階監査エンジン
│   │   ├── sigma/                   # TWSLAから移植したSigmaエンジン
│   │   └── aijudge/                 # tensai パッケージを用いたLLM判定層
│   │       ├── judge.go
│   │       └── prompt.go
│   ├── exporter/                    # 送信層 (Pure Go)
│   │   ├── mqtt.go
│   │   ├── syslog.go
│   │   └── snmptrap.go
│   ├── config/
│   │   └── config.go
│   └── pipeline/
│       └── bus.go
├── config.example.yaml
├── go.mod
├── go.sum
└── Makefile
```

---

## 8. 設定ファイル仕様 (`twagentneo.yaml`)

運用を極小化するため、ルールファイル等の指定は不要。ローカルLLM（tensai）の有効化と送信先のみを記述する。

```yaml
agent:
  id: "twagentneo-server-01"
  name: "Host-01"
  log_level: "info"

collectors:
  resource:
    enabled: true
    interval: 60s
  network:
    enabled: true
    interval: 180s
    arp_watch: true
  fim:
    enabled: true
  logs:
    enabled: true

# 2段階監査設定
audit:
  sigma:
    enabled: true              # 内蔵Sigmaルール自動実行
  ai_judge:
    enabled: true              # tensai パッケージによるローカルLLM判定
    model_path: ""             # 指定時はカスタムモデルパス、空の場合はtensaiデフォルト
    timeout: 5s                # 推論タイムアウト

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
    format: "rfc5424"

  snmp_trap:
    enabled: true
    target: "twsnmp-neo-server:162"
    version: "v3"
    community: "public"
    v3:
      user: "twsnmpUser"
      auth_protocol: "SHA256"
      auth_password: "${TRAP_AUTH_PASS}"
      priv_protocol: "AES128"
      priv_password: "${TRAP_PRIV_PASS}"
```

---

## 9. ビルド要件

- **CGO完全無効化（静的シングルバイナリ）**:
  ```bash
  CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -ldflags="-s -w" -o twagentneo-linux-amd64 ./cmd/twagentneo
  CGO_ENABLED=0 GOOS=windows GOARCH=amd64 go build -ldflags="-s -w" -o twagentneo-windows-amd64.exe ./cmd/twagentneo
  CGO_ENABLED=0 GOOS=darwin GOARCH=arm64 go build -ldflags="-s -w" -o twagentneo-darwin-arm64 ./cmd/twagentneo
  ```
  