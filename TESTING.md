# twagentneo アラートテスト手順書 (Testing Guide)

このドキュメントでは、macOS や Linux 環境において **FIM（ファイル整合性監視）** および **Sigma ルールエンジン** のアラート検知をローカル環境で安全にテストする手順を説明します。

---

## 1. 事前準備 (設定ファイル)

ローカルテスト用の設定ファイル（例: `config.yaml`）を用意します。  
監視対象として、管理者権限（root）を必要としないテスト専用ディレクトリ・ファイルを指定することで、安全にアラートを検証できます。

```yaml
agent:
  id: "twagentneo-test"
  name: "Local-TestHost"
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
    paths:
      # テスト用監視ディレクトリ (一般ユーザー権限で検証可能)
      - ./test_fim
  logs:
    enabled: true
    paths:
      # テスト用監視ログファイル
      - ./test.log

audit:
  sigma:
    enabled: true              # 内蔵Sigmaルール自動実行
  ai_judge:
    enabled: false             # テスト時はfalse (GGUFモデルがある場合はtrue)
    model_path: ""
    timeout: 5s

exporters:
  mqtt:
    enabled: false             # ローカルにMQTTブローカーがない場合はfalse推奨
    broker: "tcp://127.0.0.1:1883"
    client_id: "twagentneo-01"
    topic_prefix: "twsnmpneo/agent"

  syslog:
    enabled: false
    endpoint: "udp://127.0.0.1:514"
    format: "rfc5424"

  snmp_trap:
    enabled: false             # ローカルにSNMP Trapレシーバーがない場合はfalse推奨
    target: "127.0.0.1:162"
    version: "v2c"
    community: "trap"
```

テスト用のディレクトリと空のログファイルを作成します：

```bash
mkdir -p test_fim
touch test.log
```

---

## 2. エージェントのビルドと起動

ターミナル 1 でエージェントを起動します。

```bash
# ビルド
go build -o twagentneo ./cmd/twagentneo

# 起動 (動作確認のために詳細な収集・送信ログをコンソールに出力する場合は -debug を指定)
./twagentneo -config ./config.yaml -debug
```

起動に成功すると、内蔵 Sigma ルールが OS に合わせて自動ロードされます（macOS の場合は darwin 用ルール 33 件）。

```text
twagentneo v0.1.0 starting — os=darwin arch=arm64
agent id=twagentneo-test name=Local-TestHost
[sigma] engine ready: os=darwin rules=33
[sigma] loaded 33 rules for darwin
```

---

## 3. FIM (ファイル整合性監視) のテスト

ターミナル 2 を開き、監視対象の `test_fim` ディレクトリ内でファイル操作を行います。

### 3.1 ファイルの新規作成 (create)
```bash
echo "initial data" > test_fim/sample.txt
```
**検知ログ:**
```text
[fim] alert: op=create path=test_fim/sample.txt hash=b8a3e...
```
*(SHA-256 ハッシュが自動計算されて付与されます)*

### 3.2 ファイルの変更 (write)
```bash
echo "modified data" >> test_fim/sample.txt
```
**検知ログ:**
```text
[fim] alert: op=write path=test_fim/sample.txt hash=4f1a2...
```

### 3.3 ファイルの削除 (remove)
```bash
rm test_fim/sample.txt
```
**検知ログ:**
```text
[fim] alert: op=remove path=test_fim/sample.txt hash=
```

---

## 4. Sigma ルール検知のテスト

ターミナル 2 で、`test.log` に各種攻撃・不審なイベントに該当するログ行を追記します。

### 4.1 SSH 認証失敗・無効ユーザーログイン試行 (SSH Brute Force)
```bash
echo "Oct 22 05:00:00 host sshd[1234]: Failed password for invalid user admin from 192.168.1.50 port 55555 ssh2" >> test.log
```
**検知ログ:**
```text
[alert] sigma alert: rule=591cb457-3f82-45e7-9d78-b1933f7c4e51 title="SSH Failed Password Authentication" level=low category=linux source=./test.log
[alert] sigma alert: rule=a82d3e14-257a-4bc2-81e0-c116d41829e0 title="SSH Login Attempt With Invalid User" level=medium category=linux source=./test.log
```

### 4.2 SQL インジェクション攻撃試行 (SQLi)
```bash
echo "192.168.1.100 - - [22/Oct/2026:05:00:00 +0900] \"GET /login?user=admin' OR 1=1-- HTTP/1.1\" 401 123" >> test.log
```
**検知ログ:**
```text
[alert] sigma alert: rule=b9b16ea2-df94-4322-83b3-f0fae1bc9842 title="SQL Injection Attempt" level=high category=webserver source=./test.log
```

### 4.3 クロスサイトスクリプティング (XSS)
```bash
echo "192.168.1.100 - - [22/Oct/2026:05:00:00 +0900] \"GET /search?q=<script>alert(1)</script> HTTP/1.1\" 200 456" >> test.log
```
**検知ログ:**
```text
[alert] sigma alert: rule=76d33ca2-a7d9-43c2-bd7e-f6bb2d348a27 title="Cross-Site Scripting Attempt" level=medium category=webserver source=./test.log
```

### 4.4 ディレクトリトラバーサル攻撃試行
```bash
echo "192.168.1.100 - - [22/Oct/2026:05:00:00 +0900] \"GET /../../etc/passwd HTTP/1.1\" 403 0" >> test.log
```
**検知ログ:**
```text
[alert] sigma alert: rule=737c35eb-06b2-4916-a94f-1736b412bf5b title="Directory Traversal Attempt" level=high category=webserver source=./test.log
```

---

## 5. テスト完了後のクリーンアップ

テスト用の一時ファイルやログをリセットする場合は以下を実行します：

```bash
rm -rf test_fim/*
: > test.log
```
