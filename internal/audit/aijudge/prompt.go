package aijudge

import (
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"github.com/twsnmp/twagentneo/internal/audit"
)

// BuildPrompt constructs a structured prompt for the tensai LLM judge.
// The LLM is instructed to return a JSON object with the judgeResponseJSON schema.
func BuildPrompt(alert *audit.SecurityAlert, contextLogs []string) string {
	var sb strings.Builder

	sb.WriteString("あなたはセキュリティアナリストです。以下のセキュリティイベントを分析し、指定されたJSON形式のみで回答してください。\n\n")

	sb.WriteString("## 検知ルール\n")
	fmt.Fprintf(&sb, "- Rule ID: %s\n", alert.RuleID)
	fmt.Fprintf(&sb, "- Rule Title: %s\n", alert.RuleTitle)
	fmt.Fprintf(&sb, "- Level: %s\n", alert.Level)
	fmt.Fprintf(&sb, "- Category: %s\n", alert.Category)
	fmt.Fprintf(&sb, "- 検知時刻: %s\n\n", alert.Timestamp.Format(time.RFC3339))

	sb.WriteString("## 検知ログ\n```\n")
	sb.WriteString(alert.SourceLog)
	sb.WriteString("\n```\n\n")

	if len(alert.MatchedData) > 0 {
		sb.WriteString("## マッチしたフィールド\n")
		if j, err := json.MarshalIndent(alert.MatchedData, "", "  "); err == nil {
			sb.WriteString("```json\n")
			sb.Write(j)
			sb.WriteString("\n```\n\n")
		}
	}

	if len(contextLogs) > 0 {
		sb.WriteString("## 前後コンテキストログ（最大5件）\n```\n")
		limit := 5
		if len(contextLogs) < limit {
			limit = len(contextLogs)
		}
		for _, l := range contextLogs[:limit] {
			sb.WriteString(l)
			sb.WriteString("\n")
		}
		sb.WriteString("```\n\n")
	}

	sb.WriteString(`## 評価基準
1. **脅威判定 (is_threat)**: このイベントは実際の攻撃・不正行為か、または管理者操作・定常業務・誤検知か
2. **コンプライアンス違反 (compliance_violated)**: 特権昇格・データ持ち出し・内部統制違反などのリスクがあるか
3. **確信度 (confidence)**: 0.0〜1.0 で判定の確信度
4. **日本語要約 (summary_ja)**: 1〜2文で状況を説明
5. **推奨アクション (action_ja)**: 運用者が即座に取るべき対処を1〜2文で

## コンプライアンス違反タイプ（複数選択可）
- "Privilege_Abuse" — 特権濫用
- "Unauthorized_Access" — 不正アクセス
- "Data_Exfiltration" — データ持ち出し
- "Lateral_Movement" — 横断的移動
- "Persistence" — 永続化工作
- "Defense_Evasion" — 防御回避

## 出力形式（このJSONのみ出力すること）
` + "```json" + `
{
  "is_threat": true,
  "compliance_violated": false,
  "compliance_types": [],
  "confidence": 0.85,
  "summary_ja": "SSH認証失敗が短時間に多発しており、ブルートフォース攻撃の可能性があります。",
  "action_ja": "該当IPアドレスからのSSH接続をファイアウォールでブロックし、ログを詳細に確認してください。"
}
` + "```")

	return sb.String()
}
