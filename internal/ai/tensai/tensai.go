// Package tensai provides a local GGUF LLM inference wrapper for twagentneo,
// ported from twsnmpfk/pkg/ai/tensai. It loads Qwen-family GGUF models and
// runs inference using github.com/mattn/tensai kernels (GPU/SIMD/CPU).
package tensai

import (
	"context"
	"errors"
	"strings"
)

// LLM is the interface for local LLM text generation.
type LLM interface {
	// GenerateText generates a completion for the given prompt.
	GenerateText(ctx context.Context, prompt string, maxTokens int) (string, error)
	// Close releases resources.
	Close()
}

// TensaiLLM implements LLM for embedded inference via tensai.
type TensaiLLM struct {
	modelPath string
	engine    *Engine
	accType   AccelerationType
	accDetail string
}

// New creates a new TensaiLLM instance with automatic GPU → SIMD → CPU fallback.
// modelPath must be a path to a GGUF model file.
func New(modelPath string) (*TensaiLLM, error) {
	return NewWithOptions(modelPath, false)
}

// NewWithOptions creates a new TensaiLLM instance with optional GPU bypass.
func NewWithOptions(modelPath string, noGPU bool) (*TensaiLLM, error) {
	if modelPath == "" {
		return nil, errors.New("tensai: model path cannot be empty")
	}

	accType, accDetail := DetectAccelerationWithOptions(noGPU)

	engine, _ := LoadEngineWithOptions(modelPath, noGPU)

	return &TensaiLLM{
		modelPath: modelPath,
		engine:    engine,
		accType:   accType,
		accDetail: accDetail,
	}, nil
}

// Acceleration returns the current active acceleration type and hardware details.
func (m *TensaiLLM) Acceleration() (AccelerationType, string) {
	if m.engine != nil && m.engine.gpu != nil {
		return AccelGPU, m.accDetail
	}
	return m.accType, m.accDetail
}

// GenerateText runs inference and returns the generated text.
// If the neural engine is not loaded, a static fallback string is returned.
func (m *TensaiLLM) GenerateText(ctx context.Context, prompt string, maxTokens int) (string, error) {
	if m.engine != nil {
		if maxTokens <= 0 {
			maxTokens = 512
		}
		return m.engine.GenerateText(ctx, prompt, maxTokens, nil)
	}
	// Fallback: engine not loaded (model file missing or corrupt).
	return m.fallback(prompt), nil
}

// Close releases the engine (currently a no-op; tensai has no explicit close).
func (m *TensaiLLM) Close() {}

func (m *TensaiLLM) fallback(prompt string) string {
	if strings.Contains(prompt, "日本語") || strings.Contains(prompt, "summary_ja") {
		return `{"is_threat":false,"compliance_violated":false,"compliance_types":[],"confidence":0.0,"summary_ja":"LLMモデルが利用できないため、自動評価は実行されませんでした。","action_ja":"モデルファイルのパスを設定してください。"}`
	}
	return `{"is_threat":false,"compliance_violated":false,"compliance_types":[],"confidence":0.0,"summary_ja":"Model unavailable.","action_ja":"Configure model_path."}`
}
