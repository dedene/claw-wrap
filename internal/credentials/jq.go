package credentials

import (
	"context"
	"encoding/json"
	"fmt"
	"time"

	"github.com/itchyny/gojq"
)

// jqTimeout is the maximum time allowed for jq expression evaluation.
// This prevents infinite loops or excessive computation.
const jqTimeout = 5 * time.Second

// ApplyJQ extracts a value from JSON using a jq expression.
// Returns the result as a string. Non-string results are JSON-marshaled.
func ApplyJQ(ctx context.Context, jsonBytes []byte, jqExpr string) (string, error) {
	// Parse jq expression
	query, err := gojq.Parse(jqExpr)
	if err != nil {
		return "", fmt.Errorf("invalid jq expression: %w", err)
	}

	// Parse JSON input
	var input any
	if err := json.Unmarshal(jsonBytes, &input); err != nil {
		return "", fmt.Errorf("invalid JSON for jq: %w", err)
	}

	// Run with timeout
	ctx, cancel := context.WithTimeout(ctx, jqTimeout)
	defer cancel()

	iter := query.RunWithContext(ctx, input)

	// Get first result
	v, ok := iter.Next()
	if !ok {
		return "", fmt.Errorf("jq expression returned no results")
	}

	// Handle errors in result
	if err, ok := v.(error); ok {
		// HaltError with nil value means normal end of iteration
		if haltErr, ok := err.(*gojq.HaltError); ok && haltErr.Value() == nil {
			return "", fmt.Errorf("jq expression returned no results")
		}
		return "", fmt.Errorf("jq evaluation failed: %w", err)
	}

	// Convert to string
	return resultToString(v)
}

// resultToString converts a jq result to a string.
func resultToString(v any) (string, error) {
	switch val := v.(type) {
	case string:
		return val, nil
	case nil:
		return "", fmt.Errorf("jq expression returned null")
	case bool:
		if val {
			return "true", nil
		}
		return "false", nil
	case int:
		return fmt.Sprintf("%d", val), nil
	case float64:
		// Check if it's a whole number
		if val == float64(int64(val)) {
			return fmt.Sprintf("%d", int64(val)), nil
		}
		return fmt.Sprintf("%g", val), nil
	default:
		// For arrays and objects, return JSON representation
		result, err := json.Marshal(val)
		if err != nil {
			return "", fmt.Errorf("failed to marshal jq result: %w", err)
		}
		return string(result), nil
	}
}
