package validator

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"sync/atomic"
)

// DefaultVerificationBudget is the number of cryptographic work units one
// validation may spend before it stops with an explicit resource-limit
// result. A unit is one signature verification attempt or one DS digest
// comparison. A typical chain (root → TLD → zone → leaf) with denial proofs
// and a double-signature rollover spends well under a hundred units; the
// review's adversarial fixture (128 colliding keys × 128 bad signatures)
// would spend 16,384. The default leaves ample room for large legitimate
// key sets while bounding a hostile response to a small, fixed amount of
// CPU per request (RA6X-052).
const DefaultVerificationBudget = 2000

// ErrVerificationBudgetExhausted is returned by budget-aware verification when
// a validation has spent its cryptographic work budget or its context has
// been cancelled. Callers report it as INDETERMINATE (a resource limit), never
// as secure and never as a cryptographic failure.
var ErrVerificationBudgetExhausted = errors.New("verification work budget exhausted")

// budgetExhaustedMessage is the substring by which string-typed error fields
// (proof.Error, DSValidation.Error, RecordValidation.Error) identify an
// exhausted budget or a cancelled validation.
const budgetExhaustedMessage = "verification work budget exhausted"

// VerifyBudget is the shared, cancellation-aware work budget of one
// validation. A nil *VerifyBudget is unbounded (used by the exported
// package-level helpers and by tests that exercise them directly).
type VerifyBudget struct {
	ctx       context.Context
	limit     int64
	spent     atomic.Int64
	exhausted atomic.Bool
}

// newVerifyBudget creates a budget of limit units bound to ctx.
func newVerifyBudget(ctx context.Context, limit int64) *VerifyBudget {
	if ctx == nil {
		ctx = context.Background()
	}
	return &VerifyBudget{ctx: ctx, limit: limit}
}

// charge consumes n units. It fails once the limit is exceeded or the
// validation's context is done; every later call fails too, so a validation
// that ran out of budget cannot resume verifying in another code path.
func (b *VerifyBudget) charge(n int64) error {
	if b == nil {
		return nil
	}
	if err := b.ctx.Err(); err != nil {
		b.exhausted.Store(true)
		return fmt.Errorf("%w: validation cancelled (%v)", ErrVerificationBudgetExhausted, err)
	}
	if b.exhausted.Load() {
		return fmt.Errorf("%w (limit %d units)", ErrVerificationBudgetExhausted, b.limit)
	}
	if b.spent.Add(n) > b.limit {
		b.exhausted.Store(true)
		return fmt.Errorf("%w (limit %d units)", ErrVerificationBudgetExhausted, b.limit)
	}
	return nil
}

// Spent reports the units consumed so far.
func (b *VerifyBudget) Spent() int64 {
	if b == nil {
		return 0
	}
	return b.spent.Load()
}

// IsBudgetExhausted reports whether err (or an error message) records an
// exhausted budget or cancelled validation.
func IsBudgetExhausted(err error) bool {
	if err == nil {
		return false
	}
	return errors.Is(err, ErrVerificationBudgetExhausted) || strings.Contains(err.Error(), budgetExhaustedMessage)
}

// isBudgetExhaustedText is IsBudgetExhausted for string-typed error fields.
func isBudgetExhaustedText(msg string) bool {
	return strings.Contains(msg, budgetExhaustedMessage)
}
