package validator

import "testing"

// R-034: CNAME traversal must detect loops (bogus) and depth exhaustion
// (indeterminate) instead of silently terminating as secure.
func TestR034_CNAMEGuard(t *testing.T) {
	const maxDepth = 10

	// Self-loop A -> A.
	{
		visited := map[string]bool{canonicalizeName("a.example."): true}
		res, stop := cnameGuard("a.example.", "a.example.", 0, maxDepth, visited)
		if !stop || res == nil || res.Result != StatusBogus {
			t.Fatalf("self-CNAME must be a bogus loop, got stop=%v res=%+v", stop, res)
		}
	}

	// Two-name loop A -> B -> A: B already visited when following B -> A.
	{
		visited := map[string]bool{
			canonicalizeName("a.example."): true,
			canonicalizeName("b.example."): true,
		}
		res, stop := cnameGuard("b.example.", "a.example.", 1, maxDepth, visited)
		if !stop || res == nil || res.Result != StatusBogus {
			t.Fatalf("A->B->A must be a bogus loop, got stop=%v res=%+v", stop, res)
		}
	}

	// Case-insensitive loop: visited holds lowercase; target differs only by case.
	{
		visited := map[string]bool{canonicalizeName("target.example."): true}
		res, stop := cnameGuard("src.example.", "TARGET.Example.", 2, maxDepth, visited)
		if !stop || res == nil || res.Result != StatusBogus {
			t.Fatalf("mixed-case loop must be detected, got stop=%v res=%+v", stop, res)
		}
	}

	// Depth limit reached (acyclic): indeterminate, not secure.
	{
		visited := map[string]bool{}
		res, stop := cnameGuard("deep.example.", "next.example.", maxDepth-1, maxDepth, visited)
		if !stop || res == nil || res.Result != StatusIndeterminate {
			t.Fatalf("depth-exceeded must be indeterminate, got stop=%v res=%+v", stop, res)
		}
	}

	// Normal hop below the limit and not previously visited: proceed, and target
	// becomes visited.
	{
		visited := map[string]bool{canonicalizeName("a.example."): true}
		res, stop := cnameGuard("a.example.", "b.example.", 0, maxDepth, visited)
		if stop || res != nil {
			t.Fatalf("a normal hop must proceed, got stop=%v res=%+v", stop, res)
		}
		if !visited[canonicalizeName("b.example.")] {
			t.Fatal("cnameGuard must mark the target visited on the proceed path")
		}
	}
}
