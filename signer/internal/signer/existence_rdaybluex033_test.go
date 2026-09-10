package signer

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"syscall"
	"testing"
)

// RDAYBLUEX-033: preservation decisions fail closed. Only a confirmed
// absence is "absent"; a stat, link or create failure aborts with nothing
// moved or replaced; destinations are claimed with no-clobber semantics.

func withSeams(t *testing.T) (calls *seamCalls) {
	t.Helper()
	calls = &seamCalls{}
	origStat, origLink, origRename, origRemove := osStat, osLink, osRename, osRemove
	osRename = func(a, b string) error { calls.renames++; return origRename(a, b) }
	osRemove = func(p string) error { calls.removes++; return origRemove(p) }
	t.Cleanup(func() { osStat, osLink, osRename, osRemove = origStat, origLink, origRename, origRemove })
	return calls
}

type seamCalls struct{ renames, removes int }

func write(t *testing.T, path, content string) {
	t.Helper()
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
}

func read(t *testing.T, path string) string {
	t.Helper()
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}

func TestRDAYBLUEX033_SetAsideNeverClobbers(t *testing.T) {
	calls := withSeams(t)
	dir := t.TempDir()
	src := filepath.Join(dir, "zone.ksk.private")
	write(t, src, "unusable material")
	// .0 is an existing backup, .1 a looping symlink, .2 a dangling symlink.
	write(t, src+".invalid.0", "earlier backup")
	if err := os.Symlink(src+".invalid.1", src+".invalid.1"); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(filepath.Join(dir, "nowhere"), src+".invalid.2"); err != nil {
		t.Fatal(err)
	}
	dst, err := setAside(src, "invalid")
	if err != nil {
		t.Fatal(err)
	}
	if dst != src+".invalid.3" {
		t.Fatalf("occupied names, including symlinks, are skipped: moved to %s", dst)
	}
	if read(t, src+".invalid.0") != "earlier backup" {
		t.Fatal("the earlier backup must be untouched")
	}
	if fi, err := os.Lstat(src + ".invalid.1"); err != nil || fi.Mode()&os.ModeSymlink == 0 {
		t.Fatal("the looping symlink must be untouched")
	}
	if read(t, dst) != "unusable material" {
		t.Fatal("the material must be preserved at the new name")
	}
	if _, err := os.Lstat(src); !os.IsNotExist(err) {
		t.Fatal("the original name must be released")
	}
	if calls.renames != 0 {
		t.Fatal("with hard links available no rename is attempted")
	}
}

func TestRDAYBLUEX033_SetAsideAbortsOnFailures(t *testing.T) {
	for _, tc := range []struct {
		name string
		err  error
	}{
		{"EACCES", syscall.EACCES},
		{"EIO", syscall.EIO},
		{"ELOOP", syscall.ELOOP},
		{"transient", errors.New("transient stat failure")},
	} {
		t.Run("link "+tc.name, func(t *testing.T) {
			calls := withSeams(t)
			dir := t.TempDir()
			src := filepath.Join(dir, "zone.zsk.private")
			write(t, src, "material")
			write(t, src+".orphan.0", "existing")
			osLink = func(a, b string) error { return &os.LinkError{Op: "link", Old: a, New: b, Err: tc.err} }
			_, err := setAside(src, "orphan")
			if err == nil || !errors.Is(err, tc.err) {
				t.Fatalf("the failure must be returned: %v", err)
			}
			if read(t, src) != "material" || read(t, src+".orphan.0") != "existing" {
				t.Fatal("nothing may be moved or replaced")
			}
			if calls.renames != 0 || calls.removes != 0 {
				t.Fatalf("no rename or remove after a failed claim: %+v", calls)
			}
		})
		t.Run("fallback stat "+tc.name, func(t *testing.T) {
			calls := withSeams(t)
			dir := t.TempDir()
			src := filepath.Join(dir, "zone.zsk.private")
			write(t, src, "material")
			// Hard links "unsupported" here, and the fail-closed stat fails.
			osLink = func(a, b string) error { return &os.LinkError{Op: "link", Old: a, New: b, Err: syscall.ENOTSUP} }
			osStat = func(p string) (os.FileInfo, error) {
				if strings.Contains(p, ".orphan.") {
					return nil, &os.PathError{Op: "stat", Path: p, Err: tc.err}
				}
				return os.Stat(p)
			}
			_, err := setAside(src, "orphan")
			if err == nil || !errors.Is(err, tc.err) {
				t.Fatalf("the stat failure must be returned: %v", err)
			}
			if read(t, src) != "material" || calls.renames != 0 || calls.removes != 0 {
				t.Fatalf("nothing may be moved: %+v", calls)
			}
		})
	}
	// With hard links unsupported and a healthy stat, the rename fallback
	// still skips an occupied name.
	calls := withSeams(t)
	dir := t.TempDir()
	src := filepath.Join(dir, "zone.zsk.private")
	write(t, src, "material")
	write(t, src+".orphan.0", "existing")
	osLink = func(a, b string) error { return &os.LinkError{Op: "link", Old: a, New: b, Err: syscall.EXDEV} }
	dst, err := setAside(src, "orphan")
	if err != nil || dst != src+".orphan.1" || read(t, src+".orphan.0") != "existing" || read(t, dst) != "material" {
		t.Fatalf("fallback: %s %v", dst, err)
	}
	if calls.renames != 1 {
		t.Fatal("the fallback renames exactly once")
	}
}

func TestRDAYBLUEX033_BackupNamesAreClaimedNotGuessed(t *testing.T) {
	dir := t.TempDir()
	prefix := filepath.Join(dir, "zone.ksk.bak")
	// .0 has an (empty) .key, .1 a looping symlink for .private: both taken.
	write(t, prefix+".0.key", "")
	if err := os.Symlink(prefix+".1.private", prefix+".1.private"); err != nil {
		t.Fatal(err)
	}
	base, err := uniqueBackupBase(prefix)
	if err != nil {
		t.Fatal(err)
	}
	if base != prefix+".2" {
		t.Fatalf("occupied names are skipped whatever their state: %s", base)
	}
	for _, ext := range []string{".key", ".private"} {
		fi, err := os.Stat(base + ext)
		if err != nil || fi.Size() != 0 || fi.Mode().Perm() != 0o600 {
			t.Fatalf("both halves are claimed as private placeholders: %v %v", fi, err)
		}
	}
	if _, err := os.Stat(prefix + ".0.key"); err != nil {
		t.Fatal("the existing file is untouched")
	}
	// A second allocation cannot get the same name.
	if again, err := uniqueBackupBase(prefix); err != nil || again == base {
		t.Fatalf("a claimed name is never handed out twice: %s %v", again, err)
	}
	// A directory that cannot be written is an error, never a "free" name.
	if os.Geteuid() == 0 {
		t.Skip("directory permissions do not restrict root")
	}
	ro := filepath.Join(t.TempDir(), "ro")
	if err := os.Mkdir(ro, 0o500); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Chmod(ro, 0o700) })
	if _, err := uniqueBackupBase(filepath.Join(ro, "zone.ksk.bak")); err == nil || !errors.Is(err, syscall.EACCES) {
		t.Fatalf("EACCES must abort the allocation: %v", err)
	}
	// A directory without search permission makes even stat fail: an
	// existence check inside it must be an error, not "absent".
	noSearch := filepath.Join(t.TempDir(), "nosearch")
	if err := os.Mkdir(noSearch, 0o000); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Chmod(noSearch, 0o700) })
	if _, err := statExists(filepath.Join(noSearch, "zone.ksk.key")); err == nil || !errors.Is(err, syscall.EACCES) {
		t.Fatalf("EACCES must be reported by statExists: %v", err)
	}
	// A transient I/O failure on stat is returned and stops a preservation
	// copy before anything is written.
	withSeams(t)
	osStat = func(p string) (os.FileInfo, error) { return nil, &os.PathError{Op: "stat", Path: p, Err: syscall.EIO} }
	if _, err := copyPairUnique(filepath.Join(dir, "zone.ksk"), prefix); err == nil || !errors.Is(err, syscall.EIO) {
		t.Fatalf("EIO must abort copyPairUnique: %v", err)
	}
}

func TestRDAYBLUEX033_ConcurrentClaimsAreDistinct(t *testing.T) {
	dir := t.TempDir()
	prefix := filepath.Join(dir, "zone.zsk.bak")
	const n = 16
	var wg sync.WaitGroup
	var mu sync.Mutex
	bases := map[string]int{}
	for i := 0; i < n; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			base, err := uniqueBackupBase(prefix)
			if err != nil {
				t.Errorf("allocate: %v", err)
				return
			}
			mu.Lock()
			bases[base]++
			mu.Unlock()
		}()
	}
	wg.Wait()
	if len(bases) != n {
		t.Fatalf("%d concurrent allocations must yield %d distinct names, got %v", n, n, bases)
	}

	// Concurrent set-asides into one namespace preserve every source.
	var wg2 sync.WaitGroup
	dsts := make([]string, n)
	for i := 0; i < n; i++ {
		src := filepath.Join(dir, fmt.Sprintf("src%02d.private", i))
		write(t, src, fmt.Sprintf("material %d", i))
	}
	shared := filepath.Join(dir, "slot.private")
	for i := 0; i < n; i++ {
		wg2.Add(1)
		go func(i int) {
			defer wg2.Done()
			// Every goroutine sets aside its own file under the shared name
			// space "<slot>.orphan.N".
			src := filepath.Join(dir, fmt.Sprintf("src%02d.private", i))
			if err := os.Rename(src, shared+fmt.Sprintf(".src%02d", i)); err != nil {
				t.Errorf("rename: %v", err)
				return
			}
			dst, err := setAsideAs(shared+fmt.Sprintf(".src%02d", i), shared, "orphan")
			if err != nil {
				t.Errorf("set aside: %v", err)
				return
			}
			dsts[i] = dst
		}(i)
	}
	wg2.Wait()
	seen := map[string]bool{}
	for i, dst := range dsts {
		if dst == "" || seen[dst] {
			t.Fatalf("destination %d (%q) is missing or duplicated", i, dst)
		}
		seen[dst] = true
		if read(t, dst) != fmt.Sprintf("material %d", i) {
			t.Fatalf("material %d was lost or replaced at %s", i, dst)
		}
	}
}

// setAsideAs is setAside with the destination namespace decoupled from the
// source path, for the concurrent no-clobber test.
func setAsideAs(src, slot, reason string) (string, error) {
	for i := 0; i < 10000; i++ {
		dst := fmt.Sprintf("%s.%s.%d", slot, reason, i)
		err := osLink(src, dst)
		if err == nil {
			_ = osRemove(src)
			return dst, nil
		}
		if errors.Is(err, os.ErrExist) {
			continue
		}
		return "", err
	}
	return "", fmt.Errorf("exhausted")
}
