package bship

import (
	"bytes"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestCLISealInspectDecryptHappyPath(t *testing.T) {
	dir := testWorkspace(t)
	inputPath := filepath.Join(dir, "input.bin")
	archivePath := filepath.Join(dir, "sample.bship")
	outputPath := filepath.Join(dir, "output.bin")

	plaintext := []byte("ABCD1234")
	writeTestFile(t, inputPath, plaintext)

	if code := RunCLI([]string{"seal", "--in", inputPath, "--out", archivePath, "--threshold", "4", "--chunk-size", "4"}, ioDiscard(), ioDiscard()); code != 0 {
		t.Fatalf("seal exited with code %d", code)
	}

	var inspectOut bytes.Buffer
	if code := RunCLI([]string{"inspect", "--archive", archivePath}, &inspectOut, ioDiscard()); code != 0 {
		t.Fatalf("inspect exited with code %d", code)
	}

	var inspection Inspection
	if err := json.Unmarshal(inspectOut.Bytes(), &inspection); err != nil {
		t.Fatalf("parse inspect output: %v", err)
	}
	if inspection.RemainingPlaintext != int64(len(plaintext)) {
		t.Fatalf("remaining bytes = %d, want %d", inspection.RemainingPlaintext, len(plaintext))
	}
	if inspection.Decryptable {
		t.Fatalf("archive should not be decryptable before pruning")
	}

	if code := RunCLI([]string{"prune", "--archive", archivePath, "--keep", "0"}, ioDiscard(), ioDiscard()); code != 0 {
		t.Fatalf("prune exited with code %d", code)
	}
	if code := RunCLI([]string{"decrypt", "--archive", archivePath, "--out", outputPath}, ioDiscard(), ioDiscard()); code != 0 {
		t.Fatalf("decrypt exited with code %d", code)
	}

	got, err := os.ReadFile(outputPath)
	if err != nil {
		t.Fatalf("read output: %v", err)
	}
	if string(got) != "ABCD" {
		t.Fatalf("decrypted output = %q, want %q", got, "ABCD")
	}
}

func TestThresholdRefusal(t *testing.T) {
	dir := testWorkspace(t)
	inputPath := filepath.Join(dir, "threshold.bin")
	archivePath := filepath.Join(dir, "threshold.bship")
	writeTestFile(t, inputPath, []byte("abcdefgh"))

	_, err := SealFile(SealOptions{
		InputPath:      inputPath,
		ArchivePath:    archivePath,
		ThresholdBytes: 4,
		ChunkSizeBytes: 4,
		ArchiveID:      "threshold-test",
		Now:            fixedNow,
		Rand:           &deterministicReader{},
	})
	if err != nil {
		t.Fatalf("seal: %v", err)
	}

	if _, err := DecryptArchive(DecryptOptions{ArchivePath: archivePath}); !errors.Is(err, errThresholdExceeded) {
		t.Fatalf("decrypt error = %v, want threshold exceeded", err)
	}
	if _, err := PruneArchive(PruneOptions{ArchivePath: archivePath, Keep: []string{"0", "1"}}); !errors.Is(err, errThresholdExceeded) {
		t.Fatalf("prune error = %v, want threshold exceeded", err)
	}
}

func TestDestroyedChunkIrrecoverable(t *testing.T) {
	dir := testWorkspace(t)
	inputPath := filepath.Join(dir, "destroy.bin")
	archivePath := filepath.Join(dir, "destroy.bship")
	writeTestFile(t, inputPath, []byte("abcdefgh"))

	_, err := SealFile(SealOptions{
		InputPath:      inputPath,
		ArchivePath:    archivePath,
		ThresholdBytes: 4,
		ChunkSizeBytes: 4,
		ArchiveID:      "destroy-test",
		Now:            fixedNow,
		Rand:           &deterministicReader{},
	})
	if err != nil {
		t.Fatalf("seal: %v", err)
	}
	archive, err := PruneArchive(PruneOptions{ArchivePath: archivePath, Keep: []string{"0"}})
	if err != nil {
		t.Fatalf("prune: %v", err)
	}
	if !archive.Manifest.Chunks[1].Destroyed || archive.Capsules[1].Ciphertext != "" {
		t.Fatalf("destroyed chunk capsule still present")
	}

	wrapKey, err := decodeBase64URL(archive.State.CapsuleWrapKeyBase64)
	if err != nil {
		t.Fatalf("decode wrap key: %v", err)
	}
	if _, err := decryptChunkAt(archive, wrapKey, 1); !errors.Is(err, errDestroyedCapsule) {
		t.Fatalf("decrypt destroyed chunk error = %v, want destroyed capsule", err)
	}
}

func TestArchiveRejectsInvalidNonceLengths(t *testing.T) {
	tests := []struct {
		name   string
		mutate func(*Archive)
	}{
		{
			name: "chunk nonce",
			mutate: func(archive *Archive) {
				archive.Chunks[0].NonceBase64 = encodeBase64URL([]byte{0x01})
			},
		},
		{
			name: "capsule nonce",
			mutate: func(archive *Archive) {
				archive.Capsules[0].NonceBase64 = encodeBase64URL([]byte{0x02})
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			dir := testWorkspace(t)
			inputPath := filepath.Join(dir, "nonce.bin")
			archivePath := filepath.Join(dir, "nonce.bship")
			writeTestFile(t, inputPath, []byte("abcd"))

			_, err := SealFile(SealOptions{
				InputPath:      inputPath,
				ArchivePath:    archivePath,
				ThresholdBytes: 4,
				ChunkSizeBytes: 4,
				ArchiveID:      "nonce-test",
				Now:            fixedNow,
				Rand:           &deterministicReader{},
			})
			if err != nil {
				t.Fatalf("seal: %v", err)
			}

			archive, err := loadArchive(archivePath)
			if err != nil {
				t.Fatalf("load archive: %v", err)
			}
			tt.mutate(archive)
			if err := writeArchive(archivePath, archive); err != nil {
				t.Fatalf("write archive: %v", err)
			}

			_, err = DecryptArchive(DecryptOptions{ArchivePath: archivePath})
			if err == nil || !strings.Contains(err.Error(), "must be 12 bytes") {
				t.Fatalf("decrypt error = %v, want invalid nonce length", err)
			}
		})
	}
}

func TestNormalizeModeAcceptsPreferredAndAlias(t *testing.T) {
	tests := []struct {
		name  string
		value Mode
		want  Mode
	}{
		{name: "default empty", value: "", want: WeakMode},
		{name: "weak", value: WeakMode, want: WeakMode},
		{name: "preferred simulated strong", value: StrongMode, want: StrongMode},
		{name: "compatibility alias", value: StrongModeAlias, want: StrongMode},
		{name: "trim and case fold", value: Mode("  Simulated-Strong "), want: StrongMode},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := normalizeMode(tt.value)
			if err != nil {
				t.Fatalf("normalizeMode(%q) error = %v", tt.value, err)
			}
			if got != tt.want {
				t.Fatalf("normalizeMode(%q) = %q, want %q", tt.value, got, tt.want)
			}
		})
	}
}

func TestSealFileRejectsInvalidMode(t *testing.T) {
	dir := testWorkspace(t)
	inputPath := filepath.Join(dir, "invalid-mode.bin")
	archivePath := filepath.Join(dir, "invalid-mode.bship")
	writeTestFile(t, inputPath, []byte("abcdefgh"))

	_, err := SealFile(SealOptions{
		InputPath:      inputPath,
		ArchivePath:    archivePath,
		ThresholdBytes: 4,
		ChunkSizeBytes: 4,
		Mode:           Mode("actually-strong"),
	})
	if err == nil {
		t.Fatal("SealFile accepted invalid mode")
	}
	if !strings.Contains(err.Error(), `unsupported mode "actually-strong"`) {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestSimulatedStrongModeRejectsRollbackFromCopiedArchive(t *testing.T) {
	dir := testWorkspace(t)
	inputPath := filepath.Join(dir, "strong.bin")
	archivePath := filepath.Join(dir, "strong.bship")
	copyPath := filepath.Join(dir, "strong-copy.bship")
	storePath := filepath.Join(dir, "trusted.json")
	writeTestFile(t, inputPath, []byte("abcdefgh"))

	_, err := SealFile(SealOptions{
		InputPath:        inputPath,
		ArchivePath:      archivePath,
		ThresholdBytes:   4,
		ChunkSizeBytes:   4,
		Mode:             StrongMode,
		TrustedStorePath: storePath,
		ArchiveID:        "strong-test",
		Now:              fixedNow,
		Rand:             &deterministicReader{},
	})
	if err != nil {
		t.Fatalf("seal: %v", err)
	}
	archive, err := loadArchive(archivePath)
	if err != nil {
		t.Fatalf("load archive: %v", err)
	}
	if archive.State.CapsuleWrapKeyBase64 != "" {
		t.Fatalf("simulated-strong archive should not carry wrap key material")
	}

	copyFile(t, archivePath, copyPath)

	if _, err := PruneArchive(PruneOptions{
		ArchivePath:      archivePath,
		Keep:             []string{"0"},
		Mode:             StrongMode,
		TrustedStorePath: storePath,
	}); err != nil {
		t.Fatalf("strong prune: %v", err)
	}

	if _, err := DecryptArchive(DecryptOptions{
		ArchivePath:      copyPath,
		Mode:             StrongMode,
		TrustedStorePath: storePath,
	}); !errors.Is(err, errStaleArchiveState) {
		t.Fatalf("stale decrypt error = %v, want stale state", err)
	}

	if _, err := DecryptArchive(DecryptOptions{
		ArchivePath:      archivePath,
		Mode:             StrongMode,
		TrustedStorePath: storePath,
	}); err != nil {
		t.Fatalf("decrypt current strong archive: %v", err)
	}
}

func TestWeakModeCopyBeforePruneAttackSucceeds(t *testing.T) {
	dir := testWorkspace(t)
	inputPath := filepath.Join(dir, "weak.bin")
	archivePath := filepath.Join(dir, "weak.bship")
	copyPath := filepath.Join(dir, "weak-copy.bship")
	writeTestFile(t, inputPath, []byte("abcdefgh"))

	_, err := SealFile(SealOptions{
		InputPath:      inputPath,
		ArchivePath:    archivePath,
		ThresholdBytes: 4,
		ChunkSizeBytes: 4,
		ArchiveID:      "weak-test",
		Now:            fixedNow,
		Rand:           &deterministicReader{},
	})
	if err != nil {
		t.Fatalf("seal: %v", err)
	}

	copyFile(t, archivePath, copyPath)

	if _, err := PruneArchive(PruneOptions{ArchivePath: archivePath, Keep: []string{"0"}}); err != nil {
		t.Fatalf("prune original: %v", err)
	}
	if _, err := PruneArchive(PruneOptions{ArchivePath: copyPath, Keep: []string{"1"}}); err != nil {
		t.Fatalf("prune copy: %v", err)
	}

	first, err := DecryptArchive(DecryptOptions{ArchivePath: archivePath})
	if err != nil {
		t.Fatalf("decrypt first: %v", err)
	}
	second, err := DecryptArchive(DecryptOptions{ArchivePath: copyPath})
	if err != nil {
		t.Fatalf("decrypt second: %v", err)
	}

	combined := append(append([]byte(nil), first...), second...)
	if string(combined) != "abcdefgh" {
		t.Fatalf("combined plaintext = %q, want full original", combined)
	}
}

func TestSealFileDeterministicModeStable(t *testing.T) {
	tests := []struct {
		name      string
		mode      Mode
		withStore bool
	}{
		{name: "weak", mode: WeakMode},
		{name: "simulated-strong", mode: StrongMode, withStore: true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			dir := testWorkspace(t)
			inputPath := filepath.Join(dir, "input.bin")
			archivePathA := filepath.Join(dir, "first.bship")
			archivePathB := filepath.Join(dir, "second.bship")
			storePathA := filepath.Join(dir, "first-trusted.json")
			storePathB := filepath.Join(dir, "second-trusted.json")
			writeTestFile(t, inputPath, []byte("ABCD1234"))

			seal := func(archivePath, storePath string) {
				t.Helper()
				_, err := SealFile(SealOptions{
					InputPath:        inputPath,
					ArchivePath:      archivePath,
					ThresholdBytes:   4,
					ChunkSizeBytes:   4,
					Mode:             tt.mode,
					TrustedStorePath: storePath,
					Deterministic:    true,
					ArchiveID:        "deterministic-" + tt.name,
				})
				if err != nil {
					t.Fatalf("seal %s: %v", archivePath, err)
				}
			}

			seal(archivePathA, storePathA)
			seal(archivePathB, storePathB)

			if !bytes.Equal(readTestFile(t, archivePathA), readTestFile(t, archivePathB)) {
				t.Fatalf("%s deterministic seal output differed", tt.name)
			}
			if tt.withStore && !bytes.Equal(readTestFile(t, storePathA), readTestFile(t, storePathB)) {
				t.Fatalf("%s deterministic trusted-store output differed", tt.name)
			}

			prune := func(archivePath, storePath string) []byte {
				t.Helper()
				if _, err := PruneArchive(PruneOptions{
					ArchivePath:      archivePath,
					Keep:             []string{"0"},
					Mode:             tt.mode,
					TrustedStorePath: storePath,
				}); err != nil {
					t.Fatalf("prune %s: %v", archivePath, err)
				}
				plaintext, err := DecryptArchive(DecryptOptions{
					ArchivePath:      archivePath,
					Mode:             tt.mode,
					TrustedStorePath: storePath,
				})
				if err != nil {
					t.Fatalf("decrypt %s: %v", archivePath, err)
				}
				return plaintext
			}

			plaintextA := prune(archivePathA, storePathA)
			plaintextB := prune(archivePathB, storePathB)
			if string(plaintextA) != "ABCD" || string(plaintextB) != "ABCD" {
				t.Fatalf("%s deterministic decrypt outputs = %q and %q, want %q", tt.name, plaintextA, plaintextB, "ABCD")
			}
			if !bytes.Equal(readTestFile(t, archivePathA), readTestFile(t, archivePathB)) {
				t.Fatalf("%s deterministic pruned archive output differed", tt.name)
			}
			if tt.withStore && !bytes.Equal(readTestFile(t, storePathA), readTestFile(t, storePathB)) {
				t.Fatalf("%s deterministic pruned trusted-store output differed", tt.name)
			}
		})
	}
}

func TestSealFileWithoutDeterministicStillRandomized(t *testing.T) {
	dir := testWorkspace(t)
	inputPath := filepath.Join(dir, "input.bin")
	archivePathA := filepath.Join(dir, "first.bship")
	archivePathB := filepath.Join(dir, "second.bship")
	writeTestFile(t, inputPath, []byte("ABCD1234"))

	seal := func(path string) {
		t.Helper()
		_, err := SealFile(SealOptions{
			InputPath:      inputPath,
			ArchivePath:    path,
			ThresholdBytes: 4,
			ChunkSizeBytes: 4,
			ArchiveID:      "non-deterministic-check",
			Now:            fixedNow,
		})
		if err != nil {
			t.Fatalf("seal %s: %v", path, err)
		}
	}

	seal(archivePathA)
	seal(archivePathB)

	if bytes.Equal(readTestFile(t, archivePathA), readTestFile(t, archivePathB)) {
		t.Fatal("seal output unexpectedly matched without deterministic mode")
	}

	for _, path := range []string{archivePathA, archivePathB} {
		if _, err := PruneArchive(PruneOptions{ArchivePath: path, Keep: []string{"0"}}); err != nil {
			t.Fatalf("prune %s: %v", path, err)
		}
		plaintext, err := DecryptArchive(DecryptOptions{ArchivePath: path})
		if err != nil {
			t.Fatalf("decrypt %s: %v", path, err)
		}
		if string(plaintext) != "ABCD" {
			t.Fatalf("decrypt %s = %q, want %q", path, plaintext, "ABCD")
		}
	}
}

type deterministicReader struct {
	next byte
}

func (r *deterministicReader) Read(p []byte) (int, error) {
	for i := range p {
		p[i] = r.next
		r.next++
	}
	return len(p), nil
}

func fixedNow() time.Time {
	return time.Date(2026, time.April, 29, 0, 0, 0, 0, time.UTC)
}

func testWorkspace(t *testing.T) string {
	t.Helper()
	dir, err := os.MkdirTemp(".", "bship-test-")
	if err != nil {
		t.Fatalf("mkdir temp: %v", err)
	}
	t.Cleanup(func() {
		os.RemoveAll(dir)
	})
	return dir
}

func writeTestFile(t *testing.T, path string, data []byte) {
	t.Helper()
	if err := os.WriteFile(path, data, 0o600); err != nil {
		t.Fatalf("write %s: %v", path, err)
	}
}

func copyFile(t *testing.T, src, dst string) {
	t.Helper()
	data, err := os.ReadFile(src)
	if err != nil {
		t.Fatalf("read %s: %v", src, err)
	}
	if err := os.WriteFile(dst, data, 0o600); err != nil {
		t.Fatalf("write %s: %v", dst, err)
	}
}

type discardWriter struct{}

func (discardWriter) Write(p []byte) (int, error) {
	return len(p), nil
}

func ioDiscard() discardWriter {
	return discardWriter{}
}
