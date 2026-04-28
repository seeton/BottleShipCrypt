package bship

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"reflect"
	"testing"
)

const (
	weakVectorDir   = "test-vectors/weak-simulator-two-chunk"
	strongVectorDir = "test-vectors/simulated-strong-two-chunk"
	vectorWarning   = "Prototype/simulator test vector only; not production-security material."
	vectorPlaintext = "ABCD1234"
)

type vectorExpectations struct {
	Warning            string     `json:"warning"`
	SourcePlaintextUTF string     `json:"source_plaintext_utf8"`
	SealedInspection   Inspection `json:"sealed_inspection"`
	PrunedInspection   Inspection `json:"pruned_inspection"`
	PrunedPlaintextUTF string     `json:"pruned_plaintext_utf8"`
}

func TestDeterministicVectorFixtures(t *testing.T) {
	repoRoot, err := os.Getwd()
	if err != nil {
		t.Fatalf("getwd: %v", err)
	}

	t.Run("weak", func(t *testing.T) {
		generated := generateWeakVectorFiles(t)
		for relativePath, want := range generated {
			assertFixtureBytes(t, filepath.Join(repoRoot, relativePath), want)
		}
		validateWeakFixtures(t, repoRoot)
	})

	t.Run("simulated-strong", func(t *testing.T) {
		generated := generateStrongVectorFiles(t)
		for relativePath, want := range generated {
			assertFixtureBytes(t, filepath.Join(repoRoot, relativePath), want)
		}
		validateStrongFixtures(t, repoRoot)
	})
}

func generateWeakVectorFiles(t *testing.T) map[string][]byte {
	t.Helper()

	dir := testWorkspace(t)
	inputPath := filepath.Join(dir, "prototype-input.txt")
	archivePath := filepath.Join(dir, "weak-simulator-vector.bship")
	writeTestFile(t, inputPath, []byte(vectorPlaintext))

	if _, err := SealFile(SealOptions{
		InputPath:      inputPath,
		ArchivePath:    archivePath,
		ThresholdBytes: 4,
		ChunkSizeBytes: 4,
		ArchiveID:      "weak-simulator-vector",
		Now:            fixedNow,
		Rand:           &deterministicReader{},
	}); err != nil {
		t.Fatalf("seal weak vector: %v", err)
	}

	sealedInspection, err := InspectArchive(InspectOptions{ArchivePath: archivePath})
	if err != nil {
		t.Fatalf("inspect sealed weak vector: %v", err)
	}
	sealedArchive := readTestFile(t, archivePath)

	if _, err := PruneArchive(PruneOptions{ArchivePath: archivePath, Keep: []string{"0"}}); err != nil {
		t.Fatalf("prune weak vector: %v", err)
	}
	prunedInspection, err := InspectArchive(InspectOptions{ArchivePath: archivePath})
	if err != nil {
		t.Fatalf("inspect pruned weak vector: %v", err)
	}
	prunedPlaintext, err := DecryptArchive(DecryptOptions{ArchivePath: archivePath})
	if err != nil {
		t.Fatalf("decrypt pruned weak vector: %v", err)
	}

	return map[string][]byte{
		filepath.Join(weakVectorDir, "sealed.bship"): sealedArchive,
		filepath.Join(weakVectorDir, "pruned.bship"): readTestFile(t, archivePath),
		filepath.Join(weakVectorDir, "expected.json"): marshalVectorExpectations(t, vectorExpectations{
			Warning:            vectorWarning,
			SourcePlaintextUTF: vectorPlaintext,
			SealedInspection:   *sealedInspection,
			PrunedInspection:   *prunedInspection,
			PrunedPlaintextUTF: string(prunedPlaintext),
		}),
	}
}

func generateStrongVectorFiles(t *testing.T) map[string][]byte {
	t.Helper()

	dir := testWorkspace(t)
	inputPath := filepath.Join(dir, "prototype-input.txt")
	archivePath := filepath.Join(dir, "simulated-strong-vector.bship")
	storePath := filepath.Join(dir, "trusted-store.json")
	writeTestFile(t, inputPath, []byte(vectorPlaintext))

	if _, err := SealFile(SealOptions{
		InputPath:        inputPath,
		ArchivePath:      archivePath,
		ThresholdBytes:   4,
		ChunkSizeBytes:   4,
		Mode:             StrongMode,
		TrustedStorePath: storePath,
		ArchiveID:        "simulated-strong-vector",
		Now:              fixedNow,
		Rand:             &deterministicReader{},
	}); err != nil {
		t.Fatalf("seal strong vector: %v", err)
	}

	sealedInspection, err := InspectArchive(InspectOptions{
		ArchivePath:      archivePath,
		Mode:             StrongMode,
		TrustedStorePath: storePath,
	})
	if err != nil {
		t.Fatalf("inspect sealed strong vector: %v", err)
	}
	sealedArchive := readTestFile(t, archivePath)
	sealedStore := readTestFile(t, storePath)

	if _, err := PruneArchive(PruneOptions{
		ArchivePath:      archivePath,
		Keep:             []string{"0"},
		Mode:             StrongMode,
		TrustedStorePath: storePath,
	}); err != nil {
		t.Fatalf("prune strong vector: %v", err)
	}
	prunedInspection, err := InspectArchive(InspectOptions{
		ArchivePath:      archivePath,
		Mode:             StrongMode,
		TrustedStorePath: storePath,
	})
	if err != nil {
		t.Fatalf("inspect pruned strong vector: %v", err)
	}
	prunedPlaintext, err := DecryptArchive(DecryptOptions{
		ArchivePath:      archivePath,
		Mode:             StrongMode,
		TrustedStorePath: storePath,
	})
	if err != nil {
		t.Fatalf("decrypt pruned strong vector: %v", err)
	}

	return map[string][]byte{
		filepath.Join(strongVectorDir, "sealed.bship"):              sealedArchive,
		filepath.Join(strongVectorDir, "sealed.trusted-store.json"): sealedStore,
		filepath.Join(strongVectorDir, "pruned.bship"):              readTestFile(t, archivePath),
		filepath.Join(strongVectorDir, "pruned.trusted-store.json"): readTestFile(t, storePath),
		filepath.Join(strongVectorDir, "expected.json"): marshalVectorExpectations(t, vectorExpectations{
			Warning:            vectorWarning,
			SourcePlaintextUTF: vectorPlaintext,
			SealedInspection:   *sealedInspection,
			PrunedInspection:   *prunedInspection,
			PrunedPlaintextUTF: string(prunedPlaintext),
		}),
	}
}

func validateWeakFixtures(t *testing.T, repoRoot string) {
	t.Helper()

	expected := readVectorExpectations(t, filepath.Join(repoRoot, weakVectorDir, "expected.json"))
	assertVectorMetadata(t, expected)
	sealedArchivePath := filepath.Join(repoRoot, weakVectorDir, "sealed.bship")
	prunedArchivePath := filepath.Join(repoRoot, weakVectorDir, "pruned.bship")

	sealedInspection, err := InspectArchive(InspectOptions{ArchivePath: sealedArchivePath})
	if err != nil {
		t.Fatalf("inspect checked-in weak sealed vector: %v", err)
	}
	if !reflect.DeepEqual(*sealedInspection, expected.SealedInspection) {
		t.Fatalf("weak sealed inspection mismatch")
	}
	prunedInspection, err := InspectArchive(InspectOptions{ArchivePath: prunedArchivePath})
	if err != nil {
		t.Fatalf("inspect checked-in weak pruned vector: %v", err)
	}
	if !reflect.DeepEqual(*prunedInspection, expected.PrunedInspection) {
		t.Fatalf("weak pruned inspection mismatch")
	}
	prunedPlaintext, err := DecryptArchive(DecryptOptions{ArchivePath: prunedArchivePath})
	if err != nil {
		t.Fatalf("decrypt checked-in weak pruned vector: %v", err)
	}
	if string(prunedPlaintext) != expected.PrunedPlaintextUTF {
		t.Fatalf("weak pruned plaintext = %q, want %q", prunedPlaintext, expected.PrunedPlaintextUTF)
	}

	sealedArchive, err := loadArchive(sealedArchivePath)
	if err != nil {
		t.Fatalf("load checked-in weak sealed vector: %v", err)
	}
	prunedArchive, err := loadArchive(prunedArchivePath)
	if err != nil {
		t.Fatalf("load checked-in weak pruned vector: %v", err)
	}
	if sealedArchive.State.CapsuleWrapKeyBase64 == "" || prunedArchive.State.CapsuleWrapKeyBase64 == "" {
		t.Fatal("weak fixtures should retain archive-local wrap key material")
	}
}

func validateStrongFixtures(t *testing.T, repoRoot string) {
	t.Helper()

	expected := readVectorExpectations(t, filepath.Join(repoRoot, strongVectorDir, "expected.json"))
	assertVectorMetadata(t, expected)
	sealedArchivePath := filepath.Join(repoRoot, strongVectorDir, "sealed.bship")
	sealedStorePath := filepath.Join(repoRoot, strongVectorDir, "sealed.trusted-store.json")
	prunedArchivePath := filepath.Join(repoRoot, strongVectorDir, "pruned.bship")
	prunedStorePath := filepath.Join(repoRoot, strongVectorDir, "pruned.trusted-store.json")

	sealedInspection, err := InspectArchive(InspectOptions{
		ArchivePath:      sealedArchivePath,
		Mode:             StrongMode,
		TrustedStorePath: sealedStorePath,
	})
	if err != nil {
		t.Fatalf("inspect checked-in strong sealed vector: %v", err)
	}
	if !reflect.DeepEqual(*sealedInspection, expected.SealedInspection) {
		t.Fatalf("strong sealed inspection mismatch")
	}
	prunedInspection, err := InspectArchive(InspectOptions{
		ArchivePath:      prunedArchivePath,
		Mode:             StrongMode,
		TrustedStorePath: prunedStorePath,
	})
	if err != nil {
		t.Fatalf("inspect checked-in strong pruned vector: %v", err)
	}
	if !reflect.DeepEqual(*prunedInspection, expected.PrunedInspection) {
		t.Fatalf("strong pruned inspection mismatch")
	}
	prunedPlaintext, err := DecryptArchive(DecryptOptions{
		ArchivePath:      prunedArchivePath,
		Mode:             StrongMode,
		TrustedStorePath: prunedStorePath,
	})
	if err != nil {
		t.Fatalf("decrypt checked-in strong pruned vector: %v", err)
	}
	if string(prunedPlaintext) != expected.PrunedPlaintextUTF {
		t.Fatalf("strong pruned plaintext = %q, want %q", prunedPlaintext, expected.PrunedPlaintextUTF)
	}

	sealedArchive, err := loadArchive(sealedArchivePath)
	if err != nil {
		t.Fatalf("load checked-in strong sealed vector: %v", err)
	}
	prunedArchive, err := loadArchive(prunedArchivePath)
	if err != nil {
		t.Fatalf("load checked-in strong pruned vector: %v", err)
	}
	if sealedArchive.State.CapsuleWrapKeyBase64 != "" || prunedArchive.State.CapsuleWrapKeyBase64 != "" {
		t.Fatal("simulated-strong fixtures should keep wrap key material only in the trusted-store simulator")
	}
}

func assertFixtureBytes(t *testing.T, path string, want []byte) {
	t.Helper()

	got, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read fixture %s: %v", path, err)
	}
	if !bytes.Equal(got, want) {
		t.Fatalf("fixture %s does not match regenerated deterministic output", path)
	}
}

func marshalVectorExpectations(t *testing.T, expectations vectorExpectations) []byte {
	t.Helper()

	data, err := json.MarshalIndent(expectations, "", "  ")
	if err != nil {
		t.Fatalf("marshal vector expectations: %v", err)
	}
	return append(data, '\n')
}

func readVectorExpectations(t *testing.T, path string) vectorExpectations {
	t.Helper()

	data := readTestFile(t, path)
	var expectations vectorExpectations
	if err := json.Unmarshal(data, &expectations); err != nil {
		t.Fatalf("parse %s: %v", path, err)
	}
	return expectations
}

func assertVectorMetadata(t *testing.T, expected vectorExpectations) {
	t.Helper()

	if expected.Warning != vectorWarning {
		t.Fatalf("vector warning = %q, want %q", expected.Warning, vectorWarning)
	}
	if expected.SourcePlaintextUTF != vectorPlaintext {
		t.Fatalf("vector source plaintext = %q, want %q", expected.SourcePlaintextUTF, vectorPlaintext)
	}
}

func readTestFile(t *testing.T, path string) []byte {
	t.Helper()

	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read %s: %v", path, err)
	}
	return data
}
