package bship

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
)

const (
	weakTwoChunkVectorDir     = "test-vectors/weak-simulator-two-chunk"
	weakThreeChunkVectorDir   = "test-vectors/weak-simulator-three-chunk-tail"
	strongTwoChunkVectorDir   = "test-vectors/simulated-strong-two-chunk"
	strongThreeChunkVectorDir = "test-vectors/simulated-strong-three-chunk-stale-copy"
	vectorWarning             = "Prototype/simulator test vector only; not production-security material."
)

type vectorScenario struct {
	Dir       string
	ArchiveID string
	Plaintext string
	Threshold int64
	ChunkSize int
	Keep      []string
}

var (
	weakTwoChunkScenario = vectorScenario{
		Dir:       weakTwoChunkVectorDir,
		ArchiveID: "weak-simulator-vector",
		Plaintext: "ABCD1234",
		Threshold: 4,
		ChunkSize: 4,
		Keep:      []string{"0"},
	}
	weakThreeChunkScenario = vectorScenario{
		Dir:       weakThreeChunkVectorDir,
		ArchiveID: "weak-simulator-three-chunk-vector",
		Plaintext: "ABCDEFGHIJ",
		Threshold: 6,
		ChunkSize: 4,
		Keep:      []string{"1", "2"},
	}
	strongTwoChunkScenario = vectorScenario{
		Dir:       strongTwoChunkVectorDir,
		ArchiveID: "simulated-strong-vector",
		Plaintext: "ABCD1234",
		Threshold: 4,
		ChunkSize: 4,
		Keep:      []string{"0"},
	}
	strongThreeChunkScenario = vectorScenario{
		Dir:       strongThreeChunkVectorDir,
		ArchiveID: "simulated-strong-three-chunk-vector",
		Plaintext: "ABCDEFGHIJK",
		Threshold: 7,
		ChunkSize: 4,
		Keep:      []string{"0", "2"},
	}
)

type vectorInspectCheck struct {
	Name          string      `json:"name"`
	Archive       string      `json:"archive"`
	TrustedStore  string      `json:"trusted_store,omitempty"`
	Mode          Mode        `json:"mode,omitempty"`
	Inspection    *Inspection `json:"inspection,omitempty"`
	ErrorContains string      `json:"error_contains,omitempty"`
}

type vectorDecryptCheck struct {
	Name          string `json:"name"`
	Archive       string `json:"archive"`
	TrustedStore  string `json:"trusted_store,omitempty"`
	Mode          Mode   `json:"mode,omitempty"`
	PlaintextUTF  string `json:"plaintext_utf8,omitempty"`
	ErrorContains string `json:"error_contains,omitempty"`
}

type vectorExpectations struct {
	Warning                     string               `json:"warning"`
	SourcePlaintextUTF          string               `json:"source_plaintext_utf8"`
	ManifestChunkPlaintextSizes []int                `json:"manifest_chunk_plaintext_sizes"`
	SealedInspection            Inspection           `json:"sealed_inspection"`
	PrunedInspection            Inspection           `json:"pruned_inspection"`
	PrunedPlaintextUTF          string               `json:"pruned_plaintext_utf8"`
	ExtraInspectionChecks       []vectorInspectCheck `json:"extra_inspection_checks,omitempty"`
	ExtraDecryptionChecks       []vectorDecryptCheck `json:"extra_decryption_checks,omitempty"`
}

func TestDeterministicVectorFixtures(t *testing.T) {
	repoRoot, err := os.Getwd()
	if err != nil {
		t.Fatalf("getwd: %v", err)
	}

	cases := []struct {
		name     string
		generate func(*testing.T) map[string][]byte
		validate func(*testing.T, string)
	}{
		{
			name:     "weak/two-chunk",
			generate: generateWeakTwoChunkVectorFiles,
			validate: func(t *testing.T, repoRoot string) { validateWeakFixtures(t, repoRoot, weakTwoChunkScenario) },
		},
		{
			name:     "weak/three-chunk-tail",
			generate: generateWeakThreeChunkVectorFiles,
			validate: func(t *testing.T, repoRoot string) { validateWeakFixtures(t, repoRoot, weakThreeChunkScenario) },
		},
		{
			name:     "simulated-strong/two-chunk",
			generate: generateStrongTwoChunkVectorFiles,
			validate: func(t *testing.T, repoRoot string) { validateStrongFixtures(t, repoRoot, strongTwoChunkScenario) },
		},
		{
			name:     "simulated-strong/three-chunk-stale-copy",
			generate: generateStrongThreeChunkVectorFiles,
			validate: func(t *testing.T, repoRoot string) { validateStrongFixtures(t, repoRoot, strongThreeChunkScenario) },
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			generated := tc.generate(t)
			for relativePath, want := range generated {
				assertFixtureBytes(t, filepath.Join(repoRoot, relativePath), want)
			}
			tc.validate(t, repoRoot)
		})
	}
}

func generateWeakTwoChunkVectorFiles(t *testing.T) map[string][]byte {
	t.Helper()
	return generateWeakVectorFiles(t, weakTwoChunkScenario, nil)
}

func generateWeakThreeChunkVectorFiles(t *testing.T) map[string][]byte {
	t.Helper()
	return generateWeakVectorFiles(t, weakThreeChunkScenario, []vectorDecryptCheck{
		{
			Name:          "sealed archive remains above threshold",
			Archive:       "sealed.bship",
			ErrorContains: errThresholdExceeded.Error(),
		},
	})
}

func generateWeakVectorFiles(t *testing.T, scenario vectorScenario, extraDecryptChecks []vectorDecryptCheck) map[string][]byte {
	t.Helper()

	dir := testWorkspace(t)
	inputPath := filepath.Join(dir, "prototype-input.txt")
	archivePath := filepath.Join(dir, "weak-simulator-vector.bship")
	writeTestFile(t, inputPath, []byte(scenario.Plaintext))

	sealedArchive, err := SealFile(SealOptions{
		InputPath:      inputPath,
		ArchivePath:    archivePath,
		ThresholdBytes: scenario.Threshold,
		ChunkSizeBytes: scenario.ChunkSize,
		ArchiveID:      scenario.ArchiveID,
		Now:            fixedNow,
		Rand:           &deterministicReader{},
	})
	if err != nil {
		t.Fatalf("seal weak vector %s: %v", scenario.ArchiveID, err)
	}

	sealedInspection, err := InspectArchive(InspectOptions{ArchivePath: archivePath})
	if err != nil {
		t.Fatalf("inspect sealed weak vector %s: %v", scenario.ArchiveID, err)
	}
	sealedArchiveBytes := readTestFile(t, archivePath)

	if _, err := PruneArchive(PruneOptions{ArchivePath: archivePath, Keep: scenario.Keep}); err != nil {
		t.Fatalf("prune weak vector %s: %v", scenario.ArchiveID, err)
	}
	prunedInspection, err := InspectArchive(InspectOptions{ArchivePath: archivePath})
	if err != nil {
		t.Fatalf("inspect pruned weak vector %s: %v", scenario.ArchiveID, err)
	}
	prunedPlaintext, err := DecryptArchive(DecryptOptions{ArchivePath: archivePath})
	if err != nil {
		t.Fatalf("decrypt pruned weak vector %s: %v", scenario.ArchiveID, err)
	}

	return map[string][]byte{
		filepath.Join(scenario.Dir, "sealed.bship"): sealedArchiveBytes,
		filepath.Join(scenario.Dir, "pruned.bship"): readTestFile(t, archivePath),
		filepath.Join(scenario.Dir, "expected.json"): marshalVectorExpectations(t, vectorExpectations{
			Warning:                     vectorWarning,
			SourcePlaintextUTF:          scenario.Plaintext,
			ManifestChunkPlaintextSizes: manifestChunkPlaintextSizes(sealedArchive),
			SealedInspection:            *sealedInspection,
			PrunedInspection:            *prunedInspection,
			PrunedPlaintextUTF:          string(prunedPlaintext),
			ExtraDecryptionChecks:       extraDecryptChecks,
		}),
	}
}

func generateStrongTwoChunkVectorFiles(t *testing.T) map[string][]byte {
	t.Helper()
	return generateStrongVectorFiles(t, strongTwoChunkScenario, nil, nil)
}

func generateStrongThreeChunkVectorFiles(t *testing.T) map[string][]byte {
	t.Helper()
	return generateStrongVectorFiles(t, strongThreeChunkScenario,
		[]vectorInspectCheck{
			{
				Name:          "sealed archive rejected against advanced trusted store",
				Archive:       "sealed.bship",
				TrustedStore:  "pruned.trusted-store.json",
				Mode:          StrongMode,
				ErrorContains: errStaleArchiveState.Error(),
			},
		},
		[]vectorDecryptCheck{
			{
				Name:          "sealed archive remains above threshold",
				Archive:       "sealed.bship",
				TrustedStore:  "sealed.trusted-store.json",
				Mode:          StrongMode,
				ErrorContains: errThresholdExceeded.Error(),
			},
			{
				Name:          "sealed archive rejected against advanced trusted store",
				Archive:       "sealed.bship",
				TrustedStore:  "pruned.trusted-store.json",
				Mode:          StrongMode,
				ErrorContains: errStaleArchiveState.Error(),
			},
		},
	)
}

func generateStrongVectorFiles(
	t *testing.T,
	scenario vectorScenario,
	extraInspectChecks []vectorInspectCheck,
	extraDecryptChecks []vectorDecryptCheck,
) map[string][]byte {
	t.Helper()

	dir := testWorkspace(t)
	inputPath := filepath.Join(dir, "prototype-input.txt")
	archivePath := filepath.Join(dir, "simulated-strong-vector.bship")
	storePath := filepath.Join(dir, "trusted-store.json")
	writeTestFile(t, inputPath, []byte(scenario.Plaintext))

	sealedArchive, err := SealFile(SealOptions{
		InputPath:        inputPath,
		ArchivePath:      archivePath,
		ThresholdBytes:   scenario.Threshold,
		ChunkSizeBytes:   scenario.ChunkSize,
		Mode:             StrongMode,
		TrustedStorePath: storePath,
		ArchiveID:        scenario.ArchiveID,
		Now:              fixedNow,
		Rand:             &deterministicReader{},
	})
	if err != nil {
		t.Fatalf("seal strong vector %s: %v", scenario.ArchiveID, err)
	}

	sealedInspection, err := InspectArchive(InspectOptions{
		ArchivePath:      archivePath,
		Mode:             StrongMode,
		TrustedStorePath: storePath,
	})
	if err != nil {
		t.Fatalf("inspect sealed strong vector %s: %v", scenario.ArchiveID, err)
	}
	sealedArchiveBytes := readTestFile(t, archivePath)
	sealedStoreBytes := readTestFile(t, storePath)

	if _, err := PruneArchive(PruneOptions{
		ArchivePath:      archivePath,
		Keep:             scenario.Keep,
		Mode:             StrongMode,
		TrustedStorePath: storePath,
	}); err != nil {
		t.Fatalf("prune strong vector %s: %v", scenario.ArchiveID, err)
	}
	prunedInspection, err := InspectArchive(InspectOptions{
		ArchivePath:      archivePath,
		Mode:             StrongMode,
		TrustedStorePath: storePath,
	})
	if err != nil {
		t.Fatalf("inspect pruned strong vector %s: %v", scenario.ArchiveID, err)
	}
	prunedPlaintext, err := DecryptArchive(DecryptOptions{
		ArchivePath:      archivePath,
		Mode:             StrongMode,
		TrustedStorePath: storePath,
	})
	if err != nil {
		t.Fatalf("decrypt pruned strong vector %s: %v", scenario.ArchiveID, err)
	}

	return map[string][]byte{
		filepath.Join(scenario.Dir, "sealed.bship"):              sealedArchiveBytes,
		filepath.Join(scenario.Dir, "sealed.trusted-store.json"): sealedStoreBytes,
		filepath.Join(scenario.Dir, "pruned.bship"):              readTestFile(t, archivePath),
		filepath.Join(scenario.Dir, "pruned.trusted-store.json"): readTestFile(t, storePath),
		filepath.Join(scenario.Dir, "expected.json"): marshalVectorExpectations(t, vectorExpectations{
			Warning:                     vectorWarning,
			SourcePlaintextUTF:          scenario.Plaintext,
			ManifestChunkPlaintextSizes: manifestChunkPlaintextSizes(sealedArchive),
			SealedInspection:            *sealedInspection,
			PrunedInspection:            *prunedInspection,
			PrunedPlaintextUTF:          string(prunedPlaintext),
			ExtraInspectionChecks:       extraInspectChecks,
			ExtraDecryptionChecks:       extraDecryptChecks,
		}),
	}
}

func validateWeakFixtures(t *testing.T, repoRoot string, scenario vectorScenario) {
	t.Helper()

	expected := readVectorExpectations(t, filepath.Join(repoRoot, scenario.Dir, "expected.json"))
	sealedArchivePath := filepath.Join(repoRoot, scenario.Dir, "sealed.bship")
	prunedArchivePath := filepath.Join(repoRoot, scenario.Dir, "pruned.bship")
	assertVectorMetadata(t, expected, scenario.Plaintext, sealedArchivePath)

	sealedInspection, err := InspectArchive(InspectOptions{ArchivePath: sealedArchivePath})
	if err != nil {
		t.Fatalf("inspect checked-in weak sealed vector %s: %v", scenario.ArchiveID, err)
	}
	assertInspectionMatch(t, "weak sealed", *sealedInspection, expected.SealedInspection)

	prunedInspection, err := InspectArchive(InspectOptions{ArchivePath: prunedArchivePath})
	if err != nil {
		t.Fatalf("inspect checked-in weak pruned vector %s: %v", scenario.ArchiveID, err)
	}
	assertInspectionMatch(t, "weak pruned", *prunedInspection, expected.PrunedInspection)

	prunedPlaintext, err := DecryptArchive(DecryptOptions{ArchivePath: prunedArchivePath})
	if err != nil {
		t.Fatalf("decrypt checked-in weak pruned vector %s: %v", scenario.ArchiveID, err)
	}
	if string(prunedPlaintext) != expected.PrunedPlaintextUTF {
		t.Fatalf("weak pruned plaintext = %q, want %q", prunedPlaintext, expected.PrunedPlaintextUTF)
	}

	validateExtraInspectionChecks(t, repoRoot, scenario.Dir, expected.ExtraInspectionChecks)
	validateExtraDecryptionChecks(t, repoRoot, scenario.Dir, expected.ExtraDecryptionChecks)

	sealedArchive, err := loadArchive(sealedArchivePath)
	if err != nil {
		t.Fatalf("load checked-in weak sealed vector %s: %v", scenario.ArchiveID, err)
	}
	prunedArchive, err := loadArchive(prunedArchivePath)
	if err != nil {
		t.Fatalf("load checked-in weak pruned vector %s: %v", scenario.ArchiveID, err)
	}
	if sealedArchive.State.CapsuleWrapKeyBase64 == "" || prunedArchive.State.CapsuleWrapKeyBase64 == "" {
		t.Fatal("weak fixtures should retain archive-local wrap key material")
	}
}

func validateStrongFixtures(t *testing.T, repoRoot string, scenario vectorScenario) {
	t.Helper()

	expected := readVectorExpectations(t, filepath.Join(repoRoot, scenario.Dir, "expected.json"))
	sealedArchivePath := filepath.Join(repoRoot, scenario.Dir, "sealed.bship")
	sealedStorePath := filepath.Join(repoRoot, scenario.Dir, "sealed.trusted-store.json")
	prunedArchivePath := filepath.Join(repoRoot, scenario.Dir, "pruned.bship")
	prunedStorePath := filepath.Join(repoRoot, scenario.Dir, "pruned.trusted-store.json")
	assertVectorMetadata(t, expected, scenario.Plaintext, sealedArchivePath)

	sealedInspection, err := InspectArchive(InspectOptions{
		ArchivePath:      sealedArchivePath,
		Mode:             StrongMode,
		TrustedStorePath: sealedStorePath,
	})
	if err != nil {
		t.Fatalf("inspect checked-in strong sealed vector %s: %v", scenario.ArchiveID, err)
	}
	assertInspectionMatch(t, "strong sealed", *sealedInspection, expected.SealedInspection)

	prunedInspection, err := InspectArchive(InspectOptions{
		ArchivePath:      prunedArchivePath,
		Mode:             StrongMode,
		TrustedStorePath: prunedStorePath,
	})
	if err != nil {
		t.Fatalf("inspect checked-in strong pruned vector %s: %v", scenario.ArchiveID, err)
	}
	assertInspectionMatch(t, "strong pruned", *prunedInspection, expected.PrunedInspection)

	prunedPlaintext, err := DecryptArchive(DecryptOptions{
		ArchivePath:      prunedArchivePath,
		Mode:             StrongMode,
		TrustedStorePath: prunedStorePath,
	})
	if err != nil {
		t.Fatalf("decrypt checked-in strong pruned vector %s: %v", scenario.ArchiveID, err)
	}
	if string(prunedPlaintext) != expected.PrunedPlaintextUTF {
		t.Fatalf("strong pruned plaintext = %q, want %q", prunedPlaintext, expected.PrunedPlaintextUTF)
	}

	validateExtraInspectionChecks(t, repoRoot, scenario.Dir, expected.ExtraInspectionChecks)
	validateExtraDecryptionChecks(t, repoRoot, scenario.Dir, expected.ExtraDecryptionChecks)

	sealedArchive, err := loadArchive(sealedArchivePath)
	if err != nil {
		t.Fatalf("load checked-in strong sealed vector %s: %v", scenario.ArchiveID, err)
	}
	prunedArchive, err := loadArchive(prunedArchivePath)
	if err != nil {
		t.Fatalf("load checked-in strong pruned vector %s: %v", scenario.ArchiveID, err)
	}
	if sealedArchive.State.CapsuleWrapKeyBase64 != "" || prunedArchive.State.CapsuleWrapKeyBase64 != "" {
		t.Fatal("simulated-strong fixtures should keep wrap key material only in the trusted-store simulator")
	}
}

func validateExtraInspectionChecks(t *testing.T, repoRoot, dir string, checks []vectorInspectCheck) {
	t.Helper()

	for _, check := range checks {
		t.Run(check.Name, func(t *testing.T) {
			inspection, err := InspectArchive(InspectOptions{
				ArchivePath:      filepath.Join(repoRoot, dir, check.Archive),
				Mode:             check.Mode,
				TrustedStorePath: trustedStorePathForCheck(repoRoot, dir, check.TrustedStore),
			})
			if check.ErrorContains != "" {
				assertErrorContains(t, err, check.ErrorContains)
				return
			}
			if err != nil {
				t.Fatalf("inspect %q: %v", check.Name, err)
			}
			if check.Inspection == nil {
				t.Fatalf("inspect check %q missing inspection expectation", check.Name)
			}
			assertInspectionMatch(t, check.Name, *inspection, *check.Inspection)
		})
	}
}

func validateExtraDecryptionChecks(t *testing.T, repoRoot, dir string, checks []vectorDecryptCheck) {
	t.Helper()

	for _, check := range checks {
		t.Run(check.Name, func(t *testing.T) {
			plaintext, err := DecryptArchive(DecryptOptions{
				ArchivePath:      filepath.Join(repoRoot, dir, check.Archive),
				Mode:             check.Mode,
				TrustedStorePath: trustedStorePathForCheck(repoRoot, dir, check.TrustedStore),
			})
			if check.ErrorContains != "" {
				assertErrorContains(t, err, check.ErrorContains)
				return
			}
			if err != nil {
				t.Fatalf("decrypt %q: %v", check.Name, err)
			}
			if string(plaintext) != check.PlaintextUTF {
				t.Fatalf("decrypt %q plaintext = %q, want %q", check.Name, plaintext, check.PlaintextUTF)
			}
		})
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

func assertVectorMetadata(t *testing.T, expected vectorExpectations, wantSourcePlaintext, sealedArchivePath string) {
	t.Helper()

	if expected.Warning != vectorWarning {
		t.Fatalf("vector warning = %q, want %q", expected.Warning, vectorWarning)
	}
	if expected.SourcePlaintextUTF != wantSourcePlaintext {
		t.Fatalf("vector source plaintext = %q, want %q", expected.SourcePlaintextUTF, wantSourcePlaintext)
	}

	sealedArchive, err := loadArchive(sealedArchivePath)
	if err != nil {
		t.Fatalf("load sealed archive metadata %s: %v", sealedArchivePath, err)
	}
	gotChunkSizes := manifestChunkPlaintextSizes(sealedArchive)
	if !reflect.DeepEqual(gotChunkSizes, expected.ManifestChunkPlaintextSizes) {
		t.Fatalf("manifest chunk plaintext sizes = %v, want %v", gotChunkSizes, expected.ManifestChunkPlaintextSizes)
	}
}

func manifestChunkPlaintextSizes(archive *Archive) []int {
	sizes := make([]int, len(archive.Manifest.Chunks))
	for i, chunk := range archive.Manifest.Chunks {
		sizes[i] = chunk.PlaintextSize
	}
	return sizes
}

func assertInspectionMatch(t *testing.T, label string, got, want Inspection) {
	t.Helper()
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("%s inspection mismatch", label)
	}
}

func trustedStorePathForCheck(repoRoot, dir, file string) string {
	if file == "" {
		return ""
	}
	return filepath.Join(repoRoot, dir, file)
}

func assertErrorContains(t *testing.T, err error, want string) {
	t.Helper()
	if err == nil {
		t.Fatalf("expected error containing %q, got nil", want)
	}
	if !strings.Contains(err.Error(), want) {
		t.Fatalf("error = %q, want substring %q", err.Error(), want)
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
