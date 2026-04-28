package bship

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestCLITopLevelUsageMentionsSimulator(t *testing.T) {
	var stdout bytes.Buffer
	if code := RunCLI([]string{"help"}, &stdout, ioDiscard()); code != 0 {
		t.Fatalf("help exited with code %d", code)
	}

	usage := stdout.String()
	for _, want := range []string{
		"simulated-strong",
		"compatibility alias",
		"local JSON trusted-store simulator",
		"not a secure trusted component",
		"seal --deterministic",
		"not real security",
	} {
		if !strings.Contains(usage, want) {
			t.Fatalf("usage missing %q:\n%s", want, usage)
		}
	}
}

func TestCLISealHelpMentionsSimulatorAndReturnsZero(t *testing.T) {
	var stderr bytes.Buffer
	if code := RunCLI([]string{"seal", "-h"}, ioDiscard(), &stderr); code != 0 {
		t.Fatalf("seal -h exited with code %d", code)
	}

	help := stderr.String()
	for _, want := range []string{
		"simulated-strong",
		"\"strong\" remains a compatibility alias",
		"local JSON trusted-store simulator state",
		"not secure hardware or a trusted component",
		"-deterministic",
		"reproducible test/demo artifacts",
		"-archive-id string",
	} {
		if !strings.Contains(help, want) {
			t.Fatalf("help missing %q:\n%s", want, help)
		}
	}
}

func TestParseCLIModeAcceptsPreferredAndAlias(t *testing.T) {
	tests := []struct {
		name  string
		value string
		want  Mode
	}{
		{name: "default empty", value: "", want: WeakMode},
		{name: "weak", value: "weak", want: WeakMode},
		{name: "preferred simulated strong", value: string(StrongMode), want: StrongMode},
		{name: "compatibility alias", value: string(StrongModeAlias), want: StrongMode},
		{name: "trim and case fold", value: "  Simulated-Strong  ", want: StrongMode},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := parseCLIMode(tt.value)
			if err != nil {
				t.Fatalf("parseCLIMode(%q) error = %v", tt.value, err)
			}
			if got != tt.want {
				t.Fatalf("parseCLIMode(%q) = %q, want %q", tt.value, got, tt.want)
			}
		})
	}
}

func TestCLISimulatedStrongModeWorks(t *testing.T) {
	dir := testWorkspace(t)
	inputPath := filepath.Join(dir, "input.bin")
	archivePath := filepath.Join(dir, "sample.bship")
	storePath := filepath.Join(dir, "trusted.json")
	outputPath := filepath.Join(dir, "output.bin")

	writeTestFile(t, inputPath, []byte("abcdefgh"))

	if code := RunCLI([]string{
		"seal",
		"--in", inputPath,
		"--out", archivePath,
		"--threshold", "4",
		"--chunk-size", "4",
		"--mode", string(StrongMode),
		"--trusted-store", storePath,
	}, ioDiscard(), ioDiscard()); code != 0 {
		t.Fatalf("seal exited with code %d", code)
	}

	archive, err := loadArchive(archivePath)
	if err != nil {
		t.Fatalf("load archive: %v", err)
	}
	if archive.State.CapsuleWrapKeyBase64 != "" {
		t.Fatalf("simulated-strong archive should not carry wrap key material")
	}

	if code := RunCLI([]string{
		"prune",
		"--archive", archivePath,
		"--keep", "0",
		"--mode", string(StrongMode),
		"--trusted-store", storePath,
	}, ioDiscard(), ioDiscard()); code != 0 {
		t.Fatalf("prune exited with code %d", code)
	}

	if code := RunCLI([]string{
		"decrypt",
		"--archive", archivePath,
		"--out", outputPath,
		"--mode", string(StrongMode),
		"--trusted-store", storePath,
	}, ioDiscard(), ioDiscard()); code != 0 {
		t.Fatalf("decrypt exited with code %d", code)
	}

	got, err := os.ReadFile(outputPath)
	if err != nil {
		t.Fatalf("read output: %v", err)
	}
	if string(got) != "abcd" {
		t.Fatalf("decrypted output = %q, want %q", got, "abcd")
	}
}

func TestCLIStrongAliasWorks(t *testing.T) {
	dir := testWorkspace(t)
	inputPath := filepath.Join(dir, "input.bin")
	archivePath := filepath.Join(dir, "sample.bship")
	storePath := filepath.Join(dir, "trusted.json")

	writeTestFile(t, inputPath, []byte("abcdefgh"))

	if code := RunCLI([]string{
		"seal",
		"--in", inputPath,
		"--out", archivePath,
		"--threshold", "4",
		"--chunk-size", "4",
		"--mode", string(StrongModeAlias),
		"--trusted-store", storePath,
	}, ioDiscard(), ioDiscard()); code != 0 {
		t.Fatalf("seal exited with code %d", code)
	}

	archive, err := loadArchive(archivePath)
	if err != nil {
		t.Fatalf("load archive: %v", err)
	}
	if archive.State.CapsuleWrapKeyBase64 != "" {
		t.Fatalf("%q alias should still activate simulated-strong behavior", StrongModeAlias)
	}
}

func TestCLIRejectsUnknownMode(t *testing.T) {
	dir := testWorkspace(t)
	inputPath := filepath.Join(dir, "input.bin")
	archivePath := filepath.Join(dir, "sample.bship")
	writeTestFile(t, inputPath, []byte("abcd"))

	var stderr bytes.Buffer
	code := RunCLI([]string{
		"seal",
		"--in", inputPath,
		"--out", archivePath,
		"--mode", "actually-strong",
	}, ioDiscard(), &stderr)
	if code != 2 {
		t.Fatalf("seal exited with code %d, want 2", code)
	}
	if !strings.Contains(stderr.String(), `unsupported mode "actually-strong"`) {
		t.Fatalf("unexpected error output:\n%s", stderr.String())
	}
}

func TestCLISealDeterministicProducesStableOutputs(t *testing.T) {
	tests := []struct {
		name      string
		mode      string
		withStore bool
	}{
		{name: "weak"},
		{name: "simulated-strong", mode: string(StrongMode), withStore: true},
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

			argsFor := func(archivePath, storePath string) []string {
				args := []string{
					"seal",
					"--in", inputPath,
					"--out", archivePath,
					"--threshold", "4",
					"--chunk-size", "4",
					"--deterministic",
					"--archive-id", "cli-deterministic-" + tt.name,
				}
				if tt.mode != "" {
					args = append(args, "--mode", tt.mode, "--trusted-store", storePath)
				}
				return args
			}

			if code := RunCLI(argsFor(archivePathA, storePathA), ioDiscard(), ioDiscard()); code != 0 {
				t.Fatalf("first seal exited with code %d", code)
			}
			if code := RunCLI(argsFor(archivePathB, storePathB), ioDiscard(), ioDiscard()); code != 0 {
				t.Fatalf("second seal exited with code %d", code)
			}

			if !bytes.Equal(readTestFile(t, archivePathA), readTestFile(t, archivePathB)) {
				t.Fatalf("%s deterministic archive outputs differed", tt.name)
			}
			if tt.withStore && !bytes.Equal(readTestFile(t, storePathA), readTestFile(t, storePathB)) {
				t.Fatalf("%s deterministic trusted-store outputs differed", tt.name)
			}
		})
	}
}
