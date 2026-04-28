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
	} {
		if !strings.Contains(help, want) {
			t.Fatalf("help missing %q:\n%s", want, help)
		}
	}
}

func TestCLISimulatedStrongAliasWorks(t *testing.T) {
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
		"--mode", string(simulatedStrongMode),
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
		"--mode", string(simulatedStrongMode),
		"--trusted-store", storePath,
	}, ioDiscard(), ioDiscard()); code != 0 {
		t.Fatalf("prune exited with code %d", code)
	}

	if code := RunCLI([]string{
		"decrypt",
		"--archive", archivePath,
		"--out", outputPath,
		"--mode", string(simulatedStrongMode),
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
