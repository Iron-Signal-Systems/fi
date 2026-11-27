package recordingest

import (
	"bytes"
	"errors"
	"io"
	"strings"
	"testing"

	"github.com/Iron-Signal-Systems/fi/go/internal/spool"
)

type failingStageWriter struct{}

func (failingStageWriter) Write([]byte) (int, error) {
	return 0, io.ErrClosedPipe
}

type shortStageWriter struct{}

func (shortStageWriter) Write([]byte) (int, error) {
	return 0, nil
}

func TestInspectStagedBatch(t *testing.T) {
	data := []byte(strings.Repeat("{\"record\":1}\n", 20000))

	t.Run("same bytes and inspection", func(t *testing.T) {
		var staged bytes.Buffer

		got, err := inspectStagedBatch(
			bytes.NewReader(data), &staged,
		)
		if err != nil {
			t.Fatal(err)
		}

		want, err := spool.InspectData(bytes.NewReader(data))
		if err != nil {
			t.Fatal(err)
		}

		if got != want {
			t.Fatalf("streamed=%+v original=%+v", got, want)
		}
		if !bytes.Equal(staged.Bytes(), data) {
			t.Fatal("staged bytes differ from input")
		}
	})

	t.Run("changed bytes change hash", func(t *testing.T) {
		changed := bytes.Replace(data,
			[]byte("record"), []byte("change"), 1)

		var staged bytes.Buffer
		got, err := inspectStagedBatch(
			bytes.NewReader(changed), &staged,
		)
		if err != nil {
			t.Fatal(err)
		}

		original, err := spool.InspectData(
			bytes.NewReader(data),
		)
		if err != nil {
			t.Fatal(err)
		}

		if got.DataSHA256 == original.DataSHA256 {
			t.Fatal("changed data retained original hash")
		}
	})

	t.Run("missing newline", func(t *testing.T) {
		var staged bytes.Buffer
		if _, err := inspectStagedBatch(
			strings.NewReader("{\"record\":1}"), &staged,
		); err == nil {
			t.Fatal("accepted missing final newline")
		}
	})

	t.Run("empty", func(t *testing.T) {
		var staged bytes.Buffer
		if _, err := inspectStagedBatch(
			strings.NewReader(""), &staged,
		); err == nil {
			t.Fatal("accepted empty batch")
		}
	})

	t.Run("write failure", func(t *testing.T) {
		_, err := inspectStagedBatch(
			bytes.NewReader(data), failingStageWriter{},
		)
		if !errors.Is(err, io.ErrClosedPipe) {
			t.Fatalf("expected write failure, got %v", err)
		}
	})

	t.Run("short write", func(t *testing.T) {
		_, err := inspectStagedBatch(
			bytes.NewReader(data), shortStageWriter{},
		)
		if !errors.Is(err, io.ErrShortWrite) {
			t.Fatalf("expected short write, got %v", err)
		}
	})
}

func TestInspectStagedBatchesRequiresStreamedInspection(t *testing.T) {
	_, _, _, err := inspectStagedBatches(
		t.TempDir(),
		[]string{
			"batch-unit.jsonl",
			"batch-unit.manifest.json",
		},
		1<<20,
		map[string]spool.DataInspection{},
	)

	if err == nil ||
		!strings.Contains(err.Error(), "missing FI Phase 3 streamed inspection") {
		t.Fatalf("expected missing inspection rejection, got %v", err)
	}
}
