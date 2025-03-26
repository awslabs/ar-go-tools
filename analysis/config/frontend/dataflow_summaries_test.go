package frontend

import "testing"

func TestParseSummariesFile(t *testing.T) {
	summaries, err := ParseSummariesFile("testdata/summaries.yaml")
	if err != nil {
		t.Error(err)
	}
	t.Logf("Summaries: %+v", summaries)
}
