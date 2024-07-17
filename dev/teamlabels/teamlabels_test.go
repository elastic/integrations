package teamlabels

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestReadTeamLabels(t *testing.T) {
	cases := []struct {
		teamlabelsPath string
		valid          bool
	}{
		{
			teamlabelsPath: "testdata/team_labels-valid",
			valid:          true,
		},
		{
			teamlabelsPath: "notexsists",
			valid:          false,
		},
		{
			teamlabelsPath: "testdata/team_labels-invalid",
			valid:          true,
		},
	}

	for _, c := range cases {
		t.Run(c.teamlabelsPath, func(t *testing.T) {
			_, err := readTeamLabels(c.teamlabelsPath)
			if c.valid {
				assert.NoError(t, err)
			} else {
				assert.Error(t, err)
			}
		})
	}
}
