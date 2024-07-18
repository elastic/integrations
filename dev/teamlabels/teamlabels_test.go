package teamlabels

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
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
			valid:          false,
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

func TestGetTeamLabelsFromPath(t *testing.T) {
	cases := []struct {
		title          string
		teamlabelsPath string
		team           string
		expected       string
		expectedError  bool
	}{
		{
			title:          "team with label found",
			teamlabelsPath: "testdata/team_labels-valid-labels",
			team:           "@elastic/security-service-integrations",
			expected:       "Team:Security-Service Integrations",
			expectedError:  false,
		},
		{
			title:          "team not found",
			teamlabelsPath: "testdata/team_labels-valid-labels",
			team:           "@teamnotfound",
			expected:       "",
			expectedError:  false,
		},
		{
			title:          "valid team found but with invalid label",
			teamlabelsPath: "testdata/team_labels-invalid-label",
			team:           "@elastic/security-service-integrations",
			expected:       "",
			expectedError:  true,
		},
		{
			title:          "invalid team found but with valid label",
			teamlabelsPath: "testdata/team_labels-invalid-team",
			team:           "elastic/stack-monitoring",
			expected:       "",
			expectedError:  true,
		},
	}

	for _, c := range cases {
		t.Run(c.title, func(t *testing.T) {
			tlabels, err := GetTeamLabelsFromPath(c.teamlabelsPath)
			if c.expectedError {
				assert.Error(t, err)
				return
			}
			require.NoError(t, err)
			assert.Equal(t, c.expected, tlabels[c.team])
		})
	}
}
