package main

type changelog struct {
	entries []entry
}

type entry struct {
	version string
	changes []change
}

type change struct {
	description string
	typ string `yaml:"type"`
	link string
}

func newChangelog(initVersion string) *changelog {
	return &changelog{
		[]entry{
			{
				initVersion,
				[]change{
					{
						"initial release",
						"enhancement",
						"",
					},
				},
			},
		},
	}
}