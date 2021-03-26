package main

type changelog struct {
	Entries []entry
}

type entry struct {
	Version string
	Changes []change
}

type change struct {
	Description string
	Type string
	Link string
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