package julia

import "github.com/aquasecurity/trivy/pkg/dependency/types"

var (
	juliaV1_6Libs = []types.Library{
		{ID: "ade2ca70-3891-5945-98fb-dc099432e06a", Name: "Dates", Version: "unknown", Locations: []types.Location{{StartLine: 3, EndLine: 5}}},
		{ID: "682c06a0-de6a-54ab-a142-c8b1cf79cde6", Name: "JSON", Version: "0.21.4", Locations: []types.Location{{StartLine: 7, EndLine: 11}}},
		{ID: "a63ad114-7e13-5084-954f-fe012c677804", Name: "Mmap", Version: "unknown", Locations: []types.Location{{StartLine: 13, EndLine: 14}}},
		{ID: "69de0a69-1ddd-5017-9359-2bf0b02dc9f0", Name: "Parsers", Version: "2.4.2", Locations: []types.Location{{StartLine: 16, EndLine: 20}}},
		{ID: "de0858da-6303-5e67-8744-51eddeeeb8d7", Name: "Printf", Version: "unknown", Locations: []types.Location{{StartLine: 22, EndLine: 24}}},
		{ID: "4ec0a83e-493e-50e2-b9ac-8f72acf5a8f5", Name: "Unicode", Version: "unknown", Locations: []types.Location{{StartLine: 26, EndLine: 27}}},
	}

	juliaV1_6Deps = []types.Dependency{
		{ID: "ade2ca70-3891-5945-98fb-dc099432e06a", DependsOn: []string{"de0858da-6303-5e67-8744-51eddeeeb8d7"}},
		{ID: "682c06a0-de6a-54ab-a142-c8b1cf79cde6", DependsOn: []string{
			"4ec0a83e-493e-50e2-b9ac-8f72acf5a8f5",
			"69de0a69-1ddd-5017-9359-2bf0b02dc9f0",
			"a63ad114-7e13-5084-954f-fe012c677804",
			"ade2ca70-3891-5945-98fb-dc099432e06a",
		}},
		{ID: "69de0a69-1ddd-5017-9359-2bf0b02dc9f0", DependsOn: []string{"ade2ca70-3891-5945-98fb-dc099432e06a"}},
		{ID: "de0858da-6303-5e67-8744-51eddeeeb8d7", DependsOn: []string{"4ec0a83e-493e-50e2-b9ac-8f72acf5a8f5"}},
	}

	juliaV1_8Libs = []types.Library{
		{ID: "ade2ca70-3891-5945-98fb-dc099432e06a", Name: "Dates", Version: "1.8.5", Locations: []types.Location{{StartLine: 7, EndLine: 9}}},
		{ID: "682c06a0-de6a-54ab-a142-c8b1cf79cde6", Name: "JSON", Version: "0.21.4", Locations: []types.Location{{StartLine: 11, EndLine: 15}}},
		{ID: "a63ad114-7e13-5084-954f-fe012c677804", Name: "Mmap", Version: "1.8.5", Locations: []types.Location{{StartLine: 17, EndLine: 18}}},
		{ID: "69de0a69-1ddd-5017-9359-2bf0b02dc9f0", Name: "Parsers", Version: "2.5.10", Locations: []types.Location{{StartLine: 20, EndLine: 24}}},
		{ID: "aea7be01-6a6a-4083-8856-8a6e6704d82a", Name: "PrecompileTools", Version: "1.1.1", Locations: []types.Location{{StartLine: 26, EndLine: 30}}},
		{ID: "21216c6a-2e73-6563-6e65-726566657250", Name: "Preferences", Version: "1.4.0", Locations: []types.Location{{StartLine: 32, EndLine: 36}}},
		{ID: "de0858da-6303-5e67-8744-51eddeeeb8d7", Name: "Printf", Version: "1.8.5", Locations: []types.Location{{StartLine: 38, EndLine: 40}}},
		{ID: "9a3f8284-a2c9-5f02-9a11-845980a1fd5c", Name: "Random", Version: "1.8.5", Locations: []types.Location{{StartLine: 42, EndLine: 44}}},
		{ID: "ea8e919c-243c-51af-8825-aaa63cd721ce", Name: "SHA", Version: "0.7.0", Locations: []types.Location{{StartLine: 46, EndLine: 48}}},
		{ID: "9e88b42a-f829-5b0c-bbe9-9e923198166b", Name: "Serialization", Version: "1.8.5", Locations: []types.Location{{StartLine: 50, EndLine: 51}}},
		{ID: "fa267f1f-6049-4f14-aa54-33bafae1ed76", Name: "TOML", Version: "1.0.0", Locations: []types.Location{{StartLine: 53, EndLine: 56}}},
		{ID: "cf7118a7-6976-5b1a-9a39-7adc72f591a4", Name: "UUIDs", Version: "1.8.5", Locations: []types.Location{{StartLine: 58, EndLine: 60}}},
		{ID: "4ec0a83e-493e-50e2-b9ac-8f72acf5a8f5", Name: "Unicode", Version: "1.8.5", Locations: []types.Location{{StartLine: 62, EndLine: 63}}},
	}

	juliaV1_8Deps = []types.Dependency{
		{ID: "ade2ca70-3891-5945-98fb-dc099432e06a", DependsOn: []string{"de0858da-6303-5e67-8744-51eddeeeb8d7"}},
		{ID: "682c06a0-de6a-54ab-a142-c8b1cf79cde6", DependsOn: []string{
			"4ec0a83e-493e-50e2-b9ac-8f72acf5a8f5",
			"69de0a69-1ddd-5017-9359-2bf0b02dc9f0",
			"a63ad114-7e13-5084-954f-fe012c677804",
			"ade2ca70-3891-5945-98fb-dc099432e06a",
		}},
		{ID: "69de0a69-1ddd-5017-9359-2bf0b02dc9f0", DependsOn: []string{
			"ade2ca70-3891-5945-98fb-dc099432e06a",
			"aea7be01-6a6a-4083-8856-8a6e6704d82a",
			"cf7118a7-6976-5b1a-9a39-7adc72f591a4",
		}},
		{ID: "aea7be01-6a6a-4083-8856-8a6e6704d82a", DependsOn: []string{"21216c6a-2e73-6563-6e65-726566657250"}},
		{ID: "21216c6a-2e73-6563-6e65-726566657250", DependsOn: []string{"fa267f1f-6049-4f14-aa54-33bafae1ed76"}},
		{ID: "de0858da-6303-5e67-8744-51eddeeeb8d7", DependsOn: []string{"4ec0a83e-493e-50e2-b9ac-8f72acf5a8f5"}},
		{ID: "9a3f8284-a2c9-5f02-9a11-845980a1fd5c", DependsOn: []string{"9e88b42a-f829-5b0c-bbe9-9e923198166b", "ea8e919c-243c-51af-8825-aaa63cd721ce"}},
		{ID: "fa267f1f-6049-4f14-aa54-33bafae1ed76", DependsOn: []string{"ade2ca70-3891-5945-98fb-dc099432e06a"}},
		{ID: "cf7118a7-6976-5b1a-9a39-7adc72f591a4", DependsOn: []string{"9a3f8284-a2c9-5f02-9a11-845980a1fd5c", "ea8e919c-243c-51af-8825-aaa63cd721ce"}},
	}

	juliaV1_9DepExtLibs = []types.Library{
		{ID: "621f4979-c628-5d54-868e-fcf4e3e8185c", Name: "AbstractFFTs", Version: "1.3.1", Locations: []types.Location{{StartLine: 7, EndLine: 10}}},
	}

	juliaV1_9ShadowedDepLibs = []types.Library{
		{ID: "ead4f63c-334e-11e9-00e6-e7f0a5f21b60", Name: "A", Version: "1.9.0", Locations: []types.Location{{StartLine: 7, EndLine: 8}}},
		{ID: "f41f7b98-334e-11e9-1257-49272045fb24", Name: "B", Version: "1.9.0", Locations: []types.Location{{StartLine: 13, EndLine: 14}}},
		{ID: "edca9bc6-334e-11e9-3554-9595dbb4349c", Name: "B", Version: "1.9.0", Locations: []types.Location{{StartLine: 15, EndLine: 16}}},
	}

	juliaV1_9ShadowedDepDeps = []types.Dependency{
		{ID: "ead4f63c-334e-11e9-00e6-e7f0a5f21b60", DependsOn: []string{"f41f7b98-334e-11e9-1257-49272045fb24"}},
	}
)
