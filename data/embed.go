package data

import "embed"

var (
	//go:embed botPolicies.yaml botPolicies.json
	BotPolicies embed.FS
)
