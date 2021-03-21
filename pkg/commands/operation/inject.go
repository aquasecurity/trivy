// +build wireinject

package operation

import (
	"github.com/aquasecurity/trivy/pkg/db"
	"github.com/aquasecurity/trivy/pkg/policy"
	"github.com/google/wire"
)

func initializeDBClient(cacheDir string, quiet bool) db.Client {
	wire.Build(db.SuperSet)
	return db.Client{}
}

func initializePolicyClient() policy.Client {
	wire.Build(policy.SuperSet)
	return policy.Client{}
}
