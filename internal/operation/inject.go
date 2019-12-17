// +build wireinject

package operation

import (
	"github.com/aquasecurity/trivy/pkg/db"
	"github.com/google/wire"
)

func initializeDBClient(quiet bool) db.Client {
	wire.Build(db.SuperSet)
	return db.Client{}
}
