// +build wireinject

package operation

import (
	"github.com/aquasecurity/trivy/pkg/db"
	"github.com/google/wire"
)

func initializeDBClient() db.Client {
	wire.Build(db.SuperSet)
	return db.Client{}
}
