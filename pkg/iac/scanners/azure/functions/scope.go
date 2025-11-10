package functions

import (
	"fmt"

	"github.com/google/uuid"
)

var (
	tenantID           = uuid.NewString()
	groupID            = uuid.NewString()
	updaterID          = uuid.NewString()
	subscriptionID     = uuid.NewString()
	managingResourceID = uuid.NewString()
)

func ManagementGroup(_ ...any) any {

	return fmt.Sprintf(`{
    "id": "/providers/Microsoft.Management/managementGroups/mgPlaceholder",
    "name": "mgPlaceholder",
    "properties": {
      "details": {
        "parent": {
          "displayName": "Tenant Root Group",
          "id": "/providers/Microsoft.Management/managementGroups/%[1]s",
          "name": "%[1]s"
        },
        "updatedBy": "%[2]s",
        "updatedTime": "2020-07-23T21:05:52.661306Z",
        "version": "1"
      },
      "displayName": "Management PlaceHolder Group",
      "tenantId": "%[3]s"
    },
    "type": "/providers/Microsoft.Management/managementGroups"
  }
`, groupID, updaterID, tenantID)
}

func ManagementGroupResourceID(args ...any) any {
	if len(args) < 2 {
		return ""
	}

	switch len(args) {
	case 3:
		return fmt.Sprintf("/providers/Microsoft.Management/managementGroups/%s/providers/%s/%s/%s", groupID, args[0], args[1], args[2])
	case 4:
		return fmt.Sprintf("/providers/Microsoft.Management/managementGroups/%s/providers/%s/%s/%s", args[0], args[1], args[2], args[3])
	default:
		return fmt.Sprintf("/providers/Microsoft.Management/managementGroups/%s/providers/%s/%s", groupID, args[0], args[1])
	}

}

func Subscription(_ ...any) any {
	return fmt.Sprintf(`{
  "id": "/subscriptions/%[1]s",
  "subscriptionId": "%[1]s",
  "tenantId": "%[2]s",
  "displayName": "Placeholder Subscription"
}`, subscriptionID, tenantID)
}

func SubscriptionResourceID(args ...any) any {
	if len(args) < 2 {
		return nil
	}

	switch len(args) {

	case 3:
		return fmt.Sprintf("/subscriptions/%s/providers/%s/%s/%s", subscriptionID, args[0], args[1], args[2])
	case 4:
		// subscription ID has been provided so use that
		return fmt.Sprintf("/subscriptions/%s/providers/%s/%s/%s", args[0], args[1], args[2], args[3])
	default:

		return fmt.Sprintf("/subscriptions/%s/providers/%s/%s", subscriptionID, args[0], args[1])
	}
}

func Tenant(_ ...any) any {
	return fmt.Sprintf(`{
    "countryCode": "US",
    "displayName": "Placeholder Tenant Name",
    "id": "/tenants/%[1]s",
    "tenantId": "%[1]s"
  }`, tenantID)
}

func TenantResourceID(args ...any) any {
	if len(args) < 2 {
		return nil
	}

	switch len(args) {
	case 3:
		return fmt.Sprintf("/providers/%s/%s/%s", args[0], args[1], args[2])

	default:
		return fmt.Sprintf("/providers/%s/%s", args[0], args[1])
	}

}
