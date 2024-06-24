package functions

import (
	"fmt"
)

func ResourceID(args ...any) any {
	if len(args) < 2 {
		return nil
	}

	var resourceID string

	for _, arg := range args {
		resourceID += "/" + fmt.Sprintf("%v", arg)
	}

	return resourceID
}

func ExtensionResourceID(args ...any) any {
	if len(args) < 3 {
		return nil
	}

	var resourceID string

	for _, arg := range args {
		resourceID += "/" + fmt.Sprintf("%v", arg)
	}

	return resourceID
}

func ResourceGroup(args ...any) any {
	return fmt.Sprintf(`{
"id": "/subscriptions/%s/resourceGroups/PlaceHolderResourceGroup",
"name": "Placeholder Resource Group",
"type":"Microsoft.Resources/resourceGroups",
"location": "westus",
"managedBy": "%s",
"tags": {
},
"properties": {
  "provisioningState": "Succeeded
}
}`, subscriptionID, managingResourceID)
}
