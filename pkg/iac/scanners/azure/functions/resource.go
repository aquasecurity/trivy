package functions

import (
	"fmt"
	"strings"
)

func ResourceID(args ...any) any {
	return buildResourceID(2, args...)
}

func ExtensionResourceID(args ...any) any {
	return buildResourceID(3, args...)
}

func buildResourceID(minArgs int, args ...any) any {
	if len(args) < minArgs {
		return nil
	}

	var resourceID strings.Builder

	for _, arg := range args {
		fmt.Fprintf(&resourceID, "/%v", arg)
	}

	return resourceID.String()
}

func ResourceGroup(_ ...any) any {
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
