package workspaces

var cloudFormationEnableDiskEncryptionGoodExamples = []string{
	`---
Resources:
  GoodExample:
    Type: AWS::WorkSpaces::Workspace
    Properties:
      RootVolumeEncryptionEnabled: true
      UserVolumeEncryptionEnabled: true
      UserName: "admin"
`, `{
		    "Resources": {
		      "GoodExample": {
		        "Type": "AWS::WorkSpaces::Workspace",
		        "Properties": {
		          "RootVolumeEncryptionEnabled": true,
		          "UserVolumeEncryptionEnabled": true,
		          "UserName": "admin"
		  	  }
		  	}
		    }
		  }`,
}

var cloudFormationEnableDiskEncryptionBadExamples = []string{
	`---
Resources:
  BadExample:
    Type: AWS::WorkSpaces::Workspace
    Properties: 
      RootVolumeEncryptionEnabled: false
      UserVolumeEncryptionEnabled: false
      UserName: "admin"
`, `{
  "Resources": {
    "BadExample": {
      "Type": "AWS::WorkSpaces::Workspace",
      "Properties": {
        "RootVolumeEncryptionEnabled": false,
        "UserVolumeEncryptionEnabled": false,
        "UserName": "admin"
	  }
	}
  }
}`,
}

var cloudFormationEnableDiskEncryptionLinks = []string{}

var cloudFormationEnableDiskEncryptionRemediationMarkdown = ``
