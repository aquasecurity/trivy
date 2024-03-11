package functions

var deploymentFuncs = map[string]func(dp DeploymentData, args ...interface{}) interface{}{
	"parameters":  Parameters,
	"deployment":  Deployment,
	"environment": Environment,
	"variables":   Variables,
}
var generalFuncs = map[string]func(...interface{}) interface{}{

	"add":                 Add,
	"and":                 And,
	"array":               Array,
	"base64":              Base64,
	"base64ToJson":        Base64ToJson,
	"bool":                Bool,
	"coalesce":            Coalesce,
	"concat":              Concat,
	"contains":            Contains,
	"copyIndex":           CopyIndex,
	"createArray":         CreateArray,
	"createObject":        CreateObject,
	"dataUri":             DataUri,
	"dataUriToString":     DataUriToString,
	"dateTimeAdd":         DateTimeAdd,
	"dateTimeFromEpoch":   DateTimeFromEpoch,
	"dateTimeToEpoch":     DateTimeToEpoch,
	"div":                 Div,
	"empty":               Empty,
	"endsWith":            EndsWith,
	"equals":              Equals,
	"extensionResourceId": ExtensionResourceID,
	"false":               False,
	"float":               Float,
	"format":              Format,
	"greater":             Greater,
	"greaterOrEquals":     GreaterOrEquals,
	"guid":                Guid,
	"if":                  If,
	"indexOf":             IndexOf,
	"int":                 Int,
	"intersection":        Intersection,
	"items":               Items,
	"join":                Join,
	"lastIndexOf":         LastIndexOf,
	"length":              Length,
	"less":                Less,
	"lessOrEquals":        LessOrEquals,
	// "list":                      List,
	"managementGroup":           ManagementGroup,
	"managementGroupResourceId": ManagementGroupResourceID,
	"max":                       Max,
	"min":                       Min,
	"mod":                       Mod,
	"mul":                       Mul,
	"newGuid":                   NewGuid,
	"not":                       Not,
	"null":                      Null,
	"or":                        Or,
	"padLeft":                   PadLeft,
	"pickZones":                 PickZones,
	"range":                     Range,
	"reference":                 Reference,
	"replace":                   Replace,
	"resourceGroup":             ResourceGroup,
	"resourceId":                ResourceID,
	"skip":                      Skip,
	"split":                     Split,
	"startsWith":                StartsWith,
	"string":                    String,
	"sub":                       Sub,
	"subscription":              Subscription,
	"subscriptionResourceId":    SubscriptionResourceID,
	"substring":                 SubString,
	"tenant":                    Tenant,
	"tenantResourceId":          TenantResourceID,
	"toLower":                   ToLower,
	"toUpper":                   ToUpper,
	"trim":                      Trim,
	"true":                      True,
	"union":                     Union,
	"union:":                    Union,
	"uniqueString":              UniqueString,
	"uri":                       Uri,
	"utcNow":                    UTCNow,
}

func Evaluate(deploymentProvider DeploymentData, name string, args ...interface{}) interface{} {

	if f, ok := deploymentFuncs[name]; ok {
		return f(deploymentProvider, args...)
	}

	if f, ok := generalFuncs[name]; ok {
		return f(args...)
	}

	return nil
}
