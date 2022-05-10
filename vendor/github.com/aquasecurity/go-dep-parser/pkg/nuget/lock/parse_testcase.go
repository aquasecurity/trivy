package lock

import "github.com/aquasecurity/go-dep-parser/pkg/types"

var (
	// docker run --rm -i -t mcr.microsoft.com/dotnet/sdk:latest
	// apt -y update && apt -y install jq
	// cd /usr/local/src
	// dotnet new mvc
	// dotnet add package Newtonsoft.Json
	// dotnet add package NuGet.Frameworks
	// dotnet restore --use-lock-file
	// cat packages.lock.json | jq -rc '.dependencies[] | keys[] as $k | "{\"\($k)\", \"\(.[$k] | .resolved)\", \"\"},"'
	nuGetSimple = []types.Library{
		{"Newtonsoft.Json", "12.0.3", ""},
		{"NuGet.Frameworks", "5.7.0", ""},
	}

	// docker run --rm -i -t mcr.microsoft.com/dotnet/sdk:latest
	// apt -y update && apt -y install jq
	// cd /usr/local/src
	// dotnet new webapi
	// dotnet add package Newtonsoft.Json
	// dotnet add package NuGet.Frameworks
	// dotnet restore --use-lock-file
	// cat packages.lock.json | jq -rc '.dependencies[] | keys[] as $k | "{\"\($k)\", \"\(.[$k] | .resolved)\", \"\"},"'
	nuGetSubDependencies = []types.Library{
		{"Microsoft.Extensions.ApiDescription.Server", "3.0.0", ""},
		{"Microsoft.OpenApi", "1.1.4", ""},
		{"Newtonsoft.Json", "12.0.3", ""},
		{"NuGet.Frameworks", "5.7.0", ""},
		{"Swashbuckle.AspNetCore", "5.5.1", ""},
		{"Swashbuckle.AspNetCore.Swagger", "5.5.1", ""},
		{"Swashbuckle.AspNetCore.SwaggerGen", "5.5.1", ""},
		{"Swashbuckle.AspNetCore.SwaggerUI", "5.5.1", ""},
	}

	// mcr.microsoft.com/dotnet/sdk:latest
	// apt -y update && apt -y install jq
	// cd /usr/local/src
	// dotnet new console
	// dotnet add package Newtonsoft.Json
	// dotnet add package AWSSDK.Core
	// dotnet restore --use-lock-file
	// cat packages.lock.json | jq -rc '.dependencies[] | keys[] as $k | "{\"\($k)\", \"\(.[$k] | .resolved)\", \"\"},"'
	nuGetLegacy = []types.Library{
		{"AWSSDK.Core", "3.5.1.30", ""},
		{"Newtonsoft.Json", "12.0.3", ""},
	}

	// docker run --rm -i -t mcr.microsoft.com/dotnet/sdk:latest
	// apt -y update && apt -y install jq
	// cd /usr/local/src
	// dotnet new classlib -f net5.0
	// sed -i 's~TargetFramework>net5.0</TargetFramework~TargetFrameworks>net4.0;netstandard2.0;netstandard1.0;net35;net2.0</TargetFrameworks~' src.csproj
	// dotnet add package Newtonsoft.Json
	// dotnet restore --use-lock-file
	// dotnet add package AWSSDK.Core
	// cat packages.lock.json | jq -rc '.dependencies[] | keys[] as $k | "{\"\($k)\", \"\(.[$k] | .resolved)\", \"\"},"' | sort -u
	nuGetMultiTarget = []types.Library{
		{"AWSSDK.Core", "3.5.1.30", ""},
		{"Microsoft.Bcl.AsyncInterfaces", "1.1.0", ""},
		{"Microsoft.CSharp", "4.3.0", ""},
		{"Microsoft.NETCore.Platforms", "1.1.0", ""},
		{"Microsoft.NETCore.Targets", "1.1.0", ""},
		{"Microsoft.NETFramework.ReferenceAssemblies", "1.0.0", ""},
		{"Microsoft.NETFramework.ReferenceAssemblies.net20", "1.0.0", ""},
		{"Microsoft.NETFramework.ReferenceAssemblies.net40", "1.0.0", ""},
		{"NETStandard.Library", "1.6.1", ""},
		{"NETStandard.Library", "2.0.3", ""},
		{"Newtonsoft.Json", "12.0.3", ""},
		{"System.Collections", "4.3.0", ""},
		{"System.ComponentModel", "4.3.0", ""},
		{"System.ComponentModel.Primitives", "4.3.0", ""},
		{"System.ComponentModel.TypeConverter", "4.3.0", ""},
		{"System.Diagnostics.Debug", "4.3.0", ""},
		{"System.Diagnostics.Tools", "4.3.0", ""},
		{"System.Dynamic.Runtime", "4.3.0", ""},
		{"System.Globalization", "4.3.0", ""},
		{"System.IO", "4.3.0", ""},
		{"System.Linq", "4.3.0", ""},
		{"System.Linq.Expressions", "4.3.0", ""},
		{"System.Net.Primitives", "4.3.0", ""},
		{"System.ObjectModel", "4.3.0", ""},
		{"System.Reflection", "4.3.0", ""},
		{"System.Reflection.Extensions", "4.3.0", ""},
		{"System.Reflection.Primitives", "4.3.0", ""},
		{"System.Resources.ResourceManager", "4.3.0", ""},
		{"System.Runtime", "4.3.0", ""},
		{"System.Runtime.CompilerServices.Unsafe", "4.5.2", ""},
		{"System.Runtime.Extensions", "4.3.0", ""},
		{"System.Runtime.Serialization.Primitives", "4.3.0", ""},
		{"System.Text.Encoding", "4.3.0", ""},
		{"System.Text.Encoding.Extensions", "4.3.0", ""},
		{"System.Text.RegularExpressions", "4.3.0", ""},
		{"System.Threading", "4.3.0", ""},
		{"System.Threading.Tasks", "4.3.0", ""},
		{"System.Threading.Tasks.Extensions", "4.5.2", ""},
		{"System.Xml.ReaderWriter", "4.3.0", ""},
		{"System.Xml.XDocument", "4.3.0", ""},
	}
)
