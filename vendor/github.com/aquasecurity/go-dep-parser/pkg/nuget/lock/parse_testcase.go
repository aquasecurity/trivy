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
		{Name: "Newtonsoft.Json", Version: "12.0.3"},
		{Name: "NuGet.Frameworks", Version: "5.7.0"},
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
		{Name: "Microsoft.Extensions.ApiDescription.Server", Version: "3.0.0"},
		{Name: "Microsoft.OpenApi", Version: "1.1.4"},
		{Name: "Newtonsoft.Json", Version: "12.0.3"},
		{Name: "NuGet.Frameworks", Version: "5.7.0"},
		{Name: "Swashbuckle.AspNetCore", Version: "5.5.1"},
		{Name: "Swashbuckle.AspNetCore.Swagger", Version: "5.5.1"},
		{Name: "Swashbuckle.AspNetCore.SwaggerGen", Version: "5.5.1"},
		{Name: "Swashbuckle.AspNetCore.SwaggerUI", Version: "5.5.1"},
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
		{Name: "AWSSDK.Core", Version: "3.5.1.30"},
		{Name: "Newtonsoft.Json", Version: "12.0.3"},
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
		{Name: "AWSSDK.Core", Version: "3.5.1.30"},
		{Name: "Microsoft.Bcl.AsyncInterfaces", Version: "1.1.0"},
		{Name: "Microsoft.CSharp", Version: "4.3.0"},
		{Name: "Microsoft.NETCore.Platforms", Version: "1.1.0"},
		{Name: "Microsoft.NETCore.Targets", Version: "1.1.0"},
		{Name: "Microsoft.NETFramework.ReferenceAssemblies", Version: "1.0.0"},
		{Name: "Microsoft.NETFramework.ReferenceAssemblies.net20", Version: "1.0.0"},
		{Name: "Microsoft.NETFramework.ReferenceAssemblies.net40", Version: "1.0.0"},
		{Name: "NETStandard.Library", Version: "1.6.1"},
		{Name: "NETStandard.Library", Version: "2.0.3"},
		{Name: "Newtonsoft.Json", Version: "12.0.3"},
		{Name: "System.Collections", Version: "4.3.0"},
		{Name: "System.ComponentModel", Version: "4.3.0"},
		{Name: "System.ComponentModel.Primitives", Version: "4.3.0"},
		{Name: "System.ComponentModel.TypeConverter", Version: "4.3.0"},
		{Name: "System.Diagnostics.Debug", Version: "4.3.0"},
		{Name: "System.Diagnostics.Tools", Version: "4.3.0"},
		{Name: "System.Dynamic.Runtime", Version: "4.3.0"},
		{Name: "System.Globalization", Version: "4.3.0"},
		{Name: "System.IO", Version: "4.3.0"},
		{Name: "System.Linq", Version: "4.3.0"},
		{Name: "System.Linq.Expressions", Version: "4.3.0"},
		{Name: "System.Net.Primitives", Version: "4.3.0"},
		{Name: "System.ObjectModel", Version: "4.3.0"},
		{Name: "System.Reflection", Version: "4.3.0"},
		{Name: "System.Reflection.Extensions", Version: "4.3.0"},
		{Name: "System.Reflection.Primitives", Version: "4.3.0"},
		{Name: "System.Resources.ResourceManager", Version: "4.3.0"},
		{Name: "System.Runtime", Version: "4.3.0"},
		{Name: "System.Runtime.CompilerServices.Unsafe", Version: "4.5.2"},
		{Name: "System.Runtime.Extensions", Version: "4.3.0"},
		{Name: "System.Runtime.Serialization.Primitives", Version: "4.3.0"},
		{Name: "System.Text.Encoding", Version: "4.3.0"},
		{Name: "System.Text.Encoding.Extensions", Version: "4.3.0"},
		{Name: "System.Text.RegularExpressions", Version: "4.3.0"},
		{Name: "System.Threading", Version: "4.3.0"},
		{Name: "System.Threading.Tasks", Version: "4.3.0"},
		{Name: "System.Threading.Tasks.Extensions", Version: "4.5.2"},
		{Name: "System.Xml.ReaderWriter", Version: "4.3.0"},
		{Name: "System.Xml.XDocument", Version: "4.3.0"},
	}
)
