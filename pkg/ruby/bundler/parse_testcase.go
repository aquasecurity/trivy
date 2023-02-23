package bundler

import "github.com/aquasecurity/go-dep-parser/pkg/types"

var (
	// docker run --name bundler --rm -it ruby:2.6 bash
	// bundle init
	// bundle add dotenv json faker rubocop pry
	// bundler show | grep "*" | grep -v bundler | awk '{if(match($0, /\((.*)\)/)) printf("{\""$2"\", \""substr($0, RSTART+1, RLENGTH-2)"\", \"\"},\n");}'

	// docker run --name bundler --rm -it ruby:2.6 bash
	// bundle init
	// bundle add dotenv json faker rubocop pry
	// bundle add rails
	// bundler show | grep "*" | grep -v bundler | awk '{if(match($0, /\((.*)\)/)) printf("{\""$2"\", \""substr($0, RSTART+1, RLENGTH-2)"\", \"\"},\n");}'
	BundlerRails = []types.Library{
		{
			ID:      "actioncable@5.2.3",
			Name:    "actioncable",
			Version: "5.2.3",
		},
		{
			ID:      "actionmailer@5.2.3",
			Name:    "actionmailer",
			Version: "5.2.3",
		},
		{
			ID:      "actionpack@5.2.3",
			Name:    "actionpack",
			Version: "5.2.3",
		},
		{
			ID:      "actionview@5.2.3",
			Name:    "actionview",
			Version: "5.2.3",
		},
		{
			ID:      "activejob@5.2.3",
			Name:    "activejob",
			Version: "5.2.3",
		},
		{
			ID:      "activemodel@5.2.3",
			Name:    "activemodel",
			Version: "5.2.3",
		},
		{
			ID:      "activerecord@5.2.3",
			Name:    "activerecord",
			Version: "5.2.3",
		},
		{
			ID:      "activestorage@5.2.3",
			Name:    "activestorage",
			Version: "5.2.3",
		},
		{
			ID:      "activesupport@5.2.3",
			Name:    "activesupport",
			Version: "5.2.3",
		},
		{
			ID:      "arel@9.0.0",
			Name:    "arel",
			Version: "9.0.0",
		},
		{
			ID:      "ast@2.4.0",
			Name:    "ast",
			Version: "2.4.0",
		},
		{
			ID:      "builder@3.2.3",
			Name:    "builder",
			Version: "3.2.3",
		},
		{
			ID:      "coderay@1.1.2",
			Name:    "coderay",
			Version: "1.1.2",
		},
		{
			ID:      "concurrent-ruby@1.1.5",
			Name:    "concurrent-ruby",
			Version: "1.1.5",
		},
		{
			ID:      "crass@1.0.4",
			Name:    "crass",
			Version: "1.0.4",
		},
		{
			ID:      "dotenv@2.7.2",
			Name:    "dotenv",
			Version: "2.7.2",
		},
		{
			ID:      "erubi@1.8.0",
			Name:    "erubi",
			Version: "1.8.0",
		},
		{
			ID:      "faker@1.9.3",
			Name:    "faker",
			Version: "1.9.3",
		},
		{
			ID:      "globalid@0.4.2",
			Name:    "globalid",
			Version: "0.4.2",
		},
		{
			ID:      "i18n@1.6.0",
			Name:    "i18n",
			Version: "1.6.0",
		},
		{
			ID:      "jaro_winkler@1.5.2",
			Name:    "jaro_winkler",
			Version: "1.5.2",
		},
		{
			ID:      "json@2.2.0",
			Name:    "json",
			Version: "2.2.0",
		},
		{
			ID:      "loofah@2.2.3",
			Name:    "loofah",
			Version: "2.2.3",
		},
		{
			ID:      "mail@2.7.1",
			Name:    "mail",
			Version: "2.7.1",
		},
		{
			ID:      "marcel@0.3.3",
			Name:    "marcel",
			Version: "0.3.3",
		},
		{
			ID:      "method_source@0.9.2",
			Name:    "method_source",
			Version: "0.9.2",
		},
		{
			ID:      "mimemagic@0.3.3",
			Name:    "mimemagic",
			Version: "0.3.3",
		},
		{
			ID:      "mini_mime@1.0.1",
			Name:    "mini_mime",
			Version: "1.0.1",
		},
		{
			ID:      "mini_portile2@2.4.0",
			Name:    "mini_portile2",
			Version: "2.4.0",
		},
		{
			ID:      "minitest@5.11.3",
			Name:    "minitest",
			Version: "5.11.3",
		},
		{
			ID:      "nio4r@2.3.1",
			Name:    "nio4r",
			Version: "2.3.1",
		},
		{
			ID:      "nokogiri@1.10.3",
			Name:    "nokogiri",
			Version: "1.10.3",
		},
		{
			ID:      "parallel@1.17.0",
			Name:    "parallel",
			Version: "1.17.0",
		},
		{
			ID:      "parser@2.6.3.0",
			Name:    "parser",
			Version: "2.6.3.0",
		},
		{
			ID:      "pry@0.12.2",
			Name:    "pry",
			Version: "0.12.2",
		},
		{
			ID:      "psych@3.1.0",
			Name:    "psych",
			Version: "3.1.0",
		},
		{
			ID:      "rack@2.0.7",
			Name:    "rack",
			Version: "2.0.7",
		},
		{
			ID:      "rack-test@1.1.0",
			Name:    "rack-test",
			Version: "1.1.0",
		},
		{
			ID:      "rails@5.2.3",
			Name:    "rails",
			Version: "5.2.3",
		},
		{
			ID:      "rails-dom-testing@2.0.3",
			Name:    "rails-dom-testing",
			Version: "2.0.3",
		},
		{
			ID:      "rails-html-sanitizer@1.0.4",
			Name:    "rails-html-sanitizer",
			Version: "1.0.4",
		},
		{
			ID:      "railties@5.2.3",
			Name:    "railties",
			Version: "5.2.3",
		},
		{
			ID:      "rainbow@3.0.0",
			Name:    "rainbow",
			Version: "3.0.0",
		},
		{
			ID:      "rake@12.3.2",
			Name:    "rake",
			Version: "12.3.2",
		},
		{
			ID:      "rubocop@0.67.2",
			Name:    "rubocop",
			Version: "0.67.2",
		},
		{
			ID:      "ruby-progressbar@1.10.0",
			Name:    "ruby-progressbar",
			Version: "1.10.0",
		},
		{
			ID:      "sprockets@3.7.2",
			Name:    "sprockets",
			Version: "3.7.2",
		},
		{
			ID:      "sprockets-rails@3.2.1",
			Name:    "sprockets-rails",
			Version: "3.2.1",
		},
		{
			ID:      "thor@0.20.3",
			Name:    "thor",
			Version: "0.20.3",
		},
		{
			ID:      "thread_safe@0.3.6",
			Name:    "thread_safe",
			Version: "0.3.6",
		},
		{
			ID:      "tzinfo@1.2.5",
			Name:    "tzinfo",
			Version: "1.2.5",
		},
		{
			ID:      "unicode-display_width@1.5.0",
			Name:    "unicode-display_width",
			Version: "1.5.0",
		},
		{
			ID:      "websocket-driver@0.7.0",
			Name:    "websocket-driver",
			Version: "0.7.0",
		},
		{
			ID:      "websocket-extensions@0.1.3",
			Name:    "websocket-extensions",
			Version: "0.1.3",
		},
	}

	BundlerRailsDeps = []types.Dependency{
		{
			ID: "actioncable@5.2.3",
			DependsOn: []string{
				"actionpack@5.2.3",
				"nio4r@2.3.1",
				"websocket-driver@0.7.0",
			},
		},
		{
			ID: "actionmailer@5.2.3",
			DependsOn: []string{
				"actionpack@5.2.3",
				"actionview@5.2.3",
				"activejob@5.2.3",
				"mail@2.7.1",
				"rails-dom-testing@2.0.3",
			},
		},
		{
			ID: "actionpack@5.2.3",
			DependsOn: []string{
				"actionview@5.2.3",
				"activesupport@5.2.3",
				"rack@2.0.7",
				"rack-test@1.1.0",
				"rails-dom-testing@2.0.3",
				"rails-html-sanitizer@1.0.4",
			},
		},
		{
			ID: "actionview@5.2.3",
			DependsOn: []string{
				"activesupport@5.2.3",
				"builder@3.2.3",
				"erubi@1.8.0",
				"rails-dom-testing@2.0.3",
				"rails-html-sanitizer@1.0.4",
			},
		},
		{
			ID: "activejob@5.2.3",
			DependsOn: []string{
				"activesupport@5.2.3",
				"globalid@0.4.2",
			},
		},
		{
			ID:        "activemodel@5.2.3",
			DependsOn: []string{"activesupport@5.2.3"},
		},
		{
			ID: "activerecord@5.2.3",
			DependsOn: []string{
				"activemodel@5.2.3",
				"activesupport@5.2.3",
				"arel@9.0.0",
			},
		},
		{
			ID: "activestorage@5.2.3",
			DependsOn: []string{
				"actionpack@5.2.3",
				"activerecord@5.2.3",
				"marcel@0.3.3",
			},
		},
		{
			ID: "activesupport@5.2.3",
			DependsOn: []string{
				"concurrent-ruby@1.1.5",
				"i18n@1.6.0",
				"minitest@5.11.3",
				"tzinfo@1.2.5",
			},
		},
		{
			ID:        "faker@1.9.3",
			DependsOn: []string{"i18n@1.6.0"},
		},
		{
			ID:        "globalid@0.4.2",
			DependsOn: []string{"activesupport@5.2.3"},
		},
		{
			ID:        "i18n@1.6.0",
			DependsOn: []string{"concurrent-ruby@1.1.5"},
		},
		{
			ID: "loofah@2.2.3",
			DependsOn: []string{
				"crass@1.0.4",
				"nokogiri@1.10.3",
			},
		},
		{
			ID:        "mail@2.7.1",
			DependsOn: []string{"mini_mime@1.0.1"},
		},
		{
			ID:        "marcel@0.3.3",
			DependsOn: []string{"mimemagic@0.3.3"},
		},
		{
			ID:        "nokogiri@1.10.3",
			DependsOn: []string{"mini_portile2@2.4.0"},
		},
		{
			ID:        "parser@2.6.3.0",
			DependsOn: []string{"ast@2.4.0"},
		},
		{
			ID: "pry@0.12.2",
			DependsOn: []string{
				"coderay@1.1.2",
				"method_source@0.9.2",
			},
		},
		{
			ID:        "rack-test@1.1.0",
			DependsOn: []string{"rack@2.0.7"},
		},
		{
			ID: "rails@5.2.3",
			DependsOn: []string{
				"actioncable@5.2.3",
				"actionmailer@5.2.3",
				"actionpack@5.2.3",
				"actionview@5.2.3",
				"activejob@5.2.3",
				"activemodel@5.2.3",
				"activerecord@5.2.3",
				"activestorage@5.2.3",
				"activesupport@5.2.3",
				"railties@5.2.3",
				"sprockets-rails@3.2.1",
			},
		},
		{
			ID: "rails-dom-testing@2.0.3",
			DependsOn: []string{
				"activesupport@5.2.3",
				"nokogiri@1.10.3",
			},
		},
		{
			ID:        "rails-html-sanitizer@1.0.4",
			DependsOn: []string{"loofah@2.2.3"},
		},
		{
			ID: "railties@5.2.3",
			DependsOn: []string{
				"actionpack@5.2.3",
				"activesupport@5.2.3",
				"method_source@0.9.2",
				"rake@12.3.2",
				"thor@0.20.3",
			},
		},
		{
			ID: "rubocop@0.67.2",
			DependsOn: []string{
				"jaro_winkler@1.5.2",
				"parallel@1.17.0",
				"parser@2.6.3.0",
				"psych@3.1.0",
				"rainbow@3.0.0",
				"ruby-progressbar@1.10.0",
				"unicode-display_width@1.5.0",
			},
		},
		{
			ID: "sprockets@3.7.2",
			DependsOn: []string{
				"concurrent-ruby@1.1.5",
				"rack@2.0.7",
			},
		},
		{
			ID: "sprockets-rails@3.2.1",
			DependsOn: []string{
				"actionpack@5.2.3",
				"activesupport@5.2.3",
				"sprockets@3.7.2",
			},
		},
		{
			ID:        "tzinfo@1.2.5",
			DependsOn: []string{"thread_safe@0.3.6"},
		},
		{
			ID:        "websocket-driver@0.7.0",
			DependsOn: []string{"websocket-extensions@0.1.3"},
		},
	}

	// docker run --name bundler --rm -it ruby:2.6 bash
	// bundle init
	// bundle add dotenv json faker rubocop pry
	// bundle add rails
	// bundle add sinatra multi-json thor sass aws-sdk faraday
	// bundler show | grep "*" | grep -v bundler | awk '{if(match($0, /\((.*)\)/)) printf("{\""$2"\", \""substr($0, RSTART+1, RLENGTH-2)"\"}, \"\"},\n");}'
	BundlerMany = []types.Library{
		{
			ID:      "actioncable@5.2.3",
			Name:    "actioncable",
			Version: "5.2.3",
		},
		{
			ID:      "actionmailer@5.2.3",
			Name:    "actionmailer",
			Version: "5.2.3",
		},
		{
			ID:      "actionpack@5.2.3",
			Name:    "actionpack",
			Version: "5.2.3",
		},
		{
			ID:      "actionview@5.2.3",
			Name:    "actionview",
			Version: "5.2.3",
		},
		{
			ID:      "activejob@5.2.3",
			Name:    "activejob",
			Version: "5.2.3",
		},
		{
			ID:      "activemodel@5.2.3",
			Name:    "activemodel",
			Version: "5.2.3",
		},
		{
			ID:      "activerecord@5.2.3",
			Name:    "activerecord",
			Version: "5.2.3",
		},
		{
			ID:      "activestorage@5.2.3",
			Name:    "activestorage",
			Version: "5.2.3",
		},
		{
			ID:      "activesupport@5.2.3",
			Name:    "activesupport",
			Version: "5.2.3",
		},
		{
			ID:      "arel@9.0.0",
			Name:    "arel",
			Version: "9.0.0",
		},
		{
			ID:      "ast@2.4.0",
			Name:    "ast",
			Version: "2.4.0",
		},
		{
			ID:      "aws-eventstream@1.0.3",
			Name:    "aws-eventstream",
			Version: "1.0.3",
		},
		{
			ID:      "aws-partitions@1.154.0",
			Name:    "aws-partitions",
			Version: "1.154.0",
		},
		{
			ID:      "aws-sdk@3.0.1",
			Name:    "aws-sdk",
			Version: "3.0.1",
		},
		{
			ID:      "aws-sdk-acm@1.19.0",
			Name:    "aws-sdk-acm",
			Version: "1.19.0",
		},
		{
			ID:      "aws-sdk-acmpca@1.13.0",
			Name:    "aws-sdk-acmpca",
			Version: "1.13.0",
		},
		{
			ID:      "aws-sdk-alexaforbusiness@1.20.0",
			Name:    "aws-sdk-alexaforbusiness",
			Version: "1.20.0",
		},
		{
			ID:      "aws-sdk-amplify@1.3.0",
			Name:    "aws-sdk-amplify",
			Version: "1.3.0",
		},
		{
			ID:      "aws-sdk-apigateway@1.26.0",
			Name:    "aws-sdk-apigateway",
			Version: "1.26.0",
		},
		{
			ID:      "aws-sdk-apigatewaymanagementapi@1.3.0",
			Name:    "aws-sdk-apigatewaymanagementapi",
			Version: "1.3.0",
		},
		{
			ID:      "aws-sdk-apigatewayv2@1.4.0",
			Name:    "aws-sdk-apigatewayv2",
			Version: "1.4.0",
		},
		{
			ID:      "aws-sdk-applicationautoscaling@1.22.0",
			Name:    "aws-sdk-applicationautoscaling",
			Version: "1.22.0",
		},
		{
			ID:      "aws-sdk-applicationdiscoveryservice@1.15.0",
			Name:    "aws-sdk-applicationdiscoveryservice",
			Version: "1.15.0",
		},
		{
			ID:      "aws-sdk-appmesh@1.6.0",
			Name:    "aws-sdk-appmesh",
			Version: "1.6.0",
		},
		{
			ID:      "aws-sdk-appstream@1.25.0",
			Name:    "aws-sdk-appstream",
			Version: "1.25.0",
		},
		{
			ID:      "aws-sdk-appsync@1.12.0",
			Name:    "aws-sdk-appsync",
			Version: "1.12.0",
		},
		{
			ID:      "aws-sdk-athena@1.12.0",
			Name:    "aws-sdk-athena",
			Version: "1.12.0",
		},
		{
			ID:      "aws-sdk-autoscaling@1.20.0",
			Name:    "aws-sdk-autoscaling",
			Version: "1.20.0",
		},
		{
			ID:      "aws-sdk-autoscalingplans@1.12.0",
			Name:    "aws-sdk-autoscalingplans",
			Version: "1.12.0",
		},
		{
			ID:      "aws-sdk-backup@1.3.0",
			Name:    "aws-sdk-backup",
			Version: "1.3.0",
		},
		{
			ID:      "aws-sdk-batch@1.17.0",
			Name:    "aws-sdk-batch",
			Version: "1.17.0",
		},
		{
			ID:      "aws-sdk-budgets@1.18.0",
			Name:    "aws-sdk-budgets",
			Version: "1.18.0",
		},
		{
			ID:      "aws-sdk-chime@1.6.0",
			Name:    "aws-sdk-chime",
			Version: "1.6.0",
		},
		{
			ID:      "aws-sdk-cloud9@1.11.0",
			Name:    "aws-sdk-cloud9",
			Version: "1.11.0",
		},
		{
			ID:      "aws-sdk-clouddirectory@1.14.0",
			Name:    "aws-sdk-clouddirectory",
			Version: "1.14.0",
		},
		{
			ID:      "aws-sdk-cloudformation@1.19.0",
			Name:    "aws-sdk-cloudformation",
			Version: "1.19.0",
		},
		{
			ID:      "aws-sdk-cloudfront@1.15.0",
			Name:    "aws-sdk-cloudfront",
			Version: "1.15.0",
		},
		{
			ID:      "aws-sdk-cloudhsm@1.12.0",
			Name:    "aws-sdk-cloudhsm",
			Version: "1.12.0",
		},
		{
			ID:      "aws-sdk-cloudhsmv2@1.12.0",
			Name:    "aws-sdk-cloudhsmv2",
			Version: "1.12.0",
		},
		{
			ID:      "aws-sdk-cloudsearch@1.9.0",
			Name:    "aws-sdk-cloudsearch",
			Version: "1.9.0",
		},
		{
			ID:      "aws-sdk-cloudsearchdomain@1.9.0",
			Name:    "aws-sdk-cloudsearchdomain",
			Version: "1.9.0",
		},
		{
			ID:      "aws-sdk-cloudtrail@1.11.0",
			Name:    "aws-sdk-cloudtrail",
			Version: "1.11.0",
		},
		{
			ID:      "aws-sdk-cloudwatch@1.20.0",
			Name:    "aws-sdk-cloudwatch",
			Version: "1.20.0",
		},
		{
			ID:      "aws-sdk-cloudwatchevents@1.17.0",
			Name:    "aws-sdk-cloudwatchevents",
			Version: "1.17.0",
		},
		{
			ID:      "aws-sdk-cloudwatchlogs@1.17.0",
			Name:    "aws-sdk-cloudwatchlogs",
			Version: "1.17.0",
		},
		{
			ID:      "aws-sdk-codebuild@1.32.0",
			Name:    "aws-sdk-codebuild",
			Version: "1.32.0",
		},
		{
			ID:      "aws-sdk-codecommit@1.17.0",
			Name:    "aws-sdk-codecommit",
			Version: "1.17.0",
		},
		{
			ID:      "aws-sdk-codedeploy@1.18.0",
			Name:    "aws-sdk-codedeploy",
			Version: "1.18.0",
		},
		{
			ID:      "aws-sdk-codepipeline@1.15.0",
			Name:    "aws-sdk-codepipeline",
			Version: "1.15.0",
		},
		{
			ID:      "aws-sdk-codestar@1.11.0",
			Name:    "aws-sdk-codestar",
			Version: "1.11.0",
		},
		{
			ID:      "aws-sdk-cognitoidentity@1.10.0",
			Name:    "aws-sdk-cognitoidentity",
			Version: "1.10.0",
		},
		{
			ID:      "aws-sdk-cognitoidentityprovider@1.18.0",
			Name:    "aws-sdk-cognitoidentityprovider",
			Version: "1.18.0",
		},
		{
			ID:      "aws-sdk-cognitosync@1.9.0",
			Name:    "aws-sdk-cognitosync",
			Version: "1.9.0",
		},
		{
			ID:      "aws-sdk-comprehend@1.18.0",
			Name:    "aws-sdk-comprehend",
			Version: "1.18.0",
		},
		{
			ID:      "aws-sdk-comprehendmedical@1.3.0",
			Name:    "aws-sdk-comprehendmedical",
			Version: "1.3.0",
		},
		{
			ID:      "aws-sdk-configservice@1.26.0",
			Name:    "aws-sdk-configservice",
			Version: "1.26.0",
		},
		{
			ID:      "aws-sdk-connect@1.13.0",
			Name:    "aws-sdk-connect",
			Version: "1.13.0",
		},
		{
			ID:      "aws-sdk-core@3.48.6",
			Name:    "aws-sdk-core",
			Version: "3.48.6",
		},
		{
			ID:      "aws-sdk-costandusagereportservice@1.10.0",
			Name:    "aws-sdk-costandusagereportservice",
			Version: "1.10.0",
		},
		{
			ID:      "aws-sdk-costexplorer@1.21.0",
			Name:    "aws-sdk-costexplorer",
			Version: "1.21.0",
		},
		{
			ID:      "aws-sdk-databasemigrationservice@1.20.0",
			Name:    "aws-sdk-databasemigrationservice",
			Version: "1.20.0",
		},
		{
			ID:      "aws-sdk-datapipeline@1.9.0",
			Name:    "aws-sdk-datapipeline",
			Version: "1.9.0",
		},
		{
			ID:      "aws-sdk-datasync@1.3.0",
			Name:    "aws-sdk-datasync",
			Version: "1.3.0",
		},
		{
			ID:      "aws-sdk-dax@1.11.0",
			Name:    "aws-sdk-dax",
			Version: "1.11.0",
		},
		{
			ID:      "aws-sdk-devicefarm@1.19.0",
			Name:    "aws-sdk-devicefarm",
			Version: "1.19.0",
		},
		{
			ID:      "aws-sdk-directconnect@1.16.0",
			Name:    "aws-sdk-directconnect",
			Version: "1.16.0",
		},
		{
			ID:      "aws-sdk-directoryservice@1.15.0",
			Name:    "aws-sdk-directoryservice",
			Version: "1.15.0",
		},
		{
			ID:      "aws-sdk-dlm@1.11.0",
			Name:    "aws-sdk-dlm",
			Version: "1.11.0",
		},
		{
			ID:      "aws-sdk-docdb@1.4.0",
			Name:    "aws-sdk-docdb",
			Version: "1.4.0",
		},
		{
			ID:      "aws-sdk-dynamodb@1.26.0",
			Name:    "aws-sdk-dynamodb",
			Version: "1.26.0",
		},
		{
			ID:      "aws-sdk-dynamodbstreams@1.9.0",
			Name:    "aws-sdk-dynamodbstreams",
			Version: "1.9.0",
		},
		{
			ID:      "aws-sdk-ec2@1.80.0",
			Name:    "aws-sdk-ec2",
			Version: "1.80.0",
		},
		{
			ID:      "aws-sdk-ecr@1.14.0",
			Name:    "aws-sdk-ecr",
			Version: "1.14.0",
		},
		{
			ID:      "aws-sdk-ecs@1.36.0",
			Name:    "aws-sdk-ecs",
			Version: "1.36.0",
		},
		{
			ID:      "aws-sdk-efs@1.13.0",
			Name:    "aws-sdk-efs",
			Version: "1.13.0",
		},
		{
			ID:      "aws-sdk-eks@1.15.0",
			Name:    "aws-sdk-eks",
			Version: "1.15.0",
		},
		{
			ID:      "aws-sdk-elasticache@1.14.0",
			Name:    "aws-sdk-elasticache",
			Version: "1.14.0",
		},
		{
			ID:      "aws-sdk-elasticbeanstalk@1.19.0",
			Name:    "aws-sdk-elasticbeanstalk",
			Version: "1.19.0",
		},
		{
			ID:      "aws-sdk-elasticloadbalancing@1.12.0",
			Name:    "aws-sdk-elasticloadbalancing",
			Version: "1.12.0",
		},
		{
			ID:      "aws-sdk-elasticloadbalancingv2@1.26.0",
			Name:    "aws-sdk-elasticloadbalancingv2",
			Version: "1.26.0",
		},
		{
			ID:      "aws-sdk-elasticsearchservice@1.19.0",
			Name:    "aws-sdk-elasticsearchservice",
			Version: "1.19.0",
		},
		{
			ID:      "aws-sdk-elastictranscoder@1.11.0",
			Name:    "aws-sdk-elastictranscoder",
			Version: "1.11.0",
		},
		{
			ID:      "aws-sdk-emr@1.14.0",
			Name:    "aws-sdk-emr",
			Version: "1.14.0",
		},
		{
			ID:      "aws-sdk-firehose@1.14.0",
			Name:    "aws-sdk-firehose",
			Version: "1.14.0",
		},
		{
			ID:      "aws-sdk-fms@1.12.0",
			Name:    "aws-sdk-fms",
			Version: "1.12.0",
		},
		{
			ID:      "aws-sdk-fsx@1.4.0",
			Name:    "aws-sdk-fsx",
			Version: "1.4.0",
		},
		{
			ID:      "aws-sdk-gamelift@1.16.0",
			Name:    "aws-sdk-gamelift",
			Version: "1.16.0",
		},
		{
			ID:      "aws-sdk-glacier@1.18.0",
			Name:    "aws-sdk-glacier",
			Version: "1.18.0",
		},
		{
			ID:      "aws-sdk-globalaccelerator@1.4.0",
			Name:    "aws-sdk-globalaccelerator",
			Version: "1.4.0",
		},
		{
			ID:      "aws-sdk-glue@1.30.0",
			Name:    "aws-sdk-glue",
			Version: "1.30.0",
		},
		{
			ID:      "aws-sdk-greengrass@1.17.0",
			Name:    "aws-sdk-greengrass",
			Version: "1.17.0",
		},
		{
			ID:      "aws-sdk-guardduty@1.14.0",
			Name:    "aws-sdk-guardduty",
			Version: "1.14.0",
		},
		{
			ID:      "aws-sdk-health@1.12.0",
			Name:    "aws-sdk-health",
			Version: "1.12.0",
		},
		{
			ID:      "aws-sdk-iam@1.19.0",
			Name:    "aws-sdk-iam",
			Version: "1.19.0",
		},
		{
			ID:      "aws-sdk-importexport@1.9.0",
			Name:    "aws-sdk-importexport",
			Version: "1.9.0",
		},
		{
			ID:      "aws-sdk-inspector@1.16.0",
			Name:    "aws-sdk-inspector",
			Version: "1.16.0",
		},
		{
			ID:      "aws-sdk-iot@1.29.0",
			Name:    "aws-sdk-iot",
			Version: "1.29.0",
		},
		{
			ID:      "aws-sdk-iot1clickdevicesservice@1.11.0",
			Name:    "aws-sdk-iot1clickdevicesservice",
			Version: "1.11.0",
		},
		{
			ID:      "aws-sdk-iot1clickprojects@1.10.0",
			Name:    "aws-sdk-iot1clickprojects",
			Version: "1.10.0",
		},
		{
			ID:      "aws-sdk-iotanalytics@1.16.0",
			Name:    "aws-sdk-iotanalytics",
			Version: "1.16.0",
		},
		{
			ID:      "aws-sdk-iotdataplane@1.9.0",
			Name:    "aws-sdk-iotdataplane",
			Version: "1.9.0",
		},
		{
			ID:      "aws-sdk-iotjobsdataplane@1.10.0",
			Name:    "aws-sdk-iotjobsdataplane",
			Version: "1.10.0",
		},
		{
			ID:      "aws-sdk-kafka@1.4.0",
			Name:    "aws-sdk-kafka",
			Version: "1.4.0",
		},
		{
			ID:      "aws-sdk-kinesis@1.13.1",
			Name:    "aws-sdk-kinesis",
			Version: "1.13.1",
		},
		{
			ID:      "aws-sdk-kinesisanalytics@1.12.0",
			Name:    "aws-sdk-kinesisanalytics",
			Version: "1.12.0",
		},
		{
			ID:      "aws-sdk-kinesisanalyticsv2@1.3.0",
			Name:    "aws-sdk-kinesisanalyticsv2",
			Version: "1.3.0",
		},
		{
			ID:      "aws-sdk-kinesisvideo@1.12.0",
			Name:    "aws-sdk-kinesisvideo",
			Version: "1.12.0",
		},
		{
			ID:      "aws-sdk-kinesisvideoarchivedmedia@1.11.0",
			Name:    "aws-sdk-kinesisvideoarchivedmedia",
			Version: "1.11.0",
		},
		{
			ID:      "aws-sdk-kinesisvideomedia@1.10.0",
			Name:    "aws-sdk-kinesisvideomedia",
			Version: "1.10.0",
		},
		{
			ID:      "aws-sdk-kms@1.17.0",
			Name:    "aws-sdk-kms",
			Version: "1.17.0",
		},
		{
			ID:      "aws-sdk-lambda@1.22.0",
			Name:    "aws-sdk-lambda",
			Version: "1.22.0",
		},
		{
			ID:      "aws-sdk-lambdapreview@1.9.0",
			Name:    "aws-sdk-lambdapreview",
			Version: "1.9.0",
		},
		{
			ID:      "aws-sdk-lex@1.12.0",
			Name:    "aws-sdk-lex",
			Version: "1.12.0",
		},
		{
			ID:      "aws-sdk-lexmodelbuildingservice@1.15.0",
			Name:    "aws-sdk-lexmodelbuildingservice",
			Version: "1.15.0",
		},
		{
			ID:      "aws-sdk-licensemanager@1.3.0",
			Name:    "aws-sdk-licensemanager",
			Version: "1.3.0",
		},
		{
			ID:      "aws-sdk-lightsail@1.18.0",
			Name:    "aws-sdk-lightsail",
			Version: "1.18.0",
		},
		{
			ID:      "aws-sdk-machinelearning@1.10.0",
			Name:    "aws-sdk-machinelearning",
			Version: "1.10.0",
		},
		{
			ID:      "aws-sdk-macie@1.9.0",
			Name:    "aws-sdk-macie",
			Version: "1.9.0",
		},
		{
			ID:      "aws-sdk-marketplacecommerceanalytics@1.9.0",
			Name:    "aws-sdk-marketplacecommerceanalytics",
			Version: "1.9.0",
		},
		{
			ID:      "aws-sdk-marketplaceentitlementservice@1.9.0",
			Name:    "aws-sdk-marketplaceentitlementservice",
			Version: "1.9.0",
		},
		{
			ID:      "aws-sdk-marketplacemetering@1.11.0",
			Name:    "aws-sdk-marketplacemetering",
			Version: "1.11.0",
		},
		{
			ID:      "aws-sdk-mediaconnect@1.5.0",
			Name:    "aws-sdk-mediaconnect",
			Version: "1.5.0",
		},
		{
			ID:      "aws-sdk-mediaconvert@1.25.0",
			Name:    "aws-sdk-mediaconvert",
			Version: "1.25.0",
		},
		{
			ID:      "aws-sdk-medialive@1.28.0",
			Name:    "aws-sdk-medialive",
			Version: "1.28.0",
		},
		{
			ID:      "aws-sdk-mediapackage@1.15.0",
			Name:    "aws-sdk-mediapackage",
			Version: "1.15.0",
		},
		{
			ID:      "aws-sdk-mediastore@1.12.0",
			Name:    "aws-sdk-mediastore",
			Version: "1.12.0",
		},
		{
			ID:      "aws-sdk-mediastoredata@1.11.0",
			Name:    "aws-sdk-mediastoredata",
			Version: "1.11.0",
		},
		{
			ID:      "aws-sdk-mediatailor@1.14.0",
			Name:    "aws-sdk-mediatailor",
			Version: "1.14.0",
		},
		{
			ID:      "aws-sdk-migrationhub@1.11.0",
			Name:    "aws-sdk-migrationhub",
			Version: "1.11.0",
		},
		{
			ID:      "aws-sdk-mobile@1.9.0",
			Name:    "aws-sdk-mobile",
			Version: "1.9.0",
		},
		{
			ID:      "aws-sdk-mq@1.13.0",
			Name:    "aws-sdk-mq",
			Version: "1.13.0",
		},
		{
			ID:      "aws-sdk-mturk@1.12.0",
			Name:    "aws-sdk-mturk",
			Version: "1.12.0",
		},
		{
			ID:      "aws-sdk-neptune@1.11.0",
			Name:    "aws-sdk-neptune",
			Version: "1.11.0",
		},
		{
			ID:      "aws-sdk-opsworks@1.13.0",
			Name:    "aws-sdk-opsworks",
			Version: "1.13.0",
		},
		{
			ID:      "aws-sdk-opsworkscm@1.16.0",
			Name:    "aws-sdk-opsworkscm",
			Version: "1.16.0",
		},
		{
			ID:      "aws-sdk-organizations@1.24.0",
			Name:    "aws-sdk-organizations",
			Version: "1.24.0",
		},
		{
			ID:      "aws-sdk-pi@1.9.0",
			Name:    "aws-sdk-pi",
			Version: "1.9.0",
		},
		{
			ID:      "aws-sdk-pinpoint@1.19.0",
			Name:    "aws-sdk-pinpoint",
			Version: "1.19.0",
		},
		{
			ID:      "aws-sdk-pinpointemail@1.6.0",
			Name:    "aws-sdk-pinpointemail",
			Version: "1.6.0",
		},
		{
			ID:      "aws-sdk-pinpointsmsvoice@1.6.0",
			Name:    "aws-sdk-pinpointsmsvoice",
			Version: "1.6.0",
		},
		{
			ID:      "aws-sdk-polly@1.19.0",
			Name:    "aws-sdk-polly",
			Version: "1.19.0",
		},
		{
			ID:      "aws-sdk-pricing@1.9.0",
			Name:    "aws-sdk-pricing",
			Version: "1.9.0",
		},
		{
			ID:      "aws-sdk-quicksight@1.5.0",
			Name:    "aws-sdk-quicksight",
			Version: "1.5.0",
		},
		{
			ID:      "aws-sdk-ram@1.4.0",
			Name:    "aws-sdk-ram",
			Version: "1.4.0",
		},
		{
			ID:      "aws-sdk-rds@1.50.0",
			Name:    "aws-sdk-rds",
			Version: "1.50.0",
		},
		{
			ID:      "aws-sdk-rdsdataservice@1.4.0",
			Name:    "aws-sdk-rdsdataservice",
			Version: "1.4.0",
		},
		{
			ID:      "aws-sdk-redshift@1.23.0",
			Name:    "aws-sdk-redshift",
			Version: "1.23.0",
		},
		{
			ID:      "aws-sdk-rekognition@1.22.0",
			Name:    "aws-sdk-rekognition",
			Version: "1.22.0",
		},
		{
			ID:      "aws-sdk-resourcegroups@1.14.0",
			Name:    "aws-sdk-resourcegroups",
			Version: "1.14.0",
		},
		{
			ID:      "aws-sdk-resourcegroupstaggingapi@1.9.0",
			Name:    "aws-sdk-resourcegroupstaggingapi",
			Version: "1.9.0",
		},
		{
			ID:      "aws-sdk-resources@3.41.0",
			Name:    "aws-sdk-resources",
			Version: "3.41.0",
		},
		{
			ID:      "aws-sdk-robomaker@1.5.0",
			Name:    "aws-sdk-robomaker",
			Version: "1.5.0",
		},
		{
			ID:      "aws-sdk-route53@1.22.0",
			Name:    "aws-sdk-route53",
			Version: "1.22.0",
		},
		{
			ID:      "aws-sdk-route53domains@1.11.0",
			Name:    "aws-sdk-route53domains",
			Version: "1.11.0",
		},
		{
			ID:      "aws-sdk-route53resolver@1.4.0",
			Name:    "aws-sdk-route53resolver",
			Version: "1.4.0",
		},
		{
			ID:      "aws-sdk-s3@1.36.1",
			Name:    "aws-sdk-s3",
			Version: "1.36.1",
		},
		{
			ID:      "aws-sdk-s3control@1.4.0",
			Name:    "aws-sdk-s3control",
			Version: "1.4.0",
		},
		{
			ID:      "aws-sdk-sagemaker@1.33.0",
			Name:    "aws-sdk-sagemaker",
			Version: "1.33.0",
		},
		{
			ID:      "aws-sdk-sagemakerruntime@1.10.0",
			Name:    "aws-sdk-sagemakerruntime",
			Version: "1.10.0",
		},
		{
			ID:      "aws-sdk-secretsmanager@1.24.0",
			Name:    "aws-sdk-secretsmanager",
			Version: "1.24.0",
		},
		{
			ID:      "aws-sdk-securityhub@1.4.0",
			Name:    "aws-sdk-securityhub",
			Version: "1.4.0",
		},
		{
			ID:      "aws-sdk-serverlessapplicationrepository@1.15.0",
			Name:    "aws-sdk-serverlessapplicationrepository",
			Version: "1.15.0",
		},
		{
			ID:      "aws-sdk-servicecatalog@1.20.0",
			Name:    "aws-sdk-servicecatalog",
			Version: "1.20.0",
		},
		{
			ID:      "aws-sdk-servicediscovery@1.12.0",
			Name:    "aws-sdk-servicediscovery",
			Version: "1.12.0",
		},
		{
			ID:      "aws-sdk-ses@1.18.0",
			Name:    "aws-sdk-ses",
			Version: "1.18.0",
		},
		{
			ID:      "aws-sdk-shield@1.13.0",
			Name:    "aws-sdk-shield",
			Version: "1.13.0",
		},
		{
			ID:      "aws-sdk-signer@1.9.0",
			Name:    "aws-sdk-signer",
			Version: "1.9.0",
		},
		{
			ID:      "aws-sdk-simpledb@1.9.0",
			Name:    "aws-sdk-simpledb",
			Version: "1.9.0",
		},
		{
			ID:      "aws-sdk-sms@1.10.0",
			Name:    "aws-sdk-sms",
			Version: "1.10.0",
		},
		{
			ID:      "aws-sdk-snowball@1.14.0",
			Name:    "aws-sdk-snowball",
			Version: "1.14.0",
		},
		{
			ID:      "aws-sdk-sns@1.13.0",
			Name:    "aws-sdk-sns",
			Version: "1.13.0",
		},
		{
			ID:      "aws-sdk-sqs@1.13.0",
			Name:    "aws-sdk-sqs",
			Version: "1.13.0",
		},
		{
			ID:      "aws-sdk-ssm@1.43.0",
			Name:    "aws-sdk-ssm",
			Version: "1.43.0",
		},
		{
			ID:      "aws-sdk-states@1.14.0",
			Name:    "aws-sdk-states",
			Version: "1.14.0",
		},
		{
			ID:      "aws-sdk-storagegateway@1.21.0",
			Name:    "aws-sdk-storagegateway",
			Version: "1.21.0",
		},
		{
			ID:      "aws-sdk-support@1.9.0",
			Name:    "aws-sdk-support",
			Version: "1.9.0",
		},
		{
			ID:      "aws-sdk-swf@1.9.0",
			Name:    "aws-sdk-swf",
			Version: "1.9.0",
		},
		{
			ID:      "aws-sdk-textract@1.4.0",
			Name:    "aws-sdk-textract",
			Version: "1.4.0",
		},
		{
			ID:      "aws-sdk-transcribeservice@1.19.0",
			Name:    "aws-sdk-transcribeservice",
			Version: "1.19.0",
		},
		{
			ID:      "aws-sdk-transcribestreamingservice@1.2.0",
			Name:    "aws-sdk-transcribestreamingservice",
			Version: "1.2.0",
		},
		{
			ID:      "aws-sdk-transfer@1.5.0",
			Name:    "aws-sdk-transfer",
			Version: "1.5.0",
		},
		{
			ID:      "aws-sdk-translate@1.11.0",
			Name:    "aws-sdk-translate",
			Version: "1.11.0",
		},
		{
			ID:      "aws-sdk-waf@1.16.0",
			Name:    "aws-sdk-waf",
			Version: "1.16.0",
		},
		{
			ID:      "aws-sdk-wafregional@1.17.0",
			Name:    "aws-sdk-wafregional",
			Version: "1.17.0",
		},
		{
			ID:      "aws-sdk-workdocs@1.12.0",
			Name:    "aws-sdk-workdocs",
			Version: "1.12.0",
		},
		{
			ID:      "aws-sdk-worklink@1.4.0",
			Name:    "aws-sdk-worklink",
			Version: "1.4.0",
		},
		{
			ID:      "aws-sdk-workmail@1.11.0",
			Name:    "aws-sdk-workmail",
			Version: "1.11.0",
		},
		{
			ID:      "aws-sdk-workspaces@1.19.0",
			Name:    "aws-sdk-workspaces",
			Version: "1.19.0",
		},
		{
			ID:      "aws-sdk-xray@1.13.0",
			Name:    "aws-sdk-xray",
			Version: "1.13.0",
		},
		{
			ID:      "aws-sigv2@1.0.1",
			Name:    "aws-sigv2",
			Version: "1.0.1",
		},
		{
			ID:      "aws-sigv4@1.1.0",
			Name:    "aws-sigv4",
			Version: "1.1.0",
		},
		{
			ID:      "builder@3.2.3",
			Name:    "builder",
			Version: "3.2.3",
		},
		{
			ID:      "coderay@1.1.2",
			Name:    "coderay",
			Version: "1.1.2",
		},
		{
			ID:      "concurrent-ruby@1.1.5",
			Name:    "concurrent-ruby",
			Version: "1.1.5",
		},
		{
			ID:      "crass@1.0.4",
			Name:    "crass",
			Version: "1.0.4",
		},
		{
			ID:      "dotenv@2.7.2",
			Name:    "dotenv",
			Version: "2.7.2",
		},
		{
			ID:      "erubi@1.8.0",
			Name:    "erubi",
			Version: "1.8.0",
		},
		{
			ID:      "faker@1.9.3",
			Name:    "faker",
			Version: "1.9.3",
		},
		{
			ID:      "faraday@0.15.4",
			Name:    "faraday",
			Version: "0.15.4",
		},
		{
			ID:      "ffi@1.10.0",
			Name:    "ffi",
			Version: "1.10.0",
		},
		{
			ID:      "globalid@0.4.2",
			Name:    "globalid",
			Version: "0.4.2",
		},
		{
			ID:      "i18n@1.6.0",
			Name:    "i18n",
			Version: "1.6.0",
		},
		{
			ID:      "jaro_winkler@1.5.2",
			Name:    "jaro_winkler",
			Version: "1.5.2",
		},
		{
			ID:      "jmespath@1.4.0",
			Name:    "jmespath",
			Version: "1.4.0",
		},
		{
			ID:      "json@2.2.0",
			Name:    "json",
			Version: "2.2.0",
		},
		{
			ID:      "loofah@2.2.3",
			Name:    "loofah",
			Version: "2.2.3",
		},
		{
			ID:      "mail@2.7.1",
			Name:    "mail",
			Version: "2.7.1",
		},
		{
			ID:      "marcel@0.3.3",
			Name:    "marcel",
			Version: "0.3.3",
		},
		{
			ID:      "method_source@0.9.2",
			Name:    "method_source",
			Version: "0.9.2",
		},
		{
			ID:      "mimemagic@0.3.3",
			Name:    "mimemagic",
			Version: "0.3.3",
		},
		{
			ID:      "mini_mime@1.0.1",
			Name:    "mini_mime",
			Version: "1.0.1",
		},
		{
			ID:      "mini_portile2@2.4.0",
			Name:    "mini_portile2",
			Version: "2.4.0",
		},
		{
			ID:      "minitest@5.11.3",
			Name:    "minitest",
			Version: "5.11.3",
		},
		{
			ID:      "multi_json@1.13.1",
			Name:    "multi_json",
			Version: "1.13.1",
		},
		{
			ID:      "multipart-post@2.0.0",
			Name:    "multipart-post",
			Version: "2.0.0",
		},
		{
			ID:      "mustermann@1.0.3",
			Name:    "mustermann",
			Version: "1.0.3",
		},
		{
			ID:      "nio4r@2.3.1",
			Name:    "nio4r",
			Version: "2.3.1",
		},
		{
			ID:      "nokogiri@1.10.3",
			Name:    "nokogiri",
			Version: "1.10.3",
		},
		{
			ID:      "parallel@1.17.0",
			Name:    "parallel",
			Version: "1.17.0",
		},
		{
			ID:      "parser@2.6.3.0",
			Name:    "parser",
			Version: "2.6.3.0",
		},
		{
			ID:      "pry@0.12.2",
			Name:    "pry",
			Version: "0.12.2",
		},
		{
			ID:      "psych@3.1.0",
			Name:    "psych",
			Version: "3.1.0",
		},
		{
			ID:      "rack@2.0.7",
			Name:    "rack",
			Version: "2.0.7",
		},
		{
			ID:      "rack-protection@2.0.5",
			Name:    "rack-protection",
			Version: "2.0.5",
		},
		{
			ID:      "rack-test@1.1.0",
			Name:    "rack-test",
			Version: "1.1.0",
		},
		{
			ID:      "rails@5.2.3",
			Name:    "rails",
			Version: "5.2.3",
		},
		{
			ID:      "rails-dom-testing@2.0.3",
			Name:    "rails-dom-testing",
			Version: "2.0.3",
		},
		{
			ID:      "rails-html-sanitizer@1.0.4",
			Name:    "rails-html-sanitizer",
			Version: "1.0.4",
		},
		{
			ID:      "railties@5.2.3",
			Name:    "railties",
			Version: "5.2.3",
		},
		{
			ID:      "rainbow@3.0.0",
			Name:    "rainbow",
			Version: "3.0.0",
		},
		{
			ID:      "rake@12.3.2",
			Name:    "rake",
			Version: "12.3.2",
		},
		{
			ID:      "rb-fsevent@0.10.3",
			Name:    "rb-fsevent",
			Version: "0.10.3",
		},
		{
			ID:      "rb-inotify@0.10.0",
			Name:    "rb-inotify",
			Version: "0.10.0",
		},
		{
			ID:      "rubocop@0.67.2",
			Name:    "rubocop",
			Version: "0.67.2",
		},
		{
			ID:      "ruby-progressbar@1.10.0",
			Name:    "ruby-progressbar",
			Version: "1.10.0",
		},
		{
			ID:      "sass@3.7.4",
			Name:    "sass",
			Version: "3.7.4",
		},
		{
			ID:      "sass-listen@4.0.0",
			Name:    "sass-listen",
			Version: "4.0.0",
		},
		{
			ID:      "sinatra@2.0.5",
			Name:    "sinatra",
			Version: "2.0.5",
		},
		{
			ID:      "sprockets@3.7.2",
			Name:    "sprockets",
			Version: "3.7.2",
		},
		{
			ID:      "sprockets-rails@3.2.1",
			Name:    "sprockets-rails",
			Version: "3.2.1",
		},
		{
			ID:      "thor@0.20.3",
			Name:    "thor",
			Version: "0.20.3",
		},
		{
			ID:      "thread_safe@0.3.6",
			Name:    "thread_safe",
			Version: "0.3.6",
		},
		{
			ID:      "tilt@2.0.9",
			Name:    "tilt",
			Version: "2.0.9",
		},
		{
			ID:      "tzinfo@1.2.5",
			Name:    "tzinfo",
			Version: "1.2.5",
		},
		{
			ID:      "unicode-display_width@1.5.0",
			Name:    "unicode-display_width",
			Version: "1.5.0",
		},
		{
			ID:      "websocket-driver@0.7.0",
			Name:    "websocket-driver",
			Version: "0.7.0",
		},
		{
			ID:      "websocket-extensions@0.1.3",
			Name:    "websocket-extensions",
			Version: "0.1.3",
		},
	}

	// docker run --name bundler --rm -it ruby:3 bash
	// bundle init
	// bundle add dotenv json faker rubocop pry
	// bundle add rails
	// bundler show | grep "*" | grep -v bundler | awk '{if(match($0, /\((.*)\)/)) printf("{Name: \""$2"\", Version: \""substr($0, RSTART+1, RLENGTH-2)"\"},\n");}'
	BundlerV2RailsV7 = []types.Library{
		{
			ID:      "actioncable@7.0.3",
			Name:    "actioncable",
			Version: "7.0.3",
		},
		{
			ID:      "actionmailbox@7.0.3",
			Name:    "actionmailbox",
			Version: "7.0.3",
		},
		{
			ID:      "actionmailer@7.0.3",
			Name:    "actionmailer",
			Version: "7.0.3",
		},
		{
			ID:      "actionpack@7.0.3",
			Name:    "actionpack",
			Version: "7.0.3",
		},
		{
			ID:      "actiontext@7.0.3",
			Name:    "actiontext",
			Version: "7.0.3",
		},
		{
			ID:      "actionview@7.0.3",
			Name:    "actionview",
			Version: "7.0.3",
		},
		{
			ID:      "activejob@7.0.3",
			Name:    "activejob",
			Version: "7.0.3",
		},
		{
			ID:      "activemodel@7.0.3",
			Name:    "activemodel",
			Version: "7.0.3",
		},
		{
			ID:      "activerecord@7.0.3",
			Name:    "activerecord",
			Version: "7.0.3",
		},
		{
			ID:      "activestorage@7.0.3",
			Name:    "activestorage",
			Version: "7.0.3",
		},
		{
			ID:      "activesupport@7.0.3",
			Name:    "activesupport",
			Version: "7.0.3",
		},
		{
			ID:      "ast@2.4.2",
			Name:    "ast",
			Version: "2.4.2",
		},
		{
			ID:      "builder@3.2.4",
			Name:    "builder",
			Version: "3.2.4",
		},
		{
			ID:      "coderay@1.1.3",
			Name:    "coderay",
			Version: "1.1.3",
		},
		{
			ID:      "concurrent-ruby@1.1.10",
			Name:    "concurrent-ruby",
			Version: "1.1.10",
		},
		{
			ID:      "crass@1.0.6",
			Name:    "crass",
			Version: "1.0.6",
		},
		{
			ID:      "digest@3.1.0",
			Name:    "digest",
			Version: "3.1.0",
		},
		{
			ID:      "dotenv@2.7.6",
			Name:    "dotenv",
			Version: "2.7.6",
		},
		{
			ID:      "erubi@1.10.0",
			Name:    "erubi",
			Version: "1.10.0",
		},
		{
			ID:      "faker@2.21.0",
			Name:    "faker",
			Version: "2.21.0",
		},
		{
			ID:      "globalid@1.0.0",
			Name:    "globalid",
			Version: "1.0.0",
		},
		{
			ID:      "i18n@1.10.0",
			Name:    "i18n",
			Version: "1.10.0",
		},
		{
			ID:      "json@2.6.2",
			Name:    "json",
			Version: "2.6.2",
		},
		{
			ID:      "loofah@2.18.0",
			Name:    "loofah",
			Version: "2.18.0",
		},
		{
			ID:      "mail@2.7.1",
			Name:    "mail",
			Version: "2.7.1",
		},
		{
			ID:      "marcel@1.0.2",
			Name:    "marcel",
			Version: "1.0.2",
		},
		{
			ID:      "method_source@1.0.0",
			Name:    "method_source",
			Version: "1.0.0",
		},
		{
			ID:      "mini_mime@1.1.2",
			Name:    "mini_mime",
			Version: "1.1.2",
		},
		{
			ID:      "minitest@5.16.0",
			Name:    "minitest",
			Version: "5.16.0",
		},
		{
			ID:      "net-imap@0.2.3",
			Name:    "net-imap",
			Version: "0.2.3",
		},
		{
			ID:      "net-pop@0.1.1",
			Name:    "net-pop",
			Version: "0.1.1",
		},
		{
			ID:      "net-protocol@0.1.3",
			Name:    "net-protocol",
			Version: "0.1.3",
		},
		{
			ID:      "net-smtp@0.3.1",
			Name:    "net-smtp",
			Version: "0.3.1",
		},
		{
			ID:      "nio4r@2.5.8",
			Name:    "nio4r",
			Version: "2.5.8",
		},
		{
			ID:      "nokogiri@1.13.6",
			Name:    "nokogiri",
			Version: "1.13.6",
		},
		{
			ID:      "parallel@1.22.1",
			Name:    "parallel",
			Version: "1.22.1",
		},
		{
			ID:      "parser@3.1.2.0",
			Name:    "parser",
			Version: "3.1.2.0",
		},
		{
			ID:      "pry@0.14.1",
			Name:    "pry",
			Version: "0.14.1",
		},
		{
			ID:      "racc@1.6.0",
			Name:    "racc",
			Version: "1.6.0",
		},
		{
			ID:      "rack@2.2.3.1",
			Name:    "rack",
			Version: "2.2.3.1",
		},
		{
			ID:      "rack-test@1.1.0",
			Name:    "rack-test",
			Version: "1.1.0",
		},
		{
			ID:      "rails@7.0.3",
			Name:    "rails",
			Version: "7.0.3",
		},
		{
			ID:      "rails-dom-testing@2.0.3",
			Name:    "rails-dom-testing",
			Version: "2.0.3",
		},
		{
			ID:      "rails-html-sanitizer@1.4.3",
			Name:    "rails-html-sanitizer",
			Version: "1.4.3",
		},
		{
			ID:      "railties@7.0.3",
			Name:    "railties",
			Version: "7.0.3",
		},
		{
			ID:      "rainbow@3.1.1",
			Name:    "rainbow",
			Version: "3.1.1",
		},
		{
			ID:      "rake@13.0.6",
			Name:    "rake",
			Version: "13.0.6",
		},
		{
			ID:      "regexp_parser@2.5.0",
			Name:    "regexp_parser",
			Version: "2.5.0",
		},
		{
			ID:      "rexml@3.2.5",
			Name:    "rexml",
			Version: "3.2.5",
		},
		{
			ID:      "rubocop@1.30.1",
			Name:    "rubocop",
			Version: "1.30.1",
		},
		{
			ID:      "rubocop-ast@1.18.0",
			Name:    "rubocop-ast",
			Version: "1.18.0",
		},
		{
			ID:      "ruby-progressbar@1.11.0",
			Name:    "ruby-progressbar",
			Version: "1.11.0",
		},
		{
			ID:      "strscan@3.0.3",
			Name:    "strscan",
			Version: "3.0.3",
		},
		{
			ID:      "thor@1.2.1",
			Name:    "thor",
			Version: "1.2.1",
		},
		{
			ID:      "timeout@0.3.0",
			Name:    "timeout",
			Version: "0.3.0",
		},
		{
			ID:      "tzinfo@2.0.4",
			Name:    "tzinfo",
			Version: "2.0.4",
		},
		{
			ID:      "unicode-display_width@2.1.0",
			Name:    "unicode-display_width",
			Version: "2.1.0",
		},
		{
			ID:      "websocket-driver@0.7.5",
			Name:    "websocket-driver",
			Version: "0.7.5",
		},
		{
			ID:      "websocket-extensions@0.1.5",
			Name:    "websocket-extensions",
			Version: "0.1.5",
		},
		{
			ID:      "zeitwerk@2.6.0",
			Name:    "zeitwerk",
			Version: "2.6.0",
		},
	}

	BundlerV2RailsV7Deps = []types.Dependency{
		{
			ID: "actioncable@7.0.3",
			DependsOn: []string{
				"actionpack@7.0.3",
				"activesupport@7.0.3",
				"nio4r@2.5.8",
				"websocket-driver@0.7.5",
			},
		},
		{
			ID: "actionmailbox@7.0.3",
			DependsOn: []string{
				"actionpack@7.0.3",
				"activejob@7.0.3",
				"activerecord@7.0.3",
				"activestorage@7.0.3",
				"activesupport@7.0.3",
				"mail@2.7.1",
				"net-imap@0.2.3",
				"net-pop@0.1.1",
				"net-smtp@0.3.1",
			},
		},
		{
			ID: "actionmailer@7.0.3",
			DependsOn: []string{
				"actionpack@7.0.3",
				"actionview@7.0.3",
				"activejob@7.0.3",
				"activesupport@7.0.3",
				"mail@2.7.1",
				"net-imap@0.2.3",
				"net-pop@0.1.1",
				"net-smtp@0.3.1",
				"rails-dom-testing@2.0.3",
			},
		},
		{
			ID: "actionpack@7.0.3",
			DependsOn: []string{
				"actionview@7.0.3",
				"activesupport@7.0.3",
				"rack@2.2.3.1",
				"rack-test@1.1.0",
				"rails-dom-testing@2.0.3",
				"rails-html-sanitizer@1.4.3",
			},
		},
		{
			ID: "actiontext@7.0.3",
			DependsOn: []string{
				"actionpack@7.0.3",
				"activerecord@7.0.3",
				"activestorage@7.0.3",
				"activesupport@7.0.3",
				"globalid@1.0.0",
				"nokogiri@1.13.6",
			},
		},
		{
			ID: "actionview@7.0.3",
			DependsOn: []string{
				"activesupport@7.0.3",
				"builder@3.2.4",
				"erubi@1.10.0",
				"rails-dom-testing@2.0.3",
				"rails-html-sanitizer@1.4.3",
			},
		},
		{
			ID: "activejob@7.0.3",
			DependsOn: []string{
				"activesupport@7.0.3",
				"globalid@1.0.0",
			},
		},
		{
			ID:        "activemodel@7.0.3",
			DependsOn: []string{"activesupport@7.0.3"},
		},
		{
			ID: "activerecord@7.0.3",
			DependsOn: []string{
				"activemodel@7.0.3",
				"activesupport@7.0.3",
			},
		},
		{
			ID: "activestorage@7.0.3",
			DependsOn: []string{
				"actionpack@7.0.3",
				"activejob@7.0.3",
				"activerecord@7.0.3",
				"activesupport@7.0.3",
				"marcel@1.0.2",
				"mini_mime@1.1.2",
			},
		},
		{
			ID: "activesupport@7.0.3",
			DependsOn: []string{
				"concurrent-ruby@1.1.10",
				"i18n@1.10.0",
				"minitest@5.16.0",
				"tzinfo@2.0.4",
			},
		},
		{
			ID:        "faker@2.21.0",
			DependsOn: []string{"i18n@1.10.0"},
		},
		{
			ID:        "globalid@1.0.0",
			DependsOn: []string{"activesupport@7.0.3"},
		},
		{
			ID:        "i18n@1.10.0",
			DependsOn: []string{"concurrent-ruby@1.1.10"},
		},
		{
			ID: "loofah@2.18.0",
			DependsOn: []string{
				"crass@1.0.6",
				"nokogiri@1.13.6",
			},
		},
		{
			ID:        "mail@2.7.1",
			DependsOn: []string{"mini_mime@1.1.2"},
		},
		{
			ID: "net-imap@0.2.3",
			DependsOn: []string{
				"digest@3.1.0",
				"net-protocol@0.1.3",
				"strscan@3.0.3",
			},
		},
		{
			ID: "net-pop@0.1.1",
			DependsOn: []string{
				"digest@3.1.0",
				"net-protocol@0.1.3",
				"timeout@0.3.0",
			},
		},
		{
			ID:        "net-protocol@0.1.3",
			DependsOn: []string{"timeout@0.3.0"},
		},
		{
			ID: "net-smtp@0.3.1",
			DependsOn: []string{
				"digest@3.1.0",
				"net-protocol@0.1.3",
				"timeout@0.3.0",
			},
		},
		{
			ID:        "nokogiri@1.13.6",
			DependsOn: []string{"racc@1.6.0"},
		},
		{
			ID:        "parser@3.1.2.0",
			DependsOn: []string{"ast@2.4.2"},
		},
		{
			ID: "pry@0.14.1",
			DependsOn: []string{
				"coderay@1.1.3",
				"method_source@1.0.0",
			},
		},
		{
			ID:        "rack-test@1.1.0",
			DependsOn: []string{"rack@2.2.3.1"},
		},
		{
			ID: "rails@7.0.3",
			DependsOn: []string{
				"actioncable@7.0.3",
				"actionmailbox@7.0.3",
				"actionmailer@7.0.3",
				"actionpack@7.0.3",
				"actiontext@7.0.3",
				"actionview@7.0.3",
				"activejob@7.0.3",
				"activemodel@7.0.3",
				"activerecord@7.0.3",
				"activestorage@7.0.3",
				"activesupport@7.0.3",
				"railties@7.0.3",
			},
		},
		{
			ID: "rails-dom-testing@2.0.3",
			DependsOn: []string{
				"activesupport@7.0.3",
				"nokogiri@1.13.6",
			},
		},
		{
			ID:        "rails-html-sanitizer@1.4.3",
			DependsOn: []string{"loofah@2.18.0"},
		},
		{
			ID: "railties@7.0.3",
			DependsOn: []string{
				"actionpack@7.0.3",
				"activesupport@7.0.3",
				"method_source@1.0.0",
				"rake@13.0.6",
				"thor@1.2.1",
				"zeitwerk@2.6.0",
			},
		},
		{
			ID: "rubocop@1.30.1",
			DependsOn: []string{
				"parallel@1.22.1",
				"parser@3.1.2.0",
				"rainbow@3.1.1",
				"regexp_parser@2.5.0",
				"rexml@3.2.5",
				"rubocop-ast@1.18.0",
				"ruby-progressbar@1.11.0",
				"unicode-display_width@2.1.0",
			},
		},
		{
			ID:        "rubocop-ast@1.18.0",
			DependsOn: []string{"parser@3.1.2.0"},
		},
		{
			ID:        "tzinfo@2.0.4",
			DependsOn: []string{"concurrent-ruby@1.1.10"},
		},
		{
			ID:        "websocket-driver@0.7.5",
			DependsOn: []string{"websocket-extensions@0.1.5"},
		},
	}
)
