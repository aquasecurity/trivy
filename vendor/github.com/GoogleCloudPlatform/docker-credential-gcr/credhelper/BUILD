load("@io_bazel_rules_go//go:def.bzl", "go_library", "go_test")

go_library(
    name = "go_default_library",
    srcs = ["helper.go"],
    importpath = "github.com/GoogleCloudPlatform/docker-credential-gcr/credhelper",
    visibility = ["//visibility:public"],
    deps = [
        "//config:go_default_library",
        "//store:go_default_library",
        "//util/cmd:go_default_library",
        "//vendor/github.com/docker/docker-credential-helpers/credentials:go_default_library",
        "//vendor/golang.org/x/oauth2/google:go_default_library",
    ],
)

go_test(
    name = "go_default_test",
    srcs = [
        "helper_integration_test.go",
        "helper_unit_test.go",
    ],
    embed = [":go_default_library"],
    deps = [
        "//config:go_default_library",
        "//mock/mock_cmd:go_default_library",
        "//mock/mock_config:go_default_library",
        "//mock/mock_store:go_default_library",
        "//store:go_default_library",
        "//util/cmd:go_default_library",
        "//vendor/github.com/docker/docker-credential-helpers/credentials:go_default_library",
        "//vendor/github.com/golang/mock/gomock:go_default_library",
    ],
)
