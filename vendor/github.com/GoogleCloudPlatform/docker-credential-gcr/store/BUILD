load("@io_bazel_rules_go//go:def.bzl", "go_library", "go_test")

go_library(
    name = "go_default_library",
    srcs = ["store.go"],
    importpath = "github.com/GoogleCloudPlatform/docker-credential-gcr/store",
    visibility = ["//visibility:public"],
    deps = [
        "//config:go_default_library",
        "//util:go_default_library",
        "//vendor/github.com/docker/docker-credential-helpers/credentials:go_default_library",
        "//vendor/golang.org/x/oauth2:go_default_library",
        "//vendor/golang.org/x/oauth2/google:go_default_library",
    ],
)

go_test(
    name = "go_default_test",
    srcs = [
        "store_integration_test.go",
        "store_unit_test.go",
    ],
    embed = [":go_default_library"],
    deps = [
        "//vendor/github.com/docker/docker-credential-helpers/credentials:go_default_library",
        "//vendor/golang.org/x/oauth2:go_default_library",
    ],
)
