workspace(name = "filter")
load("@bazel_tools//tools/build_defs/repo:git.bzl", "git_repository")

git_repository(name = "proxy_wasm_cpp_sdk", commit = "c17bf8257e5ebad2399f95cc15c8ff64e515519f", remote = "https://github.com/proxy-wasm/proxy-wasm-cpp-sdk")

load("@proxy_wasm_cpp_sdk//bazel/dep:deps.bzl", "wasm_dependencies")

wasm_dependencies()

load("@proxy_wasm_cpp_sdk//bazel/dep:deps_extra.bzl", "wasm_dependencies_extra")

wasm_dependencies_extra()