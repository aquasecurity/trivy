# Builds the executables in the parent directory. Run from this directory:
#
#   docker build --output type=local,dest=.. .
#
# test.elf, test.exe and test.macho are framework-dependent single-file bundles (`PublishSingleFile`).
# apphost.elf is the same app published without `PublishSingleFile`, so it is not a bundle.
FROM mcr.microsoft.com/dotnet/sdk:8.0.427 AS build
WORKDIR /src
COPY BundleApp.csproj Program.cs ./
RUN for rid in linux-x64 win-x64 osx-arm64; do \
        dotnet publish -c Release -r "$rid" --self-contained false -p:PublishSingleFile=true -p:DebugType=none -o "/out/$rid" || exit 1; \
    done \
    && dotnet publish -c Release -r linux-x64 --self-contained false -p:DebugType=none -o /out/apphost

FROM scratch
COPY --from=build /out/linux-x64/BundleApp test.elf
COPY --from=build /out/win-x64/BundleApp.exe test.exe
COPY --from=build /out/osx-arm64/BundleApp test.macho
COPY --from=build /out/apphost/BundleApp apphost.elf