
# https://vscode.dev/github/Octogonapus/Pkg.jl/blob/manifest_check_errors/src/Operations.jl#L31
function source_path(manifest_file::String, pkg::Union{PackageSpec, PackageEntry}, julia_version = VERSION)
    pkg.tree_hash   !== nothing ? find_installed(pkg.name, pkg.uuid, pkg.tree_hash) :
    pkg.path        !== nothing ? joinpath(dirname(manifest_file), pkg.path) :
    is_or_was_stdlib(pkg.uuid, julia_version) ? Types.stdlib_path(pkg.name) :
    nothing
end

function find_installed(name::String, uuid::UUID, sha1::SHA1)
    slug_default = Base.version_slug(uuid, sha1)
    # 4 used to be the default so look there first
    for slug in (slug_default, Base.version_slug(uuid, sha1, 4))
        for depot in depots()
            path = abspath(depot, "packages", name, slug)
            ispath(path) && return path
        end
    end
    return abspath(depots1(), "packages", name, slug_default)
end



# https://vscode.dev/github/Octogonapus/Pkg.jl/blob/manifest_check_errorsiaup/julia-1.10.4%2B0.x64.linux.gnu/share/julia/base/loading.jl#L182
## package path slugs: turning UUID + SHA1 into a pair of 4-byte "slugs" ##

const slug_chars = String(['A':'Z'; 'a':'z'; '0':'9'])

function slug(x::UInt32, p::Int)
    y::UInt32 = x
    sprint(sizehint=p) do io
        n = length(slug_chars)
        for i = 1:p
            y, d = divrem(y, n)
            write(io, slug_chars[1+d])
        end
    end
end

function package_slug(uuid::UUID, p::Int=5)
    crc = _crc32c(uuid)
    return slug(crc, p)
end

function version_slug(uuid::UUID, sha1::SHA1, p::Int=5)
    crc = _crc32c(uuid)
    crc = _crc32c(sha1.bytes, crc)
    return slug(crc, p)
end
