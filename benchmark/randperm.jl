using Random
using BenchmarkTools
using FormatPreservingEncryption

macro bytes_str(s)
    bytes = s |> split |> join |> hex2bytes
    :($bytes)
end

function new_randperm!(ff, result)
    n = length(result)
    bits = zeros(UInt32, 8)
    for i in 0:n-1
        digits!(bits, i, base=2)
        while true
            encrypt!(ff, bits, bits)
            x = evalpoly(2, bits)
            if x < n
                @inbounds result[i + 1] = x + 1
                break
            end
        end
    end
    result
end

maxnum = 200
key128 = bytes"2B 7E 15 16 28 AE D2 A6 AB F7 15 88 09 CF 4F 3C"
tweak = bytes"39 38 37 36 35 34 33 32"
radix = 2

ff1 = FF1(; key_size=128, key=key128, radix, tweak)
ff3 = FF3(; key_size=128, key=key128, radix, tweak)

result = zeros(Int, maxnum)
@info "Benchmarking..."
@info "Base.randperm!"
@btime randperm!($result)
@info "FF1"
@btime new_randperm!($ff1, $result)
@assert @show isperm(result)
# @info "FF3"
# @btime new_randperm!($ff3, $result)
