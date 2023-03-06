using Random
using BenchmarkTools
using FormatPreservingEncryption

macro bytes_str(s)
    bytes = s |> split |> join |> hex2bytes
    :($bytes)
end

macro num_str(s)
    a = [parse(UInt32, c; base=36) for c in s]
    :($a)
end

function nperm(n)
    @inbounds randperm(n)[1] - 1
end

key128 = bytes"2B 7E 15 16 28 AE D2 A6 AB F7 15 88 09 CF 4F 3C"
tweak = bytes"39 38 37 36 35 34 33 32"
radix = 36

ff1 = FF1(; key_size=128, key=key128, radix, tweak)
ff3 = FF3(; key_size=128, key=key128, radix, tweak)

plain = num"h3"
cipher1 = encrypt(ff1, plain)
cipher3 = encrypt(ff3, plain)
@assert decrypt(ff1, cipher1) == plain
@assert decrypt(ff3, cipher3) == plain

@info "Benchmarking..."
@info "Base.randperm"
maxnum = radix^length(plain)
@btime nperm($maxnum)
@info "FF1.Encrypt"
@btime encrypt($ff1, $plain)
@info "FF1.Decrypt"
@btime decrypt($ff1, $cipher1)
@info "FF3.Encrypt"
@btime encrypt($ff3, $plain)
@info "FF3.Decrypt"
@btime decrypt($ff3, $cipher3)

plain = num"h3g8t7ftd2"
cipher1 = encrypt(ff1, plain)
cipher3 = encrypt(ff3, plain)
@assert decrypt(ff1, cipher1) == plain
@assert decrypt(ff3, cipher3) == plain

@info "Benchmarking 2..."
@info "Base.randperm will out of memory"
# maxnum = radix^length(plain)
# @btime nperm($maxnum)
@info "FF1.Encrypt"
@btime encrypt($ff1, $plain)
@info "FF1.Decrypt"
@btime decrypt($ff1, $cipher1)
@info "FF3.Encrypt"
@btime encrypt($ff3, $plain)
@info "FF3.Decrypt"
@btime decrypt($ff3, $cipher3)


# It's too slow right now.
# large_plain = rand(0:35, 10 * 2^20)
# large_cipher1 = encrypt(ff1, large_plain)
# large_cipher3 = encrypt(ff3, large_plain)
# @assert decrypt(ff1, large_cipher1) == large_plain
# @assert decrypt(ff3, large_cipher3) == large_plain

# @info "Benchmarking with larger data (10MB)..."
# @info "Base.randperm"
# @info "FF1.Encrypt"
# @btime encrypt($ff1, $larger_plain)
# @info "FF1.Decrypt"
# @btime decrypt($ff1, $larger_cipher1)
# @info "FF3.Encrypt"
# @btime encrypt($ff3, $larger_plain)
# @info "FF3.Decrypt"
# @btime decrypt($ff3, $larger_cipher3)
