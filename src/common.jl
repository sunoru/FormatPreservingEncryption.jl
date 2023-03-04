
abstract type AbstractFPEContext{T<:AESNI.AbstractAesKey} end

function get_block_cipher(key_size, key)
    if key_size == 128
        Aes128Key(key)
    elseif key_size == 192
        Aes192Key(key)
    elseif key_size == 256
        Aes256Key(key)
    else
        throw(ArgumentError("key_size must be 128, 192, or 256"))
    end
end

# bigendian by default
function num_in_base(X::AbstractArray, radix)
    x = BigInt(0)
    radix = BigInt(radix)
    for xi in X
        x = x * radix + xi
    end
    x
end

function str_in_base!(X::AbstractArray{UInt32}, x::BigInt, radix)
    fill!(X, UInt32(0))
    m = length(X)
    @inbounds for i in 1:m
        X[m + 1 - i] = x % radix
        x ÷= radix
    end
    X
end
str_in_base(x::BigInt, radix, len) = str_in_base!(Vector{UInt32}(undef, len), x, radix)

# https://discourse.julialang.org/t/bigint-to-bytes/91107/5
function AESNI.to_bytes(x::BigInt, len=cld(Base.GMP.MPZ.sizeinbase(n, 2), 8); bigendian=!IS_LITTLE_ENDIAN)
    bytes = Vector{UInt8}(undef, len)
    order = bigendian ? Cint(1) : Cint(-1)
    count = Ref{Csize_t}()
    @ccall "libgmp".__gmpz_export(bytes::Ptr{UInt8}, count::Ref{Csize_t}, order::Cint,
        1::Csize_t, 1::Cint, 0::Csize_t, x::Ref{BigInt})::Ptr{UInt8}
    @assert count[] ≤ length(bytes)
    return resize!(bytes, count[])
end
AESNI.to_bytes(x::AbstractArray{UInt8}; bigendian=false) = bigendian ? x : reverse(x)

function prf(aes_key, X::AbstractArray{UInt8}, y::UInt128 = UInt128(0))
    m = length(X) ÷ 16
    @inbounds for i in 1:m
        y = encrypt(aes_key, y ⊻ to_uint128(X[(i-1)*16+1:i*16]))
    end
    y
end
