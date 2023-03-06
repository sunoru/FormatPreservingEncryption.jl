# bigendian by default
function num_in_base(X, radix; bigendian=true)
    x = BigInt(0)
    radix = BigInt(radix)
    for xi in (bigendian ? X : Iterators.reverse(X))
        x = x * radix + xi
    end
    x
end

function str_in_base!(X::AbstractArray{UInt32}, x::BigInt, radix; bigendian=true)
    fill!(X, UInt32(0))
    m = length(X)
    @inbounds for i in (bigendian ? (m:-1:1) : 1:m)
        X[i] = x % radix
        x ÷= radix
    end
    X
end
str_in_base(x::BigInt, radix, len) = str_in_base!(Vector{UInt32}(undef, len), x, radix)

# https://discourse.julialang.org/t/bigint-to-bytes/91107/5
function to_bytes(x::BigInt, len=cld(Base.GMP.MPZ.sizeinbase(n, 2), 8); bigendian=true)
    bytes = Vector{UInt8}(undef, len)
    order = Cint(bigendian ? 1 : -1)
    count = Ref{Csize_t}()
    @ccall "libgmp".__gmpz_export(bytes::Ptr{UInt8}, count::Ref{Csize_t}, order::Cint,
        1::Csize_t, 1::Cint, 0::Csize_t, x::Ref{BigInt})::Ptr{UInt8}
    @assert count[] ≤ length(bytes)
    return resize!(bytes, count[])
end
# Big endian
be_bytes(x::BigInt, len=cld(Base.GMP.MPZ.sizeinbase(n, 2), 8)) = to_bytes(x, len, bigendian=true)
function be_bytes(x::Core.BuiltinInts)
    bytes = AESNI.unsafe_reinterpret_convert(UInt8, x, sizeof(x))
    @static if IS_BIG_ENDIAN
        bytes
    else
        reverse(bytes)
    end
end
le_bytes(x::BigInt, len=cld(Base.GMP.MPZ.sizeinbase(n, 2), 8)) = to_bytes(x, len, bigendian=false)
function le_bytes(x::Core.BuiltinInts)
    bytes = AESNI.unsafe_reinterpret_convert(UInt8, x, sizeof(x))
    @static if IS_BIG_ENDIAN
        reverse(bytes)
    else
        bytes
    end
end

function prf(aes_key, X::AbstractArray{UInt8}, y::UInt128)
    m = length(X) ÷ 16
    X128 = reinterpret(UInt128, X)
    @inbounds for i in 1:m
        y = encrypt(aes_key, y ⊻ X128[i])
    end
    y
end
