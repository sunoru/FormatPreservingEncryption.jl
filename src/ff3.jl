"""
    FF3(; key_size=128, key::ByteSequence, radix, tweak)
"""
struct FF3{T} <: AbstractFPEContext{T}
    aes_key::T
    radix::UInt32
    tweak::NTuple{8,UInt8}
end

function FF3(key_size, key::ByteSequence, radix, tweak)
    @assert 2 ≤ radix ≤ 2^16 "radix must be between 2 and 2^16"
    aes_key = get_block_cipher(key_size, reverse(key))
    FF3{typeof(aes_key)}(aes_key, radix, Tuple(tweak))
end
FF3(; key_size=128, key, radix, tweak) =
    FF3(key_size, key, radix, tweak)

function ff3_impl(ctx, input, is_encrypt)
    aes_key = ctx.aes_key
    tweak = ctx.tweak
    radix = ctx.radix
    n = length(input) |> UInt32
    t = length(tweak) |> UInt32
    # 1
    u = cld(n, UInt32(2))
    v = n - u
    powru = BigInt(radix)^u
    powrv = BigInt(radix)^v
    # 2
    out = UInt32.(input)
    A = @view out[1:u]
    B = @view out[u+1:end]
    # 3
    T_L, T_R = tweak[1:4], tweak[5:8]
    # 4
    for iter in UInt8(0):UInt8(7)
        i = is_encrypt ? iter : (UInt8(7) - iter)
        # 4.i
        m, powrm, W = if i & 1 == 0
            u, powru, T_R
        else
            v, powrv, T_L
        end
        # 4.ii
        B_num = num_in_base(is_encrypt ? B : A, radix, bigendian=false)
        B_bytes = le_bytes(B_num, m)
        P_REVB = (
            B_bytes...,
            Iterators.repeated(UInt8(0), 12 - length(B_bytes))...,
            W[4] ⊻ i,
            W[3:-1:1]...,
        )
        # 4.iii
        S = encrypt(aes_key, P_REVB)
        # 4.iv
        y = num_in_base(S, 256, bigendian=false)
        # 4.v
        c = mod(
            num_in_base(is_encrypt ? A : B, radix, bigendian=false) +
            (is_encrypt ? y : -y),
            powrm
        )
        # 4.vi, 4.vii & 4.viii
        A, B = B, A
        str_in_base!(is_encrypt ? B : A, c, radix, bigendian=false)
    end
    out
end

AESNI.encrypt(ctx::FF3, plain::AbstractArray{<:Integer}) = ff3_impl(ctx, plain, true)

AESNI.decrypt(ctx::FF3, cipher::AbstractArray{<:Integer}) = ff3_impl(ctx, cipher, false)
