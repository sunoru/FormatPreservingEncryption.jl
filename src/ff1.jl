"""
    FF1(; key_size=128, key, radix, tweak="")
"""
struct FF1{T} <: AbstractFPEContext{T}
    aes_key::T
    radix::UInt32
    tweak::Vector{UInt8}
end

function FF1(key_size, key, radix, tweak)
    @assert 2 ≤ radix ≤ 2^16 "radix must be between 2 and 2^16"
    aes_key = get_block_cipher(key_size, key)
    tweak = Vector{UInt8}(collect(tweak))
    FF1{typeof(aes_key)}(aes_key, radix, tweak)
end
FF1(; key_size=128, key, radix, tweak="") =
    FF1(key_size, key, radix, tweak)

function ff1_impl(ctx, input, is_encrypt)
    # TODO: optimize it
    aes_key = ctx.aes_key
    tweak = ctx.tweak
    radix = ctx.radix
    n = length(input) |> UInt32
    t = length(tweak) |> UInt32
    # 1
    u = n ÷ UInt32(2)
    v = n - u
    powru = BigInt(radix)^u
    powrv = BigInt(radix)^v
    # 2
    out = UInt32.(input)
    A = @view out[1:u]
    B = @view out[u+1:end]
    # 3
    b = cld(ceil(UInt32, v * log2(radix)), 8)
    # 4
    d = UInt32(4) * cld(b, UInt32(4)) + UInt32(4)

    # 5
    P = [
        0x1, 0x2, 0x1,
        be_bytes((radix << UInt32(8)) | UInt32(10))...,
        u % UInt8,
        be_bytes(n)...,
        be_bytes(t)...
    ]

    pad = (-t - b - UInt32(1)) % UInt32(16)
    Q = zeros(UInt8, t + pad + UInt32(1) + b)
    S = zeros(UInt8, cld(d, 16) * 16)
    # 6
    for iter in UInt8(0):UInt8(9)
        i = is_encrypt ? iter : (UInt8(9) - iter)
        # 6.i
        Q[1:t] .= tweak
        Q[t+1:t+pad] .= 0x00
        Q[t+pad+1] = i
        B_num = num_in_base(is_encrypt ? B : A, radix)
        B_bytes = be_bytes(B_num, b)
        B_bytes_len = length(B_bytes)
        Q[t+pad+2:end-B_bytes_len] .= 0x00
        Q[end-B_bytes_len+1:end] .= B_bytes
        # 6.ii
        R = encrypt(aes_key, bytes_to_uint128(P))
        R = prf(aes_key, Q, R)
        # 6.iii
        S[1:16] .= le_bytes(R)
        for j in 1:cld(d, 16)-1
            j = UInt128(j)
            tmp = be_bytes(j)
            Sj = encrypt(aes_key, R ⊻ bytes_to_uint128(tmp))
            S[16j+1:16j+16] .= le_bytes(Sj)
        end
        # 6.iv
        y = num_in_base(S[1:d], 256)
        # 6.v
        m, powrm = if i & 1 == 0
            u, powru
        else
            v, powrv
        end
        # 6.vi
        c = mod(
            num_in_base(is_encrypt ? A : B, radix) +
            (is_encrypt ? y : -y),
            powrm
        )
        # 6.vii, 6.viii & 6.ix
        A, B = B, A
        str_in_base!(is_encrypt ? B : A, c, radix)
    end
    out
end

AESNI.encrypt(ctx::FF1, plain::AbstractArray{<:Integer}) = ff1_impl(ctx, plain, true)

AESNI.decrypt(ctx::FF1, cipher::AbstractArray{<:Integer}) = ff1_impl(ctx, cipher, false)
