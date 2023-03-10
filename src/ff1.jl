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

function ff1_impl!(ctx, output, input, is_encrypt)
    @assert length(input) == length(output) "input and output must have the same length"
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
    A = @view output[1:u]
    B = @view output[u+1:end]
    # 3
    b = cld(ceil(UInt32, v * log2(radix)), 8)
    # 4
    d = UInt32(4) * cld(b, UInt32(4)) + UInt32(4)

    # 5
    P = Vector{UInt8}(undef, 16)
    @inbounds begin
        P[1] = 0x1
        P[2] = 0x2
        P[3] = 0x1
        P[4:7] .= be_bytes(radix << UInt32(8) | UInt32(10))
        P[8] = u % UInt8
        P[9:12] .= be_bytes(n)
        P[13:16] .= be_bytes(t)
    end
    P128 = bytes_to_uint128(P)

    pad = (-t - b - UInt32(1)) % UInt32(16)
    Q = zeros(UInt8, t + pad + UInt32(1) + b)
    S = zeros(UInt8, cld(d, 16) * 16)
    B_bytes = zeros(UInt8, b)
    # 6
    for iter in UInt8(0):UInt8(9)
        i = is_encrypt ? iter : (UInt8(9) - iter)
        # 6.i
        Q[1:t] .= tweak
        Q[t+1:t+pad] .= 0x00
        Q[t+pad+1] = i
        B_num = num_in_base(is_encrypt ? B : A, radix)
        B_bytes, B_bytes_len = be_bytes!(B_bytes, B_num)
        Q[t+pad+2:end-B_bytes_len] .= 0x00
        Q[end-B_bytes_len+1:end] .= @view B_bytes[1:B_bytes_len]
        # 6.ii
        R = encrypt(aes_key, P128)
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
    output
end

AESNI.encrypt(ctx::FF1, plain::AbstractArray{<:Integer}) = encrypt!(ctx, UInt32.(plain), plain)
encrypt!(ctx::FF1, cipher::AbstractArray{<:Integer}, plain::AbstractArray{<:Integer}) = ff1_impl!(ctx, cipher, plain, true)

AESNI.decrypt(ctx::FF1, cipher::AbstractArray{<:Integer}) = decrypt!(ctx, UInt32.(cipher), cipher)
decrypt!(ctx::FF1, plain::AbstractArray{<:Integer}, cipher::AbstractArray{<:Integer}) = ff1_impl!(ctx, plain, cipher, false)
