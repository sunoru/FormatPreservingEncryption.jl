
struct FF1{T} <: AbstractFPEContext{T}
    aes_key::T
    radix::UInt32
    tweak::Vector{UInt8}
    function FF1(key, radix, tweak; key_size=128)
        @assert 2 ≤ radix ≤ 2^16 "radix must be between 2 and 2^16"
        aes_key = get_block_cipher(key_size, key)
        tweak = collect(to_bytes(tweak, bigendian=true))
        new{typeof(aes_key)}(aes_key, radix, tweak)
    end
    FF1(; key_size=128, key, radix, tweak="") =
        FF1(key, radix, tweak; key_size)
end

"""
    encrypt(ctx::FF1, plain::AbstractArray{<:Integer})

Encrypt `plain` using `ctx`. `plain` must be an array of integers in the range
`0:ctx.radix-1`. The result is an array of integers in the same range.

Ref: Algorithm 7, Section 5.1, NIST SP 800-38G
"""
function AESNI.encrypt(ctx::FF1, plain::AbstractArray{<:Integer})
    # TODO: optimize it
    aes_key = ctx.aes_key
    tweak = ctx.tweak
    radix = ctx.radix
    n = length(plain) |> UInt32
    t = length(tweak) |> UInt32
    # 1
    u = n ÷ UInt32(2)
    v = n - u
    # 2
    out = UInt32.(plain)
    A = @view out[1:u]
    B = @view out[u+1:end]
    # 3
    b = cld(ceil(UInt32, v * log2(radix)), 8)
    # 4
    d = UInt32(4) * cld(b, UInt32(4)) + UInt32(4)

    # 5
    P = zeros(UInt8, 16)
    P[1] = 0x1
    P[2] = 0x2
    P[3] = 0x1
    P[8] = u % 0xff
    @static if IS_BIG_ENDIAN
        P[4:7] .= to_bytes((radix << UInt32(8)) | UInt32(10))
        P[9:12] .= to_bytes(n)
        P[13:16] .= to_bytes(t)
    else
        P[4:7] .= reverse(to_bytes((radix << UInt32(8)) | UInt32(10)))
        P[9:12] .= reverse(to_bytes(n))
        P[13:16] .= reverse(to_bytes(t))
    end

    pad = (-t - b - UInt32(1)) % UInt32(16)
    Q = zeros(UInt8, t + pad + UInt32(1) + b)
    S = zeros(UInt8, cld(d, 16) * 16)
    # 6
    for i in UInt8(0):UInt8(9)
        # 6.i
        Q[1:t] .= tweak
        Q[t+1:t+pad] .= 0x00
        Q[t+pad+1] = i
        B_num = num_in_base(B, radix)
        B_bytes = to_bytes(B_num, b, bigendian=true)
        B_bytes_len = length(B_bytes)
        Q[t+pad+2:end-B_bytes_len] .= 0x00
        Q[end-B_bytes_len+1:end] .= B_bytes
        # 6.ii
        R = encrypt(aes_key, to_uint128(P))
        R = prf(aes_key, Q, R)
        # 6.iii
        S[1:16] .= to_bytes(R)
        for j in 1:cld(d, 16)-1
            j = UInt128(j)
            tmp = @static if IS_BIG_ENDIAN
                to_bytes(j)
            else
                reverse(to_bytes(j))
            end
            Sj = encrypt(aes_key, R ⊻ to_uint128(tmp))
            S[16j+1:16j+16] .= to_bytes(Sj)
        end
        # 6.iv
        y = num_in_base(S[1:d], 256)
        # 6.v
        m = (i & 1 == 0) ? u : v
        # 6.vi
        c = (num_in_base(A, radix) + y) % (radix^m)
        # 6.vii & 6.viii
        A, B = B, A
        # 6.vii
        str_in_base!(B, c, radix)
    end
    [A..., B...]
end
