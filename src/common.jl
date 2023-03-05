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

"""
    encrypt(ctx::Union{FF1,FF3}, plain::AbstractArray{<:Integer})

Encrypt `plain` using `ctx`. `plain` must be an array of integers in the range
`0:ctx.radix-1`. The result is an array of integers in the same range.

Ref: Algorithm 7, Section 5.1-2, NIST SP 800-38G
"""
AESNI.encrypt

"""
    decrypt(ctx::Union{FF1,FF3}, cipher::AbstractArray{<:Integer})

Decrypt `cipher` using `ctx`. `cipher` must be an array of integers in the range
`0:ctx.radix-1`. The result is an array of integers in the same range.

Ref: Algorithm 7, Section 5.1-2, NIST SP 800-38G
"""
AESNI.decrypt
