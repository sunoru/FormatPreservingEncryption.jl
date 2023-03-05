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
