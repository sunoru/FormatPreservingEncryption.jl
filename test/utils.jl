macro bytes_str(s)
    bytes = s |> split |> join |> hex2bytes
    :($bytes)
end

macro num_str(s)
    a = [parse(UInt32, c; base = 36) for c in s]
    :($a)
end

macro test_cipher(type, key_size, key, radix, tweak, plain, cipher = nothing)
    quote
        ctx = $type(; key_size=$key_size, key=$key, radix=$radix, tweak=$tweak)
        plain = $plain
        cipher = $cipher
        encrypted = encrypt(ctx, plain)
        cipher = if isnothing(cipher)
            encrypted
        else
            @test encrypted == cipher
            cipher
        end
        @test decrypt(ctx, cipher) == plain
    end |> esc
end