using Test
using FormatPreservingEncryption

@testset "FF1" begin
    key = hex2bytes("2b7e151628aed2a6abf7158809cf4f3c")
    key_size = 128
    radix = 10
    tweak = hex2bytes("39383736353433323130")
    ff1 = FF1(; key_size, key, radix, tweak)
    plain = collect(0:9)
    cipher = encrypt(ff1, plain)
    @test cipher == [6, 1, 2, 4, 2, 0, 0, 7, 7, 3]
    # plain = "0123456789"
    # cipher = encrypt(ff1, plain)
    # @test cipher == "6124200773"
    # @test decrypt(ff1, cipher) == plain

end
