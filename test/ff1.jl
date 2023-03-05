using Test
using FormatPreservingEncryption

@testset "FF1" begin
    # https://csrc.nist.gov/CSRC/media/Projects/Cryptographic-Standards-and-Guidelines/documents/examples/FF1samples.pdf
    key128 = bytes"2B 7E 15 16 28 AE D2 A6 AB F7 15 88 09 CF 4F 3C"
    key192 = bytes"2B 7E 15 16 28 AE D2 A6 AB F7 15 88 09 CF 4F 3C EF 43 59 D8 D5 80 AA 4F"
    key256 = bytes"2B 7E 15 16 28 AE D2 A6 AB F7 15 88 09 CF 4F 3C EF 43 59 D8 D5 80 AA 4F 7F 03 6D 6F 04 FC 6A 94"
    tweak1 = bytes""
    tweak2 = bytes"39 38 37 36 35 34 33 32 31 30"
    tweak3 = bytes"37 37 37 37 70 71 72 73 37 37 37"
    plain10 = num"0123456789"
    plain36 = num"0123456789abcdefghi"
    # Sample 1
    @test_cipher(
        FF1, 128, key128, 10, tweak1,
        plain10, num"2433477484"
    )
    # Sample 2
    @test_cipher(
        FF1, 128, key128, 10, tweak2,
        plain10, num"6124200773"
    )
    # Sample 3
    @test_cipher(
        FF1, 128, key128, 36, tweak3,
        plain36, num"a9tv40mll9kdu509eum"
    )
    # Sample 4
    @test_cipher(
        FF1, 192, key192, 10, tweak1,
        plain10, num"2830668132"
    )
    # Sample 5
    @test_cipher(
        FF1, 192, key192, 10, tweak2,
        plain10, num"2496655549"
    )
    # Sample 6
    @test_cipher(
        FF1, 192, key192, 36, tweak3,
        plain36, num"xbj3kv35jrawxv32ysr"
    )
    # Sample 7
    @test_cipher(
        FF1, 256, key256, 10, tweak1,
        plain10, num"6657667009"
    )
    # Sample 8
    @test_cipher(
        FF1, 256, key256, 10, tweak2,
        plain10, num"1001623463"
    )
    # Sample 9
    @test_cipher(
        FF1, 256, key256, 36, tweak3,
        plain36, num"xs8a0azh2avyalyzuwd"
    )
end
