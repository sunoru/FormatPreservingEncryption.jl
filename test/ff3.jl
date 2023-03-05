@testset "FF3" begin
    # https://csrc.nist.gov/CSRC/media/Projects/Cryptographic-Standards-and-Guidelines/documents/examples/FF3samples.pdf
    key128 = bytes"EF 43 59 D8 D5 80 AA 4F 7F 03 6D 6F 04 FC 6A 94"
    key192 = bytes"EF 43 59 D8 D5 80 AA 4F 7F 03 6D 6F 04 FC 6A 94 2B 7E 15 16 28 AE D2 A6"
    key256 = bytes"EF 43 59 D8 D5 80 AA 4F 7F 03 6D 6F 04 FC 6A 94 2B 7E 15 16 28 AE D2 A6 AB F7 15 88 09 CF 4F 3C"
    tweak0 = bytes"00 00 00 00 00 00 00 00"
    tweak1 = bytes"D8 E7 92 0A FA 33 0A 73"
    tweak2 = bytes"9A 76 8A 92 F6 0E 12 D8"
    # tweak3 = bytes"37 37 37 37 70 71 72 73 37 37 37"
    plain1 = num"890121234567890000"
    plain2 = num"89012123456789000000789000000"
    plain26 = num"0123456789abcdefghi"

    # Sample 1
    @test_cipher(
        FF3, 128, key128, 10, tweak1,
        plain1, num"750918814058654607"
    )
    # Sample 2
    @test_cipher(
        FF3, 128, key128, 10, tweak2,
        plain1, num"018989839189395384"
    )
    # Sample 3
    @test_cipher(
        FF3, 128, key128, 10, tweak1,
        plain2, num"48598367162252569629397416226"
    )
    # Sample 4
    @test_cipher(
        FF3, 128, key128, 10, tweak0,
        plain2, num"34695224821734535122613701434"
    )
    # Sample 5
    @test_cipher(
        FF3, 128, key128, 26, tweak2,
        plain26, num"g2pk40i992fn20cjakb"
    )

    # Sample 6
    @test_cipher(
        FF3, 192, key192, 10, tweak1,
        plain1, num"646965393875028755"
    )
    # Sample 7
    @test_cipher(
        FF3, 192, key192, 10, tweak2,
        plain1, num"961610514491424446"
    )
    # Sample 8
    @test_cipher(
        FF3, 192, key192, 10, tweak1,
        plain2, num"53048884065350204541786380807"
    )
    # Sample 9
    @test_cipher(
        FF3, 192, key192, 10, tweak0,
        plain2, num"98083802678820389295041483512"
    )
    # Sample 10
    @test_cipher(
        FF3, 192, key192, 26, tweak2,
        plain26, num"i0ihe2jfj7a9opf9p88"
    )

    # Sample 11
    @test_cipher(
        FF3, 256, key256, 10, tweak1,
        plain1, num"922011205562777495"
    )
    # Sample 12
    @test_cipher(
        FF3, 256, key256, 10, tweak2,
        plain1, num"504149865578056140"
    )
    # Sample 13
    @test_cipher(
        FF3, 256, key256, 10, tweak1,
        plain2, num"04344343235792599165734622699"
    )
    # Sample 14
    @test_cipher(
        FF3, 256, key256, 10, tweak0,
        plain2, num"30859239999374053872365555822"
    )
    # Sample 15
    @test_cipher(
        FF3, 256, key256, 26, tweak2,
        plain26, num"p0b2godfja9bhb7bk38"
    )
end
