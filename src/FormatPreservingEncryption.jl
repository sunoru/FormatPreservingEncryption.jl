module FormatPreservingEncryption

using AESNI
using AESNI: to_bytes, to_uint128, IS_BIG_ENDIAN

export FF1, FF3
export encrypt, decrypt
include("./common.jl")
include("./ff1.jl")
# include("./ff3.jl")

end
