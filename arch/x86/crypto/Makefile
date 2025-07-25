# SPDX-License-Identifier: GPL-2.0
#
# x86 crypto algorithms

obj-$(CONFIG_CRYPTO_TWOFISH_586) += twofish-i586.o
twofish-i586-y := twofish-i586-asm_32.o twofish_glue.o
obj-$(CONFIG_CRYPTO_TWOFISH_X86_64) += twofish-x86_64.o
twofish-x86_64-y := twofish-x86_64-asm_64.o twofish_glue.o
obj-$(CONFIG_CRYPTO_TWOFISH_X86_64_3WAY) += twofish-x86_64-3way.o
twofish-x86_64-3way-y := twofish-x86_64-asm_64-3way.o twofish_glue_3way.o
obj-$(CONFIG_CRYPTO_TWOFISH_AVX_X86_64) += twofish-avx-x86_64.o
twofish-avx-x86_64-y := twofish-avx-x86_64-asm_64.o twofish_avx_glue.o

obj-$(CONFIG_CRYPTO_SERPENT_SSE2_586) += serpent-sse2-i586.o
serpent-sse2-i586-y := serpent-sse2-i586-asm_32.o serpent_sse2_glue.o
obj-$(CONFIG_CRYPTO_SERPENT_SSE2_X86_64) += serpent-sse2-x86_64.o
serpent-sse2-x86_64-y := serpent-sse2-x86_64-asm_64.o serpent_sse2_glue.o
obj-$(CONFIG_CRYPTO_SERPENT_AVX_X86_64) += serpent-avx-x86_64.o
serpent-avx-x86_64-y := serpent-avx-x86_64-asm_64.o serpent_avx_glue.o
obj-$(CONFIG_CRYPTO_SERPENT_AVX2_X86_64) += serpent-avx2.o
serpent-avx2-y := serpent-avx2-asm_64.o serpent_avx2_glue.o

obj-$(CONFIG_CRYPTO_DES3_EDE_X86_64) += des3_ede-x86_64.o
des3_ede-x86_64-y := des3_ede-asm_64.o des3_ede_glue.o

obj-$(CONFIG_CRYPTO_CAMELLIA_X86_64) += camellia-x86_64.o
camellia-x86_64-y := camellia-x86_64-asm_64.o camellia_glue.o
obj-$(CONFIG_CRYPTO_CAMELLIA_AESNI_AVX_X86_64) += camellia-aesni-avx-x86_64.o
camellia-aesni-avx-x86_64-y := camellia-aesni-avx-asm_64.o camellia_aesni_avx_glue.o
obj-$(CONFIG_CRYPTO_CAMELLIA_AESNI_AVX2_X86_64) += camellia-aesni-avx2.o
camellia-aesni-avx2-y := camellia-aesni-avx2-asm_64.o camellia_aesni_avx2_glue.o

obj-$(CONFIG_CRYPTO_BLOWFISH_X86_64) += blowfish-x86_64.o
blowfish-x86_64-y := blowfish-x86_64-asm_64.o blowfish_glue.o

obj-$(CONFIG_CRYPTO_CAST5_AVX_X86_64) += cast5-avx-x86_64.o
cast5-avx-x86_64-y := cast5-avx-x86_64-asm_64.o cast5_avx_glue.o

obj-$(CONFIG_CRYPTO_CAST6_AVX_X86_64) += cast6-avx-x86_64.o
cast6-avx-x86_64-y := cast6-avx-x86_64-asm_64.o cast6_avx_glue.o

obj-$(CONFIG_CRYPTO_AEGIS128_AESNI_SSE2) += aegis128-aesni.o
aegis128-aesni-y := aegis128-aesni-asm.o aegis128-aesni-glue.o

obj-$(CONFIG_CRYPTO_AES_NI_INTEL) += aesni-intel.o
aesni-intel-y := aesni-intel_asm.o aesni-intel_glue.o
aesni-intel-$(CONFIG_64BIT) += aes-ctr-avx-x86_64.o \
			       aes-gcm-aesni-x86_64.o \
			       aes-xts-avx-x86_64.o
ifeq ($(CONFIG_AS_VAES)$(CONFIG_AS_VPCLMULQDQ),yy)
aesni-intel-$(CONFIG_64BIT) += aes-gcm-avx10-x86_64.o
endif

obj-$(CONFIG_CRYPTO_GHASH_CLMUL_NI_INTEL) += ghash-clmulni-intel.o
ghash-clmulni-intel-y := ghash-clmulni-intel_asm.o ghash-clmulni-intel_glue.o

obj-$(CONFIG_CRYPTO_POLYVAL_CLMUL_NI) += polyval-clmulni.o
polyval-clmulni-y := polyval-clmulni_asm.o polyval-clmulni_glue.o

obj-$(CONFIG_CRYPTO_NHPOLY1305_SSE2) += nhpoly1305-sse2.o
nhpoly1305-sse2-y := nh-sse2-x86_64.o nhpoly1305-sse2-glue.o
obj-$(CONFIG_CRYPTO_NHPOLY1305_AVX2) += nhpoly1305-avx2.o
nhpoly1305-avx2-y := nh-avx2-x86_64.o nhpoly1305-avx2-glue.o

obj-$(CONFIG_CRYPTO_CURVE25519_X86) += curve25519-x86_64.o

obj-$(CONFIG_CRYPTO_SM3_AVX_X86_64) += sm3-avx-x86_64.o
sm3-avx-x86_64-y := sm3-avx-asm_64.o sm3_avx_glue.o

obj-$(CONFIG_CRYPTO_SM4_AESNI_AVX_X86_64) += sm4-aesni-avx-x86_64.o
sm4-aesni-avx-x86_64-y := sm4-aesni-avx-asm_64.o sm4_aesni_avx_glue.o

obj-$(CONFIG_CRYPTO_SM4_AESNI_AVX2_X86_64) += sm4-aesni-avx2-x86_64.o
sm4-aesni-avx2-x86_64-y := sm4-aesni-avx2-asm_64.o sm4_aesni_avx2_glue.o

obj-$(CONFIG_CRYPTO_ARIA_AESNI_AVX_X86_64) += aria-aesni-avx-x86_64.o
aria-aesni-avx-x86_64-y := aria-aesni-avx-asm_64.o aria_aesni_avx_glue.o

obj-$(CONFIG_CRYPTO_ARIA_AESNI_AVX2_X86_64) += aria-aesni-avx2-x86_64.o
aria-aesni-avx2-x86_64-y := aria-aesni-avx2-asm_64.o aria_aesni_avx2_glue.o

obj-$(CONFIG_CRYPTO_ARIA_GFNI_AVX512_X86_64) += aria-gfni-avx512-x86_64.o
aria-gfni-avx512-x86_64-y := aria-gfni-avx512-asm_64.o aria_gfni_avx512_glue.o

# Disable GCOV in odd or sensitive code
GCOV_PROFILE_curve25519-x86_64.o := n
