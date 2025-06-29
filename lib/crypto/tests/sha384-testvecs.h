/* This file was generated by: ./scripts/crypto/gen-hash-testvecs.py sha384 */

static const struct {
	size_t data_len;
	u8 digest[SHA384_DIGEST_SIZE];
} sha384_testvecs[] = {
	{
		.data_len = 0,
		.digest = {
			0x38, 0xb0, 0x60, 0xa7, 0x51, 0xac, 0x96, 0x38,
			0x4c, 0xd9, 0x32, 0x7e, 0xb1, 0xb1, 0xe3, 0x6a,
			0x21, 0xfd, 0xb7, 0x11, 0x14, 0xbe, 0x07, 0x43,
			0x4c, 0x0c, 0xc7, 0xbf, 0x63, 0xf6, 0xe1, 0xda,
			0x27, 0x4e, 0xde, 0xbf, 0xe7, 0x6f, 0x65, 0xfb,
			0xd5, 0x1a, 0xd2, 0xf1, 0x48, 0x98, 0xb9, 0x5b,
		},
	},
	{
		.data_len = 1,
		.digest = {
			0x07, 0x34, 0x9d, 0x74, 0x48, 0x76, 0xa5, 0x72,
			0x78, 0x02, 0xb8, 0x6e, 0x21, 0x59, 0xb0, 0x75,
			0x09, 0x68, 0x11, 0x39, 0x53, 0x61, 0xee, 0x8d,
			0xf2, 0x01, 0xf3, 0x90, 0x53, 0x7c, 0xd3, 0xde,
			0x13, 0x9f, 0xd2, 0x74, 0x28, 0xfe, 0xe1, 0xc8,
			0x2e, 0x95, 0xc6, 0x7d, 0x69, 0x4d, 0x04, 0xc6,
		},
	},
	{
		.data_len = 2,
		.digest = {
			0xc4, 0xef, 0x6e, 0x8c, 0x19, 0x1c, 0xaa, 0x0e,
			0x86, 0xf2, 0x68, 0xa1, 0xa0, 0x2d, 0x2e, 0xb2,
			0x84, 0xbc, 0x5d, 0x53, 0x31, 0xf8, 0x03, 0x75,
			0x56, 0xf4, 0x8b, 0x23, 0x1a, 0x68, 0x15, 0x9a,
			0x60, 0xb2, 0xec, 0x05, 0xe1, 0xd4, 0x5e, 0x9e,
			0xe8, 0x7c, 0x9d, 0xe4, 0x0f, 0x9c, 0x3a, 0xdd,
		},
	},
	{
		.data_len = 3,
		.digest = {
			0x29, 0xd2, 0x02, 0xa2, 0x77, 0x24, 0xc7, 0xa7,
			0x23, 0x0c, 0x3e, 0x30, 0x56, 0x47, 0xdb, 0x75,
			0xd4, 0x41, 0xf8, 0xb3, 0x8e, 0x26, 0xf6, 0x92,
			0xbc, 0x20, 0x2e, 0x96, 0xcc, 0x81, 0x5f, 0x32,
			0x82, 0x60, 0xe2, 0xcf, 0x23, 0xd7, 0x3c, 0x90,
			0xb2, 0x56, 0x8f, 0xb6, 0x0f, 0xf0, 0x6b, 0x80,
		},
	},
	{
		.data_len = 16,
		.digest = {
			0x21, 0x4c, 0xac, 0xfe, 0xbd, 0x40, 0x74, 0x1f,
			0xa2, 0x2d, 0x2f, 0x35, 0x91, 0xfd, 0xc9, 0x97,
			0x88, 0x12, 0x6c, 0x0c, 0x6e, 0xd8, 0x50, 0x0b,
			0x4b, 0x2c, 0x89, 0xa6, 0xa6, 0x4a, 0xad, 0xd7,
			0x72, 0x62, 0x2c, 0x62, 0x81, 0xcd, 0x24, 0x74,
			0xf5, 0x44, 0x05, 0xa0, 0x97, 0xea, 0xf1, 0x78,
		},
	},
	{
		.data_len = 32,
		.digest = {
			0x06, 0x8b, 0x92, 0x9f, 0x8b, 0x64, 0xb2, 0x80,
			0xde, 0xcc, 0xde, 0xc3, 0x2f, 0x22, 0x27, 0xe8,
			0x3b, 0x6e, 0x16, 0x21, 0x14, 0x81, 0xbe, 0x5b,
			0xa7, 0xa7, 0x14, 0x8a, 0x00, 0x8f, 0x0d, 0x38,
			0x11, 0x63, 0xe8, 0x3e, 0xb9, 0xf1, 0xcf, 0x87,
			0xb1, 0x28, 0xe5, 0xa1, 0x89, 0xa8, 0x7a, 0xde,
		},
	},
	{
		.data_len = 48,
		.digest = {
			0x9e, 0x37, 0x76, 0x62, 0x98, 0x39, 0xbe, 0xfd,
			0x2b, 0x91, 0x20, 0x54, 0x8f, 0x21, 0xe7, 0x30,
			0x0a, 0x01, 0x7a, 0x65, 0x0b, 0xc9, 0xb3, 0x89,
			0x3c, 0xb6, 0xd3, 0xa8, 0xff, 0xc9, 0x1b, 0x5c,
			0xd4, 0xac, 0xb4, 0x7e, 0xba, 0x94, 0xc3, 0x8a,
			0x26, 0x41, 0xf6, 0xd5, 0xed, 0x6f, 0x27, 0xa7,
		},
	},
	{
		.data_len = 49,
		.digest = {
			0x03, 0x1f, 0xef, 0x5a, 0x16, 0x28, 0x78, 0x10,
			0x29, 0xe8, 0xe2, 0xe4, 0x84, 0x36, 0x19, 0x10,
			0xaa, 0xea, 0xde, 0x06, 0x39, 0x5f, 0xb2, 0x36,
			0xca, 0x24, 0x4f, 0x7b, 0x66, 0xf7, 0xe7, 0x31,
			0xf3, 0x9b, 0x74, 0x1e, 0x17, 0x20, 0x88, 0x62,
			0x50, 0xeb, 0x5f, 0x9a, 0xa7, 0x2c, 0xf4, 0xc9,
		},
	},
	{
		.data_len = 63,
		.digest = {
			0x10, 0xce, 0xed, 0x26, 0xb8, 0xac, 0xc1, 0x1b,
			0xe6, 0xb9, 0xeb, 0x7c, 0xae, 0xcd, 0x55, 0x5a,
			0x20, 0x2a, 0x7b, 0x43, 0xe6, 0x3e, 0xf0, 0x3f,
			0xd9, 0x2f, 0x8c, 0x52, 0xe2, 0xf0, 0xb6, 0x24,
			0x2e, 0xa4, 0xac, 0x24, 0x3a, 0x54, 0x99, 0x71,
			0x65, 0xab, 0x97, 0x2d, 0xb6, 0xe6, 0x94, 0x20,
		},
	},
	{
		.data_len = 64,
		.digest = {
			0x24, 0x6d, 0x9f, 0x59, 0x42, 0x36, 0xca, 0x34,
			0x36, 0x41, 0xa2, 0xcd, 0x69, 0xdf, 0x3d, 0xcb,
			0x64, 0x94, 0x54, 0xb2, 0xed, 0xc1, 0x1c, 0x31,
			0xe3, 0x26, 0xcb, 0x71, 0xe6, 0x98, 0xb2, 0x56,
			0x74, 0x30, 0xa9, 0x15, 0x98, 0x9d, 0xb3, 0x07,
			0xcc, 0xa8, 0xcc, 0x6f, 0x42, 0xb0, 0x9d, 0x2b,
		},
	},
	{
		.data_len = 65,
		.digest = {
			0x85, 0x1f, 0xbc, 0x5e, 0x2a, 0x00, 0x7d, 0xc2,
			0x21, 0x4c, 0x28, 0x14, 0xc5, 0xd8, 0x0c, 0xe8,
			0x55, 0xa5, 0xa0, 0x77, 0xda, 0x8f, 0xce, 0xd4,
			0xf0, 0xcb, 0x30, 0xb8, 0x9c, 0x47, 0xe1, 0x33,
			0x92, 0x18, 0xc5, 0x1f, 0xf2, 0xef, 0xb5, 0xe5,
			0xbc, 0x63, 0xa6, 0xe5, 0x9a, 0xc9, 0xcc, 0xf1,
		},
	},
	{
		.data_len = 127,
		.digest = {
			0x26, 0xd2, 0x4c, 0xb6, 0xce, 0xd8, 0x22, 0x2b,
			0x44, 0x10, 0x6f, 0x59, 0xf7, 0x0d, 0xb9, 0x3f,
			0x7d, 0x29, 0x75, 0xf1, 0x71, 0xb2, 0x71, 0x23,
			0xef, 0x68, 0xb7, 0x25, 0xae, 0xb8, 0x45, 0xf8,
			0xa3, 0xb2, 0x2d, 0x7a, 0x83, 0x0a, 0x05, 0x61,
			0xbc, 0x73, 0xf1, 0xf9, 0xba, 0xfb, 0x3d, 0xc2,
		},
	},
	{
		.data_len = 128,
		.digest = {
			0x7c, 0xe5, 0x7f, 0x5e, 0xea, 0xd9, 0x7e, 0x54,
			0x14, 0x30, 0x6f, 0x37, 0x02, 0x71, 0x0f, 0xf1,
			0x14, 0x16, 0xfa, 0xeb, 0x6e, 0x1e, 0xf0, 0xbe,
			0x10, 0xed, 0x01, 0xbf, 0xa0, 0x9d, 0xcb, 0x07,
			0x5f, 0x8b, 0x7f, 0x44, 0xe1, 0xd9, 0x13, 0xf0,
			0x29, 0xa2, 0x54, 0x32, 0xd9, 0xb0, 0x69, 0x69,
		},
	},
	{
		.data_len = 129,
		.digest = {
			0xc5, 0x54, 0x1f, 0xcb, 0x9d, 0x8f, 0xdf, 0xbf,
			0xab, 0x55, 0x92, 0x1d, 0x3b, 0x93, 0x79, 0x26,
			0xdf, 0xba, 0x9a, 0x28, 0xff, 0xa0, 0x6c, 0xae,
			0x7b, 0x53, 0x8d, 0xfa, 0xef, 0x35, 0x88, 0x19,
			0x16, 0xb8, 0x72, 0x86, 0x76, 0x2a, 0xf5, 0xe6,
			0xec, 0xb2, 0xd7, 0xd4, 0xbe, 0x1a, 0xe4, 0x9f,
		},
	},
	{
		.data_len = 256,
		.digest = {
			0x74, 0x9d, 0x77, 0xfb, 0xe8, 0x0f, 0x0c, 0x2d,
			0x86, 0x0d, 0x49, 0xea, 0x2b, 0xd0, 0x13, 0xd1,
			0xe8, 0xb8, 0xe1, 0xa3, 0x7b, 0x48, 0xab, 0x6a,
			0x21, 0x2b, 0x4c, 0x48, 0x32, 0xb5, 0xdc, 0x31,
			0x7f, 0xd0, 0x32, 0x67, 0x9a, 0xc0, 0x85, 0x53,
			0xef, 0xe9, 0xfb, 0xe1, 0x8b, 0xd8, 0xcc, 0xc2,
		},
	},
	{
		.data_len = 511,
		.digest = {
			0x7b, 0xa9, 0xde, 0xa3, 0x07, 0x5c, 0x4c, 0xaa,
			0x31, 0xc6, 0x9e, 0x55, 0xd4, 0x3f, 0x52, 0xdd,
			0xde, 0x36, 0x70, 0x96, 0x59, 0x6e, 0x90, 0x78,
			0x4c, 0x6a, 0x27, 0xde, 0x83, 0x84, 0xc3, 0x35,
			0x53, 0x76, 0x1d, 0xbf, 0x83, 0x64, 0xcf, 0xf2,
			0xb0, 0x3e, 0x07, 0x27, 0xe4, 0x25, 0x6c, 0x56,
		},
	},
	{
		.data_len = 513,
		.digest = {
			0x53, 0x50, 0xf7, 0x3b, 0x86, 0x1d, 0x7a, 0xe2,
			0x5d, 0x9b, 0x71, 0xfa, 0x25, 0x23, 0x5a, 0xfe,
			0x8c, 0xb9, 0xac, 0x8a, 0x9d, 0x6c, 0x99, 0xbc,
			0x01, 0x9e, 0xa0, 0xd6, 0x3c, 0x03, 0x46, 0x21,
			0xb6, 0xd0, 0xb0, 0xb3, 0x23, 0x23, 0x58, 0xf1,
			0xea, 0x4e, 0xf2, 0x1a, 0x2f, 0x14, 0x2b, 0x5a,
		},
	},
	{
		.data_len = 1000,
		.digest = {
			0x06, 0x03, 0xb3, 0xba, 0x14, 0xe0, 0x28, 0x07,
			0xd5, 0x15, 0x97, 0x1f, 0x87, 0xef, 0x80, 0xba,
			0x48, 0x03, 0xb6, 0xc5, 0x47, 0xca, 0x8c, 0x95,
			0xed, 0x95, 0xfd, 0x27, 0xb6, 0x83, 0xda, 0x6d,
			0xa7, 0xb2, 0x1a, 0xd2, 0xb5, 0x89, 0xbb, 0xb4,
			0x00, 0xbc, 0x86, 0x54, 0x7d, 0x5a, 0x91, 0x63,
		},
	},
	{
		.data_len = 3333,
		.digest = {
			0xd3, 0xe0, 0x6e, 0x7d, 0x80, 0x08, 0x53, 0x07,
			0x8c, 0x0f, 0xc2, 0xce, 0x9f, 0x09, 0x86, 0x31,
			0x28, 0x24, 0x3c, 0x3e, 0x2d, 0x36, 0xb4, 0x28,
			0xc7, 0x1b, 0x70, 0xf9, 0x35, 0x9b, 0x10, 0xfa,
			0xc8, 0x5e, 0x2b, 0x32, 0x7f, 0x65, 0xd2, 0x68,
			0xb2, 0x84, 0x90, 0xf6, 0xc8, 0x6e, 0xb8, 0xdb,
		},
	},
	{
		.data_len = 4096,
		.digest = {
			0x39, 0xeb, 0xc4, 0xb3, 0x08, 0xe2, 0xdd, 0xf3,
			0x9f, 0x5e, 0x44, 0x93, 0x63, 0x8b, 0x39, 0x57,
			0xd7, 0xe8, 0x7e, 0x3d, 0x74, 0xf8, 0xf6, 0xab,
			0xfe, 0x74, 0x51, 0xe4, 0x1b, 0x4a, 0x23, 0xbc,
			0x69, 0xfc, 0xbb, 0xa7, 0x71, 0xa7, 0x86, 0x24,
			0xcc, 0x85, 0x70, 0xf2, 0x31, 0x0d, 0x47, 0xc0,
		},
	},
	{
		.data_len = 4128,
		.digest = {
			0x23, 0xc3, 0x97, 0x06, 0x79, 0xbe, 0x8a, 0xe9,
			0x1f, 0x1a, 0x43, 0xad, 0xe6, 0x76, 0x23, 0x13,
			0x64, 0xae, 0xda, 0xe7, 0x8b, 0x88, 0x96, 0xb6,
			0xa9, 0x1a, 0xb7, 0x80, 0x8e, 0x1c, 0x94, 0x98,
			0x09, 0x08, 0xdb, 0x8e, 0x4d, 0x0a, 0x09, 0x65,
			0xe5, 0x21, 0x1c, 0xd9, 0xab, 0x64, 0xbb, 0xea,
		},
	},
	{
		.data_len = 4160,
		.digest = {
			0x4f, 0x4a, 0x88, 0x9f, 0x40, 0x89, 0xfe, 0xb6,
			0xda, 0x9d, 0xcd, 0xa5, 0x27, 0xd2, 0x29, 0x71,
			0x58, 0x60, 0xd4, 0x55, 0xfe, 0x92, 0xcd, 0x51,
			0x8b, 0xec, 0x3b, 0xd3, 0xd1, 0x3e, 0x8d, 0x36,
			0x7b, 0xb1, 0x41, 0xef, 0xec, 0x9d, 0xdf, 0xcd,
			0x4e, 0xde, 0x5a, 0xe5, 0xe5, 0x16, 0x14, 0x54,
		},
	},
	{
		.data_len = 4224,
		.digest = {
			0xb5, 0xa5, 0x3e, 0x86, 0x39, 0x20, 0x49, 0x4c,
			0xcd, 0xb6, 0xdd, 0x03, 0xfe, 0x36, 0x6e, 0xa6,
			0xfc, 0xff, 0x19, 0x33, 0x0c, 0x52, 0xea, 0x37,
			0x94, 0xda, 0x5b, 0x27, 0xd1, 0x99, 0x5a, 0x89,
			0x40, 0x78, 0xfa, 0x96, 0xb9, 0x2f, 0xa0, 0x48,
			0xc9, 0xf8, 0x5c, 0xf0, 0x95, 0xf4, 0xea, 0x61,
		},
	},
	{
		.data_len = 16384,
		.digest = {
			0x6f, 0x48, 0x6f, 0x21, 0xb9, 0xc1, 0xcc, 0x92,
			0x4e, 0xed, 0x6b, 0xef, 0x51, 0x88, 0xdf, 0xfd,
			0xcb, 0x3d, 0x44, 0x9c, 0x37, 0x85, 0xb4, 0xc5,
			0xeb, 0x60, 0x55, 0x58, 0x01, 0x47, 0xbf, 0x75,
			0x9b, 0xa8, 0x82, 0x8c, 0xec, 0xe8, 0x0e, 0x58,
			0xc1, 0x26, 0xa2, 0x45, 0x87, 0x3e, 0xfb, 0x8d,
		},
	},
};

static const struct {
	size_t data_len;
	size_t key_len;
	u8 mac[SHA384_DIGEST_SIZE];
} hmac_sha384_testvecs[] = {
	{
		.data_len = 0,
		.key_len = 0,
		.mac = {
			0x6c, 0x1f, 0x2e, 0xe9, 0x38, 0xfa, 0xd2, 0xe2,
			0x4b, 0xd9, 0x12, 0x98, 0x47, 0x43, 0x82, 0xca,
			0x21, 0x8c, 0x75, 0xdb, 0x3d, 0x83, 0xe1, 0x14,
			0xb3, 0xd4, 0x36, 0x77, 0x76, 0xd1, 0x4d, 0x35,
			0x51, 0x28, 0x9e, 0x75, 0xe8, 0x20, 0x9c, 0xd4,
			0xb7, 0x92, 0x30, 0x28, 0x40, 0x23, 0x4a, 0xdc,
		},
	},
	{
		.data_len = 1,
		.key_len = 1,
		.mac = {
			0xe5, 0x20, 0x5e, 0xd4, 0x0a, 0xd8, 0x37, 0xff,
			0xf9, 0x0e, 0x2b, 0xf2, 0xca, 0x15, 0x65, 0xec,
			0xb3, 0xfb, 0x14, 0xa1, 0xc3, 0xdc, 0x9e, 0xa0,
			0x96, 0x99, 0xeb, 0x18, 0x24, 0x90, 0x42, 0xef,
			0x63, 0x3c, 0x38, 0xd3, 0x19, 0x6b, 0x7f, 0xef,
			0x07, 0xb3, 0xb8, 0xb0, 0x43, 0x5f, 0xef, 0xed,
		},
	},
	{
		.data_len = 2,
		.key_len = 31,
		.mac = {
			0x47, 0x08, 0x60, 0x37, 0xe9, 0x47, 0x0d, 0x56,
			0xa9, 0x81, 0xa1, 0xdf, 0x05, 0x1e, 0x41, 0x4e,
			0x7f, 0xf9, 0x51, 0xb3, 0x47, 0x7e, 0x04, 0x4f,
			0x0a, 0x05, 0x13, 0x6e, 0xd8, 0x4e, 0x6d, 0x98,
			0x91, 0x89, 0xe1, 0xdc, 0x7f, 0x23, 0x03, 0x2e,
			0x47, 0x9e, 0x7c, 0xe0, 0x68, 0x08, 0xd2, 0x57,
		},
	},
	{
		.data_len = 3,
		.key_len = 32,
		.mac = {
			0xb9, 0x83, 0xdc, 0x7c, 0xb2, 0x48, 0x04, 0xc7,
			0xdf, 0x9f, 0x8b, 0xbe, 0x17, 0x80, 0xc5, 0x13,
			0x24, 0x10, 0x1c, 0xf1, 0x38, 0x75, 0x87, 0xe6,
			0x3a, 0x2e, 0xa2, 0xed, 0x33, 0xdb, 0xfc, 0xd7,
			0x0c, 0x8e, 0x89, 0x92, 0x14, 0x19, 0xef, 0x43,
			0xef, 0x6b, 0xc7, 0xc5, 0x4d, 0x3f, 0xa4, 0x41,
		},
	},
	{
		.data_len = 16,
		.key_len = 33,
		.mac = {
			0xee, 0x3b, 0x6b, 0x7f, 0xec, 0xe1, 0xc4, 0x8f,
			0x01, 0x91, 0xc9, 0x1a, 0x18, 0xb3, 0x0f, 0x34,
			0xad, 0xe5, 0x1f, 0x51, 0x9a, 0x0b, 0xec, 0xa3,
			0xc1, 0x0e, 0xf7, 0x7e, 0xb5, 0xd5, 0xe6, 0x22,
			0x44, 0x23, 0x85, 0x2c, 0xe0, 0xb6, 0x81, 0xac,
			0x7b, 0x41, 0x49, 0x18, 0x92, 0x0a, 0xd5, 0xc1,
		},
	},
	{
		.data_len = 32,
		.key_len = 64,
		.mac = {
			0x4d, 0x1f, 0xd0, 0x53, 0x5e, 0x04, 0x2b, 0xd6,
			0xfd, 0xd6, 0xa2, 0xed, 0xa2, 0x49, 0x36, 0xbf,
			0x44, 0x8e, 0x42, 0x1c, 0x8a, 0xde, 0x44, 0xbb,
			0x43, 0x84, 0xec, 0x70, 0xbb, 0x2d, 0xd3, 0x66,
			0x51, 0xc0, 0xed, 0xd1, 0xcd, 0x5b, 0x11, 0xf2,
			0x1c, 0xe6, 0x7d, 0xe9, 0xcd, 0xab, 0xff, 0x02,
		},
	},
	{
		.data_len = 48,
		.key_len = 65,
		.mac = {
			0x12, 0xfc, 0x9f, 0x95, 0xcd, 0x88, 0xed, 0x8a,
			0x6a, 0x87, 0x36, 0x45, 0x63, 0xb9, 0xc8, 0x46,
			0xf5, 0x06, 0x97, 0x24, 0x19, 0xc8, 0xfa, 0xfd,
			0xcf, 0x2b, 0x78, 0x5d, 0x44, 0xf1, 0x82, 0xbf,
			0x93, 0xea, 0x9c, 0x84, 0xe5, 0xba, 0x27, 0x21,
			0x2f, 0x3b, 0xd0, 0xfe, 0x2c, 0x53, 0x72, 0x31,
		},
	},
	{
		.data_len = 49,
		.key_len = 66,
		.mac = {
			0x8e, 0x8f, 0x3d, 0xd7, 0xe6, 0x14, 0x0c, 0xf2,
			0xf6, 0x9a, 0x19, 0xda, 0x4c, 0xb2, 0xc4, 0x84,
			0x63, 0x76, 0x5b, 0xae, 0x17, 0xe0, 0xdf, 0x92,
			0x82, 0xcf, 0x85, 0xbd, 0xce, 0xde, 0x3b, 0x49,
			0xfe, 0x0a, 0xfb, 0xdc, 0x9a, 0xc0, 0x9e, 0xc7,
			0x4f, 0x2c, 0x0f, 0xd3, 0xb9, 0x82, 0x1a, 0xaa,
		},
	},
	{
		.data_len = 63,
		.key_len = 127,
		.mac = {
			0xc9, 0x17, 0xbb, 0x8f, 0x4f, 0x13, 0xba, 0x99,
			0x4e, 0x48, 0x6a, 0x23, 0x12, 0x61, 0x7b, 0xa0,
			0x63, 0xcb, 0x47, 0xfd, 0xbd, 0xd3, 0xfd, 0x94,
			0xe7, 0x0b, 0xec, 0x04, 0x44, 0x5a, 0xfe, 0xb0,
			0x97, 0x5b, 0x80, 0x4c, 0x02, 0x5c, 0x92, 0x05,
			0x45, 0xe6, 0xe3, 0x0d, 0x21, 0xa5, 0x9a, 0x11,
		},
	},
	{
		.data_len = 64,
		.key_len = 128,
		.mac = {
			0xbf, 0x20, 0x44, 0xe1, 0x91, 0xcf, 0x2b, 0x53,
			0xcb, 0xcb, 0x89, 0xc2, 0x1b, 0x8e, 0xcb, 0xb0,
			0x12, 0xd2, 0x77, 0x21, 0x7e, 0x8f, 0x40, 0x0f,
			0x1e, 0xa4, 0xe7, 0x38, 0x69, 0x0f, 0x58, 0xba,
			0x42, 0x78, 0x57, 0x4e, 0x7a, 0xf0, 0xb0, 0xf2,
			0xe0, 0x17, 0x17, 0xcf, 0xee, 0x26, 0x53, 0x81,
		},
	},
	{
		.data_len = 65,
		.key_len = 129,
		.mac = {
			0x44, 0xe7, 0x53, 0x94, 0xaa, 0x33, 0xb0, 0xde,
			0x8e, 0xef, 0x85, 0x19, 0x69, 0x1e, 0xba, 0x69,
			0x7f, 0xe1, 0x17, 0xc3, 0x91, 0xd6, 0x7b, 0x07,
			0x61, 0xed, 0x81, 0x4c, 0x01, 0x65, 0x36, 0xbd,
			0x7d, 0x4f, 0x70, 0xd7, 0x0d, 0xb8, 0xfc, 0xaf,
			0x48, 0x1c, 0x96, 0x37, 0xf9, 0xc8, 0x72, 0x00,
		},
	},
	{
		.data_len = 127,
		.key_len = 1000,
		.mac = {
			0x98, 0x11, 0x57, 0xfe, 0xa5, 0xd0, 0xed, 0x5e,
			0xc5, 0x7e, 0xb3, 0x53, 0x9d, 0x12, 0x38, 0x41,
			0x0a, 0x78, 0x75, 0xd4, 0x0f, 0xa6, 0x9f, 0x05,
			0xd3, 0x2e, 0xcd, 0xad, 0x78, 0xea, 0x09, 0xdc,
			0xdc, 0x2b, 0x56, 0x41, 0xb1, 0x5a, 0x6b, 0xd8,
			0x3e, 0xe7, 0xac, 0x01, 0x4b, 0xb8, 0x52, 0x42,
		},
	},
	{
		.data_len = 128,
		.key_len = 1024,
		.mac = {
			0xaa, 0x48, 0xa9, 0x1a, 0x47, 0xbf, 0x87, 0xec,
			0x9e, 0xe6, 0x0f, 0x98, 0x2a, 0xb0, 0xa7, 0x84,
			0x9a, 0x87, 0x5c, 0x75, 0x7e, 0xb5, 0xf1, 0x0a,
			0x01, 0x20, 0x75, 0xfd, 0xbf, 0xb8, 0x59, 0xad,
			0x1d, 0xa6, 0x59, 0x2c, 0xf2, 0x5e, 0xfd, 0xdc,
			0x3c, 0x39, 0x4c, 0xcd, 0x0a, 0x5f, 0xb0, 0x1f,
		},
	},
	{
		.data_len = 129,
		.key_len = 0,
		.mac = {
			0x0a, 0xa9, 0x08, 0xdf, 0x29, 0xc4, 0x9e, 0xb3,
			0x80, 0x32, 0xab, 0xf5, 0x61, 0xb2, 0xdf, 0x31,
			0xc7, 0x7b, 0xb6, 0xb6, 0x30, 0x45, 0x85, 0x6b,
			0x76, 0xbc, 0x83, 0xfd, 0x94, 0xe5, 0x91, 0x33,
			0x40, 0x01, 0x2d, 0xcf, 0x22, 0x27, 0x35, 0x5e,
			0x25, 0xac, 0xfe, 0x14, 0xb4, 0xec, 0x13, 0xa7,
		},
	},
	{
		.data_len = 256,
		.key_len = 1,
		.mac = {
			0x0d, 0x94, 0xcc, 0xcd, 0xbd, 0x89, 0xdc, 0xb4,
			0xcf, 0x93, 0x02, 0x8c, 0x1d, 0x37, 0xbd, 0x00,
			0xa4, 0x9c, 0x24, 0xb2, 0xf7, 0xa5, 0xbf, 0x97,
			0x5a, 0x9b, 0x27, 0xc2, 0x28, 0xcf, 0xce, 0x3e,
			0x8d, 0xa0, 0x14, 0x03, 0x64, 0xc2, 0x80, 0xec,
			0x09, 0xcb, 0x57, 0x81, 0x2f, 0x70, 0x15, 0x1f,
		},
	},
	{
		.data_len = 511,
		.key_len = 31,
		.mac = {
			0xb7, 0x4b, 0x98, 0x94, 0x29, 0xfd, 0x21, 0xba,
			0x99, 0xc4, 0x36, 0x2b, 0x8d, 0x71, 0xa5, 0x15,
			0xd0, 0x2f, 0xc2, 0x4d, 0x15, 0x33, 0xa2, 0x52,
			0x58, 0x74, 0xe7, 0x40, 0x5e, 0x75, 0x32, 0x70,
			0x64, 0x7d, 0xce, 0x13, 0xf2, 0x01, 0x38, 0x71,
			0x0e, 0x8d, 0xea, 0x8b, 0x78, 0x23, 0x65, 0x28,
		},
	},
	{
		.data_len = 513,
		.key_len = 32,
		.mac = {
			0xba, 0xc4, 0x7a, 0xf3, 0x62, 0xfc, 0x56, 0x8b,
			0x77, 0xde, 0x56, 0x64, 0x51, 0x0d, 0xaa, 0x50,
			0x7c, 0x77, 0xbc, 0xd4, 0x44, 0x78, 0x0e, 0xae,
			0x8a, 0xa2, 0x52, 0x7b, 0x3b, 0x87, 0x5f, 0x66,
			0xf9, 0x28, 0x6a, 0x0a, 0xd6, 0xbf, 0x40, 0xcf,
			0xa3, 0xb0, 0x70, 0x60, 0xb1, 0x36, 0x4d, 0x3b,
		},
	},
	{
		.data_len = 1000,
		.key_len = 33,
		.mac = {
			0xf7, 0x54, 0x6b, 0x0d, 0x52, 0x46, 0x95, 0x1b,
			0xb2, 0xc1, 0xd9, 0x89, 0x8c, 0xdf, 0x56, 0xfc,
			0x05, 0xd5, 0x1c, 0x0a, 0x60, 0xef, 0x06, 0xfa,
			0x40, 0x18, 0xf7, 0xa3, 0xdb, 0x5e, 0xcb, 0x94,
			0xa7, 0x8f, 0x6f, 0x01, 0x8d, 0x40, 0x83, 0x1e,
			0x32, 0x22, 0xa5, 0xa6, 0x83, 0xb7, 0x57, 0x9e,
		},
	},
	{
		.data_len = 3333,
		.key_len = 64,
		.mac = {
			0x46, 0x1f, 0x32, 0xf7, 0x8e, 0x21, 0x52, 0x70,
			0xe6, 0x45, 0xa4, 0xb5, 0x13, 0x92, 0xbe, 0x5e,
			0x5b, 0x9e, 0xa8, 0x9a, 0x22, 0x3a, 0x49, 0xbb,
			0xc5, 0xab, 0xfb, 0x05, 0xed, 0x13, 0xcb, 0xe2,
			0x71, 0xc1, 0x22, 0xca, 0x3b, 0x65, 0x08, 0xb3,
			0x9c, 0x1a, 0x03, 0xd0, 0x8e, 0xf8, 0xf0, 0x8b,
		},
	},
	{
		.data_len = 4096,
		.key_len = 65,
		.mac = {
			0xb4, 0x0d, 0x90, 0x01, 0x69, 0x2b, 0xc8, 0xab,
			0x6b, 0xe9, 0x8c, 0xa5, 0xa9, 0x46, 0xc0, 0x90,
			0x84, 0xec, 0x6d, 0x6b, 0x64, 0x88, 0x66, 0x55,
			0x61, 0x04, 0x2d, 0xd8, 0x30, 0x9a, 0x2f, 0x3b,
			0x3d, 0xa3, 0x11, 0x50, 0xcc, 0x6a, 0xe4, 0xb2,
			0x41, 0x18, 0xd7, 0x70, 0x57, 0x01, 0x67, 0x1c,
		},
	},
	{
		.data_len = 4128,
		.key_len = 66,
		.mac = {
			0xbd, 0x68, 0x84, 0xea, 0x22, 0xbf, 0xe2, 0x0e,
			0x86, 0x61, 0x5e, 0x58, 0x38, 0xfd, 0xce, 0x91,
			0x3a, 0x67, 0xda, 0x2b, 0xce, 0x71, 0xaf, 0xbc,
			0xf2, 0x75, 0xa5, 0xa8, 0xa2, 0xe2, 0x45, 0x12,
			0xab, 0x67, 0x3d, 0x4e, 0x1c, 0x42, 0xe1, 0x5d,
			0x6c, 0xb1, 0xd2, 0xb0, 0x16, 0xd5, 0x5c, 0xaf,
		},
	},
	{
		.data_len = 4160,
		.key_len = 127,
		.mac = {
			0x91, 0xe1, 0x89, 0x46, 0x28, 0x01, 0xe1, 0xd3,
			0x21, 0x12, 0xda, 0x6e, 0xe0, 0x17, 0x14, 0xd0,
			0x07, 0x5a, 0x9f, 0xca, 0xad, 0x6a, 0x6b, 0x89,
			0xf3, 0x6e, 0x21, 0x92, 0x52, 0x18, 0x21, 0x9d,
			0xc6, 0xe6, 0x5d, 0xca, 0xc3, 0x4d, 0xed, 0xe7,
			0xb9, 0x51, 0x51, 0x13, 0x12, 0xff, 0x73, 0x91,
		},
	},
	{
		.data_len = 4224,
		.key_len = 128,
		.mac = {
			0x15, 0x8f, 0xae, 0x57, 0xa2, 0x69, 0xe0, 0xb7,
			0x15, 0xb2, 0xd9, 0x33, 0xfd, 0x62, 0x5d, 0xc9,
			0x38, 0xad, 0xc0, 0xbc, 0x9c, 0xd4, 0x8f, 0xed,
			0x93, 0x2d, 0x66, 0x6b, 0x57, 0x26, 0xda, 0xdc,
			0x4b, 0x14, 0x00, 0x82, 0x0d, 0x1a, 0x27, 0x37,
			0xa6, 0x91, 0x61, 0x04, 0x20, 0xc9, 0x6b, 0x61,
		},
	},
	{
		.data_len = 16384,
		.key_len = 129,
		.mac = {
			0x65, 0x25, 0x4f, 0xfc, 0x9b, 0x4d, 0xe5, 0xd7,
			0x2c, 0xb7, 0xb1, 0x2f, 0xf9, 0xb7, 0x7b, 0x98,
			0x80, 0x45, 0x23, 0xdc, 0x0b, 0xd1, 0x76, 0xc1,
			0x81, 0xfd, 0x89, 0x08, 0x96, 0x9a, 0x35, 0xbd,
			0x0c, 0x7c, 0x0e, 0x26, 0xab, 0xa4, 0x03, 0x55,
			0x4d, 0x3a, 0xc0, 0x0a, 0x10, 0x45, 0x1a, 0x46,
		},
	},
};
