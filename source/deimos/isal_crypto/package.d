module deimos.isal_crypto;

extern (C):

enum ISAL_CRYPTO_MAJOR_VERSION = 2;
enum ISAL_CRYPTO_MINOR_VERSION = 21;
enum ISAL_CRYPTO_PATCH_VERSION = 0;

extern (D) auto ISAL_CRYPTO_MAKE_VERSION(T0, T1, T2)(auto ref T0 maj, auto ref T1 min, auto ref T2 patch)
{
    return maj * 0x10000 + min * 0x100 + patch;
}

enum ISAL_CRYPTO_VERSION = ISAL_CRYPTO_MAKE_VERSION(ISAL_CRYPTO_MAJOR_VERSION, ISAL_CRYPTO_MINOR_VERSION, ISAL_CRYPTO_PATCH_VERSION);

public import deimos.isal_crypto.aes_cbc;
public import deimos.isal_crypto.aes_gcm;
public import deimos.isal_crypto.aes_keyexp;
public import deimos.isal_crypto.aes_xts;
public import deimos.isal_crypto.md5_mb;
public import deimos.isal_crypto.mh_sha1;
public import deimos.isal_crypto.mh_sha1_murmur3_x64_128;
public import deimos.isal_crypto.mh_sha256;
public import deimos.isal_crypto.multi_buffer;
public import deimos.isal_crypto.rolling_hashx;
public import deimos.isal_crypto.sha1_mb;
public import deimos.isal_crypto.sha256_mb;
public import deimos.isal_crypto.sha512_mb;

//_ISAL_CRYPTO_H_
