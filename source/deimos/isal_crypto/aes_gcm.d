/**********************************************************************
  Copyright(c) 2011-2016 Intel Corporation All rights reserved.

  Redistribution and use in source and binary forms, with or without
  modification, are permitted provided that the following conditions
  are met:
    * Redistributions of source code must retain the above copyright
      notice, this list of conditions and the following disclaimer.
    * Redistributions in binary form must reproduce the above copyright
      notice, this list of conditions and the following disclaimer in
      the documentation and/or other materials provided with the
      distribution.
    * Neither the name of Intel Corporation nor the names of its
      contributors may be used to endorse or promote products derived
      from this software without specific prior written permission.

  THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
  "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
  LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR
  A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT
  OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
  SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT
  LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
  DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
  THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
  (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
  OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
**********************************************************************/

/**
 *  @file aes_gcm.h
 *  @brief AES GCM encryption/decryption function prototypes.
 *
 * At build time there is an option to use non-temporal loads and stores
 * selected by defining the compile time option NT_LDST. The use of this option
 * places the following restriction on the gcm encryption functions:
 *
 * - The plaintext and cyphertext buffers must be aligned on a 16 byte boundary.
 *
 * - When using the streaming API, all partial input buffers must be a multiple
 *   of 16 bytes long except for the last input buffer.
 *
 * - In-place encryption/decryption is not recommended.
 *
 */

/*
; References:
;       This code was derived and highly optimized from the code described in paper:
;               Vinodh Gopal et. al. Optimized Galois-Counter-Mode Implementation on Intel Architecture Processors. August, 2010
;
;       For the shift-based reductions used in this code, we used the method described in paper:
;               Shay Gueron, Michael E. Kounavis. Intel Carry-Less Multiplication Instruction and its Usage for Computing the GCM Mode. January, 2010.
;
;
;
; Assumptions: Support for SSE4.1 or greater, AVX or AVX2
;
;
; iv:
;       0                   1                   2                   3
;       0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
;       +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
;       |                             Salt  (From the SA)               |
;       +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
;       |                     Initialization Vector                     |
;       |         (This is the sequence number from IPSec header)       |
;       +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
;       |                              0x1                              |
;       +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
;
; TLen:
;       from the definition of the spec, TLen can only be 8, 12 or 16 bytes.
;
 */

module deimos.isal_crypto.aes_gcm;

nothrow @nogc:

extern (C):

/* Authenticated Tag Length in bytes. Valid values are 16 (most likely), 12 or 8. */
enum MAX_TAG_LEN = 16;
//
// IV data is limited to 16 bytes. The last DWORD (4 bytes) must be 0x1
//
enum GCM_IV_LEN = 16;
enum GCM_IV_DATA_LEN = 12;
enum GCM_IV_END_START = 12;

enum LONGEST_TESTED_AAD_LENGTH = 2 * 1024;

// Key lengths of 128 and 256 supported
enum GCM_128_KEY_LEN = 16;
enum GCM_256_KEY_LEN = 32;

enum GCM_BLOCK_LEN = 16;
enum GCM_ENC_KEY_LEN = 16;
enum GCM_KEY_SETS = 15; /*exp key + 14 exp round keys*/

/**
 * @brief holds intermediate key data needed to improve performance
 *
 * gcm_data hold internal key information used by gcm128 and gcm256.
 */
struct gcm_data
{
    ubyte[GCM_ENC_KEY_LEN * GCM_KEY_SETS] expanded_keys;
    ubyte[GCM_ENC_KEY_LEN] shifted_hkey_1; // store HashKey <<1 mod poly here
    ubyte[GCM_ENC_KEY_LEN] shifted_hkey_2; // store HashKey^2 <<1 mod poly here
    ubyte[GCM_ENC_KEY_LEN] shifted_hkey_3; // store HashKey^3 <<1 mod poly here
    ubyte[GCM_ENC_KEY_LEN] shifted_hkey_4; // store HashKey^4 <<1 mod poly here
    ubyte[GCM_ENC_KEY_LEN] shifted_hkey_5; // store HashKey^5 <<1 mod poly here
    ubyte[GCM_ENC_KEY_LEN] shifted_hkey_6; // store HashKey^6 <<1 mod poly here
    ubyte[GCM_ENC_KEY_LEN] shifted_hkey_7; // store HashKey^7 <<1 mod poly here
    ubyte[GCM_ENC_KEY_LEN] shifted_hkey_8; // store HashKey^8 <<1 mod poly here
    ubyte[GCM_ENC_KEY_LEN] shifted_hkey_1_k; // store XOR of High 64 bits and Low 64 bits of  HashKey <<1 mod poly here (for Karatsuba purposes)
    ubyte[GCM_ENC_KEY_LEN] shifted_hkey_2_k; // store XOR of High 64 bits and Low 64 bits of  HashKey^2 <<1 mod poly here (for Karatsuba purposes)
    ubyte[GCM_ENC_KEY_LEN] shifted_hkey_3_k; // store XOR of High 64 bits and Low 64 bits of  HashKey^3 <<1 mod poly here (for Karatsuba purposes)
    ubyte[GCM_ENC_KEY_LEN] shifted_hkey_4_k; // store XOR of High 64 bits and Low 64 bits of  HashKey^4 <<1 mod poly here (for Karatsuba purposes)
    ubyte[GCM_ENC_KEY_LEN] shifted_hkey_5_k; // store XOR of High 64 bits and Low 64 bits of  HashKey^5 <<1 mod poly here (for Karatsuba purposes)
    ubyte[GCM_ENC_KEY_LEN] shifted_hkey_6_k; // store XOR of High 64 bits and Low 64 bits of  HashKey^6 <<1 mod poly here (for Karatsuba purposes)
    ubyte[GCM_ENC_KEY_LEN] shifted_hkey_7_k; // store XOR of High 64 bits and Low 64 bits of  HashKey^7 <<1 mod poly here (for Karatsuba purposes)
    ubyte[GCM_ENC_KEY_LEN] shifted_hkey_8_k; // store XOR of High 64 bits and Low 64 bits of  HashKey^8 <<1 mod poly here (for Karatsuba purposes)
    // init, update and finalize context data
    ubyte[GCM_BLOCK_LEN] aad_hash;
    ulong aad_length;
    ulong in_length;
    ubyte[GCM_BLOCK_LEN] partial_block_enc_key;
    ubyte[GCM_BLOCK_LEN] orig_IV;
    ubyte[GCM_BLOCK_LEN] current_counter;
    ulong partial_block_length;
}

/**
 * @brief holds intermediate key data needed to improve performance
 *
 * gcm_key_data hold internal key information used by gcm128, gcm192 and gcm256.
 */

align(16) struct gcm_key_data
{
    ubyte[GCM_ENC_KEY_LEN * GCM_KEY_SETS] expanded_keys;
    ubyte[GCM_ENC_KEY_LEN] shifted_hkey_1; // store HashKey <<1 mod poly here
    ubyte[GCM_ENC_KEY_LEN] shifted_hkey_2; // store HashKey^2 <<1 mod poly here
    ubyte[GCM_ENC_KEY_LEN] shifted_hkey_3; // store HashKey^3 <<1 mod poly here
    ubyte[GCM_ENC_KEY_LEN] shifted_hkey_4; // store HashKey^4 <<1 mod poly here
    ubyte[GCM_ENC_KEY_LEN] shifted_hkey_5; // store HashKey^5 <<1 mod poly here
    ubyte[GCM_ENC_KEY_LEN] shifted_hkey_6; // store HashKey^6 <<1 mod poly here
    ubyte[GCM_ENC_KEY_LEN] shifted_hkey_7; // store HashKey^7 <<1 mod poly here
    ubyte[GCM_ENC_KEY_LEN] shifted_hkey_8; // store HashKey^8 <<1 mod poly here
    ubyte[GCM_ENC_KEY_LEN] shifted_hkey_1_k; // store XOR of High 64 bits and Low 64 bits of  HashKey <<1 mod poly here (for Karatsuba purposes)
    ubyte[GCM_ENC_KEY_LEN] shifted_hkey_2_k; // store XOR of High 64 bits and Low 64 bits of  HashKey^2 <<1 mod poly here (for Karatsuba purposes)
    ubyte[GCM_ENC_KEY_LEN] shifted_hkey_3_k; // store XOR of High 64 bits and Low 64 bits of  HashKey^3 <<1 mod poly here (for Karatsuba purposes)
    ubyte[GCM_ENC_KEY_LEN] shifted_hkey_4_k; // store XOR of High 64 bits and Low 64 bits of  HashKey^4 <<1 mod poly here (for Karatsuba purposes)
    ubyte[GCM_ENC_KEY_LEN] shifted_hkey_5_k; // store XOR of High 64 bits and Low 64 bits of  HashKey^5 <<1 mod poly here (for Karatsuba purposes)
    ubyte[GCM_ENC_KEY_LEN] shifted_hkey_6_k; // store XOR of High 64 bits and Low 64 bits of  HashKey^6 <<1 mod poly here (for Karatsuba purposes)
    ubyte[GCM_ENC_KEY_LEN] shifted_hkey_7_k; // store XOR of High 64 bits and Low 64 bits of  HashKey^7 <<1 mod poly here (for Karatsuba purposes)
    ubyte[GCM_ENC_KEY_LEN] shifted_hkey_8_k; // store XOR of High 64 bits and Low 64 bits of  HashKey^8 <<1 mod poly here (for Karatsuba purposes)
    ubyte[GCM_ENC_KEY_LEN * (48-16)] shifted_hkey_n_k; // Note, this assumes ISA-L built without GCM_BIG_DATA (use 128 instead of 48 for GCM_BIG_DATA)
}

/**
 * @brief holds GCM operation context
 */
struct gcm_context_data
{
    // init, update and finalize context data
    ubyte[GCM_BLOCK_LEN] aad_hash;
    ulong aad_length;
    ulong in_length;
    ubyte[GCM_BLOCK_LEN] partial_block_enc_key;
    ubyte[GCM_BLOCK_LEN] orig_IV;
    ubyte[GCM_BLOCK_LEN] current_counter;
    ulong partial_block_length;
}

/* ------------------ New interface for separate expanded keys ------------ */

/**
 * @brief GCM-AES Encryption using 128 bit keys
 *
 * @requires SSE4.1 and AESNI
 */

//!< GCM expanded key data
//!< GCM operation context data
//!< Ciphertext output. Encrypt in-place is allowed
//!< Plaintext input
//!< Length of data in Bytes for encryption
//!< iv pointer to 12 byte IV structure.
//!< Internally, library concates 0x00000001 value to it.
//!< Additional Authentication Data (AAD)
//!< Length of AAD
//!< Authenticated Tag output
//!< Authenticated Tag Length in bytes (must be a multiple of 4 bytes).
//!< Valid values are 16 (most likely), 12 or 8
void aes_gcm_enc_128 (
    const(gcm_key_data)* key_data,
    gcm_context_data* context_data,
    ubyte* out_,
    const(ubyte)* in_,
    ulong len,
    ubyte* iv,
    const(ubyte)* aad,
    ulong aad_len,
    ubyte* auth_tag,
    ulong auth_tag_len);

/**
 * @brief GCM-AES Encryption using 256 bit keys
 *
 * @requires SSE4.1 and AESNI
 */

//!< GCM expanded key data
//!< GCM operation context data
//!< Ciphertext output. Encrypt in-place is allowed
//!< Plaintext input
//!< Length of data in Bytes for encryption
//!< iv pointer to 12 byte IV structure.
//!< Internally, library concates 0x00000001 value to it.
//!< Additional Authentication Data (AAD)
//!< Length of AAD
//!< Authenticated Tag output
//!< Authenticated Tag Length in bytes (must be a multiple of 4 bytes).
//!< Valid values are 16 (most likely), 12 or 8
void aes_gcm_enc_256 (
    const(gcm_key_data)* key_data,
    gcm_context_data* context_data,
    ubyte* out_,
    const(ubyte)* in_,
    ulong len,
    ubyte* iv,
    const(ubyte)* aad,
    ulong aad_len,
    ubyte* auth_tag,
    ulong auth_tag_len);

/**
 * @brief GCM-AES Decryption using 128 bit keys
 *
 * @requires SSE4.1 and AESNI
 */

//!< GCM expanded key data
//!< GCM operation context data
//!< Plaintext output. Decrypt in-place is allowed
//!< Ciphertext input
//!< Length of data in Bytes for decryption
//!< iv pointer to 12 byte IV structure.
//!< Internally, library concates 0x00000001 value to it.
//!< Additional Authentication Data (AAD)
//!< Length of AAD
//!< Authenticated Tag output
//!< Authenticated Tag Length in bytes (must be a multiple of 4 bytes).
//!< Valid values are 16 (most likely), 12 or 8
void aes_gcm_dec_128 (
    const(gcm_key_data)* key_data,
    gcm_context_data* context_data,
    ubyte* out_,
    const(ubyte)* in_,
    ulong len,
    ubyte* iv,
    const(ubyte)* aad,
    ulong aad_len,
    ubyte* auth_tag,
    ulong auth_tag_len);

/**
 * @brief GCM-AES Decryption using 128 bit keys
 *
 * @requires SSE4.1 and AESNI
 */

//!< GCM expanded key data
//!< GCM operation context data
//!< Plaintext output. Decrypt in-place is allowed
//!< Ciphertext input
//!< Length of data in Bytes for decryption
//!< iv pointer to 12 byte IV structure.
//!< Internally, library concates 0x00000001 value to it.
//!< Additional Authentication Data (AAD)
//!< Length of AAD
//!< Authenticated Tag output
//!< Authenticated Tag Length in bytes (must be a multiple of 4 bytes).
//!< Valid values are 16 (most likely), 12 or 8
void aes_gcm_dec_256 (
    const(gcm_key_data)* key_data,
    gcm_context_data* context_data,
    ubyte* out_,
    const(ubyte)* in_,
    ulong len,
    ubyte* iv,
    const(ubyte)* aad,
    ulong aad_len,
    ubyte* auth_tag,
    ulong auth_tag_len);

/**
 * @brief Start a AES-GCM Encryption message 128 bit key
 *
 * @requires SSE4.1 and AESNI
 */

//!< GCM expanded key data
//!< GCM operation context data
//!< Pointer to 12 byte IV structure
//!< Internally, library concates 0x00000001 value to it
//!< Additional Authentication Data (AAD)
//!< Length of AAD
void aes_gcm_init_128 (
    const(gcm_key_data)* key_data,
    gcm_context_data* context_data,
    ubyte* iv,
    const(ubyte)* aad,
    ulong aad_len);

/**
 * @brief Start a AES-GCM Encryption message 256 bit key
 *
 * @requires SSE4.1 and AESNI
 */

//!< GCM expanded key data
//!< GCM operation context data
//!< Pointer to 12 byte IV structure
//!< Internally, library concates 0x00000001 value to it
//!< Additional Authentication Data (AAD)
//!< Length of AAD
void aes_gcm_init_256 (
    const(gcm_key_data)* key_data,
    gcm_context_data* context_data,
    ubyte* iv,
    const(ubyte)* aad,
    ulong aad_len);

/**
 * @brief Encrypt a block of a AES-128-GCM Encryption message
 *
 * @requires SSE4.1 and AESNI
 */

//!< GCM expanded key data
//!< GCM operation context data
//!< Ciphertext output. Encrypt in-place is allowed.
//!< Plaintext input
//!< Length of data in Bytes for encryption
void aes_gcm_enc_128_update (
    const(gcm_key_data)* key_data,
    gcm_context_data* context_data,
    ubyte* out_,
    const(ubyte)* in_,
    ulong len);

/**
 * @brief Encrypt a block of a AES-256-GCM Encryption message
 *
 * @requires SSE4.1 and AESNI
 */

//!< GCM expanded key data
//!< GCM operation context data
//!< Ciphertext output. Encrypt in-place is allowed.
//!< Plaintext input
//!< Length of data in Bytes for encryption
void aes_gcm_enc_256_update (
    const(gcm_key_data)* key_data,
    gcm_context_data* context_data,
    ubyte* out_,
    const(ubyte)* in_,
    ulong len);

/**
 * @brief Decrypt a block of a AES-128-GCM Encryption message
 *
 * @requires SSE4.1 and AESNI
 */

//!< GCM expanded key data
//!< GCM operation context data
//!< Plaintext output. Decrypt in-place is allowed.
//!< Ciphertext input
//!< Length of data in Bytes for decryption
void aes_gcm_dec_128_update (
    const(gcm_key_data)* key_data,
    gcm_context_data* context_data,
    ubyte* out_,
    const(ubyte)* in_,
    ulong len);

/**
 * @brief Decrypt a block of a AES-256-GCM Encryption message
 *
 * @requires SSE4.1 and AESNI
 */

//!< GCM expanded key data
//!< GCM operation context data
//!< Plaintext output. Decrypt in-place is allowed.
//!< Ciphertext input
//!< Length of data in Bytes for decryption
void aes_gcm_dec_256_update (
    const(gcm_key_data)* key_data,
    gcm_context_data* context_data,
    ubyte* out_,
    const(ubyte)* in_,
    ulong len);

/**
 * @brief End encryption of a AES-128-GCM Encryption message
 *
 * @requires SSE4.1 and AESNI
 */

//!< GCM expanded key data
//!< GCM operation context data
//!< Authenticated Tag output
//!< Authenticated Tag Length in bytes (must be a multiple of 4 bytes).
//!< Valid values are 16 (most likely), 12 or 8
void aes_gcm_enc_128_finalize (
    const(gcm_key_data)* key_data,
    gcm_context_data* context_data,
    ubyte* auth_tag,
    ulong auth_tag_len);

/**
 * @brief End encryption of a AES-256-GCM Encryption message
 *
 * @requires SSE4.1 and AESNI
 */

//!< GCM expanded key data
//!< GCM operation context data
//!< Authenticated Tag output
//!< Authenticated Tag Length in bytes (must be a multiple of 4 bytes).
//!< Valid values are 16 (most likely), 12 or 8
void aes_gcm_enc_256_finalize (
    const(gcm_key_data)* key_data,
    gcm_context_data* context_data,
    ubyte* auth_tag,
    ulong auth_tag_len);

/**
 * @brief End decryption of a AES-128-GCM Encryption message
 *
 * @requires SSE4.1 and AESNI
 */

//!< GCM expanded key data
//!< GCM operation context data
//!< Authenticated Tag output
//!< Authenticated Tag Length in bytes (must be a multiple of 4 bytes).
//!< Valid values are 16 (most likely), 12 or 8
void aes_gcm_dec_128_finalize (
    const(gcm_key_data)* key_data,
    gcm_context_data* context_data,
    ubyte* auth_tag,
    ulong auth_tag_len);

/**
 * @brief End decryption of a AES-256-GCM Encryption message
 *
 * @requires SSE4.1 and AESNI
 */

//!< GCM expanded key data
//!< GCM operation context data
//!< Authenticated Tag output
//!< Authenticated Tag Length in bytes (must be a multiple of 4 bytes).
//!< Valid values are 16 (most likely), 12 or 8
void aes_gcm_dec_256_finalize (
    const(gcm_key_data)* key_data,
    gcm_context_data* context_data,
    ubyte* auth_tag,
    ulong auth_tag_len);

/**
 * @brief Pre-processes GCM key data 128 bit
 *
 * Prefills the gcm key data with key values for each round and
 * the initial sub hash key for tag encoding
 *
 * @requires SSE4.1 and AESNI
 */

//!< Pointer to key data
//!< GCM expanded key data
void aes_gcm_pre_128 (const(void)* key, gcm_key_data* key_data);

/**
 * @brief Pre-processes GCM key data 128 bit
 *
 * Prefills the gcm key data with key values for each round and
 * the initial sub hash key for tag encoding
 *
 * @requires SSE4.1 and AESNI
 */

//!< Pointer to key data
//!< GCM expanded key data
void aes_gcm_pre_256 (const(void)* key, gcm_key_data* key_data);

/* ---- NT versions ---- */
/**
 * @brief GCM-AES Encryption using 128 bit keys, Non-temporal data
 *
 * Non-temporal version of encrypt has additional restrictions:
 * - The plaintext and cyphertext buffers must be aligned on a 16 byte boundary.
 * - In-place encryption/decryption is not recommended. Performance can be slow.
 *
 * @requires SSE4.1 and AESNI
 */

//!< GCM expanded key data
//!< GCM operation context data
//!< Ciphertext output. Encrypt in-place is allowed
//!< Plaintext input
//!< Length of data in Bytes for encryption
//!< iv pointer to 12 byte IV structure.
//!< Internally, library concates 0x00000001 value to it.
//!< Additional Authentication Data (AAD)
//!< Length of AAD
//!< Authenticated Tag output
//!< Authenticated Tag Length in bytes (must be a multiple of 4 bytes).
//!< Valid values are 16 (most likely), 12 or 8
void aes_gcm_enc_128_nt (
    const(gcm_key_data)* key_data,
    gcm_context_data* context_data,
    ubyte* out_,
    const(ubyte)* in_,
    ulong len,
    ubyte* iv,
    const(ubyte)* aad,
    ulong aad_len,
    ubyte* auth_tag,
    ulong auth_tag_len);

/**
 * @brief GCM-AES Encryption using 256 bit keys, Non-temporal data
 *
 * Non-temporal version of encrypt has additional restrictions:
 * - The plaintext and cyphertext buffers must be aligned on a 16 byte boundary.
 * - In-place encryption/decryption is not recommended. Performance can be slow.
 *
 * @requires SSE4.1 and AESNI
 */

//!< GCM expanded key data
//!< GCM operation context data
//!< Ciphertext output. Encrypt in-place is allowed
//!< Plaintext input
//!< Length of data in Bytes for encryption
//!< iv pointer to 12 byte IV structure.
//!< Internally, library concates 0x00000001 value to it.
//!< Additional Authentication Data (AAD)
//!< Length of AAD
//!< Authenticated Tag output
//!< Authenticated Tag Length in bytes (must be a multiple of 4 bytes).
//!< Valid values are 16 (most likely), 12 or 8
void aes_gcm_enc_256_nt (
    const(gcm_key_data)* key_data,
    gcm_context_data* context_data,
    ubyte* out_,
    const(ubyte)* in_,
    ulong len,
    ubyte* iv,
    const(ubyte)* aad,
    ulong aad_len,
    ubyte* auth_tag,
    ulong auth_tag_len);

/**
 * @brief GCM-AES Decryption using 128 bit keys, Non-temporal data
 *
 * Non-temporal version of decrypt has additional restrictions:
 * - The plaintext and cyphertext buffers must be aligned on a 16 byte boundary.
 * - In-place encryption/decryption is not recommended. Performance can be slow.
 *
 * @requires SSE4.1 and AESNI
 */

//!< GCM expanded key data
//!< GCM operation context data
//!< Plaintext output. Decrypt in-place is allowed
//!< Ciphertext input
//!< Length of data in Bytes for decryption
//!< iv pointer to 12 byte IV structure.
//!< Internally, library concates 0x00000001 value to it.
//!< Additional Authentication Data (AAD)
//!< Length of AAD
//!< Authenticated Tag output
//!< Authenticated Tag Length in bytes (must be a multiple of 4 bytes).
//!< Valid values are 16 (most likely), 12 or 8
void aes_gcm_dec_128_nt (
    const(gcm_key_data)* key_data,
    gcm_context_data* context_data,
    ubyte* out_,
    const(ubyte)* in_,
    ulong len,
    ubyte* iv,
    const(ubyte)* aad,
    ulong aad_len,
    ubyte* auth_tag,
    ulong auth_tag_len);

/**
 * @brief GCM-AES Decryption using 128 bit keys, Non-temporal data
 *
 * Non-temporal version of decrypt has additional restrictions:
 * - The plaintext and cyphertext buffers must be aligned on a 16 byte boundary.
 * - In-place encryption/decryption is not recommended. Performance can be slow.
 *
 * @requires SSE4.1 and AESNI
 */

//!< GCM expanded key data
//!< GCM operation context data
//!< Plaintext output. Decrypt in-place is allowed
//!< Ciphertext input
//!< Length of data in Bytes for decryption
//!< iv pointer to 12 byte IV structure.
//!< Internally, library concates 0x00000001 value to it.
//!< Additional Authentication Data (AAD)
//!< Length of AAD
//!< Authenticated Tag output
//!< Authenticated Tag Length in bytes (must be a multiple of 4 bytes).
//!< Valid values are 16 (most likely), 12 or 8
void aes_gcm_dec_256_nt (
    const(gcm_key_data)* key_data,
    gcm_context_data* context_data,
    ubyte* out_,
    const(ubyte)* in_,
    ulong len,
    ubyte* iv,
    const(ubyte)* aad,
    ulong aad_len,
    ubyte* auth_tag,
    ulong auth_tag_len);

/**
 * @brief Encrypt a block of a AES-128-GCM Encryption message, Non-temporal data
 *
 * Non-temporal version of encrypt update has additional restrictions:
 * - The plaintext and cyphertext buffers must be aligned on a 16 byte boundary.
 * - All partial input buffers must be a multiple of 16 bytes long except for
 *   the last input buffer.
 * - In-place encryption/decryption is not recommended. Performance can be slow.
 *
 * @requires SSE4.1 and AESNI
 */

//!< GCM expanded key data
//!< GCM operation context data
//!< Ciphertext output. Encrypt in-place is allowed.
//!< Plaintext input
//!< Length of data in Bytes for encryption
void aes_gcm_enc_128_update_nt (
    const(gcm_key_data)* key_data,
    gcm_context_data* context_data,
    ubyte* out_,
    const(ubyte)* in_,
    ulong len);

/**
 * @brief Encrypt a block of a AES-256-GCM Encryption message, Non-temporal data
 *
 * Non-temporal version of encrypt update has additional restrictions:
 * - The plaintext and cyphertext buffers must be aligned on a 16 byte boundary.
 * - All partial input buffers must be a multiple of 16 bytes long except for
 *   the last input buffer.
 * - In-place encryption/decryption is not recommended. Performance can be slow.
 *
 * @requires SSE4.1 and AESNI
 */

//!< GCM expanded key data
//!< GCM operation context data
//!< Ciphertext output. Encrypt in-place is allowed.
//!< Plaintext input
//!< Length of data in Bytes for encryption
void aes_gcm_enc_256_update_nt (
    const(gcm_key_data)* key_data,
    gcm_context_data* context_data,
    ubyte* out_,
    const(ubyte)* in_,
    ulong len);

/**
 * @brief Decrypt a block of a AES-128-GCM Encryption message, Non-temporal data
 *
 * Non-temporal version of decrypt update has additional restrictions:
 * - The plaintext and cyphertext buffers must be aligned on a 16 byte boundary.
 * - All partial input buffers must be a multiple of 16 bytes long except for
 *   the last input buffer.
 * - In-place encryption/decryption is not recommended. Performance can be slow.
 *
 * @requires SSE4.1 and AESNI
 */

//!< GCM expanded key data
//!< GCM operation context data
//!< Plaintext output. Decrypt in-place is allowed.
//!< Ciphertext input
//!< Length of data in Bytes for decryption
void aes_gcm_dec_128_update_nt (
    const(gcm_key_data)* key_data,
    gcm_context_data* context_data,
    ubyte* out_,
    const(ubyte)* in_,
    ulong len);

/**
 * @brief Decrypt a block of a AES-256-GCM Encryption message, Non-temporal data
 *
 * Non-temporal version of decrypt update has additional restrictions:
 * - The plaintext and cyphertext buffers must be aligned on a 16 byte boundary.
 * - All partial input buffers must be a multiple of 16 bytes long except for
 *   the last input buffer.
 * - In-place encryption/decryption is not recommended. Performance can be slow.
 *
 * @requires SSE4.1 and AESNI
 */

//!< GCM expanded key data
//!< GCM operation context data
//!< Plaintext output. Decrypt in-place is allowed.
//!< Ciphertext input
//!< Length of data in Bytes for decryption
void aes_gcm_dec_256_update_nt (
    const(gcm_key_data)* key_data,
    gcm_context_data* context_data,
    ubyte* out_,
    const(ubyte)* in_,
    ulong len);

/* ------------------ Old interface for backward compatability ------------ */

/**
 * @brief GCM-AES Encryption using 128 bit keys - older interface
 *
 * @requires SSE4.1 and AESNI
 *
 */
//!< GCM context
//!< Ciphertext output. Encrypt in-place is allowed.
//!< Plaintext input
//!< Length of data in Bytes for encryption.
//!< Pre-counter block j0: 4 byte salt (from Security Association) concatenated with 8 byte Initialization Vector (from IPSec ESP Payload) concatenated with 0x00000001. 16-byte pointer.
//!< Additional Authentication Data (AAD).
//!< Length of AAD.
//!< Authenticated Tag output.
//!< Authenticated Tag Length in bytes (must be a multiple of 4 bytes). Valid values are 16 (most likely), 12 or 8.
void aesni_gcm128_enc (
    gcm_data* my_ctx_data,
    ubyte* out_,
    const(ubyte)* in_,
    ulong plaintext_len,
    ubyte* iv,
    const(ubyte)* aad,
    ulong aad_len,
    ubyte* auth_tag,
    ulong auth_tag_len);

/**
 * @brief GCM-AES Decryption  using 128 bit keys - older interface
 *
 * @requires SSE4.1 and AESNI
 *
 */
//!< GCM context
//!< Plaintext output. Decrypt in-place is allowed.
//!< Ciphertext input
//!< Length of data in Bytes for encryption.
//!< Pre-counter block j0: 4 byte salt (from Security Association) concatenated with 8 byte Initialisation Vector (from IPSec ESP Payload) concatenated with 0x00000001. 16-byte pointer.
//!< Additional Authentication Data (AAD).
//!< Length of AAD.
//!< Authenticated Tag output.
//!< Authenticated Tag Length in bytes (must be a multiple of 4 bytes). Valid values are 16 (most likely), 12 or 8.
void aesni_gcm128_dec (
    gcm_data* my_ctx_data,
    ubyte* out_,
    const(ubyte)* in_,
    ulong plaintext_len,
    ubyte* iv,
    const(ubyte)* aad,
    ulong aad_len,
    ubyte* auth_tag,
    ulong auth_tag_len);

/**
 * @brief start a AES-128-GCM Encryption message - older interface
 *
 * @requires SSE4.1 and AESNI
 *
 */
//!< GCM context
//!< Pre-counter block j0: 4 byte salt (from Security Association) concatenated with 8 byte Initialization Vector (from IPSec ESP Payload) concatenated with 0x00000001. 16-byte pointer.
//!< Additional Authentication Data (AAD).
//!< Length of AAD.
void aesni_gcm128_init (
    gcm_data* my_ctx_data,
    ubyte* iv,
    const(ubyte)* aad,
    ulong aad_len);

/**
 * @brief encrypt a block of a AES-128-GCM Encryption message - older interface
 *
 * @requires SSE4.1 and AESNI
 *
 */
//!< GCM context
//!< Ciphertext output. Encrypt in-place is allowed.
//!< Plaintext input
//!< Length of data in Bytes for encryption.
void aesni_gcm128_enc_update (
    gcm_data* my_ctx_data,
    ubyte* out_,
    const(ubyte)* in_,
    ulong plaintext_len);

/**
 * @brief decrypt a block of a AES-128-GCM Encryption message - older interface
 *
 * @requires SSE4.1 and AESNI
 *
 */
//!< GCM context
//!< Ciphertext output. Encrypt in-place is allowed.
//!< Plaintext input
//!< Length of data in Bytes for encryption.
void aesni_gcm128_dec_update (
    gcm_data* my_ctx_data,
    ubyte* out_,
    const(ubyte)* in_,
    ulong plaintext_len);

/**
 * @brief End encryption of a AES-128-GCM Encryption message - older interface
 *
 * @requires SSE4.1 and AESNI
 *
 */
//!< GCM context
//!< Authenticated Tag output.
//!< Authenticated Tag Length in bytes. Valid values are 16 (most likely), 12 or 8.
void aesni_gcm128_enc_finalize (
    gcm_data* my_ctx_data,
    ubyte* auth_tag,
    ulong auth_tag_len);

/**
 * @brief End decryption of a AES-128-GCM Encryption message - older interface
 *
 * @requires SSE4.1 and AESNI
 *
 */
//!< GCM context
//!< Authenticated Tag output.
//!< Authenticated Tag Length in bytes. Valid values are 16 (most likely), 12 or 8.
void aesni_gcm128_dec_finalize (
    gcm_data* my_ctx_data,
    ubyte* auth_tag,
    ulong auth_tag_len);

/**
 * @brief pre-processes key data - older interface
 *
 * Prefills the gcm data with key values for each round and the initial sub hash key for tag encoding
 */
void aesni_gcm128_pre (ubyte* key, gcm_data* gdata);

/**
 * @brief GCM-AES Encryption using 256 bit keys
 *
 * @requires SSE4.1 and AESNI
 *
 */
//!< GCM context
//!< Ciphertext output. Encrypt in-place is allowed.
//!< Plaintext input
//!< Length of data in Bytes for encryption.
//!< Pre-counter block j0: 4 byte salt (from Security Association) concatenated with 8 byte Initialization Vector (from IPSec ESP Payload) concatenated with 0x00000001. 16-byte pointer.
//!< Additional Authentication Data (AAD).
//!< Length of AAD.
//!< Authenticated Tag output.
//!< Authenticated Tag Length in bytes (must be a multiple of 4 bytes). Valid values are 16 (most likely), 12 or 8.
void aesni_gcm256_enc (
    gcm_data* my_ctx_data,
    ubyte* out_,
    const(ubyte)* in_,
    ulong plaintext_len,
    ubyte* iv,
    const(ubyte)* aad,
    ulong aad_len,
    ubyte* auth_tag,
    ulong auth_tag_len);

/**
 * @brief GCM-AES Decryption using 256 bit keys - older interface
 *
 * @requires SSE4.1 and AESNI
 *
 */
//!< GCM context
//!< Plaintext output. Decrypt in-place is allowed.
//!< Ciphertext input
//!< Length of data in Bytes for encryption.
//!< Pre-counter block j0: 4 byte salt (from Security Association) concatenated with 8 byte Initialisation Vector (from IPSec ESP Payload) concatenated with 0x00000001. 16-byte pointer.
//!< Additional Authentication Data (AAD).
//!< Length of AAD.
//!< Authenticated Tag output.
//!< Authenticated Tag Length in bytes (must be a multiple of 4 bytes). Valid values are 16 (most likely), 12 or 8.
void aesni_gcm256_dec (
    gcm_data* my_ctx_data,
    ubyte* out_,
    const(ubyte)* in_,
    ulong plaintext_len,
    ubyte* iv,
    const(ubyte)* aad,
    ulong aad_len,
    ubyte* auth_tag,
    ulong auth_tag_len);

/**
 * @brief start a AES-256-GCM Encryption message - older interface
 *
 * @requires SSE4.1 and AESNI
 *
 */
//!< GCM context
//!< Pre-counter block j0: 4 byte salt (from Security Association) concatenated with 8 byte Initialization Vector (from IPSec ESP Payload) concatenated with 0x00000001. 16-byte pointer.
//!< Additional Authentication Data (AAD).
//!< Length of AAD.
void aesni_gcm256_init (
    gcm_data* my_ctx_data,
    ubyte* iv,
    const(ubyte)* aad,
    ulong aad_len);

/**
 * @brief encrypt a block of a AES-256-GCM Encryption message - older interface
 *
 * @requires SSE4.1 and AESNI
 *
 */
//!< GCM context
//!< Ciphertext output. Encrypt in-place is allowed.
//!< Plaintext input
//!< Length of data in Bytes for encryption.
void aesni_gcm256_enc_update (
    gcm_data* my_ctx_data,
    ubyte* out_,
    const(ubyte)* in_,
    ulong plaintext_len);

/**
 * @brief decrypt a block of a AES-256-GCM Encryption message - older interface
 *
 * @requires SSE4.1 and AESNI
 *
 */
//!< GCM context
//!< Ciphertext output. Encrypt in-place is allowed.
//!< Plaintext input
//!< Length of data in Bytes for encryption.
void aesni_gcm256_dec_update (
    gcm_data* my_ctx_data,
    ubyte* out_,
    const(ubyte)* in_,
    ulong plaintext_len);

/**
 * @brief End encryption of a AES-256-GCM Encryption message - older interface
 *
 * @requires SSE4.1 and AESNI
 *
 */
//!< GCM context
//!< Authenticated Tag output.
//!< Authenticated Tag Length in bytes. Valid values are 16 (most likely), 12 or 8.
void aesni_gcm256_enc_finalize (
    gcm_data* my_ctx_data,
    ubyte* auth_tag,
    ulong auth_tag_len);

/**
 * @brief End decryption of a AES-256-GCM Encryption message - older interface
 *
 * @requires SSE4.1 and AESNI
 *
 */
//!< GCM context
//!< Authenticated Tag output.
//!< Authenticated Tag Length in bytes. Valid values are 16 (most likely), 12 or 8.
void aesni_gcm256_dec_finalize (
    gcm_data* my_ctx_data,
    ubyte* auth_tag,
    ulong auth_tag_len);

/**
 * @brief pre-processes key data - older interface
 *
 * Prefills the gcm data with key values for each round and the initial sub hash key for tag encoding
 */
void aesni_gcm256_pre (ubyte* key, gcm_data* gdata);

//__cplusplus
//ifndef _AES_GCM_h
