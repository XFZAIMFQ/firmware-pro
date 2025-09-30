#ifndef _SE_THD89_H_
#define _SE_THD89_H_

#include "bip32.h"
#include "secbool.h"
#include "thd89.h"

#define SESSION_KEYLEN          (16) // 会话密钥长度

#define PUBLIC_REGION_SIZE      (0x800) // 2KB
#define PRIVATE_REGION_SIZE     (0x800) // 2KB

#define MAX_AUTHORIZATION_LEN   128 // 最大授权长度

#define PIN_MAX_LENGTH          (50) // 最大PIN长度
#define PASSPHRASE_MAX_LENGTH   (50) // 最大口令长度

#define SESSION_TYPE_NORMAL     0 // 普通会话
#define SESSION_TYPE_PASSPHRASE 1 // 口令会话

typedef enum
{
    PIN_SUCCESS,                      // 成功
    USER_PIN_ENTERED,                 // 用户PIN已输入
    USER_PIN_FAILED,                  // 用户PIN失败
    PASSPHRASE_PIN_ENTERED,           // 口令PIN已输入
    PASSPHRASE_PIN_NO_MATCHED,        // 口令PIN不匹配
    USER_PIN_NOT_ENTERED,             // 用户PIN未输入
    WIPE_CODE_ENTERED,                // 擦除代码已输入
    PIN_SAME_AS_USER_PIN,             // 与用户PIN相同
    PIN_SAME_AS_WIPE_CODE,            // 与擦除代码相同
    PIN_PASSPHRASE_MAX_ITEMS_REACHED, // 
    PIN_PASSPHRASE_SAVE_FAILED,       // 密钥保存失败
    PIN_PASSPHRASE_READ_FAILED,       // 密钥读取失败
    PIN_FAILED                        // 失败
} pin_result_t;

typedef enum
{
    PIN_TYPE_USER,                          // 用户PIN
    PIN_TYPE_USER_CHECK,                    // 用户PIN检查
    PIN_TYPE_USER_AND_PASSPHRASE_PIN,       // 用户和口令PIN
    PIN_TYPE_PASSPHRASE_PIN,                // 口令PIN
    PIN_TYPE_PASSPHRASE_PIN_CHECK,          // 口令PIN检查
    PIN_TYPE_USER_AND_PASSPHRASE_PIN_CHECK, // 用户和口令PIN检查
    PIN_TYPE_MAX                            // 最大PIN次数
} pin_type_t;

#define FIDO2_RESIDENT_CREDENTIALS_SIZE       (512)
#define FIDO2_RESIDENT_CREDENTIALS_COUNT      (60)
#define FIDO2_RESIDENT_CREDENTIALS_FLAGS      "\x66\x69\x64\x6F" // "fido"
#define FIDO2_RESIDENT_CREDENTIALS_HEADER_LEN (6)
typedef struct
{
    uint8_t credential_id_flag[4];
    uint16_t credential_length;
    uint8_t rp_id_hash[32];
    uint8_t credential_id[474];
} __attribute__((packed)) CTAP_credential_id_storage;
_Static_assert(
    sizeof(CTAP_credential_id_storage) == FIDO2_RESIDENT_CREDENTIALS_SIZE,
    "CTAP_credential_id_storage size must be flash page size"
);

typedef secbool (*UI_WAIT_CALLBACK)(uint32_t wait, uint32_t progress, const char* message);
void se_set_ui_callback(UI_WAIT_CALLBACK callback);

secbool se_transmit_mac(
    uint8_t ins,
    uint8_t p1,
    uint8_t p2,
    uint8_t* data,
    uint16_t data_len,
    uint8_t* recv,
    uint16_t* recv_len
);

secbool se_get_rand(uint8_t* rand, uint16_t rand_len);    // 获取随机数
secbool se_reset_se(void);                                // 重置
secbool se_random_encrypted(uint8_t* rand, uint16_t len); // 获取加密随机数
secbool se_random_encrypted_ex(uint8_t addr, uint8_t* session_key, uint8_t* rand, uint16_t len); // 获取加密随机数
secbool se_sync_session_key(void);                                                               // 同步会话密钥
secbool se_device_init(uint8_t mode, const char* passphrase);                                    // 设备初始化
secbool se_ecdsa_get_pubkey(uint32_t* address, uint8_t count, uint8_t* pubkey);                  // 获取公钥

secbool se_reset_storage(void);                                          // 重置存储
secbool se_set_sn(const char* serial, uint8_t len);                      // 设置序列号
secbool se_get_sn(char** serial);                                        // 获取序列号
int se_get_version(uint8_t addr, char* ver, uint16_t in_len);            // 获取版本
int se_get_build_id(uint8_t addr, char* build_id, uint16_t in_len);      // 获取构建ID
int se_get_hash(uint8_t addr, uint8_t* hash, uint16_t in_len);           // 获取哈希
int se_get_boot_version(uint8_t addr, char* ver, uint16_t in_len);       // 获取引导版本
int se_get_boot_build_id(uint8_t addr, char* build_id, uint16_t in_len); // 获取引导构建ID
int se_get_boot_hash(uint8_t addr, uint8_t* hash, uint16_t in_len);      // 获取引导哈希
char* se01_get_version(void);                                            // se01获取版本
char* se01_get_build_id(void);                                           // se01获取构建ID
uint8_t* se01_get_hash(void);                                            // se01获取哈希
char* se01_get_boot_version(void);                                       // se01获取引导版本
char* se01_get_boot_build_id(void);                                      // se01获取引导构建ID
uint8_t* se01_get_boot_hash(void);                                       // se01获取引导哈希
char* se02_get_version(void);                                            // se02获取版本
char* se02_get_build_id(void);                                           // se02获取构建ID
uint8_t* se02_get_hash(void);                                            // se02获取哈希
char* se02_get_boot_version(void);                                       // se02获取引导版本
char* se02_get_boot_build_id(void);                                      // se02获取引导构建ID
uint8_t* se02_get_boot_hash(void);                                       // se02获取引导哈希
char* se03_get_version(void);                                            // se03获取版本
char* se03_get_build_id(void);                                           // se03获取构建ID
uint8_t* se03_get_hash(void);                                            // se03获取哈希
char* se03_get_boot_version(void);                                       // se03获取引导版本
char* se03_get_boot_build_id(void);                                      // se03获取引导构建ID
uint8_t* se03_get_boot_hash(void);                                       // se03获取引导哈希
char* se04_get_version(void);                                            // se04获取版本
char* se04_get_build_id(void);                                           // se04获取构建ID
uint8_t* se04_get_hash(void);                                            // se04获取哈希
char* se04_get_boot_version(void);                                       // se04获取引导版本
char* se04_get_boot_build_id(void);                                      // se04获取引导构建ID
uint8_t* se04_get_boot_hash(void);                                       // se04获取引导哈希
secbool se_isInitialized(void);                                          // 是否初始化
secbool se_hasPin(void);                                                 // 是否有PIN
secbool se_setPin(const char* pin);                                      // 设置PIN
secbool se_verifyPin(const char* pin, pin_type_t pin_type);              // 验证PIN
secbool se_changePin(const char* oldpin, const char* newpin);            // 更改PIN
uint32_t se_pinFailedCounter(void);                                      // PIN失败计数
secbool se_getRetryTimes(uint8_t* ptimes);                               // 获取重试次数
pin_result_t se_get_pin_result_type(void);                               // 获取PIN结果类型
secbool se_set_pin_passphrase(
    const char* pin,
    const char* passphrase_pin,
    const char* passphrase,
    bool* override
);                                                                           // 设置PIN口令
secbool se_delete_pin_passphrase(const char* passphrase_pin, bool* current); // 删除PIN口令
pin_result_t se_get_pin_passphrase_ret(void);                                // 获取PIN口令结果
secbool se_get_pin_passphrase_space(uint8_t* space);                         // 获取PIN口令空间
secbool se_check_passphrase_btc_test_address(const char* address);           // 检查口令BTC测试地址
secbool se_change_pin_passphrase(const char* old_pin, const char* new_pin);  // 更改PIN口令
secbool se_clearSecsta(void);                                                // 清除安全状态
secbool se_getSecsta(void);                                                  // 获取安全状态
secbool se_set_u2f_counter(uint32_t u2fcounter);                             // 设置U2F计数器
secbool se_get_u2f_counter(uint32_t* u2fcounter);                            // 获取U2F计数器
secbool se_set_mnemonic(const char* mnemonic, uint16_t len);                 // 设置助记词
secbool se_import_slip39(
    const uint8_t* master_secret,
    uint8_t len,
    uint8_t backup_type,
    uint16_t identifier,
    uint8_t iteration_exponent
);                                                  // 导入slip39
secbool se_sessionStart(uint8_t* session_id_bytes); // 开始会话
secbool se_sessionOpen(uint8_t* session_id_bytes);  // 打开会话

secbool se_get_session_seed_state(uint8_t* state); // 获取会话种子状态
secbool se_session_is_open(void);                  // 会话是否打开

secbool se_sessionClose(void);                     // 关闭会话
secbool se_sessionClear(void);                     // 清除会话
secbool se_session_get_type(uint8_t* type);        // 获取会话类型
secbool se_session_get_current_id(uint8_t id[32]); // 获取当前会话ID

secbool se_set_public_region(uint16_t offset, const void* val_dest, uint16_t len);  // 设置公有区
secbool se_get_public_region(uint16_t offset, void* val_dest, uint16_t len);        // 获取公有区
secbool se_set_private_region(uint16_t offset, const void* val_dest, uint16_t len); // 设置私有区
secbool se_get_private_region(uint16_t offset, void* val_dest, uint16_t len);       // 获取私有区

secbool se_get_pubkey(uint8_t* pubkey);                                                     // 获取公钥
secbool se_get_ecdh_pubkey(uint8_t addr, uint8_t* key);                                     // 获取ecdh公钥
secbool se_lock_ecdh_pubkey(uint8_t addr);                                                  // 锁定ecdh公钥
secbool se_write_certificate(const uint8_t* cert, uint16_t cert_len);                       // 写入证书
secbool se_read_certificate(uint8_t* cert, uint16_t* cert_len);                             // 读取证书
secbool se_has_cerrificate(void);                                                           // 是否有证书
secbool se_sign_message(uint8_t* msg, uint32_t msg_len, uint8_t* signature);                // 签名消息
secbool se_sign_message_with_write_key(uint8_t* msg, uint32_t msg_len, uint8_t* signature); // 使用写入的密钥签名消息
secbool se_set_private_key_extern(uint8_t key[32]);                                         // 设置外部私钥
secbool se_set_session_key_ex(uint8_t addr, const uint8_t* session_key);                    // 设置会话密钥
secbool se_set_session_key(const uint8_t* session_key);                                     // 设置会话密钥

secbool se_containsMnemonic(const char* mnemonic);                 // 是否包含助记词
secbool se_exportMnemonic(char* mnemonic, uint16_t dest_size);     // 导出助记词
secbool se_set_needs_backup(bool needs_backup);                    // 设置是否需要备份
secbool se_get_needs_backup(bool* needs_backup);                   // 获取是否需要备份
secbool se_hasWipeCode(void);                                      // 是否有清除码
secbool se_changeWipeCode(const char* pin, const char* wipe_code); // 更改清除码

uint8_t* se_session_startSession(const uint8_t* received_session_id); // 开始会话
secbool se_gen_session_seed(const char* passphrase, bool cardano);    // 生成会话种子
secbool se_derive_keys(
    HDNode* out,
    const char* curve,
    const uint32_t* address_n,
    size_t address_n_count,
    uint32_t* fingerprint
); // 派生密钥
secbool se_derive_xmr_key(
    const char* curve,
    const uint32_t* address_n,
    size_t address_n_count,
    uint8_t* pubkey,
    uint8_t* prikey_hash
);                                                                                               // 派生XMR密钥
secbool se_derive_xmr_private_key(const uint8_t* pubkey, const uint32_t index, uint8_t* prikey); // 派生XMR私钥
secbool se_xmr_get_tx_key(const uint8_t* rand, const uint8_t* hash, uint8_t* out); // 获取XMR交易密钥
secbool se_node_sign_digest(const uint8_t* hash, uint8_t* sig, uint8_t* by);       // 节点签名摘要
int se_ecdsa_sign_digest(
    const uint8_t curve,
    const uint8_t canonical,
    const uint8_t* digest,
    uint8_t* sig,
    uint8_t* pby
); // ECDSA签名摘要

int se_secp256k1_sign_digest(
    const uint8_t canonical,
    const uint8_t* digest,
    uint8_t* sig,
    uint8_t* pby
);                                                                               // secp256k1签名摘要
int se_nist256p1_sign_digest(const uint8_t* digest, uint8_t* sig, uint8_t* pby); // nist256p1签名摘要

int se_ed25519_sign(const uint8_t* msg, uint16_t msg_len, uint8_t* sig);        // ed25519签名
int se_ed25519_sign_ext(const uint8_t* msg, uint16_t msg_len, uint8_t* sig);    // ed25519签名扩展
int se_ed25519_sign_keccak(const uint8_t* msg, uint16_t msg_len, uint8_t* sig); // ed25519签名keccak

int se_get_shared_key(const char* curve, const uint8_t* peer_public_key, uint8_t* session_key); // 获取共享密钥

secbool se_derive_tweak_private_keys(const uint8_t* root_hash);         // 派生调整私钥
int se_bip340_sign_digest(const uint8_t* digest, uint8_t sig[64]);      // bip340签名摘要
int se_bch_schnorr_sign_digest(const uint8_t* digest, uint8_t sig[64]); // bch schnorr签名摘要

int se_aes256_encrypt(
    const uint8_t* data,
    uint16_t data_len,
    const uint8_t* iv,
    uint8_t* value,
    uint16_t value_len,
    uint8_t* out
); // AES256加密
int se_aes256_decrypt(
    const uint8_t* data,
    uint16_t data_len,
    const uint8_t* iv,
    uint8_t* value,
    uint16_t value_len,
    uint8_t* out
); // AES256解密

int se_nem_aes256_encrypt(
    const uint8_t* ed25519_public_key,
    const uint8_t* iv,
    const uint8_t* salt,
    uint8_t* payload,
    uint16_t size,
    uint8_t* out
); // NEM AES256加密
int se_nem_aes256_decrypt(
    const uint8_t* ed25519_public_key,
    const uint8_t* iv,
    const uint8_t* salt,
    uint8_t* payload,
    uint16_t size,
    uint8_t* out
);                                      // NEM AES256解密
int se_slip21_node(uint8_t* data);      // slip21节点
int se_slip21_fido_node(uint8_t* data); // slip21 fido节点

secbool se_authorization_set(
    const uint32_t authorization_type,
    const uint8_t* authorization,
    uint32_t authorization_len
);                                                                                           // 设置授权
secbool se_authorization_get_type(uint32_t* authorization_type);                             // 获取授权类型
secbool se_authorization_get_data(uint8_t* authorization_data, uint32_t* authorization_len); // 获取授权数据
void se_authorization_clear(void);                                                           // 清除授权

secbool se_fingerprint_state(void);  // 指纹状态
secbool se_fingerprint_lock(void);   // 锁定指纹
secbool se_fingerprint_unlock(void); // 解锁指纹

secbool se_fp_write(uint32_t offset, const void* val_dest, uint32_t len, uint8_t index, uint8_t total); // 写入分段数据
secbool se_fp_read(uint32_t offset, void* val_dest, uint32_t len, uint8_t index, uint8_t total); // 读取分段数据

int se_lite_card_ecdh(const uint8_t* publickey, uint8_t* sessionkey); // lite卡ecdh

secbool se_gen_fido_seed(uint8_t* percent); // 生成fido种子
secbool se_u2f_register(
    const uint8_t app_id[32],
    const uint8_t challenge[32],
    uint8_t key_handle[64],
    uint8_t pub_key[65],
    uint8_t sign[64]
);                                                                                                 // U2F注册
secbool se_u2f_gen_handle_and_node(const uint8_t app_id[32], uint8_t key_handle[64], HDNode* out); // U2F生成句柄和节点
secbool se_u2f_validate_handle(const uint8_t app_id[32], const uint8_t key_handle[64]);            // U2F验证句柄
secbool se_u2f_authenticate(
    const uint8_t app_id[32],
    const uint8_t key_handle[64],
    const uint8_t challenge[32],
    uint8_t* u2f_counter,
    uint8_t sign[64]
); // U2F认证
secbool se_derive_fido_keys(
    HDNode* out,
    const char* curve,
    const uint32_t* address_n,
    size_t address_n_count,
    uint32_t* fingerprint
);                                                                     // 派生FIDO密钥
secbool se_fido_hdnode_sign_digest(const uint8_t* hash, uint8_t* sig); // FIDO HD节点签名摘要
secbool se_fido_att_sign_digest(const uint8_t* hash, uint8_t* sig);    // FIDO att签名摘要
secbool se_get_fido2_resident_credentials(uint32_t index, uint8_t* dest, uint16_t* dst_len); // 获取FIDO2常驻凭据
secbool se_set_fido2_resident_credentials(uint32_t index, const uint8_t* src, uint16_t len); // 设置FIDO2常驻凭据
secbool se_delete_fido2_resident_credentials(uint32_t index);                                // 删除FIDO2常驻凭据
secbool se_delete_all_fido2_credentials(void);                                               // 删除所有FIDO2凭据

secbool session_generate_seed_percent(uint8_t* percent); // 会话生成种子百分比
#endif
