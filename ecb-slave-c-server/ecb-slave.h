#ifndef ECBS
#define ECBS

#ifdef __cplusplus
extern "C" {
#endif

#include "framer7b.h"

#include <stdint.h>
#include <stdlib.h>
#include <stdbool.h>


// Settings
enum {
    ECBS__MAX_SIG = 32,
    ECBS__ALLOW_SEND_STREAM_AFTER_RECV_MS = 10,
};

enum {
    ECBS__ENC_FILLER = 0x5A,

    ECBS__PD_TYPE_MASK = 0b1111,
    ECBS__PD_DIR_MASK = 0b10000,
    ECBS__PD_DIR_IS_REQ = ECBS__PD_DIR_MASK,
    ECBS__PD_DIR_IS_ANSW = 0x00,
    ECBS__PD_IS_ENC_MASK = 0b100000,
    ECBS__PD_TYPE_WRITE = 0b0000,
    ECBS__PD_TYPE_WRITE_NO_ANSW = 0b0010,
    ECBS__PD_TYPE_READ = 0b0001,
    ECBS__PD_TYPE_STREAM_OPEN = 0b0011,
    ECBS__PD_TYPE_STREAM_CLOSE = 0b0100,
    ECBS__PD_TYPE_STREAM_DATA = 0b0101,
    ECBS__PD_TYPE_ENC_OPEN = 0b0110,
    ECBS__PD_TYPE_WRITE_AUTH_REQ = 0b0111,
    ECBS__PD_TYPE_WRITE_WITH_AUTH = 0b1000,
    ECBS__PD_TYPE_ERR = 0b1111,

    ECBS__BROADCAST_ADDR = 0x00,
    ECBS__MIN_PACKET_SIZE = 9,
    ECBS__MAX_DATA_SIZE = FRAMER7B__DATA_SIZE - ECBS__MIN_PACKET_SIZE,
};

enum {
    ECBS_SIG__RESET = 0,
    ECBS_SIG__INFO = 1,
    ECBS_SIG__AUTH_KEY = 14,
    ECBS_SIG__PICK = 15,
    
    ECBS_SIG_BOOT__BEGIN = 16,
    ECBS_SIG_BOOT__END = 17,
    ECBS_SIG_BOOT__CHECKSUM = 18,
    ECBS_SIG_BOOT__FW_KEY = 19,
    ECBS_SIG_BOOT__WRITE = 20,
    ECBS_SIG_BOOT__APP_INFO = 22,
    ECBS_SIG_BOOT__GO_APP = 23,
};

typedef enum EcbsErr {
    ECBS_ERR__APP = 0x01,
    ECBS_ERR__NO_SIG = 0x02,
    ECBS_ERR__NO_OPERATION = 0x03,
    ECBS_ERR__ENC_REQUIRED = 0x04,
    ECBS_ERR__AUTH_REQUIRED = 0x05,
    ECBS_ERR__NO_ENC_SESSION = 0x06,
    ECBS_ERR__INTERNAL = 0x07,
    ECBS_ERR__INCORRECT_SIGN = 0x08,
    ECBS_ERR__ENC_NOT_SUPPORTED = 0x08,
} EcbsErr;

typedef enum EcbsState {
    ECBS_STATE__RECEIVE,
    ECBS_STATE__SEND
} EcbsState;

typedef enum EcbsProtectLevel {
    ECBS_PROTECT_LEVEL__NO,
    ECBS_PROTECT_LEVEL__ENC,
    ECBS_PROTECT_LEVEL__ENC_AND_WRITE_AUTH,
} EcbsProtectLevel;

typedef struct EcbsSig {
    int sig;
    enum EcbsProtectLevel protect_level;
    uint8_t stream_pub_period_ms;
    uint32_t tl_stream_pub_ms;
    bool is_stream_allowed;
    int (*read)(uint16_t sig, uint8_t* buf);
    int (*write)(uint16_t sig, const uint8_t* data, uint16_t ndata);
} EcbsSig;

typedef struct Ecbs {
    Framer7b framer;
    uint8_t addr;
    uint8_t auth_key[16];
    bool is_enc_init;
    uint8_t session_key[16];
    bool is_enc_session;
    EcbsState state;
    uint16_t ptr;
    uint16_t nsend;
    EcbsSig sig[ECBS__MAX_SIG];
    uint16_t err_description_size;
    uint8_t write_auth_rand_key[sizeof(uint64_t)];
    int stream_sig;
    uint32_t tl_read;
    bool is_buffer_sending;

    bool (*read)(uint8_t* byte);
    bool (*write)(uint8_t data);
    uint32_t (*get_rand)(void);
    uint32_t (*get_time_ms)(void);
    bool (*write_buf)(uint8_t const* data, uint16_t ndata);
    bool (*get_write_state)(void);
} Ecbs;

void ecbs__init(
    struct Ecbs* ecbs,
    uint8_t addr,
    uint32_t (*get_time_ms)(void),
    bool (*read)(uint8_t* byte),
    bool (*write)(uint8_t data));

void ecbs__init_enc(struct Ecbs* ecbs, const uint8_t auth_key[16], uint32_t (*get_rand)(void));

void ecbs__init_write_buf(
    struct Ecbs* ecbs,
    bool (*write_buf)(uint8_t const* data, uint16_t ndata),
    bool (*get_write_state)(void));

void ecbs__drop_enc_session(struct Ecbs* ecbs);

int ecbs__add_sig(
    struct Ecbs* ecbs,
    uint16_t sig,
    enum EcbsProtectLevel protect_level,
    int (*read)(uint16_t sig, uint8_t* buf),
    int (*write)(uint16_t sig, const uint8_t* data, uint16_t ndata));

int ecbs__allow_stream_at_sig(struct Ecbs* ecbs, uint16_t sig, uint8_t stream_pub_period_ms);
int ecbs__flush_stream_at_sig(struct Ecbs* ecbs, uint16_t sig);

void ecbs__add_err_description(struct Ecbs* ecbs, char const* const fmt, ...);

void ecbs__loop(struct Ecbs* ecbs);

#ifdef __cplusplus
}
#endif

#endif
