#include <ecbs_applvl.h>

#include <sockpp/udp_socket.h>

#include "structopt.hpp"

#include <cerrno>
#include <chrono>
#include <cstdint>
#include <cstdio>
#include <cstring>
#include <iostream>
#include <optional>
#include <stdexcept>
#include <string>
#include <thread>

enum {
    APP__DEFAULT_PORT = 25001,
    APP__DEFAULT_ADDRESS = 1,
    IO_LOOP_PERIOD_US = 100,
    // Must be slightly less than the master side timeout, see ../README.md.
    EP_ANSWER_TIMEOUT_MS = 100,

    // TLV record: [type:u8][length:u8][value].
    TLV_HEADER_SIZE = 2,
    DEVICE_INFO_PAYLOAD_SIZE = TLV_HEADER_SIZE + ECBS_DEVICE_INFO__NAME_SIZE
        + TLV_HEADER_SIZE + ECBS_DEVICE_INFO__FW_VERSION_SIZE
        + TLV_HEADER_SIZE + ECBS_DEVICE_INFO__SERIAL_SIZE,

    UDP_DATAGRAM_SIZE = FRAMER7B_FRAME_SIZE(ECBS__MAX_PAYLOAD_SIZE + ECBS__MIN_PACKET_SIZE),
};

// DEVICE_INFO(65281) answer content, see ../servers_info.md and ../README.md.
constexpr char DEVICE_INFO_NAME[] = "ecb-slave-c-server";
constexpr uint8_t DEVICE_INFO_FW_VERSION[ECBS_DEVICE_INFO__FW_VERSION_SIZE] = {1, 0, 0};
constexpr char DEVICE_INFO_SERIAL[] = "0000001";

static_assert(sizeof(DEVICE_INFO_NAME) <= ECBS_DEVICE_INFO__NAME_SIZE, "DEVICE_INFO_NAME is too big");
static_assert(sizeof(DEVICE_INFO_SERIAL) <= ECBS_DEVICE_INFO__SERIAL_SIZE, "DEVICE_INFO_SERIAL is too big");
static_assert((int)DEVICE_INFO_PAYLOAD_SIZE <= (int)ECBS__MAX_PAYLOAD_SIZE, "DEVICE_INFO payload is too big");

struct Arguments {
    // UDP port to listen on.
    std::optional<uint16_t> port = APP__DEFAULT_PORT;
    // Slave bus address.
    std::optional<uint16_t> address = APP__DEFAULT_ADDRESS;
};

STRUCTOPT(Arguments, port, address);

struct Ecbs g_ecbs;
sockpp::udp_socket* g_sock = nullptr;
sockpp::inet_address g_peer;
uint8_t g_rx_datagram[UDP_DATAGRAM_SIZE] = {0};
uint16_t g_rx_pos = 0;
uint16_t g_rx_size = 0;

static void safe_c_print(char const* const str) {
    std::fputs(str, stdout);
}

static uint64_t get_time_ms_cb(void) {
    static std::chrono::steady_clock::time_point const start = std::chrono::steady_clock::now();
    return (uint64_t)std::chrono::duration_cast<std::chrono::milliseconds>(
        std::chrono::steady_clock::now() - start).count();
}

// ecbs transport read: serve the current datagram, take a new one when it is exhausted.
static int read_cb(uint8_t* const buf, uint16_t const buf_size) {
    if (g_rx_pos >= g_rx_size) {
        sockpp::inet_address peer;
        ssize_t const n = g_sock->recv_from(g_rx_datagram, sizeof(g_rx_datagram), &peer);
        if (0 > n) {
            int const err = g_sock->last_error();
            if ((EWOULDBLOCK == err) || (EAGAIN == err)) {
                return 0;
            }
            std::cerr << "UDP receive failed: " << g_sock->last_error_str() << std::endl;
            return ER_IO;
        }
        g_peer = peer;
        g_rx_size = (uint16_t)n;
        g_rx_pos = 0;
    }

    uint16_t const available = (uint16_t)(g_rx_size - g_rx_pos);
    uint16_t const n = (available < buf_size) ? available : buf_size;
    std::memcpy(buf, &g_rx_datagram[g_rx_pos], n);
    g_rx_pos = (uint16_t)(g_rx_pos + n);
    return n;
}

// ecbs transport write: the core sends each frame with a single write() call while the
// transport accepts it fully, so one UDP datagram carries exactly one ECB frame.
static int write_cb(uint8_t const* const data, uint16_t const ndata) {
    ssize_t const n = g_sock->send_to(data, ndata, g_peer);
    if (n != (ssize_t)ndata) {
        std::cerr << "UDP send failed: " << g_sock->last_error_str() << std::endl;
        return ER_IO;
    }
    return ndata;
}

static uint8_t* tlv_put_bytes(uint8_t* const pos, uint8_t const type, uint8_t const* const data, uint8_t const size) {
    pos[0] = type;
    pos[1] = size;
    std::memcpy(&pos[TLV_HEADER_SIZE], data, size);
    return &pos[TLV_HEADER_SIZE + size];
}

static uint8_t* tlv_put_string(uint8_t* const pos, uint8_t const type, char const* const str) {
    // Strings are UTF-8 with the terminating NULL included in the size, see ../README.md.
    return tlv_put_bytes(pos, type, reinterpret_cast<uint8_t const*>(str), (uint8_t)(std::strlen(str) + 1));
}

// DEVICE_INFO(65281): READ answer with NAME(1), FW_VERSION(2) and SERIAL(3) TLV records.
static int device_info_read_cb(EcbsDataId const, EcbsRequestToken const token, void* const) {
    uint8_t payload[DEVICE_INFO_PAYLOAD_SIZE] = {0};
    uint8_t* pos = payload;
    pos = tlv_put_string(pos, ECBS_DEVICE_INFO_TLV__NAME, DEVICE_INFO_NAME);
    pos = tlv_put_bytes(pos, ECBS_DEVICE_INFO_TLV__FW_VERSION, DEVICE_INFO_FW_VERSION,
        ECBS_DEVICE_INFO__FW_VERSION_SIZE);
    pos = tlv_put_string(pos, ECBS_DEVICE_INFO_TLV__SERIAL, DEVICE_INFO_SERIAL);
    return ecbs__send_read_answer(&g_ecbs, token, payload, (uint16_t)(pos - payload));
}

// PICK(65282): connectivity check, answer any WRITE, stay silent for WRITE_NO_ANSW.
static int pick_write_cb(EcbsDataId const, EcbsRequestToken const token, bool const is_answer_needed,
    uint8_t const* const, uint16_t const, void* const) {
    if (is_answer_needed) {
        return ecbs__send_write_answer(&g_ecbs, token);
    }

    return 0;
}

int main(int argc, char** argv) {
    safe_c__init(safe_c_print);
    sockpp::socket_initializer::initialize();

    try {
        Arguments const opt = structopt::app("ecb-slave-c-server", "1.0.0").parse<Arguments>(argc, argv);
        uint16_t const port = opt.port.value();
        uint16_t const address = opt.address.value();
        if (0 == port) {
            throw std::runtime_error("Port cannot be zero.");
        }
        if (ECBS__BROADCAST_ADDR == address) {
            throw std::runtime_error("Broadcast address cannot be used as the slave address.");
        }

        sockpp::udp_socket sock;
        g_sock = &sock;
        if (!sock.bind(sockpp::inet_address(port))) {
            throw std::runtime_error("Fail to bind UDP port " + std::to_string(port) + ": " + sock.last_error_str());
        }
        if (!sock.set_non_blocking(true)) {
            throw std::runtime_error("Fail to set the UDP socket non-blocking: " + sock.last_error_str());
        }

        int rc = ecbs__init(&g_ecbs, (EcbsAddr)address, get_time_ms_cb, read_cb, write_cb, NULL);
        if (0 != rc) {
            throw std::runtime_error("ecbs__init() failed: " + std::to_string(rc));
        }

        rc = ecbs__register_endpoint(&g_ecbs, ECBS_STD_DATA_ID__INFO, EP_ANSWER_TIMEOUT_MS, NULL,
            device_info_read_cb, NULL);
        if (0 != rc) {
            throw std::runtime_error("ecbs__register_endpoint(DEVICE_INFO) failed: " + std::to_string(rc));
        }

        rc = ecbs__register_endpoint(&g_ecbs, ECBS_STD_DATA_ID__PICK, EP_ANSWER_TIMEOUT_MS, NULL, NULL,
            pick_write_cb);
        if (0 != rc) {
            throw std::runtime_error("ecbs__register_endpoint(PICK) failed: " + std::to_string(rc));
        }

        std::cout << "ECB slave " << address << " on UDP port " << port << ", endpoints: DEVICE_INFO("
            << ECBS_STD_DATA_ID__INFO << "), PICK(" << ECBS_STD_DATA_ID__PICK << ")" << std::endl;

        while (true) {
            std::this_thread::sleep_for(std::chrono::microseconds(IO_LOOP_PERIOD_US));
            ecbs__process(&g_ecbs);
        }
    } catch (std::exception const& e) {
        std::cerr << "Exception: " << e.what() << std::endl;
        return 1;
    }

    return 0;
}
