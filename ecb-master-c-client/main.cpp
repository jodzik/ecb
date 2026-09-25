#include <ecbm.h>

#include <sockpp/udp_socket.h>

#include "structopt.hpp"

#include <atomic>
#include <charconv>
#include <chrono>
#include <cstdint>
#include <cstdio>
#include <cstring>
#include <expected>
#include <format>
#include <iostream>
#include <optional>
#include <print>
#include <sstream>
#include <string>
#include <string_view>
#include <system_error>
#include <thread>
#include <utility>
#include <vector>

enum {
    APP__DEFAULT_PORT = 25001,
    APP__DEFAULT_ADDRESS = 1,
    IO_LOOP_PERIOD_US = 100,
    // Must be bigger than the slave side endpoint answer timeout, see ../README.md.
    REQUEST_TIMEOUT_MS = 200,
    REQUEST_RETRIES = 2,
    UDP_DATAGRAM_SIZE = FRAMER7B_FRAME_SIZE(ECBM__MAX_PAYLOAD_SIZE + ECBM__MIN_PACKET_SIZE),
    PAYLOAD_SIZE = ECBM__MAX_PAYLOAD_SIZE,
};

constexpr std::string_view APP__DEFAULT_HOST = "127.0.0.1";

struct Arguments {
    // Host of the slave server.
    std::optional<std::string> host = std::string(APP__DEFAULT_HOST);
    // UDP port of the slave server.
    std::optional<uint16_t> port = APP__DEFAULT_PORT;
    // Default target slave bus address, can be changed at runtime by the 'a' command.
    std::optional<uint16_t> address = APP__DEFAULT_ADDRESS;
};

STRUCTOPT(Arguments, host, port, address);

struct Ecbm g_ecbm;
sockpp::udp_socket* g_sock = nullptr;
uint8_t g_rx_datagram[UDP_DATAGRAM_SIZE] = {0};
uint16_t g_rx_pos = 0;
uint16_t g_rx_size = 0;
EcbmAddr g_addr = APP__DEFAULT_ADDRESS;
std::atomic<bool> g_run = true;

static void safe_c_print(char const* const str) {
    std::fputs(str, stdout);
}

static uint64_t get_time_ms_cb(void) {
    static std::chrono::steady_clock::time_point const start = std::chrono::steady_clock::now();
    return (uint64_t)std::chrono::duration_cast<std::chrono::milliseconds>(
        std::chrono::steady_clock::now() - start).count();
}

static void sleep_ms_cb(uint32_t const ms) {
    std::this_thread::sleep_for(std::chrono::milliseconds(ms));
}

// ecbm transport read: serve the current datagram, take a new one when it is exhausted.
// The socket is connected, so only the slave server datagrams are received.
static int read_cb(uint8_t* const buf, uint16_t const buf_size) {
    if (g_rx_pos >= g_rx_size) {
        sockpp::result<size_t> const res = g_sock->recv(g_rx_datagram, sizeof(g_rx_datagram));
        if (!res) {
            std::error_code const err = res.error();
            if ((std::errc::operation_would_block == err) || (std::errc::resource_unavailable_try_again == err)) {
                return 0;
            }
            std::cerr << "UDP receive failed: " << res.error_message() << std::endl;
            return ER_IO;
        }
        g_rx_size = (uint16_t)res.value();
        g_rx_pos = 0;
    }

    uint16_t const available = (uint16_t)(g_rx_size - g_rx_pos);
    uint16_t const n = (available < buf_size) ? available : buf_size;
    std::memcpy(buf, &g_rx_datagram[g_rx_pos], n);
    g_rx_pos = (uint16_t)(g_rx_pos + n);
    return n;
}

// ecbm transport write: the core sends each frame with a single write() call while the
// transport accepts it fully, so one UDP datagram carries exactly one ECB frame.
static int write_cb(uint8_t const* const data, uint16_t const ndata) {
    sockpp::result<size_t> const res = g_sock->send(data, ndata);
    if (!res || (res.value() != (size_t)ndata)) {
        std::cerr << "UDP send failed: " << res.error_message() << std::endl;
        return ER_IO;
    }
    return ndata;
}

static std::string to_hex_str(uint8_t const* const data, uint16_t const size) {
    std::string str = "[";
    for (uint16_t i = 0; i < size; i++) {
        str += std::format("{}{:02X}", (0 < i) ? " " : "", data[i]);
    }
    str += ']';
    return str;
}

// Printable ASCII bytes are kept, everything else incl. UTF-8 tails and NULL shows as '?'.
static std::string to_ascii_str(uint8_t const* const data, uint16_t const size) {
    std::string str;
    str.reserve(size);
    for (uint16_t i = 0; i < size; i++) {
        uint8_t const b = data[i];
        str += ((0x20 <= b) && (0x7E >= b)) ? (char)b : '?';
    }
    return str;
}

static void pub_handler_cb(EcbmAddr const addr, EcbmDataId const data_id, uint8_t const* const data,
    uint16_t const data_size, void* const) {
    std::println("PUB_DATA addr={} data_id={} size={}: {}", addr, data_id, data_size, to_hex_str(data, data_size));
}

static void rx_thread_fn(void) {
    while (g_run.load(std::memory_order_relaxed)) {
        (void)ecbm__poll(&g_ecbm);
        std::this_thread::sleep_for(std::chrono::microseconds(IO_LOOP_PERIOD_US));
    }
}

static char const* error_name(int const rc) {
    switch (rc) {
    case ER_INVAL: return "ER_INVAL";
    case ER_BUSY: return "ER_BUSY";
    case ER_IO: return "ER_IO";
    case ER_PROTO: return "ER_PROTO";
    case ER_ENT_TOO_BIG: return "ER_ENT_TOO_BIG";
    case ER_TIMEDOUT: return "ER_TIMEDOUT";
    case ER_PROTO_INTERNAL: return "ER_PROTO_INTERNAL";
    default: return nullptr;
    }
}

static void print_request_error(std::string_view const op, EcbmAddr const addr, EcbmDataId const data_id,
    int const rc, uint16_t const required_size) {
    if (0 < rc) {
        std::println("{} addr={} data_id={} failed: slave error code {}", op, addr, data_id, rc);
        return;
    }

    if (ER_ENT_TOO_BIG == rc) {
        std::println("{} addr={} data_id={} failed: answer too big, {} bytes required", op, addr, data_id,
            required_size);
        return;
    }

    char const* const name = error_name(rc);
    std::println("{} addr={} data_id={} failed: {}({})", op, addr, data_id, (nullptr != name) ? name : "error", rc);
}

// Parse an unsigned number with the given base, the whole token must be consumed.
static std::expected<uint16_t, std::string> parse_number(std::string_view const token, uint16_t const max,
    int const base) {
    uint16_t value = 0;
    auto const [ptr, ec] = std::from_chars(token.data(), token.data() + token.size(), value, base);
    if ((std::errc{} != ec) || (ptr != token.data() + token.size())) {
        return std::unexpected(std::format("invalid value '{}'", token));
    }
    if (value > max) {
        return std::unexpected(std::format("value '{}' is out of range (max {})", token, max));
    }
    return value;
}

// Parse the payload hex byte tokens(e.g. "01" "ff") starting at the start index.
static std::expected<uint16_t, std::string> parse_payload(std::vector<std::string> const& tokens, size_t const start,
    uint8_t* const buf) {
    if ((tokens.size() - start) > PAYLOAD_SIZE) {
        return std::unexpected(std::format("payload too big, max {} bytes", (int)PAYLOAD_SIZE));
    }

    uint16_t size = 0;
    for (size_t i = start; i < tokens.size(); i++) {
        auto const byte = parse_number(tokens[i], 0xFF, 16);
        if (!byte) {
            return std::unexpected(std::move(byte).error());
        }
        buf[size] = *byte;
        size = (uint16_t)(size + 1);
    }

    return size;
}

static std::vector<std::string> split_line(std::string const& line) {
    std::istringstream stream(line);
    std::vector<std::string> tokens;
    std::string token;
    while (stream >> token) {
        tokens.push_back(token);
    }
    return tokens;
}

static void print_help(void) {
    std::println("commands:");
    std::println("  h                        - this help");
    std::println("  q                        - quit");
    std::println("  a <addr>                 - set the target slave address(1..254, 255 for 'wn' broadcast)");
    std::println("  r <data_id>              - READ, prints the answer as a bin array and as a string");
    std::println("  w <data_id> [hex...]     - WRITE, e.g. 'w 65282' or 'w 65280 01'");
    std::println("  wn <data_id> [hex...]    - WRITE without answer, address 255 means broadcast");
}

static void cmd_set_addr(std::vector<std::string> const& tokens) {
    if (2 != tokens.size()) {
        std::println("usage: a <addr>");
        return;
    }

    auto const addr = parse_number(tokens[1], 0xFF, 10);
    if (!addr) {
        std::println("a: {}", std::move(addr).error());
        return;
    }

    g_addr = *addr;
    std::println("target address: {}", g_addr);
}

static void cmd_read(std::vector<std::string> const& tokens) {
    if (2 != tokens.size()) {
        std::println("usage: r <data_id>");
        return;
    }

    auto const data_id = parse_number(tokens[1], 0xFFFF, 10);
    if (!data_id) {
        std::println("r: {}", std::move(data_id).error());
        return;
    }

    if (ECBM__BROADCAST_ADDR == g_addr) {
        std::println("r: broadcast address cannot be used for READ");
        return;
    }

    uint8_t payload[PAYLOAD_SIZE] = {0};
    uint16_t size = 0;
    int const rc = ecbm__read(&g_ecbm, g_addr, *data_id, payload, sizeof(payload), &size, REQUEST_TIMEOUT_MS,
        REQUEST_RETRIES);
    if (0 != rc) {
        print_request_error("READ", g_addr, *data_id, rc, size);
        return;
    }

    std::println("READ addr={} data_id={} ok, {} bytes:", g_addr, *data_id, size);
    std::println("bin: {}", to_hex_str(payload, size));
    std::println("str: {}", to_ascii_str(payload, size));
}

static void cmd_write(bool const no_answer, std::vector<std::string> const& tokens) {
    if (2 > tokens.size()) {
        std::println("usage: {} <data_id> [hex...]", no_answer ? "wn" : "w");
        return;
    }

    auto const data_id = parse_number(tokens[1], 0xFFFF, 10);
    if (!data_id) {
        std::println("{}: {}", no_answer ? "wn" : "w", std::move(data_id).error());
        return;
    }

    uint8_t payload[PAYLOAD_SIZE] = {0};
    auto const payload_res = parse_payload(tokens, 2, payload);
    if (!payload_res) {
        std::println("{}: {}", no_answer ? "wn" : "w", std::move(payload_res).error());
        return;
    }

    std::string_view const op = no_answer ? "WRITE_NO_ANSW" : "WRITE";
    if (!no_answer && (ECBM__BROADCAST_ADDR == g_addr)) {
        std::println("{} addr={} data_id={} failed: broadcast address cannot be used for WRITE, use 'wn'",
            op, g_addr, *data_id);
        return;
    }

    int rc = 0;
    if (no_answer) {
        rc = ecbm__write_no_answer(&g_ecbm, g_addr, *data_id, payload, *payload_res);
        if (0 == rc) {
            std::println("{} addr={} data_id={} sent", op, g_addr, *data_id);
            return;
        }
    }
    else {
        rc = ecbm__write(&g_ecbm, g_addr, *data_id, payload, *payload_res, REQUEST_TIMEOUT_MS, REQUEST_RETRIES);
        if (0 == rc) {
            std::println("{} addr={} data_id={} ok", op, g_addr, *data_id);
            return;
        }
    }

    print_request_error(op, g_addr, *data_id, rc, 0);
}

static void repl(void) {
    std::string line;
    while (true) {
        std::print("> ");
        std::fflush(stdout);
        if (!std::getline(std::cin, line)) {
            std::println("");
            break;
        }

        std::vector<std::string> const tokens = split_line(line);
        if (tokens.empty()) {
            continue;
        }

        std::string const& cmd = tokens[0];
        if (("q" == cmd) || ("quit" == cmd)) {
            break;
        }
        if (("h" == cmd) || ("help" == cmd)) {
            print_help();
        }
        else if ("a" == cmd) {
            cmd_set_addr(tokens);
        }
        else if (("r" == cmd) || ("read" == cmd)) {
            cmd_read(tokens);
        }
        else if (("w" == cmd) || ("write" == cmd)) {
            cmd_write(false, tokens);
        }
        else if (("wn" == cmd) || ("wna" == cmd)) {
            cmd_write(true, tokens);
        }
        else {
            std::println("unknown command '{}', type 'h' for help", cmd);
        }
    }
}

int main(int argc, char** argv) {
    safe_c__init(safe_c_print);
    sockpp::socket_initializer::initialize();

    try {
        Arguments const opt = structopt::app("ecb-master-c-client", "1.0.0").parse<Arguments>(argc, argv);
        std::string const host = opt.host.value();
        uint16_t const port = opt.port.value();
        uint16_t const address = opt.address.value();
        if (0 == port) {
            throw std::runtime_error("Port cannot be zero.");
        }
        if (ECBM__BROADCAST_ADDR == address) {
            throw std::runtime_error("Broadcast address cannot be the default target.");
        }
        g_addr = (EcbmAddr)address;

        sockpp::udp_socket sock;
        g_sock = &sock;
        sockpp::result<> const non_blocking_res = sock.set_non_blocking(true);
        if (!non_blocking_res) {
            throw std::runtime_error("Fail to make the UDP socket non-blocking: " + non_blocking_res.error_message());
        }

        // Connect the UDP socket to the slave server, it also binds the ephemeral
        // source port for the answers.
        sockpp::result<> const connect_res = sock.connect(sockpp::inet_address(host, port));
        if (!connect_res) {
            throw std::runtime_error("Fail to connect the UDP socket to " + host + ":" + std::to_string(port)
                + ": " + connect_res.error_message());
        }

        int rc = ecbm__init(&g_ecbm, get_time_ms_cb, read_cb, write_cb, NULL, sleep_ms_cb, pub_handler_cb, NULL);
        if (0 != rc) {
            throw std::runtime_error("ecbm__init() failed: " + std::to_string(rc));
        }

        std::thread rx_thread(rx_thread_fn);

        std::println("ECB master client, slave {}:{}, target address {}, type 'h' for help.", host, port, g_addr);
        repl();

        g_run.store(false, std::memory_order_relaxed);
        rx_thread.join();
    } catch (std::exception const& e) {
        std::cerr << "Exception: " << e.what() << std::endl;
        return 1;
    }

    return 0;
}
