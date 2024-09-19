#include "ecb-slave.h"

#include "serial/serial.h"
#include "structopt.hpp"
#include "circular_buffer.h"
#include "tcp_listener.hpp"
#include "tcp_stream.hpp"
#include "json.hpp"

#include <cstdint>
#include <optional>
#include <string>
#include <stdexcept>
#include <vector>
#include <chrono>
#include <thread>
#include <mutex>
#include <fstream>
#include <ctime>
#include <unordered_map>

using namespace std;
using json = nlohmann::json;

struct Arguments {

	struct Tcp : structopt::sub_command {
		uint16_t port;
	};

	struct SerialPorts : structopt::sub_command {
		optional<bool> verbose = false;
	};

	struct Serial : structopt::sub_command {
		string port;
        optional<uint32_t> baudrate = 115200;
	};

	Tcp tcp;
    SerialPorts serial_ports;
    Serial serial;
};

STRUCTOPT(Arguments::Tcp, port);
STRUCTOPT(Arguments::SerialPorts, verbose);
STRUCTOPT(Arguments::Serial, port);
STRUCTOPT(Arguments, tcp, serial_ports, serial);

struct SignalData {
    std::string name;
    std::vector<uint8_t> data;
};

std::shared_ptr<serial::Serial> g_serial;
std::vector<char> g_io_vector_write;
CircularBuffer<char> g_io_buffer_read(4096);
std::mutex g_tcp_io_mutex;
std::unordered_map<uint16_t, SignalData> g_signals_data;

void tcp_server(std::unique_ptr<TcpListener> tcp_listener) {
    while (true) {
        TcpStream tcp_stream = tcp_listener->accept_connection();
        cout << "Connection accepted.." << endl;
        while (true) {
            try {
                if (!tcp_stream.is_write_available()) {
                    cout << "Connection closed." << endl;
                    break;
                }
                const std::lock_guard<std::mutex> io_vector_lock(g_tcp_io_mutex);
                if (g_io_vector_write.size() > 0) {
                    // cout << "write " << g_io_vector_write.size() << " bytes" << endl;
                    tcp_stream.write(g_io_vector_write);
                    g_io_vector_write.clear();
                }
                if (tcp_stream.is_read_available()) {
                    std::vector<char> buf = tcp_stream.read();
                    if (0 == buf.size()) {
                        cout << "Connection closed." << endl;
                        break;
                    }
                    g_io_buffer_read.push_back(buf);
                }
            } catch (std::exception const& e) {
                cout << "Exception while handle stream: " << e.what() << endl;
                break;
            }
            this_thread::sleep_for(std::chrono::milliseconds(2));
        }
    }
}

bool read_cb_tcp(uint8_t* const byte) {
    std::lock_guard<std::mutex> io_vector_lock(g_tcp_io_mutex);
    if (g_io_buffer_read.size() > 0) {
        *byte = static_cast<uint8_t>(g_io_buffer_read.at(0));
        g_io_buffer_read.pop_front();
        return true;
    } else {
        return false;
    }
}

bool write_cb_tcp(uint8_t const byte) {
    std::lock_guard<std::mutex> io_vector_lock(g_tcp_io_mutex);
    g_io_vector_write.push_back(static_cast<char>(byte));
    return true;
}

bool write_buf_cb_tcp(uint8_t const* const data, uint16_t ndata) {
    std::lock_guard<std::mutex> io_vector_lock(g_tcp_io_mutex);
    g_io_vector_write.insert(g_io_vector_write.end(), data, &data[ndata]);
    return true;
}

bool get_write_state_cb_tcp() {
    return true;
}

bool read_cb_serial(uint8_t* const byte) {
    if (g_serial->available() > 0) {
        return g_serial->read(byte, 1) == 1 ? true : false;
    } else {
        return false;
    }
}

bool write_cb_serial(uint8_t const byte) {
    return g_serial->write(&byte, 1) == 1 ? true : false;
}

uint32_t get_rand_cb() {
    uint16_t rand1 = (uint16_t)rand();
    uint16_t rand2 = (uint16_t)rand();
    return rand1 | rand2 << 16;
}

uint32_t get_time_ms_cb() {
    using namespace std::chrono;

    static milliseconds const start_ms = duration_cast<milliseconds>(system_clock::now().time_since_epoch());

    milliseconds now_ms = duration_cast<milliseconds>(system_clock::now().time_since_epoch());
    return (uint32_t)(now_ms - start_ms).count();
}

int sig_read_cb(uint16_t const sig, uint8_t* const buf) {
    SignalData const& signal_data = g_signals_data[sig];
    std::memcpy(buf, signal_data.data.data(), signal_data.data.size());
    return static_cast<int>(signal_data.data.size());
}

int sig_write_cb(uint16_t const sig, uint8_t const* const data, uint16_t const ndata) {
    SignalData& signal_data = g_signals_data[sig];
    signal_data.data.clear();
    for (uint16_t i = 0; i < ndata; i++) {
        signal_data.data.push_back(data[i]);
    }
    cout << "Write to signal " << signal_data.name << "(" << sig << ") " << ndata << " bytes." << endl;
    return 0;
}

int main(int argc, char** argv)
{
    try {
        struct Ecbs ecbs = {0};

        std::ifstream settings_file("settings.json");
        json const settings = json::parse(settings_file);
        uint8_t const address = settings["address"];

        auto opt = structopt::app("ecb-slave-c-server", "1.0.0").parse<Arguments>(argc, argv);
        if (opt.tcp.has_value()) {
            auto tcp_listener = std::make_unique<TcpListener>(opt.tcp.port);
            std::thread tcp_server_thread(tcp_server, std::move(tcp_listener));
            tcp_server_thread.detach();
            ecbs__init(&ecbs, address, get_time_ms_cb, read_cb_tcp, NULL);
            ecbs__init_write_buf(&ecbs, write_buf_cb_tcp, get_write_state_cb_tcp);
            cout << "IO init as TCP on port " << opt.tcp.port << endl;
        }
        else if (opt.serial_ports.has_value()) {
            vector<serial::PortInfo> ports = serial::list_ports();
            for (auto p : ports) {
                cout << p.port << " " << p.description << " " << p.hardware_id << endl;
            }
            return 0;
        } else if (opt.serial.has_value()) {
            g_serial = std::make_shared<serial::Serial>(opt.serial.port, opt.serial.baudrate.value(), serial::Timeout(1, 1));
            if (!g_serial->isOpen()) {
                throw runtime_error("fail to open com port: " + opt.serial.port);
            }
            ecbs__init(&ecbs, address, get_time_ms_cb, read_cb_serial, write_cb_serial);
            cout << "IO init as Serial on port " << opt.serial.port << endl;
        } else {
            cout << "type '-h' arg for help" << endl;
            return 1;
        }

        json const auth_key_j = settings["auth_key"];
        if (auth_key_j.is_array() && auth_key_j.size() == 16) {
            vector<uint8_t> const auth_key = auth_key_j;
            srand((unsigned int)time(NULL));
            ecbs__init_enc(&ecbs, auth_key.data(), get_rand_cb);
            cout << "Encryption success init." << endl;
        }

        for (json const& signal : settings["signals"]) {
            cout << "Add signal ";
            uint16_t const index = signal["index"];
            std::string const name = signal["name"];
            std::string const mode = signal["mode"];
            cout << name << "(" << index << ")";
            enum EcbsProtectLevel protect_level = ECBS_PROTECT_LEVEL__NO;
            if (std::string::npos != mode.find('e')) {
                protect_level = ECBS_PROTECT_LEVEL__ENC;
            } else if (std::string::npos != mode.find('a')) {
                protect_level = ECBS_PROTECT_LEVEL__ENC_AND_WRITE_AUTH;
            }
            cout << " with protect_level=" << protect_level;
            int (*read_cb)(uint16_t, uint8_t*) = NULL;
            int (*write_cb)(uint16_t, uint8_t const*, uint16_t) = NULL;
            SignalData signal_data = {
                .name = name,
                .data = vector<uint8_t>(),
            };
            if (signal.contains("data")) {
                json const& data_j = signal["data"];
                if (data_j.is_array()) {
                    for (json const& d : data_j) {
                        signal_data.data.push_back(d);
                    }
                } else if (data_j.is_string()) {
                    std::string data_str = data_j;
                    for (auto const& c : data_str) {
                        signal_data.data.push_back(c);
                    }
                }
            }
            if (std::string::npos != mode.find('r')) {
                read_cb = sig_read_cb;
            }
            if (std::string::npos != mode.find('w')) {
                write_cb = sig_write_cb;
            }
            cout << " mode=" << (read_cb ? "r" : "") << (write_cb ? "w" : "");
            g_signals_data[index] = signal_data;
            int const rc = ecbs__add_sig(&ecbs, index, protect_level, read_cb, write_cb);
            if (0 != rc) {
                throw std::runtime_error("ecbs__add_sig() failed: " + std::to_string(rc));
            }
            if (signal.contains("stream_pub_period_ms")) {
                int const rc = ecbs__allow_stream_at_sig(&ecbs, index, signal["stream_pub_period_ms"]);
                if (0 != rc) {
                    throw std::runtime_error("ecbs__allow_stream_at_sig() failed: " + std::to_string(rc));
                }
                cout << " stream_pub_period_ms=" << signal["stream_pub_period_ms"];
            }
            cout << endl;
        }

        while (true) {
            this_thread::sleep_for(std::chrono::microseconds(100));
            ecbs__loop(&ecbs);
        }
    } catch (std::exception const& e) {
        cout << "Exception: " << e.what() << endl;
        return 1;
    }

    return 0;
}

