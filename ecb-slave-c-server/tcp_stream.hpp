#pragma once

#include <cstdint>
#include <stdexcept>
#include <string>
#include <vector>

#include <winsock2.h>
#include <Ws2tcpip.h>

class TcpStream {
public:
    TcpStream(SOCKET const client, SOCKADDR_IN const& client_addr)
    : _client(client), _client_addr(client_addr) {
        char client_addr_str[INET_ADDRSTRLEN] = {};
        inet_ntop(AF_INET, &_client_addr.sin_addr, client_addr_str, INET_ADDRSTRLEN);
    }

    ~TcpStream() {
        closesocket(_client);
    }

    void set_nonblock_mode(bool const is_nonblock) {
        int nonblock_flag = is_nonblock ? 1 : 0;
        if (SOCKET_ERROR == ioctlsocket(_client, FIONBIO, (u_long FAR *)&nonblock_flag)) {
            throw std::runtime_error("Error ioctlsocket: " + std::to_string(WSAGetLastError()));
        }
    }

    bool is_read_available() {
        fd_set fd;
        FD_ZERO(&fd);
        FD_SET(_client, &fd);
        struct timeval tv;
        tv.tv_sec = 0;
        tv.tv_usec = 0;
        if (SOCKET_ERROR == select(1, &fd, NULL, NULL, &tv)) {
            throw std::runtime_error("Error select: " + std::to_string(WSAGetLastError()));
        }
        if (FD_ISSET(_client, &fd)) {
            return true;
        } else {
            return false;
        }
    }

    bool is_write_available() {
        fd_set fd;
        FD_ZERO(&fd);
        FD_SET(_client, &fd);
        struct timeval tv;
        tv.tv_sec = 0;
        tv.tv_usec = 0;
        if (SOCKET_ERROR == select(1, NULL, &fd, NULL, &tv)) {
            throw std::runtime_error("Error select: " + std::to_string(WSAGetLastError()));
        }
        if (FD_ISSET(_client, &fd)) {
            return true;
        } else {
            return false;
        }
    }

    virtual size_t read(char* const buffer, size_t buffer_size) {
        int const rc = recv(_client, buffer, buffer_size, 0);
        if (SOCKET_ERROR == rc) {
            throw std::runtime_error("Error recv: " + std::to_string(WSAGetLastError()));
        }
        return static_cast<size_t>(rc);
    }

    virtual std::vector<char> read() {
        size_t const BUFFER_SIZE = 1024;
        char buffer[BUFFER_SIZE] = {};
        std::vector<char> data;

        while (true) {
            int const rc = recv(_client, buffer, BUFFER_SIZE, 0);
            if (SOCKET_ERROR == rc) {
                throw std::runtime_error("Error recv: " + std::to_string(WSAGetLastError()));
            }
            data.insert(data.end(), buffer, &buffer[rc]);
            if (BUFFER_SIZE != rc) {
                break;
            }
        }

        return data;
    }

    void write(std::vector<char> const& data) {
        int const rc = send(_client, data.data(), static_cast<int>(data.size()), 0);
        if (SOCKET_ERROR == rc) {
            throw std::runtime_error("Error send: " + std::to_string(WSAGetLastError()));
        }
        if (rc != data.size()) {
            throw std::runtime_error("Error send: sended amount of bytes not equal desired: " +
                std::to_string(rc) + ", " + std::to_string(data.size()));
        }
    }

private:
    SOCKET _client = 0;
    SOCKADDR_IN _client_addr{};
};