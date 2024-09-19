#pragma once

#include "tcp_stream.hpp"

#include <cstdint>
#include <stdexcept>
#include <string>

#include <winsock2.h>
#include <Ws2tcpip.h>

class TcpListener {
public:
    TcpListener(uint16_t const port) : _port(port) {
        WSAStartup(MAKEWORD(2, 2), &_wsad_data);

        // Setup the socket
        SOCKET server = 0;
        SOCKADDR_IN server_addr{};
        server_addr.sin_addr.s_addr = INADDR_ANY;
        server_addr.sin_family = AF_INET;
        server_addr.sin_port = htons(_port);

        server = socket(AF_INET, SOCK_STREAM, 0);
        if (INVALID_SOCKET == server) {
            throw std::runtime_error("Error socket create: " + std::to_string(WSAGetLastError()));
        } 

        const int bind_result = bind(server, (SOCKADDR *)&server_addr, sizeof(server_addr));
        if (0 != bind_result) {
            throw std::runtime_error("Error binding socket: " + std::to_string(WSAGetLastError()));
        }

        const int listen_result = listen(server, 0);
        if (0 != listen_result) {
            throw std::runtime_error("Error listening on socket: " + std::to_string(WSAGetLastError()));
        }

        _server = server;
    }

    TcpListener(TcpListener const&) = delete;

    ~TcpListener() {
        closesocket(_server);
        WSACleanup();
    }

    TcpStream accept_connection() {
        SOCKET client = 0;
        SOCKADDR_IN client_addr{};
        int client_addr_size = sizeof(client_addr);

        client = accept(_server, (SOCKADDR *)&client_addr, &client_addr_size);
        if (INVALID_SOCKET == client) {
            throw std::runtime_error("Error accepting on socket: " + std::to_string(client));
        }

        return TcpStream(client, client_addr);
    }

    uint16_t get_port() {
        return this->_port;
    }

private:
    WSADATA _wsad_data{};
    SOCKET _server = 0;
    uint16_t _port = 0;
};
