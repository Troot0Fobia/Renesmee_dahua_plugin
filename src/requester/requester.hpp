/*
 *
 * Copyright (c) 2025 Troot0Fobia. All Rights Reserved.
 */

#pragma once

#include "api_DTOs.hpp"
#include "plugin_api.hpp"
#include <cstdint>
#include <curl/curl.h>
#include <optional>
#include <string_view>
#include <vector>
#ifdef _WIN32
    #include <winsock2.h>
    #include <ws2topip.h>
#else
    #include <sys/poll.h>
#endif


const std::string_view REALM_TAG = "Realm:";
const std::string_view RANDOM_TAG = "Random:";
const std::string_view EOL_TAG = "\r\n";

enum RequestType {
    pollRequest = 0x01u,
    authRequest = 0x08u,
};

struct Session {
    CURL *curl = nullptr;
    curl_socket_t socketfd;
    const __Addr *addr = nullptr;
    const __Proxy *proxy = nullptr;
    struct pollfd poll_fds[1];
};

bool establishConnection(Session *const session, LogCallback log, void *ctx);
std::vector<uint8_t> createRequestBody(uint8_t requestType);
bool sendRequest(const Session *const session,
                 const std::vector<uint8_t> &data,
                 LogCallback log,
                 void *ctx);
std::optional<std::vector<uint8_t>> receiveResponse(Session *const session);
bool isValidResponse(const std::vector<uint8_t> &response, RequestType type);
std::optional<std::pair<std::string_view, std::string_view>>
parsePollResponse(std::string_view response);

