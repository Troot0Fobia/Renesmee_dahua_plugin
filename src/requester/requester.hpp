/*
 *
 * Copyright (c) 2025 Troot0Fobia. All Rights Reserved.
 */

#pragma once

#include "api_DTOs.hpp"
#include "plugin_api.hpp"
#include <cstdint>
#include <cstdlib>
#include <curl/curl.h>
#include <optional>
#include <string_view>
#include <variant>
#include <vector>
#ifdef _WIN32
    #include <winsock2.h>
    #include <ws2topip.h>
#else
    #include <sys/poll.h>
#endif


enum RequestType {
    pollRequest = 0x01u,
    authRequest = 0x08u,
};

struct ResponseData {
    char *response;
    size_t size;
};

struct Session {
    CURL *curl = nullptr;
    curl_socket_t socketfd;
    const __Addr *addr = nullptr;
    const __Proxy *proxy = nullptr;
    struct pollfd poll_fds[1];
    struct curl_slist *headers_list = NULL;
    int interface_type = INTERFACE_TYPE_UNKNOWN;
    ResponseData response_data = {static_cast<char *>(malloc(0)), 0};
};

bool establishConnection(Session *const session,
                         LogCallback log,
                         void *ctx);
std::vector<uint8_t> createRequestBody(int interface_type, uint8_t requestType);
bool sendRequest(Session *const session,
                 const std::vector<uint8_t> &data,
                 LogCallback log,
                 void *ctx);
std::optional<std::vector<uint8_t>> receiveResponse(Session *const session);
bool isValidResponse(const std::vector<uint8_t> &response,
                     int interface_type,
                     RequestType type);
std::optional<std::variant<std::pair<std::string_view, std::string_view>,
                           std::string_view>>
parsePollResponse(int interface_type, const std::vector<uint8_t> &response);
std::vector<uint8_t>
createPayload(const std::variant<std::pair<std::string_view, std::string_view>,
                                 std::string_view> &device_data,
              std::string_view username,
              std::string_view password);
int validateResponse(const std::vector<uint8_t> &response);

