/*
 *
 * Copyright (c) 2025 Troot0Fobia. All Rights Reserved.
 */

#include "requester.hpp"
#include "api_DTOs.hpp"
#include <cstring>
#include <curl/easy.h>
#include <format>
#include <optional>
#include <string>
#include <utility>
#include <vector>


bool establishConnection(Session *const session) {
    if (!session || !session->proxy || !session->curl || !session->addr) {
        return false;
    }

    curl_easy_reset(session->curl);

    curl_easy_setopt(session->curl, CURLOPT_CONNECT_ONLY, 1L);
    curl_easy_setopt(session->curl, CURLOPT_PROXYTYPE, CURLPROXY_HTTP);
    curl_easy_setopt(session->curl, CURLOPT_PROXY, session->proxy->addr.ip);
    curl_easy_setopt(session->curl, CURLOPT_PROXYPORT,
                     session->proxy->addr.port);
    curl_easy_setopt(session->curl, CURLOPT_PROXYUSERNAME,
                     session->proxy->creds.login);
    curl_easy_setopt(session->curl, CURLOPT_PROXYPASSWORD,
                     session->proxy->creds.password);
    curl_easy_setopt(session->curl, CURLOPT_HTTPPROXYTUNNEL, 1L);
    curl_easy_setopt(session->curl, CURLOPT_CONNECTTIMEOUT, 10L);
    curl_easy_setopt(session->curl, CURLOPT_TIMEOUT, 30L);
    curl_easy_setopt(session->curl, CURLOPT_SERVER_RESPONSE_TIMEOUT, 25L);
    curl_easy_setopt(session->curl, CURLOPT_URL,
                     std::format("{}:{}",
                                 session->addr->ip,
                                 session->addr->port).c_str());

    CURLcode res = curl_easy_perform(session->curl);
    if (res != CURLE_OK) {
        return false;
    }

    res = curl_easy_getinfo(session->curl,
                            CURLINFO_ACTIVESOCKET,
                            &session->socketfd);
    if (res != CURLE_OK) {
        return false;
    }

    session->poll_fds[0].fd = session->socketfd;
    session->poll_fds[0].events = POLLIN;

    return true;
}

std::vector<uint8_t> createRequestBody(uint8_t requestType) {
    std::vector<uint8_t> requestBody(32, 0x00);
    requestBody[0] = 0xa0u;
    requestBody[1] = 0x05u;
    requestBody[3] = 0x60u;
    requestBody[24] = 0x05u;
    requestBody[25] = 0x02u;
    requestBody[27] = requestType;
    requestBody[30] = 0xa1u;
    requestBody[31] = 0xaau;

    return requestBody;
}

bool sendRequest(const Session *const session,
                 const std::vector<uint8_t> &data) {
    size_t sended_data = 0;
    size_t requestSize = data.size();
    CURLcode res = curl_easy_send(session->curl,
                                  data.data(),
                                  requestSize,
                                  &sended_data);

    if (res != CURLE_OK) {
        return false;
    }

    if (sended_data != requestSize) {
        sended_data = 0;
        size_t restDataSize = requestSize - sended_data;
        res = curl_easy_send(session->curl,
                             data.data() + sended_data,
                             restDataSize,
                             &sended_data);

        if (res != CURLE_OK || sended_data != restDataSize) {
            return false;
        }
    }

    return true;
}

std::optional<std::vector<uint8_t>> receiveResponse(Session *const session) {
    std::vector<uint8_t> response;
    int attempts = 5;

    while (attempts--) {
        int poll_res = poll(session->poll_fds, 1, 30000);

        if (poll_res == -1) {
            return std::nullopt;
        }

        if (session->poll_fds[0].revents & POLLIN) {
            uint8_t buffer[512];  // change it later
            size_t read_data{0};

            CURLcode res = curl_easy_recv(session->curl,
                                          buffer,
                                          sizeof(buffer),
                                          &read_data);

            if (res == CURLE_AGAIN) {
                continue;
            }

            if (res != CURLE_OK || !read_data) {
                break;
            }

            response.insert(response.end(), buffer, buffer + read_data);

            if (response.size() >= 32) {
                return response;
            }
        }
    }

    // return response;
    return std::nullopt;
}

bool isValidResponse(const std::vector<uint8_t> &response, RequestType type) {
    if (response.size() < 32) {
        return false;
    }

    if (type == RequestType::pollRequest) {
        return response[0] == 0xb0 &&
               // response[3] == 0x68 &&
               response[8] == 0x01 &&
               response[9] == 0x0e &&
               response[26] == 0xf9 &&
               response[31] == 0x02;
    }

    if (type == RequestType::authRequest) {
        return response[0] == 0xb0 &&
               // response[3] == 0x68 &&
               response[26] == 0xf9 &&
               response[31] == 0x02;
    }

    return false;
}

std::optional<std::pair<std::string_view, std::string_view>>
parsePollResponse(std::string_view response) {
    size_t start_pos = response.find(REALM_TAG);
    size_t end_pos = response.find(EOL_TAG);
    if (start_pos == std::string::npos ||
        end_pos == std::string::npos ||
        end_pos <= start_pos) {
        return std::nullopt;
    }

    std::string_view realm{response.data() + start_pos + REALM_TAG.size(),
                           response.data() + end_pos};

    size_t next_pos = end_pos + EOL_TAG.size();
    start_pos = response.find(RANDOM_TAG, next_pos);
    end_pos = response.find(EOL_TAG, next_pos);
    if (start_pos == std::string::npos ||
        end_pos == std::string::npos ||
        end_pos <= start_pos) {
        return std::nullopt;
    }

    std::string_view random{response.data() + start_pos + RANDOM_TAG.size(),
                            response.data() + end_pos};

    return std::make_pair(realm, random);
}

