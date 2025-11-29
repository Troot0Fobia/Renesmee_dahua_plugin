/*
 *
 * Copyright (c) 2025 Troot0Fobia. All Rights Reserved.
 */

#include "requester.hpp"
#include "api_DTOs.hpp"
#include "plugin_api.hpp"
#include <cstring>
#include <curl/curl.h>
#include <format>
#include <optional>
#include <string>
#include <thread>
#include <utility>
#include <vector>


bool establishConnection(Session *const session, LogCallback log, void *ctx) {
    if (!session || !session->proxy || !session->curl || !session->addr) {
        log(ctx,
            PluginLogLevel::ERROR,
            "Not session or proxy or curl handler or addr does not provided");
        if (!session) {
            log(ctx, PluginLogLevel::DEBUG, "Session does not provided");
        } else if (!session->proxy) {
            log(ctx, PluginLogLevel::DEBUG, "Proxy does not provided");
        } else if (!session->curl) {
            log(ctx, PluginLogLevel::DEBUG, "Curl does not provided");
        } else if (!session->addr) {
            log(ctx, PluginLogLevel::DEBUG, "Addr does not provided");
        }
        return false;
    }

    int attempts = 5;
    char errbuf[CURL_ERROR_SIZE];

    while (attempts--) {
        log(ctx,
            PluginLogLevel::DEBUG,
            std::format("Attempt #{} to establish connection",
                        5 - attempts).c_str());

        memset(errbuf, 0, CURL_ERROR_SIZE);
        curl_easy_cleanup(session->curl);
        session->curl = curl_easy_init();

        curl_easy_setopt(session->curl, CURLOPT_ERRORBUFFER, errbuf);
        curl_easy_setopt(session->curl, CURLOPT_CONNECT_ONLY, 1L);
        curl_easy_setopt(session->curl, CURLOPT_PROXYTYPE, CURLPROXY_SOCKS5);
        curl_easy_setopt(session->curl, CURLOPT_PROXY, session->proxy->addr.ip);
        curl_easy_setopt(session->curl, CURLOPT_PROXYPORT,
                         session->proxy->addr.port);
        curl_easy_setopt(session->curl, CURLOPT_PROXYUSERNAME,
                         session->proxy->creds.login);
        curl_easy_setopt(session->curl, CURLOPT_PROXYPASSWORD,
                         session->proxy->creds.password);
        curl_easy_setopt(session->curl, CURLOPT_CONNECTTIMEOUT, 10L);
        curl_easy_setopt(session->curl, CURLOPT_TIMEOUT, 30L);
        curl_easy_setopt(session->curl, CURLOPT_SERVER_RESPONSE_TIMEOUT, 25L);
        curl_easy_setopt(session->curl, CURLOPT_URL,
                         std::format("{}:{}",
                                     session->addr->ip,
                                     session->addr->port).c_str());

        CURLcode res = curl_easy_perform(session->curl);
        if (res != CURLE_OK) {
            log(ctx,
                PluginLogLevel::ERROR,
                std::format("Error code {} and message from curl "
                            "while trying establish "
                            "connection with proxy: {}\n",
                            static_cast<int>(res),
                            strlen(errbuf) ? errbuf : curl_easy_strerror(res))
                .c_str());
            std::this_thread::sleep_for(std::chrono::milliseconds(50));
            continue;
        }

        memset(errbuf, 0, CURL_ERROR_SIZE);
        res = curl_easy_getinfo(session->curl,
                                CURLINFO_ACTIVESOCKET,
                                &session->socketfd);
        if (res != CURLE_OK) {
            log(ctx,
                PluginLogLevel::ERROR,
                std::format("Error code {} and message from curl "
                            "while trying receive "
                            "socket: {}\n",
                            static_cast<int>(res),
                            strlen(errbuf) ? errbuf : curl_easy_strerror(res))
                .c_str());
            std::this_thread::sleep_for(std::chrono::milliseconds(50));
            continue;
        }

        session->poll_fds[0].fd = session->socketfd;
        session->poll_fds[0].events = POLLIN;

        return true;
    }

    return false;
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
                 const std::vector<uint8_t> &data,
                 LogCallback log,
                 void *ctx) {
    std::string requestType =
        data[27] == RequestType::pollRequest ? "poll" : "creds";
    int attempts = 5;
    char errbuf[CURL_ERROR_SIZE];
    curl_easy_setopt(session->curl, CURLOPT_ERRORBUFFER, errbuf);

    while (attempts--) {
        log(ctx,
            PluginLogLevel::DEBUG,
            std::format("Attempt #{} to send {} request to {}:{}",
                        5 - attempts,
                        requestType,
                        session->addr->ip,
                        session->addr->port).c_str());

        size_t sended_data = 0;
        size_t requestSize = data.size();
        memset(errbuf, 0, CURL_ERROR_SIZE);
        CURLcode res = curl_easy_send(session->curl,
                                      data.data(),
                                      requestSize,
                                      &sended_data);

        if (res != CURLE_OK) {
            log(ctx,
                PluginLogLevel::ERROR,
                std::format("Error code {} and message from curl "
                            "while trying to send {} request to {}:{}: {}\n",
                            static_cast<int>(res),
                            requestType,
                            session->addr->ip,
                            session->addr->port,
                            strlen(errbuf) ? errbuf : curl_easy_strerror(res))
                .c_str());
            std::this_thread::sleep_for(std::chrono::milliseconds(50));
            continue;
        }

        if (sended_data != requestSize) {
            size_t restDataSize = requestSize - sended_data;
            memset(errbuf, 0, CURL_ERROR_SIZE);
            const unsigned char *rest_data = data.data() + sended_data;
            sended_data = 0;
            res = curl_easy_send(session->curl,
                                 rest_data,
                                 restDataSize,
                                 &sended_data);

            if (res != CURLE_OK || sended_data != restDataSize) {
                log(ctx,
                    PluginLogLevel::ERROR,
                    std::format("Error code {} and message from curl while "
                                "trying to finish {} request to {}:{}: {}\n",
                                static_cast<int>(res),
                                requestType,
                                session->addr->ip,
                                session->addr->port,
                                strlen(errbuf) ? errbuf : curl_easy_strerror(res))
                    .c_str());
                std::this_thread::sleep_for(std::chrono::milliseconds(50));
                continue;
            }
        }
        return true;
    }

    return false;
}

std::optional<std::vector<uint8_t>> receiveResponse(Session *const session) {
    std::vector<uint8_t> response;
    int attempts = 5;

    while (attempts--) {
#ifdef _WIN32
        int poll_res = WSAPoll(session->poll_fds, 1, 30000);
#else
        int poll_res = poll(session->poll_fds, 1, 30000);
#endif

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

    return std::nullopt;
}

bool isValidResponse(const std::vector<uint8_t> &response, RequestType type) {
    if (response.size() < 32) {
        return false;
    }

    if (type == RequestType::pollRequest) {
        return response[0] == 0xb0 &&
               response[8] == 0x01 &&
               response[26] == 0xf9 &&
               response[31] == 0x02;
    }

    if (type == RequestType::authRequest) {
        return response[0] == 0xb0 &&
               response[26] == 0xf9 &&
               response[31] == 0x02;
    }

    return false;
}

std::optional<std::pair<std::string_view, std::string_view>>
parsePollResponse(std::string_view response) {
    size_t start_pos = response.find(REALM_TAG);
    if (start_pos == std::string::npos) {
        return std::nullopt;
    }
    size_t end_pos = response.find(EOL_TAG, start_pos);
    if (end_pos == std::string::npos ||
        end_pos <= start_pos) {
        return std::nullopt;
    }

    std::string_view realm{response.data() + start_pos + REALM_TAG.size(),
                           response.data() + end_pos};

    start_pos = response.find(RANDOM_TAG, end_pos + EOL_TAG.size());
    if (start_pos == std::string::npos) {
        return std::nullopt;
    }
    end_pos = response.find(EOL_TAG, start_pos);
    if (end_pos == std::string::npos ||
        end_pos <= start_pos) {
        return std::nullopt;
    }

    std::string_view random{response.data() + start_pos + RANDOM_TAG.size(),
                            response.data() + end_pos};

    return std::make_pair(realm, random);
}

