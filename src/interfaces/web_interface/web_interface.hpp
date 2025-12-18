#pragma once

#include "requester/requester.hpp"
#include <cstdint>
#include <string>
#include <string_view>
#include <vector>

namespace web_interface {

const std::string_view USER_AGENT =
"User-Agent: Mozilla/5.0 (X11; Ubuntu; Linux i686 on x86_64) "
"AppleWebKit/537.36 "
"(KHTML, like Gecko) Chrome/53.0.2820.59 Safari/537.36";

static size_t write_response(char *prt,
                             size_t size,
                             size_t nmemb,
                             void *userdata);
std::string to_simple_string(const std::vector<uint8_t> &data);
bool configureCurl(Session *const session);
std::vector<uint8_t> createRequestBody();
bool sendRequest(Session *const session,
                 const std::vector<uint8_t> &data,
                 LogCallback log,
                 void *ctx);
std::optional<std::vector<uint8_t>> receiveResponse(Session *const session);
bool isValidResponse(const std::vector<uint8_t> &response, RequestType type);
std::vector<uint8_t> createPayload(std::string_view response_data,
                                   std::string_view username,
                                   std::string_view password);
int validateResponse(const std::vector<uint8_t> &response);

}  // namespace web_interface
