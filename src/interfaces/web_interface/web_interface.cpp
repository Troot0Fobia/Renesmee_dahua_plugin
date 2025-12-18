#include "web_interface.hpp"
#include "hasher/hasher.hpp"
#include "nlohmann/json.hpp"
#include "requester/requester.hpp"
#include <algorithm>
#include <chrono>
#include <cstdint>
#include <curl/curl.h>
#include <exception>
#include <format>
#include <iterator>
#include <optional>
#include <string>
#include <thread>
#include <vector>

namespace web_interface {

using json = nlohmann::json;


json poll_structure = json::parse(R"(
    {
        "method": "global.login",
        "params": {
            "userName": "",
            "password": "",
            "clientType": "Web3.0"
        },
        "id": 1
    }
)");

json creds_structure = json::parse(R"(
    {
        "method": "global.login",
        "params": {
            "userName": "admin",
            "password": "",
            "clientType": "Web3.0",
            "authorityType": "Default",
            "passwordType": "Default"
        },
        "id": 2,
        "session": ""
    }
)");

size_t write_response(char *contents, size_t size, size_t nmemb,
                      void *userdata) {
    size_t realsize = size * nmemb;
    ResponseData *response = static_cast<ResponseData *>(userdata);

    char *ptr = static_cast<char *>(
        realloc(response->response, response->size + realsize + 1));

    response->response = ptr;
    memcpy(&(response->response[response->size]), contents, realsize);
    response->size += realsize;
    response->response[response->size] = 0;

    return realsize;
}


bool configureCurl(Session *const session) {
    curl_easy_setopt(session->curl, CURLOPT_FOLLOWLOCATION, 1L);
    curl_easy_setopt(session->curl, CURLOPT_AUTOREFERER, 1L);
    curl_easy_setopt(session->curl, CURLOPT_WRITEFUNCTION, write_response);

    if (session->headers_list) {
        curl_slist_free_all(session->headers_list);
        session->headers_list = NULL;
    }

    session->headers_list = curl_slist_append(session->headers_list,
                                              USER_AGENT.data());
    session->headers_list =
        curl_slist_append(session->headers_list,
                          std::format("Origin: http://{}:{}",
                                      session->addr->ip,
                                      session->addr->port).c_str());
    session->headers_list =
        curl_slist_append(session->headers_list,
                          std::format("Referer: http://{}:{}",
                                      session->addr->ip,
                                      session->addr->port).c_str());
    session->headers_list = curl_slist_append(session->headers_list,
                                              "Connection: keep-alive");

    curl_easy_setopt(session->curl, CURLOPT_HTTPHEADER, session->headers_list);
    std::string_view tls_char = "";
    if (session->addr->port == 443) {
        tls_char = "s";
    }
    curl_easy_setopt(session->curl, CURLOPT_URL,
                     std::format("http{}://{}:{}/RPC2_Login",
                                 tls_char,
                                 session->addr->ip,
                                 session->addr->port).c_str());

    return true;
}

std::vector<uint8_t> createRequestBody() {
    return to_byte_vector(poll_structure.dump());
}

bool sendRequest(Session *const session,
                 const std::vector<uint8_t> &data,
                 LogCallback log,
                 void *ctx) {
    std::string body;
    std::transform(data.begin(),
                   data.end(),
                   std::back_inserter(body),
                   [](uint8_t byte){ return static_cast<char>(byte); });
    curl_easy_setopt(session->curl, CURLOPT_WRITEDATA,
                     static_cast<void *>(&session->response_data));
    curl_easy_setopt(session->curl, CURLOPT_POSTFIELDS, body.c_str());
    curl_easy_setopt(session->curl, CURLOPT_POSTFIELDSIZE, body.size());
    std::string requestType =
        body.find("session") == std::string::npos ? "poll" : "creds";

    int attempts = 5;
    char errbuf[CURL_ERROR_SIZE];
    curl_easy_setopt(session->curl, CURLOPT_ERRORBUFFER, errbuf);

    while (attempts--) {
        log(ctx,
            PluginLogLevel::DEBUG,
            std::format("Attempt #{} to send web {} request to {}:{}",
                        5 - attempts,
                        requestType,
                        session->addr->ip,
                        session->addr->port).c_str());

        memset(errbuf, 0, CURL_ERROR_SIZE);
        CURLcode res = curl_easy_perform(session->curl);
        if (res != CURLE_OK) {
            log(ctx,
                PluginLogLevel::ERROR,
                std::format("Error code {} and message "
                            "from curl while trying to send "
                            "web {} request to {}:{}: {}\n",
                            static_cast<int>(res),
                            requestType,
                            session->addr->ip,
                            session->addr->port,
                            strlen(errbuf) ? errbuf : curl_easy_strerror(res))
                .c_str());
            std::this_thread::sleep_for(std::chrono::milliseconds(50));
            continue;
        }

        return true;
    }

    return false;
}

std::optional<std::vector<uint8_t>> receiveResponse(Session *const session) {
    std::vector<uint8_t> response =
        to_byte_vector(std::string{session->response_data.response});
    free(session->response_data.response);
    session->response_data.response = static_cast<char *>(malloc(0));
    session->response_data.size = 0;

    return response;
}

bool isValidResponse(const std::vector<uint8_t> &response, RequestType type) {
    std::string response_string;
    std::transform(response.begin(),
                   response.end(),
                   std::back_inserter(response_string),
                   [](uint8_t byte){ return static_cast<char>(byte); });
    try {
        json response_json = json::parse(response_string);
        if (type == RequestType::pollRequest) {
            int error_code = response_json["error"]["code"].get<int>();
            return error_code == 268632079;
        } else if (type == RequestType::authRequest) {
            return response_json.contains("error")
                   && response_json["error"].contains("code")
                   && response_json.contains("id")
                   && response_json.contains("session")
                   && response_json.contains("result");
        }
    } catch (const std::exception &e) {
        return false;
    }

    return false;
}

std::vector<uint8_t> createPayload(std::string_view response_data,
                                   std::string_view username,
                                   std::string_view password) {
    try {
        json response_json = json::parse(response_data);
        std::string encription =
            response_json["params"]["encryption"].get<std::string>();
        std::string hashed_pass = "";

        if (!encription.compare("Default")) {
            std::string random = response_json["params"]["random"];
            std::string realm = response_json["params"]["realm"];
            hashed_pass = createFirstStep(username, random, realm, password);
        } else if (!encription.compare("OldDigest")) {
            hashed_pass = collapse_data(md5(to_byte_vector(password)));
        } else {
            hashed_pass = password;
        }
        auto session = response_json["session"];

        json creds_json = creds_structure;
        creds_json["session"] = session;
        creds_json["params"]["userName"] = std::string(username);
        creds_json["params"]["password"] = hashed_pass;
        creds_json["params"]["authorityType"] =
            response_json["params"]["encryption"];
        creds_json["params"]["passwordType"] =
            response_json["params"]["encryption"];

        return to_byte_vector(creds_json.dump());
    } catch (const std::exception &ex) {
        return {};
    }

    return {};
}

int validateResponse(const std::vector<uint8_t> &response) {
    try {
        std::string response_str;
        std::transform(response.begin(),
                       response.end(),
                       std::back_inserter(response_str),
                       [](uint8_t byte){ return static_cast<char>(byte); });
        json response_json = json::parse(response_str);
        if (response_json["result"].get<bool>()) {
            return 1;
        }
        int err_code = response_json["error"]["code"].get<int>();
        if (err_code == 268632072 || err_code == 268632081) {
            return -1;
        }
        if (err_code == 268632079) {
            return -2;
        }
        if (err_code == 268632070) {
            return -3;
        }
    } catch (const std::exception &ex) {
        return 0;
    }

    return 0;
}

}  // namespace web_interface
