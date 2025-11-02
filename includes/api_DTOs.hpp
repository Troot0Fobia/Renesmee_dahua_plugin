#pragma once

#ifndef API_DTOS_H
#define API_DTOS_H

struct __Addr {
    const char* ip;
    unsigned short port;
};

struct __Creds {
    const char* login;
    const char* password;
};

struct __Proxy {
    __Addr addr;
    __Creds creds;
    const char* protocol;
};

#endif // API_DTOS_H
