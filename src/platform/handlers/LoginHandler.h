#ifndef __LOGIN_HANDLER_H__
#define __LOGIN_HANDLER_H__

#include <Poco/Net/HTTPRequestHandler.h>
#include <Poco/Net/HTTPServerRequest.h>
#include <Poco/Net/HTTPServerResponse.h>
#include <Poco/Data/SessionPool.h>
#include <Poco/Redis/Client.h>

namespace FQW::Auth
{

class LoginHandler : public Poco::Net::HTTPRequestHandler
{
public:
    LoginHandler(Poco::Data::SessionPool & sessionPool, Poco::Redis::Client & redisClient) 
        : sessionPool_{sessionPool}, redisClient_{redisClient} 
    {
    }

    void handleRequest(Poco::Net::HTTPServerRequest & req, Poco::Net::HTTPServerResponse & res) final;

private:
    Poco::Data::SessionPool & sessionPool_;
    Poco::Redis::Client & redisClient_;
};

} // namespace FQW::Auth

#endif // __LOGIN_HANDLER_H__
