#ifndef __AUTH_FACTORY_H__
#define __AUTH_FACTORY_H__

#include <Poco/Net/HTTPRequestHandlerFactory.h>

#include <handlers/LoginHandler.h>
#include <handlers/RegisterHandler.h>
#include <handlers/RefreshHandler.h>
#include <handlers/ErrorHandler.h>

namespace FQW::Auth
{

class AuthFactory : public Poco::Net::HTTPRequestHandlerFactory
{
public:
    AuthFactory(Poco::Data::SessionPool & sessionPool, Poco::Redis::Client & redisClient) 
        : sessionPool_(sessionPool), redisClient_(redisClient) 
    {
    }

    Poco::Net::HTTPRequestHandler * createRequestHandler(const Poco::Net::HTTPServerRequest & request) final;

private:
    Poco::Data::SessionPool & sessionPool_;
    Poco::Redis::Client & redisClient_;
};

} // namespace FQW::Auth

#endif // __AUTH_FACTORY_H__
