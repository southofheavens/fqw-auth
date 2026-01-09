#ifndef __HANDLERS_H__
#define __HANDLERS_H__

#include <Poco/Net/HTTPRequestHandler.h>
#include <Poco/Net/HTTPServerRequest.h>
#include <Poco/Net/HTTPServerResponse.h>
#include <Poco/Data/SessionPool.h>
#include <Poco/Redis/Client.h>

namespace FQW::Auth::Handlers
{

/**
 * 
 */
class LoginHandler : public Poco::Net::HTTPRequestHandler // POST
{
public:
    LoginHandler(Poco::Data::SessionPool & sessionPool, Poco::Redis::Client & redisClient);

private:
    void handleRequest(Poco::Net::HTTPServerRequest & req, Poco::Net::HTTPServerResponse & res) override;

private:
    Poco::Data::SessionPool & sessionPool_;
    Poco::Redis::Client & redisClient_;
};

/**
 * 
 */
class RegisterHandler : public Poco::Net::HTTPRequestHandler // POST
{
public:
    RegisterHandler(Poco::Data::SessionPool & sessionPool);

private:
    void handleRequest(Poco::Net::HTTPServerRequest & req, Poco::Net::HTTPServerResponse & res) override;

private:
    Poco::Data::SessionPool & sessionPool_;
};

/**
 * 
 */
class RefreshHandler : public Poco::Net::HTTPRequestHandler // POST
{
public:
    RefreshHandler(Poco::Data::SessionPool & sessionPool, Poco::Redis::Client & redisClient);

private:
    void handleRequest(Poco::Net::HTTPServerRequest & req, Poco::Net::HTTPServerResponse & res) override;

private:
    Poco::Data::SessionPool & sessionPool_;
    Poco::Redis::Client & redisClient_;
};

/**
 * 
 */
class ErrorHandler : public Poco::Net::HTTPRequestHandler
{
public:
    ErrorHandler() = default;

private:
    void handleRequest(Poco::Net::HTTPServerRequest & req, Poco::Net::HTTPServerResponse & res) override;
};

} // namespace FQW::Auth::Handlers

#endif // __HANDLERS_H__
