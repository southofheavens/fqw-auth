#ifndef __HANDLERS_H__
#define __HANDLERS_H__

#include <Poco/Net/HTTPRequestHandler.h>
#include <Poco/Net/HTTPServerRequest.h>
#include <Poco/Net/HTTPServerResponse.h>
#include <Poco/Data/SessionPool.h>

namespace Auth::Handlers
{

/**
 * 
 */
class LoginHandler : public Poco::Net::HTTPRequestHandler // POST
{
public:
    LoginHandler(Poco::Data::SessionPool& sessionPool);

private:
    void handleRequest(Poco::Net::HTTPServerRequest& req, Poco::Net::HTTPServerResponse& res) override;

private:
    Poco::Data::SessionPool& sessionPool_;
};

/**
 * 
 */
class RegisterHandler : public Poco::Net::HTTPRequestHandler // POST
{
public:
    RegisterHandler(Poco::Data::SessionPool& sessionPool);

private:
    void handleRequest(Poco::Net::HTTPServerRequest& req, Poco::Net::HTTPServerResponse& res) override;

private:
    Poco::Data::SessionPool& sessionPool_;
};

/**
 * 
 */
class ErrorHandler : public Poco::Net::HTTPRequestHandler
{
public:
    ErrorHandler() = default;

private:
    void handleRequest(Poco::Net::HTTPServerRequest& req, Poco::Net::HTTPServerResponse& res) override;
};

} // namespace Handlers

#endif // __HANDLERS_H__
