#ifndef __REGISTER_HANDLER_H__
#define __REGISTER_HANDLER_H__

#include <Poco/Net/HTTPRequestHandler.h>
#include <Poco/Net/HTTPServerRequest.h>
#include <Poco/Net/HTTPServerResponse.h>
#include <Poco/Data/SessionPool.h>

namespace FQW::Auth
{

class RegisterHandler : public Poco::Net::HTTPRequestHandler
{
public:
    RegisterHandler(Poco::Data::SessionPool & sessionPool) : sessionPool_{sessionPool} 
    {
    }

    void handleRequest(Poco::Net::HTTPServerRequest & req, Poco::Net::HTTPServerResponse & res) final;

private:
    Poco::Data::SessionPool & sessionPool_;
};
    
} // namespace FQW::Auth

#endif // __REGISTER_HANDLER_H__
