#ifndef __ERROR_HANDLER_H__
#define __ERROR_HANDLER_H__

#include <Utils.h>

#include <Poco/Net/HTTPRequestHandler.h>
#include <Poco/Net/HTTPServerRequest.h>
#include <Poco/Net/HTTPServerResponse.h>

namespace FQW::Auth
{

class ErrorHandler : public Poco::Net::HTTPRequestHandler
{
public:
    ErrorHandler() = default;

    void handleRequest(Poco::Net::HTTPServerRequest & req, Poco::Net::HTTPServerResponse & res) final
    {
        res.setStatusAndReason(Poco::Net::HTTPResponse::HTTP_BAD_REQUEST);
        Auth::Utils::sendJsonResponse(res, "error", "Non-existent URL or bad method");
    }
};

} // namespace FQW::Auth

#endif // __ERROR_HANDLER_H__
