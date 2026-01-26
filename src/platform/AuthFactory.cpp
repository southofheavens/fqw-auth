#include <AuthFactory.h>

namespace FQW::Auth
{

Poco::Net::HTTPRequestHandler * AuthFactory::createRequestHandler(const Poco::Net::HTTPServerRequest & request) 
{
    std::string uri = request.getURI();
    std::string method = request.getMethod();
    
    if (method == "POST")
    {
        if (uri == "/login") {
            return new FQW::Auth::LoginHandler(sessionPool_, redisClient_);
        }
        else if (uri == "/register") {
            return new FQW::Auth::RegisterHandler(sessionPool_);
        }
        else if (uri == "/refresh") {
            return new FQW::Auth::RefreshHandler(sessionPool_, redisClient_);
        }
        else {
            return new FQW::Auth::ErrorHandler();
        }
    }
    else {
        return new FQW::Auth::ErrorHandler();
    }
}

} // namespace FQW::Auth
