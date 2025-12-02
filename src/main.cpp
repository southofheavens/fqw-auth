#include <iostream>
#include <unordered_set>

#include <Utils.h>
#include <Handlers.h>

#include <Poco/Data/PostgreSQL/Connector.h>
#include <Poco/Data/Session.h>
#include <Poco/Data/RecordSet.h>
#include <Poco/Data/Statement.h>
#include <Poco/Net/HTTPServer.h>
#include <Poco/Net/HTTPRequestHandler.h>
#include <Poco/Net/HTTPRequestHandlerFactory.h>
#include <Poco/Net/HTTPServerRequest.h>
#include <Poco/Net/HTTPServerResponse.h>
#include <Poco/Net/ServerSocket.h>
#include <Poco/Util/ServerApplication.h>
#include <Poco/Data/SessionPool.h>
#include <Poco/StreamCopier.h>
#include <Poco/JSON/Parser.h>
#include <Poco/JSON/Object.h>
#include <Poco/URI.h>
#include <Poco/Data/RecordSet.h>

/**
 * 
 */
class AuthFactory : public Poco::Net::HTTPRequestHandlerFactory
{
public:
    AuthFactory(Poco::Data::SessionPool& sessionPool) : sessionPool_(sessionPool) {}

private:
    Poco::Net::HTTPRequestHandler* createRequestHandler(const Poco::Net::HTTPServerRequest& request) override
    {
        std::string uri = request.getURI();
        std::string method = request.getMethod();
        
        if (method == "POST")
        {
            if (uri == "/login") {
                return new Auth::Handlers::LoginHandler(sessionPool_);
            }
            else if (uri == "/register") {
                return new Auth::Handlers::RegisterHandler(sessionPool_);
            }
            else {
                // ErrorHandler
            }
        }
        else {
            // ErrorHandler
        }
    }

private:
    Poco::Data::SessionPool& sessionPool_;
};

/**
 * 
 */
class AuthServer : public Poco::Util::ServerApplication
{
protected:
    void initialize(Application& self) override
    {
        ServerApplication::initialize(self);
    }

    void uninitialize() override
    {
        ServerApplication::uninitialize();
    }

    int main(const std::vector<std::string>&) override
    {
        try
        {
            Auth::Utils::libsodiumInitialize();
            srand(std::chrono::system_clock::now().time_since_epoch().count());

            Poco::Data::PostgreSQL::Connector::registerConnector();
            std::string connectionString = "host=localhost port=5432 dbname=something user=postgres password=postgres";
            Poco::Data::SessionPool sessionPool("PostgreSQL", connectionString, 1, 10);

            Poco::Net::ServerSocket svs(8080);
            
            Poco::Net::HTTPServer srv
            (
                new AuthFactory(sessionPool), 
                svs, 
                new Poco::Net::HTTPServerParams
            );

            srv.start();
            std::cout << "Сервер запущен на порту 8080..." << std::endl;
            
            waitForTerminationRequest();
            
            srv.stop();

            Poco::Data::PostgreSQL::Connector::unregisterConnector();
            
            return Application::EXIT_OK;
        }
        catch (const Poco::Exception& e) {
            std::cerr << e.displayText() << '\n';
        }
        catch (const std::exception& e) {
            std::cerr << e.what() << '\n';
        }
    }
};

POCO_SERVER_MAIN(AuthServer)
