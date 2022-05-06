#pragma once
#include <deque>
#include <boost/thread.hpp>
#include "../wbagent/sharedinclude/GatewayMessage.hpp"

class ClientSession;
class greenlink_server;

/// <summary>
/// mediator를 참조하는 class들이 mediator behavior 실행요청을 위해 command queue에 등록하는 object class
/// </summary>
class CommandRequest
{
public:
    CommandRequest(std::string cmdID, std::string parameter1, std::string parameter2)
        : m_CommandID(cmdID), m_Parameter1(parameter1), m_Parameter2(parameter2)
    {
    }

    const std::string GetCommandID()
    {
        return m_CommandID;
    }

    /// <summary>
    /// 일반적인 용도로 사용된 Request의 매개변수를 구한다.
    /// </summary>
    /// <param name="parameter1"></param>
    /// <param name="parameter2"></param>
    void GetParameter(std::string& parameter1, std::string& parameter2)
    {
        parameter1 = m_Parameter1;
        parameter2 = m_Parameter2;
    }

private:
    std::string m_CommandID;
    std::string m_Parameter1;
    std::string m_Parameter2;
};

class BaseMediator
{
public :
    BaseMediator() {};
    ~BaseMediator() {};
    virtual void notify(std::string event) = 0;
};

/// <summary>
/// wbagent central controller class
/// SerialSession -> Mediator::PushSensorData -> Mediator::m_SensorDataQueue[2][]
/// ServerSession -> Mediator::PushRequest(CommandRequest) -> Mediator::dequeueRequest
/// ah_scheduler -> Mediator::PushRequest(5분측정데이터전송요청) -> Mediator::dequeueRequest
/// Main -> Mediator::PushRequest(CommandRequest) -> Mediator::dequeuRequest
/// </summary>
class Mediator: BaseMediator 
{
public:
    
    Mediator(boost::asio::io_service& ioContext, ClientSession* client, greenlink_server* server);
    ~Mediator();
    // 나중에 사용할 이유가 있으면 작성하자.
    virtual void notify(std::string event) {};
    void PushRequest(CommandRequest new_request);
    void Stop();

private:
    void dequeueRequest();

private:
    boost::mutex m_mutex;
    boost::asio::io_service& m_IoContext;
    ClientSession* m_Client;
    greenlink_server* m_Server;
    bool m_bStop = false;
    int m_DequeueFreq = 100;
    std::string m_ClientID;
    std::string m_ChimneyCode;
    std::deque<CommandRequest> m_Requests;
    boost::asio::deadline_timer m_RequestDequeTimer;
};