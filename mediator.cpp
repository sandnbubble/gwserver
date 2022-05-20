#include "mediator.hpp"
#include "server.hpp"
#include "clientsession.hpp"
#include <boost/signals2.hpp>

extern char* _client_id;
extern char* _chimney_code;

Mediator::Mediator(boost::asio::io_service& ioContext, ClientSession* client, greenlink_server* server) :
    m_IoContext(ioContext),
    m_RequestDequeTimer(ioContext),
    m_Client(client),
    m_Server(server)
{
    m_Server->SetMediator(this);
    m_Client->SetMediator(this);

    m_ClientID = _client_id;
    m_ChimneyCode = _chimney_code;

    m_RequestDequeTimer.expires_from_now(boost::posix_time::millisec(m_DequeueFreq));
    m_RequestDequeTimer.async_wait(boost::bind(&Mediator::dequeueRequest, this));
}

Mediator::~Mediator()
{
    BOOST_LOG_TRIVIAL(debug) << "Weil be destroyed " <<  __FUNCTION__;
}

void Mediator::Stop()
{
    m_bStop = true;
}

void Mediator::PushRequest(CommandRequest new_request)
{
    try
    {
        boost::lock_guard<boost::mutex> lock(m_mutex);
        m_Requests.push_back(new_request);
    }
    catch (std::exception& e)
    {
        BOOST_LOG_TRIVIAL(error) << "PushRequest failed " << __LINE__ << ", " << __FUNCTION__ << " in " << __FILE__;
    }
}

/// <summary>
/// ServerSession과 ClientSession간의 IPC를 위한 메시지큐 관리메서드
/// Socket 메시지를 Queue를 통해 전달하는 것은 너무 느리다. 다른 방법을 연구중.
/// </summary>
void Mediator::dequeueRequest()
{
    //auto t = std::chrono::system_clock::now();
    //std::time_t time_t = std::chrono::system_clock::to_time_t(t);
    //tm tm_t = *localtime(&time_t);
    //BOOST_LOG_TRIVIAL(trace) << "current time " << boost::format("%02d") % tm_t.tm_hour << ":" << boost::format("%02d") % tm_t.tm_min << ":" << boost::format("%02d") % tm_t.tm_sec << " in " << __FUNCTION__;
    try
    {
        if (!m_Requests.empty())
        {
            CommandRequest curRequest = m_Requests.front();
            std::string command_id = curRequest.GetCommandID();
            std::string subCommand1="", subCommand2="";
            curRequest.GetParameter(subCommand1, subCommand2);

            
            if (command_id == "PDUM")
            {
                boost::shared_ptr<GatewayMessage> msg(new GatewayMessage(command_id.c_str(), (char*)m_ClientID.c_str(), (char*)m_ChimneyCode.c_str(), subCommand1.c_str(), subCommand1.size()));
                m_Client->sendPDUM(msg);
            }
            else if (command_id == "TDUM")
            {
                m_Server->PushRequest(CommandRequest("TDUM", subCommand1, ""));
            }
            else if (command_id == "PFST")
            {
                boost::shared_ptr<GatewayMessage> msg(new GatewayMessage(command_id.c_str(), 
                    (char*)m_ClientID.c_str(), (char*)m_ChimneyCode.c_str(), subCommand1.data(), subCommand1.size()));
                int nResult = 0;
                m_Client->SendMsg(msg, false, false, true, nResult);
            }
            else if (command_id == "PCNG")
            {
                boost::shared_ptr<GatewayMessage> msg(new GatewayMessage(command_id.c_str(), (char*)m_ClientID.c_str(), (char*)m_ChimneyCode.c_str(), "", 0));
                int nResult = 0;
                m_Client->SendMsg(msg, true, true, false, nResult);
            }
            else if (command_id == "PSEP")
            {
                boost::shared_ptr<GatewayMessage> 
                    msg(new GatewayMessage(command_id.c_str(), (char*)m_ClientID.c_str(), (char*)m_ChimneyCode.c_str(), subCommand1.c_str(), subCommand1.size()));
                int nResult = 0;
                m_Client->SendMsg(msg, false, false, true, nResult);
            }
            else if (command_id == "PSET")
            {
                boost::shared_ptr<GatewayMessage>
                    msg(new GatewayMessage(command_id.c_str(), (char*)m_ClientID.c_str(), (char*)m_ChimneyCode.c_str(), subCommand1.c_str(), subCommand1.size()));
                int nResult = 0;
                m_Client->SendMsg(msg, false, false, true, nResult);
            }
            else if (command_id == "PFCC")
            {
                boost::shared_ptr<GatewayMessage>
                    msg(new GatewayMessage(command_id.c_str(), (char*)m_ClientID.c_str(), (char*)m_ChimneyCode.c_str(), subCommand1.c_str(), subCommand1.size()));
                int nResult = 0;
                m_Client->SendMsg(msg, false, false, true, nResult);
            }
            else if (command_id == "PAST")
            {
                boost::shared_ptr<GatewayMessage>
                    msg(new GatewayMessage(command_id.c_str(), (char*)m_ClientID.c_str(), (char*)m_ChimneyCode.c_str(), subCommand1.c_str(), subCommand1.size()));
                int nResult = 0;
                m_Client->SendMsg(msg, false, false, true, nResult);
            }
            else if (command_id == "PFCR")
            {
                boost::shared_ptr<GatewayMessage>
                    msg(new GatewayMessage(command_id.c_str(), (char*)m_ClientID.c_str(), (char*)m_ChimneyCode.c_str(), subCommand1.c_str(), subCommand1.size()));
                int nResult = 0;
                m_Client->SendMsg(msg, true, true, false, nResult);
            }
            else if (command_id == "PRSI" || command_id == "URSI")
            {
                if (command_id == "URSI")
                    command_id = "PRSI";
                boost::shared_ptr<GatewayMessage>
                    msg(new GatewayMessage(command_id.c_str(), (char*)m_ClientID.c_str(), (char*)m_ChimneyCode.c_str(), subCommand1.c_str(), subCommand1.size()));
                int nResult = 0;
                m_Client->SendMsg(msg, false, false, true, nResult);
            }
            else if (command_id == "PUPG")
            {
                boost::shared_ptr<GatewayMessage>
                    msg(new GatewayMessage(command_id.c_str(), (char*)m_ClientID.c_str(), (char*)m_ChimneyCode.c_str(), subCommand1.data(), subCommand1.size()));
                int nResult = 0;
                m_Client->SendMsg(msg, false, false, true, nResult);
            }
            else if (command_id == "PVER")
            {
                boost::shared_ptr<GatewayMessage>
                    msg(new GatewayMessage(command_id.c_str(), (char*)m_ClientID.c_str(), (char*)m_ChimneyCode.c_str(), subCommand1.c_str(), subCommand1.size()));
                int nResult = 0;
                m_Client->SendMsg(msg, true, true, false, nResult);
            }
            else if (command_id == "PFRS")
            {
                boost::shared_ptr<GatewayMessage>
                    msg(new GatewayMessage(command_id.c_str(), (char*)m_ClientID.c_str(), (char*)m_ChimneyCode.c_str(), subCommand1.c_str(), subCommand1.size()));
                int nResult = 0;
                m_Client->SendMsg(msg, false, false, true, nResult);
            }
            // 여기서부터의 조건은 통신서버의 원격명령에 대한 게이트웨이의 응답을 전송해주는 기능들을 수행할 조건들이다.
            else if (command_id == "TCNG")
            {
                // Server thread로 연결된 wbadmin에 수신패킷을 전송하도록 한다.
                m_Server->PushRequest(CommandRequest("TCNG", subCommand1, subCommand2));
            }
            else
            {
                BOOST_LOG_TRIVIAL(warning) << "Unknown request " << command_id;
            }

            {
                // 독립적인 스택을 사용하기 위해 block처리
                boost::lock_guard<boost::mutex> lock(m_mutex);
                m_Requests.pop_front();
            }
        }

        if (m_bStop == false)
        {
            m_RequestDequeTimer.expires_from_now(boost::posix_time::millisec(m_DequeueFreq));
            m_RequestDequeTimer.async_wait(boost::bind(&Mediator::dequeueRequest, this));
        }
    }
    catch (std::exception& e)
    {
        // 이전 코드에서 exception이 발생한 경우 message dequeue를 하지 못하는 경우가 발생할 수 있음.
        // 예외처리에 dequeue 추가해서 해결했지만 다른 방안을 모색중.
        {
            boost::lock_guard<boost::mutex> lock(m_mutex);
            m_Requests.pop_front();
        }
        // exception 에러가 발생한 경우 io_service를 유지하기 위한 코드
        if (m_bStop == false)
        {
            m_RequestDequeTimer.expires_from_now(boost::posix_time::millisec(m_DequeueFreq));
            m_RequestDequeTimer.async_wait(boost::bind(&Mediator::dequeueRequest, this));
        }
        BOOST_LOG_TRIVIAL(warning) << "Excepiton : " << e.what() << "in " << __LINE__  << " " << __FUNCTION__;
    }
}

