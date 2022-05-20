#pragma once
#include "../wbagent/sharedinclude/basic_session.hpp"
#include "../wbagent/sharedinclude/basic_client.hpp"
#include "../wbagent/seed128cbc/KISA_SEED_CBC.h"
#include "mediator.hpp"

class Settings;
class greenlink_server;
using namespace boost::asio;
using namespace boost::system;
using boost::asio::ip::tcp;


/// <summary>
/// session에 부착되는 abstract(interface) class
/// 파생클라스는 pure virtual function인 notifyMsg를 반드시 구현해서 GatewayChannel을 통해
/// session간 communication을 해야한다.
/// </summary>
class ChannelClient
{
public:
    virtual ~ChannelClient() {}
    // pure virtual function
    virtual void notifyMsg(std::string clientType, boost::shared_ptr<GatewayMessage> msg) = 0;
    std::string GetClientType()
    {
        return m_ClientType;
    };
    void SetClientType(std::string client_type)
    {
        m_ClientType = client_type;
    };

private:
    std::string m_ClientType = "wbagent";
};

/// <summary>
/// sesson간 communication을 위한 class.
/// wbagent는 greenlink, wbagent_ui타입의 client들이 연결된다.
/// greenlink는 한개지만 wbagent_ui는 복수개 연결될 수 있다. 
/// NanoPi에 설치된 wbagent_ui는 항상 연결되고 관리자용으로 개발한 wbadmin은 
/// 필요에 따라 연결될 수 있다. wbadmin은 wbagent_ui와 동일타입으로 취급한다.
/// wbagent_ui, wbadmin이 database설정등을 변경하고 wbagent에 적용하기 위해서는
/// wbagent를 재시작하거나 NanoPi를 reboot해야하는 경우가 있다.
/// wbadmin에서 wbagent를 종료하려면 wbagent에 연결된 wbagent_ui를 
/// 종료시켜야한다. wbadmin session은 wbagent_ui session에 직접 연결되지 않는다.
/// 하지만 wbadmin session은 중재자 역할을 하는 GatewayChannel를 이용해 종료명령을
/// wbagent_ui session에 전송할 수 있다. 
/// greenlink, wbagent_ui client가 wbagent에 연결되면 session이 생성되고 
/// GatewayChannel에 등록된다. GatewayChannel은 등록된 session정보를 이용하여 특정타입 모든
/// session의 notifyMsg를 GatewayChannel::broadcast(client_type, msg)로 호출할 수있다.
/// channel_participatn::notifyMsg는 pure virtual funcation을 선언하고
/// ServerSession은 notifyMsg를 구현해야 한다.
/// </summary>
class GatewayChannel
{
public:
    GatewayChannel()
    {
        std::cout << "Create GatewayChannel " << m_Clients.size() << " " << __FUNCTION__ << " " << this << std::endl;
    };

    ~GatewayChannel()
    {
        std::cout << "Leave channel " << m_Clients.size() << " " << __FUNCTION__ << " " << this << std::endl;
    }
    void Join(boost::shared_ptr<ChannelClient> client)
    {
        m_Clients.insert(client);
    }

    /// <summary>
    /// channel에서 leave하면 shared_ptr로 insert된 client를 erase한다.
    /// client가 erase되면 ServerSession::~ServerSession() destructor가 호출되고 
    /// ServerSession은 destroy된다. 따라서 leave는 반드시 ServerSession call stack의
    /// 최상위인 handleReadHeader와 handleReadBody의 예외처리 루틴에서 호출해야한다.
    /// 그외의 다른 코드에서 leave를 호출하면 handleReadBody 메서드의 마지막 코드인
    /// ReadMsgAsync에서 segment fault에러가 발생하며 wbagent는 비정상 종료된다.
    /// remote client와 연결은 끊어진다. 
    /// </summary>
    /// <param name="client"></param>
    void Leave(boost::shared_ptr<ChannelClient> client)
    {
        m_Clients.erase(client);
    }

    // 현재 채널에 연결된 모든 client들의 notifyMsg를 call한다.
    // ChannelClient::notifyMsg의 구현에 따라 기능이 결정된다.
    void BroadcastMsg(std::string clientType, boost::shared_ptr<GatewayMessage> msg)
    {
        std::for_each(m_Clients.begin(), m_Clients.end(), boost::bind(&ChannelClient::notifyMsg, _1, clientType, msg));
    }

    size_t getChannelSize()
    {
        return m_Clients.size();
    }
private:
    std::set<boost::shared_ptr<ChannelClient>> m_Clients;
};


class ServerSession : public BasicSession, public ChannelClient, public boost::enable_shared_from_this<ServerSession>
{
public:
    ServerSession(io_service& io_context, greenlink_server* pServer, GatewayChannel* channel);
    ~ServerSession();

    inline const std::string GetRemoteIP() { return m_RemoteIP; }
    inline void SetRemoteIP(std::string remoteIpName) { m_RemoteIP = remoteIpName; }

    void Start();
    void Stop()
    {
        m_bStop = true;
        BOOST_LOG_TRIVIAL(debug) << "연결 종료 (" << GetRemoteIP() << "), 연결중인 Clients : " << m_Channel->getChannelSize();
    }
    inline virtual void Close()
    {
        m_bStop = true;
        m_Channel->Leave(shared_from_this());
        BasicSession::Close();
        BOOST_LOG_TRIVIAL(debug) << "연결 종료 (" << GetRemoteIP() << "), 연결중인 Clients : " << m_Channel->getChannelSize();
    }

    inline void SetMediator(Mediator* mediator) { m_Mediator = mediator; };


private:
    virtual void notifyMsg(std::string clientid, boost::shared_ptr<GatewayMessage> msg);
    void readMsgAsync(char* pData, size_t nReadLen);
    void handleReadHeader(const error_code& ec, size_t GetMsgLength);
    void handleReadBody(const error_code& ec, size_t nReadLen);
    bool sendPTIM();
    void sendACK(char ack, bool bPrint=true);
    std::string getStrACK(char ack);
    std::string parsePayload(std::string strCommand, std::string strPayload);
    bool IsWBAdmin(char* pCommandID);

    void processGatewayPacket();
    void processWBAdminPacket();


private:
    // 수신 TOFF 개수. 하나의 세션에서 한번만 온다.
    unsigned int m_nTOFF = 0;
    // 수신 TDDD 개수. 하나의 세션에서 한번만 온다.
    unsigned int m_nTDDD = 0;
    bool m_bStop = false;
    std::string m_RemoteIP = "";
    GatewayMessage m_ReadMsg;
    Mediator* m_Mediator;
    greenlink_server* m_pServer;
    GatewayChannel* m_Channel;
};


class greenlink_server
{
public:
    greenlink_server(io_service& io_context, const tcp::endpoint& endpoint);
    inline greenlink_server::~greenlink_server() { delete m_Channel; }
    void listenClient();
    void SetMediator(Mediator* mediator) { m_Mediator = mediator; };
    GatewayChannel* GetGatewayChennel() { return m_Channel; };
    void PushRequest(CommandRequest new_request);

private:
    void dequeueRequest();

private:
    io_service& m_IoContext;
    tcp::acceptor m_Acceptor;
    Mediator* m_Mediator;
    // 세션들간의 통신을 위한 채널
    GatewayChannel* m_Channel;

    deadline_timer m_TimerDequeRequest;
    boost::mutex m_mutex;
    std::deque<CommandRequest> m_Requests;
    bool m_bStop = false;
    unsigned int m_DequeueFreq = 100;

};
