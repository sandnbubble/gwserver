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
/// session�� �����Ǵ� abstract(interface) class
/// �Ļ�Ŭ�󽺴� pure virtual function�� notifyMsg�� �ݵ�� �����ؼ� GatewayChannel�� ����
/// session�� communication�� �ؾ��Ѵ�.
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
/// sesson�� communication�� ���� class.
/// wbagent�� greenlink, wbagent_uiŸ���� client���� ����ȴ�.
/// greenlink�� �Ѱ����� wbagent_ui�� ������ ����� �� �ִ�. 
/// NanoPi�� ��ġ�� wbagent_ui�� �׻� ����ǰ� �����ڿ����� ������ wbadmin�� 
/// �ʿ信 ���� ����� �� �ִ�. wbadmin�� wbagent_ui�� ����Ÿ������ ����Ѵ�.
/// wbagent_ui, wbadmin�� database�������� �����ϰ� wbagent�� �����ϱ� ���ؼ���
/// wbagent�� ������ϰų� NanoPi�� reboot�ؾ��ϴ� ��찡 �ִ�.
/// wbadmin���� wbagent�� �����Ϸ��� wbagent�� ����� wbagent_ui�� 
/// ������Ѿ��Ѵ�. wbadmin session�� wbagent_ui session�� ���� ������� �ʴ´�.
/// ������ wbadmin session�� ������ ������ �ϴ� GatewayChannel�� �̿��� ��������
/// wbagent_ui session�� ������ �� �ִ�. 
/// greenlink, wbagent_ui client�� wbagent�� ����Ǹ� session�� �����ǰ� 
/// GatewayChannel�� ��ϵȴ�. GatewayChannel�� ��ϵ� session������ �̿��Ͽ� Ư��Ÿ�� ���
/// session�� notifyMsg�� GatewayChannel::broadcast(client_type, msg)�� ȣ���� ���ִ�.
/// channel_participatn::notifyMsg�� pure virtual funcation�� �����ϰ�
/// ServerSession�� notifyMsg�� �����ؾ� �Ѵ�.
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
    /// channel���� leave�ϸ� shared_ptr�� insert�� client�� erase�Ѵ�.
    /// client�� erase�Ǹ� ServerSession::~ServerSession() destructor�� ȣ��ǰ� 
    /// ServerSession�� destroy�ȴ�. ���� leave�� �ݵ�� ServerSession call stack��
    /// �ֻ����� handleReadHeader�� handleReadBody�� ����ó�� ��ƾ���� ȣ���ؾ��Ѵ�.
    /// �׿��� �ٸ� �ڵ忡�� leave�� ȣ���ϸ� handleReadBody �޼����� ������ �ڵ���
    /// ReadMsgAsync���� segment fault������ �߻��ϸ� wbagent�� ������ ����ȴ�.
    /// remote client�� ������ ��������. 
    /// </summary>
    /// <param name="client"></param>
    void Leave(boost::shared_ptr<ChannelClient> client)
    {
        m_Clients.erase(client);
    }

    // ���� ä�ο� ����� ��� client���� notifyMsg�� call�Ѵ�.
    // ChannelClient::notifyMsg�� ������ ���� ����� �����ȴ�.
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
        BOOST_LOG_TRIVIAL(debug) << "���� ���� (" << GetRemoteIP() << "), �������� Clients : " << m_Channel->getChannelSize();
    }
    inline virtual void Close()
    {
        m_bStop = true;
        m_Channel->Leave(shared_from_this());
        BasicSession::Close();
        BOOST_LOG_TRIVIAL(debug) << "���� ���� (" << GetRemoteIP() << "), �������� Clients : " << m_Channel->getChannelSize();
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
    // ���� TOFF ����. �ϳ��� ���ǿ��� �ѹ��� �´�.
    unsigned int m_nTOFF = 0;
    // ���� TDDD ����. �ϳ��� ���ǿ��� �ѹ��� �´�.
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
    // ���ǵ鰣�� ����� ���� ä��
    GatewayChannel* m_Channel;

    deadline_timer m_TimerDequeRequest;
    boost::mutex m_mutex;
    std::deque<CommandRequest> m_Requests;
    bool m_bStop = false;
    unsigned int m_DequeueFreq = 100;

};
