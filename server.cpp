#include <fstream>
#include "server.hpp"

extern bool g_AlwaysNAK;
extern bool g_NoResponse;
extern bool g_bPrintTDUM;

extern "C" int encText(unsigned char* pSrc, unsigned char* pDest);
extern "C" int descText(unsigned char* pSrc, unsigned char* pDest, int nEncLen);

ServerSession::ServerSession(io_service& io_context, greenlink_server* pServer, GatewayChannel* pChannel)
    : BasicSession(io_context), m_pServer(pServer), m_Channel(pChannel)
{
}

ServerSession::~ServerSession()
{
    int nClient = m_Channel->getChannelSize();
    //std::cout << "Client was disconnected (" << GetRemoteIP() << "), connected clients =" << nClient << " in " << __FUNCTION__ << " " << this << std::endl;
}

void ServerSession::Start()
{
    SetRemoteIP(boost::lexical_cast<std::string>(GetSocket().remote_endpoint()));
    m_Channel->Join(shared_from_this());
    readMsgAsync(m_ReadMsg.GetData(), GatewayMessage::HEADER_LENGTH);
}

bool ServerSession::IsWBAdmin(char* pCommandID)
{
    std::string strCommandID = pCommandID;
    // ���ŵ� ����� �Ʒ��� ���� ���� wbadmin->wbiotserver�� ����ó�� 
    if (strCommandID == "PDUM" || strCommandID == "PFST" || strCommandID == "PCNG" || strCommandID == "PSEP" ||
        strCommandID == "PUPG" || strCommandID == "PVER" || strCommandID == "PSET" || strCommandID == "PFCC" ||
        strCommandID == "PAST" || strCommandID == "PFCR" || strCommandID == "PFRS" || strCommandID == "PRSI" || 
        strCommandID == "ULOG")
    {
        return true;
    }
    else
        return false;
}
/// <summary>
/// ����� wbagent_ui�� �޽��� ����
/// �� �޼���� ChannelClient::notifyMsg ���������Լ�
/// notifyMsg�� �������� ������ ������ ������ �߻��Ѵ�.
/// 
/// GatewayChannel -- channel_participient --> basic_session --> ServerSession  (type greenlink)
///           -- channel_participient --> basic_session --> ServerSession  (type wbagent_ui)
///           -- channel_participient --> basic_session --> ServerSession  (type wbagent_ui)
/// wbchennel::broadcast�� m_Channel.broadcast("wbagent_ui", msg)�� ���� call�ϸ� GatewayChannel�� ����� client�� 
/// wbagent_ui type�� client�鿡�� �޽����� broadcasting �ϰԵǰ� wbaget_ui type�� session::notifyMsg�� ����ȴ�.
/// ���� ����ϰ� �ִ� client type�� "greenlink", "wbagent_ui"
/// </summary>
/// <param name="clientid"></param>
/// <param name="msg"></param>
void ServerSession::notifyMsg(std::string client_type, boost::shared_ptr<GatewayMessage> msg)
{
    // broadcast ��� ���ԵǴ��� Ȯ��
    if ((GetClientType() == client_type))
    {
        if (strncmp(msg->GetCommandID(), "STOP", 4) == 0)
        {
            // ��� ������ �����Ѵ�. ����� ������ ����Ǹ� wbagent_ui�� ����ǰ� wbagent�� ���������� �����Ѵ�.
            Close();
        }
        else
        {
            SendPacketAsync(msg->GetData(), msg->GetMsgLength());
        }
    }
}


/// <summary>
/// wbadmin�� wbserver_ui���� ������ ���ݸ�ɿɼ��� �Ľ��ؼ� wbagent�� ������ �޽����� �����Ѵ�.
/// </summary>
/// <param name="strCommand">��ɾ�</param>
/// <param name="strPayload">�ɼ�</param>
/// <returns></returns>
std::string ServerSession::parsePayload(std::string strCommand, std::string strPayload)
{
    std::set<char> delimsOption{ ',' };
    std::vector<std::string> strCommandOptions = convert::SplitString(strPayload, delimsOption);
    std::ostringstream os;
    if (strCommand == "PAST")
    {
        int nItems = atoi(strCommandOptions[0].c_str());
        if (nItems == 0) return "";
        std::string strItems = strCommandOptions[0];
        convert::InsertBlank(strItems, 2);
        os << strItems;
        for (int nItem = 0; nItem < nItems; nItem++)
        {
            int OptionSize[] = { 5, 1, 6, 6, 6 };
            for (int nOption = 0; nOption < 5; nOption++)
            {
                std::string strCommandOption = strCommandOptions[1 + nItem * 5 + nOption];
                convert::InsertBlank(strCommandOption, OptionSize[nOption]);
                os << strCommandOption;
            }
        }
    }
    else if (strCommand == "PSEP")
    {
        // ��й�ȣ ���� ��û
        std::string strPasswd = strCommandOptions[0];
        convert::InsertBlank(strPasswd, 10);
        unsigned char cipherPasswd[16];
        int nLen = encText((unsigned char*)strPasswd.c_str(), cipherPasswd);
        if (nLen > 0)
        {
            std::string strCommandOptions = "";
            strCommandOptions.assign((const char*)cipherPasswd);
            os << strCommandOptions;
        }
    }
    else if (strCommand == "PFRS")
    {
        int nItems = atoi(strCommandOptions[0].c_str());
        if (nItems == 0) return "";
        std::string strItems = strCommandOptions[0];
        convert::InsertBlank(strItems, 2);
        os << strItems;
        for (int nItem = 0; nItem < nItems; nItem++)
        {
            int OptionSize[] = { 5, 5 };
            for (int nOption = 0; nOption < 2; nOption++)
            {
                std::string strCommandOption = strCommandOptions[1 + nItem * 2 + nOption];
                convert::InsertBlank(strCommandOption, OptionSize[nOption]);
                os << strCommandOption;
            }
        }
    }
    else if (strCommand == "PUPG")
    {
        std::ostringstream osPayload;
        // ������ PUPG �������� �׽�Ʈ
        //int OptionSize[] = { 1, 40, 5, 50, 10, 10 };
        int OptionSize[] = { 1, 40, 5, 50, 10, 10, 15 };
        int nMaxOption = sizeof(OptionSize)/sizeof(int);
        for (int nOption = 0; nOption < nMaxOption; nOption++)
        {
            std::string strCommandOption = strCommandOptions[nOption];
            convert::InsertBlank(strCommandOption, OptionSize[nOption]);
            osPayload << strCommandOption;
        }

        unsigned char encData[200] = { 0 };
        int nEncLen = encText((unsigned char*)osPayload.str().c_str(), encData);
        std::string strPayload = "";
        strPayload.assign((const char*)encData, nEncLen);
        os << strPayload;
    }
    else if (strCommand == "PRSI" || strCommand == "URSI")
    {
        std::string strHostIP = strCommandOptions[0];
        convert::InsertBlank(strHostIP, 15);
        unsigned char cipherPasswd[16+1];
        int nLen = encText((unsigned char*)strHostIP.c_str(), cipherPasswd);
        if (nLen > 0)
        {
            std::string strCommandOptions = "";
            strCommandOptions.assign((const char*)cipherPasswd);
            os << strCommandOptions;
        }
    }
    else
    {
        for (std::string cur : strCommandOptions)
        {
            os << cur;
        }
    }
    return os.str();
}

void ServerSession::sendACK(char ack, bool bPrint)
{
    if (g_NoResponse == false)
    {
        char pACK[1 + 1] = { 0 };
        pACK[0] = ack;
        if (g_AlwaysNAK == true)
        {
            pACK[0] = ack = GatewayEnum::NAK;
        }

        write(GetSocket(), buffer(pACK, 1));
        std::string strACK = "";
        switch (ack)
        {
        case GatewayEnum::ACK:
            strACK = "ACK";
            break;
        case GatewayEnum::NAK:
            strACK = "NAK";
            break;
        case GatewayEnum::EOT:
            strACK = "EOT";
            break;
        default:
            BOOST_LOG_TRIVIAL(fatal) << "Unknown ACK";
            return;
        }
        if (bPrint)
            BOOST_LOG_TRIVIAL(debug) << "[TX]" << strACK;
    }
    else
    {
        BOOST_LOG_TRIVIAL(fatal) << "[No Response]";
    }
}

std::string ServerSession::getStrACK(char ack)
{
    std::string strACK = "";
    switch (ack)
    {
    case GatewayEnum::ACK:
        strACK = "ACK";
        break;
    case GatewayEnum::NAK:
        strACK = "NAK";
        break;
    case GatewayEnum::EOT:
        strACK = "EOT";
        break;
    default:
        abort();
    }
    return strACK;
}

void ServerSession::readMsgAsync(char* pData, size_t nReadLen)
{
    // 1����Ʈ ACK, NAK, EOT�� �����ϱ����� async_read_some ���
    GetSocket().async_read_some(
        boost::asio::buffer(pData, nReadLen),
        boost::bind(&ServerSession::handleReadHeader, shared_from_this(), _1, boost::asio::placeholders::bytes_transferred));
    //boost::asio::async_read(GetSocket(),
    //    boost::asio::buffer(pData, nReadLen),
    //    boost::bind(&ServerSession::handleReadHeader, shared_from_this(), placeholders::error, placeholders::bytes_transferred));
}

void ServerSession::handleReadHeader(const boost::system::error_code& ec, std::size_t GetMsgLength)
{
    try
    {
        if (!ec)
        {
            if (GetMsgLength == GatewayMessage::HEADER_LENGTH)
            {
                if (m_ReadMsg.DecodeHeader() == false)
                    THROW_WBAGENT_EXCEPTION_FATAL("Can not parse paceket " + ec.message(), -2);
                boost::asio::async_read(GetSocket(),
                    boost::asio::buffer(m_ReadMsg.GetBody(), m_ReadMsg.GetBodyLength()),
                    boost::bind(&ServerSession::handleReadBody, shared_from_this(), _1, _2));
            }
            else if (GetMsgLength == 1)
            {
                //if (&& ((int)m_ReadMsg.GetData()[0] == GatewayEnum::EOT
                //    || (int)m_ReadMsg.GetData()[0] == GatewayEnum::ACK
                //    || (int)m_ReadMsg.GetData()[0] == GatewayEnum::NAK))
                BOOST_LOG_TRIVIAL(debug) << "[RX]" << getStrACK(m_ReadMsg.GetData()[0]);
                if (m_ReadMsg.GetData()[0] == GatewayEnum::EOT)
                {
                    if (m_nTOFF > 0)
                        BOOST_LOG_TRIVIAL(info) << "TOFF ���� ����: " << m_nTOFF;
                    if (m_nTDDD > 0)
                        BOOST_LOG_TRIVIAL(info) << "TDDD ���� ����: " << m_nTDDD;
                }
                readMsgAsync(m_ReadMsg.GetData(), GatewayMessage::HEADER_LENGTH);
            }
            else
            {
                THROW_WBAGENT_EXCEPTION_FATAL("Unknown packet was received " + ec.message(), -2);
            }

        }
        else
        {
            if (ec != boost::asio::error::operation_aborted)
                THROW_WBAGENT_EXCEPTION_FATAL("Remote client was disconnected" + ec.message(), -2);
        }
    }
    catch (std::exception& e)
    {
        Close();
    }
}

/// <summary>
/// ����Ʈ���̿��� ������ ��Ŷ ó��
/// </summary>
void ServerSession::processGatewayPacket()
{
    BOOST_LOG_TRIVIAL(debug) << "[RX]" << m_ReadMsg.MakeRawPrintString();
    BOOST_LOG_TRIVIAL(info) << m_ReadMsg.MakePrintString();
    // m.ReadMsg�� GatewayMessage ������ CRC�� �߰����� �ʵ��� bAppendCRC�� false�� ����
    boost::shared_ptr<GatewayMessage> msg(new GatewayMessage(m_ReadMsg.GetData(), m_ReadMsg.GetMsgLength(), false));
    m_Channel->BroadcastMsg("wbadmin", msg);

    // WBIoTGATE                    WBServer
    // connect -------------------->
    //         TTIM---------------->
    //         <----------------PTIM  
    //         <----------------EOT
    //         <--------------------disconnect
    if (!strncmp(m_ReadMsg.GetCommandID(), "TTIM", 4))
    {
        sendPTIM();
        sendACK(GatewayEnum::EOT);
        Close();
    }
    else
    {
        if (!strncmp(m_ReadMsg.GetCommandID(), "TOFF", 4))
        {
            // ������ ��带 ���� ���ŵ� TOFF ���� ī��Ʈ
            m_nTOFF++;
        }
        else if (!strncmp(m_ReadMsg.GetCommandID(), "TDDD", 4))
        {
            m_nTDDD++;
        }
        sendACK(GatewayEnum::ACK);
    }
}

/// <summary>
/// WBAdmin���� ������ ULOG�� ���ݸ��ó��
/// </summary>
/// <param name="error"></param>
/// <param name="nReadLen"></param>
void ServerSession::processWBAdminPacket()
{
    if (!strncmp(m_ReadMsg.GetCommandID(), "ULOG", 4))
    {
        // ULOG�� ��� BroadCast ������ ���� type�� ����
        SetClientType("wbadmin");
    }
    else
    {
        // wbagdmin�� ���� ���ݸ���� mediator�� ���� wbagent�� �����Ѵ�.
        std::string strBody = m_ReadMsg.GetBody();
        strBody[strBody.size() - 2] = 0;
        strBody[strBody.size() - 1] = 0;
        std::string strCommandOptions = parsePayload(m_ReadMsg.GetCommandID(), strBody);
        m_Mediator->PushRequest(CommandRequest(m_ReadMsg.GetCommandID(), strCommandOptions, ""));
    }
}

void ServerSession::handleReadBody(const boost::system::error_code& error, size_t nReadLen)
{
    bool bSendACK = true;
    bool ret = false;
    boost::system::error_code ec;

    if (!error)
    {
        m_ReadMsg.GetData()[m_ReadMsg.GetMsgLength()] = 0;
        
        if (IsWBAdmin(m_ReadMsg.GetCommandID()) == false)
        {
            processGatewayPacket();
        }
        else
        {
            processWBAdminPacket();
        }
        readMsgAsync(m_ReadMsg.GetData(), GatewayMessage::HEADER_LENGTH);
    }
    else
    {
        throw WBAgentExceptionFatal("Error: " + error.message());
    }
}

/// <summary>
/// greenlink_client�� pset�� ����
/// </summary>
/// <param name="msg"></param>
/// <returns></returns>
bool ServerSession::sendPTIM()
{
    boost::posix_time::ptime curtime = boost::posix_time::second_clock::local_time();

    int year = curtime.date().year() - 2000;
    int month = curtime.date().month();
    int day = curtime.date().day();
    int hour = curtime.time_of_day().hours();
    int minutes = curtime.time_of_day().minutes();
    int seconds = curtime.time_of_day().seconds();

    std::string dtCur = convert::StringFormat("%02d%02d%02d%02d%02d%02d", year, month, day, hour, minutes, seconds);
    boost::shared_ptr<GatewayMessage> msg(new GatewayMessage("PTIM", "1100001", "001", dtCur.c_str(), dtCur.size()));
    bool ret = false;
    boost::system::error_code ec;
    int msg_len = msg->GetMsgLength();
    char* pData = msg->GetData();
    ret = SendPacketWithTimeout(msg->GetData(), msg->GetMsgLength(), ec);
    if (ret == true)
    {
        ret = ReadPacketSync(m_ReadMsg.GetData(), 1, ec);
        if (ret == true)
        {
            BOOST_LOG_TRIVIAL(debug) << "[RX]" << getStrACK(m_ReadMsg.GetData()[0]);
        }
        else
        {
            std::cout << "Error code " << ec << " " << ec.message() << std::endl;
            std::cout << "Canceled async read operation " << std::endl;
        }
    }
    else
    {
        std::cout << "Error code " << ec << " " << ec.message() << std::endl;
        std::cout << "Canceled async write operation" << std::endl;
    }
    return ret;
}


greenlink_server::greenlink_server(boost::asio::io_service& ioContext, const tcp::endpoint& endPoint)
    : m_IoContext(ioContext),
    m_TimerDequeRequest(ioContext),
    m_Acceptor(ioContext, endPoint)
{
    m_Channel = new GatewayChannel;
    m_TimerDequeRequest.expires_from_now(boost::posix_time::millisec(m_DequeueFreq));
    m_TimerDequeRequest.async_wait(boost::bind(&greenlink_server::dequeueRequest, this));
    listenClient();
}


void greenlink_server::listenClient()
{
    try
    {
        boost::shared_ptr<ServerSession> newSession(new ServerSession(m_IoContext, this, m_Channel));

        m_Acceptor.async_accept(
            newSession->GetSocket(),
            [this, newSession](boost::system::error_code ec)
            {
                if (!ec)
                {
                    newSession->SetMediator(m_Mediator);
                    newSession->Start();
                    std::cout << std::endl << std::endl << std::endl;
                    BOOST_LOG_TRIVIAL(debug) << "�����(" << newSession->GetRemoteIP() << ")";
                }
                listenClient();
            });
    }
    catch (std::exception& e)
    {
        BOOST_LOG_TRIVIAL(fatal) << __FUNCTION__ << ", " << e.what();
    }
}


void greenlink_server::PushRequest(CommandRequest new_request)
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


void greenlink_server::dequeueRequest()
{
    try
    {
        if (!m_Requests.empty())
        {
            CommandRequest curRequest = m_Requests.front();
            std::string command_id = curRequest.GetCommandID();
            std::string strSubCommand1 = "", strSubCommand2 = "";
            curRequest.GetParameter(strSubCommand1, strSubCommand2);
            if (command_id == "TCMD")
            {
                boost::shared_ptr<GatewayMessage> msg(new GatewayMessage(strSubCommand1.data(), strSubCommand1.size(), false));
                GetGatewayChennel()->BroadcastMsg("wbadmin", msg);
            }
            boost::lock_guard<boost::mutex> lock(m_mutex);
            m_Requests.pop_front();
        }
        if (m_bStop == false)
        {
            m_TimerDequeRequest.expires_from_now(boost::posix_time::millisec(m_DequeueFreq));
            m_TimerDequeRequest.async_wait(boost::bind(&greenlink_server::dequeueRequest, this));

        }
    }
    catch (std::exception& e)
    {
        boost::lock_guard<boost::mutex> lock(m_mutex);
        m_Requests.pop_front();
        if (m_bStop == false)
        {
            m_TimerDequeRequest.expires_from_now(boost::posix_time::millisec(m_DequeueFreq));
            m_TimerDequeRequest.async_wait(boost::bind(&greenlink_server::dequeueRequest, this));
        }
        BOOST_LOG_TRIVIAL(warning) << "Excepiton : " << e.what() << "in " << __LINE__ << " " << __FUNCTION__;
    }
}

