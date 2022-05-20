#pragma once

#include <boost/bind.hpp>
#include <boost/thread/thread.hpp>

#include "../wbagent/sharedinclude/mysqlfunc.hpp"
#include "../wbagent/sharedinclude/settings.hpp"
#include "../wbagent/sharedinclude/basic_session.hpp"
#include "mediator.hpp"
#include <mutex>

class Settings;
class Mediator;

extern std::string strIP;
extern bool g_NoResponse;
extern bool g_AlwaysNAK;
extern bool g_bPrintTDUM;

class ClientSession : public  BasicSession
{
public:

    ClientSession(io_service& io_context, const tcp::resolver::iterator& endpoints)
        : BasicSession(io_context, endpoints),
        m_EndPoint(endpoints),
        m_WaitTimer(io_context),
        m_Mediator(nullptr)
    {
        m_ClientID = "9900001";
        m_ChimneyCode = "001";

        m_WaitTimer.expires_from_now(boost::posix_time::seconds(1));
        m_WaitTimer.async_wait(boost::bind(&ClientSession::idleHandler, this, 1));
    }


    ~ClientSession()
    {
        BOOST_LOG_TRIVIAL(info) << "Completed client mission";
    }

    void Close()
    {
        if (GetSocket().is_open())
        {
            std::string hostIP = boost::lexical_cast<std::string>(GetSocket().remote_endpoint());
            BOOST_LOG_TRIVIAL(debug) << "��������(" << hostIP << ")";
            BasicSession::Close();
        }
    }
    /// <summary>
    /// ���� ���Ḧ ���� �������� io_service job���� �Ϸ��ϰ� �� �̻� �������� �ʰ��Ѵ�.
    /// �ܺο��� io_service.stop�� ����ϴ� ���� �������� job�� �ϷḦ ������ �� ����.
    /// </summary>
    void Stop()
    {
        m_bStop = true;
    }

    /// <summary>
    /// read timeout�� ������ �� �ִ� async_read
    /// </summary>
    /// <param name="pData">���ŵ�����</param>
    /// <param name="nWriteLen">���ű���</param>
    /// <param name="ec_ret">������ȯ�� 0:����, �ƴϸ� ����</param>
    /// <param name="nTimeout">timeout seconds</param>
    /// <returns>���� true, ���и� false</returns>
    size_t ReadPacketSync(char* pData, size_t nReadLen, error_code& ecRet, int nTimeout = 30)
    {
        size_t readLen = 0;
        ecRet = boost::asio::error::would_block;

        GetDeadlineTimer().expires_from_now(boost::posix_time::seconds(nTimeout));
        GetDeadlineTimer().async_wait([this](error_code ec)
            {
                if (ec != error::operation_aborted)
                {
                    GetSocket().cancel();
                }
            });
        try
        {
            GetSocket().async_read_some(
                boost::asio::buffer(pData, nReadLen),
                [&](error_code ec, std::size_t nLen) { ecRet = ec; readLen = nLen; });
        }
        catch (std::exception& e)
        {
            std::cout << e.what() << std::endl;
            return 0;
        }
        do { GetIoContext().run_one(); } while (ecRet == boost::asio::error::would_block);
        if (ecRet)
        {
            BOOST_LOG_TRIVIAL(error) << ecRet.message() << " " << __LINE__ << " in " << __FUNCTION__ << " " << __FILE__;
            return 0;
        }
        return readLen;
    }

    /// <summary>
    /// �����帣 remote�κ��� message�� �����Ѵ�. default timeout = 3 seconds
    /// </summary>
    /// <returns></returns>
    size_t ReadMsgSync()
    {
        size_t nPayloadLen = 0;
        boost::system::error_code ec;
        size_t nHeaderLen = ReadPacketSync(m_ReadMsg.GetData(), GatewayMessage::HEADER_LENGTH, ec);
        if (nHeaderLen == GatewayMessage::HEADER_LENGTH)
        {
            if (m_ReadMsg.DecodeHeader())
            {
                nPayloadLen = ReadPacketSync(m_ReadMsg.GetBody(), m_ReadMsg.GetBodyLength(), ec);
                return nHeaderLen + nPayloadLen;
            }
            else
                return 0;
        }
        else
            return nHeaderLen;
    }

    bool SendMsg(boost::shared_ptr<GatewayMessage> msg, bool bRecvMsg, bool bWaitEOT, bool bSendEOT, int& nResult)
    {
        return sendMsg(msg, bRecvMsg, bWaitEOT, bSendEOT, nResult);
    }
    // �����ڷ��û
    void sendPDUM(boost::shared_ptr<GatewayMessage> msg)
    {
        bool bRet = false;
        if (Connect() == true)
        {
            bool ret = false;
            boost::system::error_code ec;
            size_t nRecvTDUM = 0;
            BOOST_LOG_TRIVIAL(debug) << "[TX]" << msg->MakeRawPrintString();
            BOOST_LOG_TRIVIAL(info) << msg->MakePrintString();
            ret = SendPacketWithTimeout(msg->GetData(), msg->GetMsgLength(), ec);
            if (ret == true)
            {
                for (;;)
                {
                    ret = ReadMsgSync();
                    if (ret != 0)
                    {
                        if (m_ReadMsg.GetData()[0] == GatewayEnum::EOT)
                            break;
                        else
                        {
                            // ���� �������� crc value�� üũ�ϰ� ���Ű���� ����
                            // async_read_some�� ����ϸ� body ������ �Ϸ���� ���� ���¿��� crc������ �߻��ϰ�
                            // handle_read_body�� ������� �ʰ� ������ body�� ä�ﶧ���� �۾��� �����Ǵ� ������ �ִ�.
                            // socket_.cancel�δ� handle_read_body�� ������� �ʱ⶧���� ���� ��� ������ ����������
                            // ���� �ʴ´�. �ذ��� �� ���� �����ϵ�.
                            m_ReadMsg.GetData()[m_ReadMsg.GetMsgLength()] = 0;
                            bool bRet = m_ReadMsg.CheckCRC();
                            char ack_value = GatewayEnum::ACK;
                            if (bRet)
                            {
                                if (g_bPrintTDUM == true)
                                {
                                    BOOST_LOG_TRIVIAL(debug) << "[RX]" << m_ReadMsg.MakeRawPrintString();
                                    BOOST_LOG_TRIVIAL(info) << m_ReadMsg.MakePrintString();
                                }
                                if (g_AlwaysNAK)
                                    ack_value = GatewayEnum::NAK;
                                else
                                    ack_value = GatewayEnum::ACK;
                                nRecvTDUM++;
                            }
                            else
                                ack_value = GatewayEnum::NAK;
                            sendACK(ack_value, false);
                        }
                    }
                    else
                    {
                        BOOST_LOG_TRIVIAL(fatal) << "Error code " << ec << " " << ec.message() << std::endl;
                        BOOST_LOG_TRIVIAL(fatal) << "Canceled async read operation " << std::endl;
                        break;
                    }
                }
                BOOST_LOG_TRIVIAL(info) << "TDUM ���� ���� : " << nRecvTDUM;
            }
            Close();
        }
        return;
    }

    // Mediator�� �̺�Ʈ�� notify�ϱ� ���� mediator referenc�� setup�Ѵ�. 
    inline void SetMediator(Mediator* mediator) { m_Mediator = mediator; };

private:
    /// <summary>
    /// io_service�� �����ϱ� ���� complete handler (���ȣ����)
    /// </summary>
    /// <param name="timeout"></param>
    void idleHandler(size_t timeout)
    {
        if (m_bStop == true) return;

        m_WaitTimer.expires_from_now(boost::posix_time::seconds(timeout));
        m_WaitTimer.async_wait(boost::bind(&ClientSession::idleHandler, this, timeout));
    }

    bool Connect()
    {
        bool bRet = BasicSession::Connect(strIP, "9090");
        if (bRet == true)
        {
            std::string hostIP = boost::lexical_cast<std::string>(GetSocket().remote_endpoint());
            std::cout << std::endl << std::endl << std::endl;
            BOOST_LOG_TRIVIAL(debug) << "�����(" << hostIP << ")";
        }
        else
            BOOST_LOG_TRIVIAL(debug) << "�������(" << strIP << ")";
        return bRet;
    }
    /// <summary>
    /// �޽��� ���� �޼��� �Լ�
    /// ó���� �� �ִ� ���� type
    /// �޽��� ���� type 1
    /// 1. �޽��� ����
    /// 2. �޽��� ���� 1ȸ (check crc)
    /// 3. ACK/NAK ����
    /// �޽��� ���� type 2
    /// 1. �޽��� ����
    /// 2. ACK/NAK ����
    /// �޽��� ���� type 3
    /// PTIM ����� type1�� �����ϰ� �������� EOT�� �޾ƾ��Ѵ�.
    /// </summary>
    /// <param name="msg"></param>
    /// ���۸޽���
    /// <param name="bRecvMsg"></param>
    /// bRecvMsg�� true�� ������Ŷ�� �޽���
    /// bRecvMsg�� false�� ������Ŷ�� ACK/NAK
    /// <param name="bWaitEOT"></param>
    /// bWaitEOT�� true�� EOT�� ���ŵɶ����� 3�� wait
    /// <returns>ACK, NAK, EOT</returns>
    bool sendMsg(boost::shared_ptr<GatewayMessage> msg, bool bRecvMsg, bool bWaitEOT, bool bSendEOT, int &nResult)
    {
        if (Connect() == false)
            return false;
        bool ret = false;
        boost::system::error_code ec;
        size_t nWritten = 0;
        for (int retry = 0; retry < 2; retry++)
        {
            ret = SendPacketWithTimeout(msg->GetData(), msg->GetMsgLength(), ec);
            if (ret == true)
            {
                BOOST_LOG_TRIVIAL(debug) << "[TX]" << msg->MakeRawPrintString();
                if (bRecvMsg)
                {
                    // ������Ŷ�� �޽����� ���
                    ret = ReadMsgSync();
                    if (ret != 0)
                    {
                        m_ReadMsg.GetData()[m_ReadMsg.GetMsgLength()] = 0;
                        bool bRet = m_ReadMsg.CheckCRC();
                        char ack_value = GatewayEnum::ACK;
                        if (bRet)
                        {
                            BOOST_LOG_TRIVIAL(debug) << "[RX]" << m_ReadMsg.MakeRawPrintString();
                            BOOST_LOG_TRIVIAL(info) << m_ReadMsg.MakePrintString();
                            if (g_AlwaysNAK)
                                ack_value = GatewayEnum::NAK;
                            else
                                ack_value = GatewayEnum::ACK;
                            sendACK(ack_value);
                            // gateway�� ���� �޽����� ������ �� Server thread�� �����ؼ� �������� wbadmin�� 
                            // ��Ŷ�� �����ؾ��ϴµ� ����� ����. Server thread�� �޽����� �����ؾ��ϴµ� ����
                            // server thread���� ����ϴ� Ư�� ť�� ���� Ǯ���ϸ� ���ŵ� �޽����� ó���ϴ� ������δ�
                            // ���������� ���� �ȳ��� ������ �����ȴ�. �������� ť�� ������� �ʰ� ���� ������ ����ϴ� 
                            // ����� ã�ƾ��Ѵ�. boost���� �����ϴ� �ñ׳��� ������߰ڴ�.
                            // �ϴ� PDUM�� ���� ���ο��� �ۼ����� �ݺ��ϴ� ����� �����ϰ� ��ȸ�� ��Ŷ���� ���Ź޴�
                            // ���ݸ���� mediator�� ���� �����غ���.
                            m_Mediator->PushRequest(CommandRequest(m_ReadMsg.GetCommandID(), m_ReadMsg.GetData(), ""));
                            break;
                        }
                        else
                            sendACK(GatewayEnum::NAK);
                    }
                    else
                    {
                        BOOST_LOG_TRIVIAL(fatal) << "Error code " << ec << " " << ec.message() << std::endl;
                        BOOST_LOG_TRIVIAL(fatal) << "Canceled async read operation " << std::endl;
                        break;
                    }
                }
                else
                {
                    // ������Ŷ�� ACK,NAK,EOT ���¶��
                    if (ReadPacketSync(m_ReadMsg.GetData(), 1, ec, 70))
                    {
                        nResult = (int)m_ReadMsg.GetData()[0];
                        dispACK(nResult);
                        if (nResult == GatewayEnum::ACK)
                        {
                            ret = true;
                            break;
                        }
                        else if (nResult == GatewayEnum::NAK)
                        {
                            ret = false;
                            nResult = GatewayEnum::NAK;
                        }
                        else
                        {
                            ret = false;
                            nResult = GatewayEnum::UNKNOWN_ACK;
                        }
                    }
                    else
                    {
                        ret = false;
                        nResult = GatewayEnum::TIMEOUT;
                        BOOST_LOG_TRIVIAL(warning) << ec.message() << " " << __LINE__ << " in " << __FUNCTION__ << " " << __FILE__;
                    }
                }
            }
            else
            {
                nResult = GatewayEnum::TIMEOUT;
                BOOST_LOG_TRIVIAL(error) << "Canceled async write operation(retry count : " << retry + 1 << ")" << ec << " " << ec.message()
                    << " " << __LINE__ << " in " << __FUNCTION__ << " " << __FILE__;
            }
        }
        // EOT�� ��ٷ��� �Ѵٸ�
        if (ret == true && bWaitEOT == true)
        {
            if (ReadPacketSync(m_ReadMsg.GetData(), 1, ec))
            {
                dispACK(GatewayEnum::EOT);
            }
            else
            {
                // EOT�� ���� ���� ����� ������ GW�������� ������ ����Ǿ� ���� �ʴ�. ���� �ؾ���
                ret = false;
                nResult = GatewayEnum::TIMEOUT;
                BOOST_LOG_TRIVIAL(error) << "Failed to receive EOT " << __LINE__ << " in " << __FUNCTION__;
            }
        }

        if (bSendEOT == true)
        {
            sendACK(GatewayEnum::EOT);
        }
        Close();
        return ret;
    }
    // BasicSession�� �Ļ�Ŭ�󽺿��� �����ؾ��ϴ� pure virtual function������ 
    // ClientSession�� ������� �ʱ� ������ dummy method�� �����Ѵ�.
    virtual void handleReadHeader(const boost::system::error_code& ec, std::size_t length) {};
    virtual void handleReadBody(const error_code& ec, size_t nReadLen) {}

    /// <summary>
    /// ����� ������� ��û�� ���ó���� �����Ѵ�.
    /// GW���������� header, payload�� �����Ǿ� �ִµ� �� �������ݸ� ���ܷ� header, payload����
    /// ACK, NAK, EOT 1 byte�� �����Ѵ�. �Ϲ����� socket programming�� ��Ģ�� ��߳��� ����Ǿ�
    /// ������ ������ �� �ۿ� ���� �����̴�. �̰� ������ header->payload->header->payload ���·�
    /// ����ó���� ���� ���ϰ� ����� ó���� �κ��� �ִ�. payload���� �ϼ��� ��Ŷ�� �����ϰ� header����
    /// ����� �� �޼���� ������ ���� ������ ������ ACK, NAK, EOT�� ���Ź޾ƾ� �ϴ� ���� �񵿱��
    /// ó���� �� ����. ACK�� ���� �Ŀ� �߰����� ������ �ؾ� �ϴ� ��찡 �ֱ� �����̴�.
    /// header�� ���� 1byte���� �����ؾ��ϱ� ������ �񵿱�� ���� �޴°��� �ſ� ��ٷӴ�. 
    /// �� ������ �ذ��ϱ����� ACK,NAK,EOT�� ���Ź޾ƾ��ϴ� ��� ����� ó���Ͽ���.
    /// ��ü�帧�� �񵿱�� �ϰ� ���ۿ� ���� ������ �޴� ���� iocontext�� �������� �����Ͽ�
    /// ����ȭ ��ƾ�� ��������ϰ� �ֵ�.
    /// sendMsg�� �����ϱ� �ٶ���.
    /// </summary>
    /// <param name="ack">enum { ACK = 0x06, NAK = 0x15, EOT = 0x04 }</param>
    void sendACK(char ack, bool bPrint=true)
    {
        if (g_NoResponse == false)
        {
            char pACK[1 + 1] = { 0 };
            pACK[0] = ack;
            if (g_AlwaysNAK == true)
            {
                pACK[0] = ack = GatewayEnum::NAK;
            }
            boost::asio::write(GetSocket(), boost::asio::buffer(pACK, 1));
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
            if (bPrint == true)
                BOOST_LOG_TRIVIAL(debug) << "[TX]" << strACK;
        }
        else
        {
            BOOST_LOG_TRIVIAL(fatal) << "[NoResponse is true]";
        }
    }

    void dispACK(char ack)
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
            strACK = "Unknown ACK";
            return;
        }
        BOOST_LOG_TRIVIAL(debug) << "[RX]" << strACK;
    }


private:
    bool m_bStop = false;
    deadline_timer m_WaitTimer;
    GatewayMessage m_ReadMsg;
    std::string m_ClientID;
    std::string m_ChimneyCode;
    Mediator* m_Mediator;
    tcp::resolver::iterator m_EndPoint;
};



