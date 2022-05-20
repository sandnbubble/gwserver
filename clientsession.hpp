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
            BOOST_LOG_TRIVIAL(debug) << "연결종료(" << hostIP << ")";
            BasicSession::Close();
        }
    }
    /// <summary>
    /// 안전 종료를 위해 진행중인 io_service job들을 완료하고 더 이상 유지하지 않게한다.
    /// 외부에서 io_service.stop을 사용하는 것은 진행중인 job의 완료를 보장할 수 없다.
    /// </summary>
    void Stop()
    {
        m_bStop = true;
    }

    /// <summary>
    /// read timeout을 지정할 수 있는 async_read
    /// </summary>
    /// <param name="pData">수신데이터</param>
    /// <param name="nWriteLen">수신길이</param>
    /// <param name="ec_ret">에러반환값 0:성공, 아니면 실패</param>
    /// <param name="nTimeout">timeout seconds</param>
    /// <returns>성공 true, 실패를 false</returns>
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
    /// 동기모드르 remote로부터 message를 수신한다. default timeout = 3 seconds
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
    // 저장자료요청
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
                            // 수신 데이터의 crc value를 체크하고 수신결과를 전송
                            // async_read_some을 사용하면 body 수신이 완료되지 않은 상태에서 crc에러가 발생하고
                            // handle_read_body는 종료되지 않고 부족한 body를 채울때까지 작업이 지연되는 문제가 있다.
                            // socket_.cancel로는 handle_read_body가 종료되지 않기때문에 이후 모든 수신이 정상적으로
                            // 되지 않는다. 해결할 수 없는 문제일듯.
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
                BOOST_LOG_TRIVIAL(info) << "TDUM 수신 개수 : " << nRecvTDUM;
            }
            Close();
        }
        return;
    }

    // Mediator로 이벤트를 notify하기 위해 mediator referenc를 setup한다. 
    inline void SetMediator(Mediator* mediator) { m_Mediator = mediator; };

private:
    /// <summary>
    /// io_service를 유지하기 위한 complete handler (재귀호출사용)
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
            BOOST_LOG_TRIVIAL(debug) << "연결됨(" << hostIP << ")";
        }
        else
            BOOST_LOG_TRIVIAL(debug) << "연결실패(" << strIP << ")";
        return bRet;
    }
    /// <summary>
    /// 메시지 전송 메서드 함수
    /// 처리할 수 있는 전송 type
    /// 메시지 전송 type 1
    /// 1. 메시지 전송
    /// 2. 메시지 수신 1회 (check crc)
    /// 3. ACK/NAK 전송
    /// 메시지 전송 type 2
    /// 1. 메시지 전송
    /// 2. ACK/NAK 수신
    /// 메시지 전송 type 3
    /// PTIM 명령은 type1을 실행하고 마지막에 EOT를 받아야한다.
    /// </summary>
    /// <param name="msg"></param>
    /// 전송메시지
    /// <param name="bRecvMsg"></param>
    /// bRecvMsg가 true면 수신패킷이 메시지
    /// bRecvMsg가 false면 수신패킷이 ACK/NAK
    /// <param name="bWaitEOT"></param>
    /// bWaitEOT가 true면 EOT가 수신될때까지 3초 wait
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
                    // 수신패킷이 메시지인 경우
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
                            // gateway로 부터 메시지를 수신한 후 Server thread로 전달해서 연결중인 wbadmin에 
                            // 패킷을 전송해야하는데 방법이 없다. Server thread로 메시지를 전송해야하는데 현재
                            // server thread에서 사용하는 특정 큐를 무한 풀링하며 수신된 메시지를 처리하는 방식으로는
                            // 느려터져서 답이 안나올 것으로 예측된다. 스레간에 큐를 사용하지 않고 직접 소켓을 사용하는 
                            // 방법을 찾아야한다. boost에서 제공하는 시그널을 살펴봐야겠다.
                            // 일단 PDUM과 같이 내부에서 송수신을 반복하는 기능을 제외하고 일회성 패킷만을 수신받는
                            // 원격명령을 mediator를 위해 구현해본다.
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
                    // 수신패킷이 ACK,NAK,EOT 형태라면
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
        // EOT를 기다려야 한다면
        if (ret == true && bWaitEOT == true)
        {
            if (ReadPacketSync(m_ReadMsg.GetData(), 1, ec))
            {
                dispACK(GatewayEnum::EOT);
            }
            else
            {
                // EOT를 받지 못할 경우의 로직이 GW프로토콜 문서에 기술되어 있지 않다. 문의 해야함
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
    // BasicSession의 파생클라스에서 정의해야하는 pure virtual function이지만 
    // ClientSession은 사용하지 않기 때문에 dummy method로 정의한다.
    virtual void handleReadHeader(const boost::system::error_code& ec, std::size_t length) {};
    virtual void handleReadBody(const error_code& ec, size_t nReadLen) {}

    /// <summary>
    /// 연결된 대상으로 요청한 결과처리를 전송한다.
    /// GW프로토콜은 header, payload로 구성되어 있는데 이 프로토콜만 예외로 header, payload없이
    /// ACK, NAK, EOT 1 byte만 전송한다. 일반적인 socket programming의 원칙에 어긋나게 설계되어
    /// 있지만 수용할 수 밖에 없는 입장이다. 이것 때문에 header->payload->header->payload 형태로
    /// 수신처리를 하지 못하고 동기로 처리한 부분이 있다. payload까지 완성된 패킷을 수신하고 header없이
    /// 결과를 이 메서드로 보내는 것은 문제가 없지만 ACK, NAK, EOT를 수신받아야 하는 경우는 비동기로
    /// 처리할 수 없다. ACK를 수신 후에 추가적인 전송을 해야 하는 경우가 있기 때문이다.
    /// header가 없이 1byte만을 수신해야하기 때문에 비동기로 수신 받는것이 매우 까다롭다. 
    /// 이 문제를 해결하기위해 ACK,NAK,EOT를 수신받아야하는 경우 동기로 처리하였다.
    /// 전체흐름은 비동기로 하고 전송에 대한 응답을 받는 경우는 iocontext를 수동으로 제어하여
    /// 동기화 루틴을 만들어사용하고 있따.
    /// sendMsg를 참고하기 바란다.
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



