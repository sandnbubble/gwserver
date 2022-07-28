// WBIoTServer.cpp : Defines the entry point for the application.
//


#include "gwserver.h"
#include "server.hpp"
#include "clientsession.hpp"
#include "mediator.hpp"

extern "C" int encText(unsigned char* pSrc, unsigned char* pDest);
extern "C" int descText(unsigned char* pSrc, unsigned char* pDest, int nEncLen);

// greenlink server와 greenlink client 모듈은 테스트 에물레이터이기 때문에
// settings를 통해 아래의 전역변수값을 set하지 않고 고정된 값을 사용한다.
char* _client_id = "9900001";
char* _chimney_code = "001";

std::string strIP = "44.151.63.107";
std::string strPort = "9090";
// 테스트버전 포트
std::string strLocalPort = "5010";
bool g_NoResponse = false;
bool g_AlwaysNAK = false;
bool g_bPrintTDUM = false;

typedef struct
{
    std::string strCommand;
    std::string strCommandOption;
}COMMAND_OPTION;

std::vector<COMMAND_OPTION> CommandOptions;
bool loadIni()
{
    try
    {
        CommandOptions.clear();
#ifdef _DEBUG_
        std::ifstream file("/iotgw/bin/gwserver.ini");
#else
        std::ifstream file("gwserver.ini");
#endif
        if (file.is_open())
        {
            std::string strLine;
            std::set<char> delimsCommand{ ' ' }, delimsOption{ ',' };
            while (file)
            {
                strLine = "";
                getline(file, strLine);
                std::vector<std::string> strCommandLine = convert::SplitString(strLine, delimsCommand);
                std::string strCommand = strCommandLine[0];
                if (strCommand[0] == '#' || strCommand.empty())
                    continue;
                COMMAND_OPTION commandOptions;
                commandOptions.strCommand = strCommand;
                commandOptions.strCommandOption = strCommandLine[1];
                CommandOptions.push_back(commandOptions);
            }
            file.close();
            return true;
        }
        else
        {
            std::cout << "설정파일을 찾을 수 없습니다. (gwserver.ini)" << std::endl;
            return false;
        }
    }
    catch (std::exception& e)
    {
        std::cout << e.what() << std::endl;
        return false;
    }
}


std::string DispCommandOptions(std::string strCommand)
{
    for (COMMAND_OPTION cur : CommandOptions)
    {
        if (cur.strCommand == strCommand)
        {
            return cur.strCommand + " " + cur.strCommandOption;
        }
    }
    return strCommand + " [기본값]";
}

std::string GetCommandOptions(std::string strCommand)
{
    for (COMMAND_OPTION cur : CommandOptions)
    {
        if (cur.strCommand == strCommand)
        {
            std::set<char> delimsOption{ ',' };
            std::vector<std::string> strCommandOptions = convert::SplitString(cur.strCommandOption, delimsOption);
            std::ostringstream os;
            if (strCommand == "PAST")
            {
                int nItems = atoi(strCommandOptions[0].c_str());
                if (nItems == 0) break;
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
            else if (strCommand == "PFRS")
            {
                int nItems = atoi(strCommandOptions[0].c_str());
                if (nItems == 0) break;
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
                int OptionSize[] = { 1, 40, 5, 50, 10, 10, 15 };
                for (int nOption = 0; nOption < 7; nOption++)
                {
                    std::string strCommandOption = strCommandOptions[nOption];
                    convert::InsertBlank(strCommandOption, OptionSize[nOption]);
                    os << strCommandOption;
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
    }
    return "";
}

void editCommandOptions()
{
    // CreateProcess를 사용하는 것을 고려해보라고 하지만 의미없다.
#ifdef _DEBUG_
    WinExec("notepad /wbiot/bin/wbtester.ini", SW_NORMAL);
#else
    WinExec("notepad wbtester.ini", SW_NORMAL);
#endif
}

WORD get_colour(boost::log::trivial::severity_level level)
{
    switch (level)
    {
    case boost::log::trivial::trace: return 0x08;
    case boost::log::trivial::debug: return 0x07;
    case boost::log::trivial::info: return 0x0A;
    case boost::log::trivial::warning: return 0x03;
    case boost::log::trivial::error: return 0x0E;
    case boost::log::trivial::fatal: return 0x0C;
    default: return 0x0F;
    }
}

void coloured_console_sink::consume(boost::log::record_view const& rec, string_type const& formatted_string)
{
    auto level = rec.attribute_values()["Severity"].extract<boost::log::trivial::severity_level>();
    auto hstdout = GetStdHandle(STD_OUTPUT_HANDLE);

    CONSOLE_SCREEN_BUFFER_INFO csbi;
    GetConsoleScreenBufferInfo(hstdout, &csbi);

    SetConsoleTextAttribute(hstdout, get_colour(level.get()));
    boost::posix_time::ptime curtime = boost::posix_time::second_clock::local_time();
    int year = curtime.date().year();
    int month = curtime.date().month();
    int day = curtime.date().day();
    int hour = curtime.time_of_day().hours();
    int minutes = curtime.time_of_day().minutes();
    int seconds = curtime.time_of_day().seconds();
    std::string strDateTime = "";
    if (level.get() != boost::log::trivial::trace)
        strDateTime = convert::StringFormat("[%4d-%02d-%02d %02d:%02d:%02d]", year, month, day, hour, minutes, seconds);
    std::cout << strDateTime << formatted_string << std::endl;
    SetConsoleTextAttribute(hstdout, csbi.wAttributes);
}

void DispCommand()
{
    BOOST_LOG_TRIVIAL(trace) << "[ 1]  저장자료요청\t\t\t" << " " << DispCommandOptions("PDUM");
    BOOST_LOG_TRIVIAL(trace) << "[ 2]  미전송자료 전송시간 변경요청\t" << " " << DispCommandOptions("PFST");
    BOOST_LOG_TRIVIAL(trace) << "[ 3]  GW 설정정보 요청\t\t\t" << " " << DispCommandOptions("PCNG");
    BOOST_LOG_TRIVIAL(trace) << "[ 4]  비밀번호 변경 요청\t\t" << " " << DispCommandOptions("PSEP");
    BOOST_LOG_TRIVIAL(trace) << "[ 5]  GW 업그레이드 요청\t\t" << " " << DispCommandOptions("PUPG");
    BOOST_LOG_TRIVIAL(trace) << "[ 6]  버전정보 요청\t\t\t" << " " << DispCommandOptions("PVER");
    BOOST_LOG_TRIVIAL(trace) << "[ 7]  GW 시간 변경 요청\t\t\t" << " " << DispCommandOptions("PSET");
    BOOST_LOG_TRIVIAL(trace) << "[ 8]  시설코드 변경 요청\t\t" << " " << DispCommandOptions("PFCC");
    BOOST_LOG_TRIVIAL(trace) << "[ 9]  측정범위 변경 요청\t\t" << " " << DispCommandOptions("PAST");
    BOOST_LOG_TRIVIAL(trace) << "[10] 방지시설 정상여부 관계정보 요청\t" << " " << DispCommandOptions("PFCR");
    BOOST_LOG_TRIVIAL(trace) << "[11] 방지시설 정상여부 관계정보 변경요청" << " " << DispCommandOptions("PFRS");
    BOOST_LOG_TRIVIAL(trace) << "[12] 통신서버 IP변경 요청\t\t" << " " << DispCommandOptions("PRSI");
    BOOST_LOG_TRIVIAL(trace) << "[e] 설정파일수정, [L] 설정파일적용, [i] WBIoTGATE IP 변경";
    BOOST_LOG_TRIVIAL(trace) << "[N] 강제NAK, [n] 정상NAK, [B] 무응답, [b] 정상응답, [d] 디버그모드, [r] 릴리즈모드 ";
    BOOST_LOG_TRIVIAL(trace) << "q  종료";
}

int RunSystem()
{
    try
    {
        boost::asio::io_service io_context_server;
        boost::asio::io_service io_context_client;
        boost::asio::io_service io_context_mediator;

        // setting for server side
        tcp::endpoint local_endpoint(tcp::v4(), std::atoi(strLocalPort.c_str()));
        // ubuntu에서는 port bind시에 예외가 발생하지만 윈도우에서는 아래코드가 사용중인
        // port를 bind해도 예외가 발생하지 않는 문제가 있어서 뮤텍스를 사용해 중복실행을 방지함.
        // 윈도우에 특정포트를 공유하는 시스템 서비스가 있던 것으로 기억하는데 그걸 막을 수 있는
        // 방법을 찾아볼것
        greenlink_server server(io_context_server, local_endpoint);

        boost::asio::ip::tcp::resolver resolver(io_context_client);
        boost::asio::ip::tcp::resolver::results_type server_endpoints = resolver.resolve(strIP, strPort);
        ClientSession client(io_context_client, server_endpoints);
        Mediator mediator(io_context_mediator, &client, &server);

        // create threads
        boost::thread mediator_thread(boost::bind(&boost::asio::io_service::run, &io_context_mediator));
        boost::thread server_thread(boost::bind(&boost::asio::io_service::run, &io_context_server));

        DispCommand();
        int nkey = '0';
        char pInput[256] = { 0 };
        std::string strInput = "";
        while (1)
        {
            std::cin.getline(pInput, 256);
            strInput = pInput;
            if (strInput.empty())
                continue;
            else if (strInput == "clear")
            {
                std::cout << "\x1B[2J\x1B[H";
            }
            else if (strInput == "i" || strInput == "I")
            {
                std::cout << "Input new host ip[" << strIP << "] ";
                char pLine[256] = { 0 };
                std::cin.getline((char*)pLine, 256);
                std::string strNewHostIP = "";
                strNewHostIP.assign((char*)pLine);
                if (strNewHostIP.empty() == false)
                    strIP = strNewHostIP;
                BOOST_LOG_TRIVIAL(trace) << "Current host ip : " << strIP;
            }
            else if (strInput == "q" || strInput == "Q")
            {
                break;
            }
            else if (strInput == "h" || strInput == "H")
            {
                DispCommand();
            }
            else if (strInput == "e" || strInput == "E")
            {
                editCommandOptions();
            }
            else if (strInput == "l" || strInput == "L")
            {
                loadIni();
                DispCommand();
            }
            else if (strInput == "n")
            {
                g_AlwaysNAK = false;
                BOOST_LOG_TRIVIAL(trace) << "정상적인 응답을 게이트웨이로 전송하게 설정";
            }
            else if (strInput == "N")
            {
                g_AlwaysNAK = true;
                BOOST_LOG_TRIVIAL(trace) << "항상 NAK를 응답으로 게이트웨이로 전송하게 설정";
            }
            else if (strInput == "b")
            {
                g_NoResponse = false;
                BOOST_LOG_TRIVIAL(trace) << "강제 무응답 해제";
            }
            else if (strInput == "B")
            {
                g_NoResponse = true;
                BOOST_LOG_TRIVIAL(trace) << "강제 무응답 설정";
            }
            else if (strInput == "d")
            {
                g_bPrintTDUM = true;
                BOOST_LOG_TRIVIAL(trace) << "디버그 모드";
            }
            else if (strInput == "r")
            {
                g_bPrintTDUM = false;
                BOOST_LOG_TRIVIAL(trace) << "릴리즈 모드";
            }

            else if (strInput == "1")
            {
                // PDUM
                std::string strCommandOptions = GetCommandOptions("PDUM");
                if (strCommandOptions.empty())
                {
                    using days = std::chrono::duration<int, std::ratio_multiply<std::ratio<24>, std::chrono::hours::period>>;
                    using years = std::chrono::duration<int, std::ratio_multiply<std::ratio<146097, 400>, days::period>>;
                    using months = std::chrono::duration<int, std::ratio_divide<years::period, std::ratio<12>>>;
                    auto start = std::chrono::system_clock::now() - days{ 1 };
                    auto end = std::chrono::system_clock::now();
                    std::time_t time_start = std::chrono::system_clock::to_time_t(start);
                    std::time_t time_end = std::chrono::system_clock::to_time_t(end);
                    tm tm_start = *localtime(&time_start);
                    tm tm_end = *localtime(&time_end);
                    strCommandOptions = convert::StringFormat("%02d%02d%02d%02d%02d%02d%02d%02d%02d%02d",
                        tm_start.tm_year + 1900 - 2000, tm_start.tm_mon + 1, tm_start.tm_mday, tm_start.tm_hour, tm_start.tm_min,
                        tm_end.tm_year - 100, tm_end.tm_mon + 1, tm_end.tm_mday, tm_end.tm_hour, tm_end.tm_min);
                }
                mediator.PushRequest(CommandRequest("PDUM", strCommandOptions, ""));
            }
            else if (strInput == "2")
            {
                // PFST
                std::string strCommandOptions = GetCommandOptions("PFST");
                if (strCommandOptions.empty())
                {
                    BOOST_LOG_TRIVIAL(fatal) << "Can not found PFST options" << std::endl;
                    break;
                }
                mediator.PushRequest(CommandRequest("PFST", strCommandOptions, ""));
            }
            else if (strInput == "3")
            {
                // GW 설정정보 요청
                mediator.PushRequest(CommandRequest("PCNG", "", ""));
            }
            else if (strInput == "4")
            {
                // 비밀번호 변경 요청
                std::string strPasswd = GetCommandOptions("PSEP");
                convert::InsertBlank(strPasswd, 10);
                unsigned char cipherPasswd[16];
                int nLen = encText((unsigned char*)strPasswd.c_str(), cipherPasswd);
                if (nLen > 0)
                {
                    std::string strCommandOptions = "";
                    strCommandOptions.assign((const char*)cipherPasswd);
                    mediator.PushRequest(CommandRequest("PSEP", strCommandOptions, ""));
                }
            }
            else if (strInput == "5")
            {
                std::stringstream os;
                std::string strCommandOptions = GetCommandOptions("PUPG");
                if (strCommandOptions.empty())
                {
                    char type = '1';
                    std::string ftp_ip = "192.168.1.100";
                    std::string ftp_port = "22";
                    std::string path = "/download/gateway.exe";
                    std::string id = "user";
                    std::string passwd = "password";
                    std::string server_ip = "192.168.1.100";
                    // 왼쪽 정렬하고 남은 오른쪽부분은 공백문자로 패딩
                    convert::InsertBlank(ftp_ip, 40);
                    convert::InsertBlank(ftp_port, 5);
                    convert::InsertBlank(path, 50);
                    convert::InsertBlank(id, 10);
                    convert::InsertBlank(passwd, 10);
                    convert::InsertBlank(server_ip, 15);
                    os << type << ftp_ip << ftp_port << path << id << passwd << server_ip;
                    strCommandOptions = os.str();
                }
                unsigned char encData[200] = { 0 };
                int nEncLen = encText((unsigned char*)strCommandOptions.c_str(), encData);
                strCommandOptions = "";
                strCommandOptions.assign((const char*)encData, nEncLen);
                mediator.PushRequest(CommandRequest("PUPG", strCommandOptions, ""));
            }
            else if (strInput == "6")
            {
                mediator.PushRequest(CommandRequest("PVER", "", ""));
            }
            else if (strInput == "7")
            {
                std::string strCommandOptions = GetCommandOptions("PSET");
                if (strCommandOptions.empty())
                {
                    boost::posix_time::ptime curtime = boost::posix_time::second_clock::local_time();

                    int year = curtime.date().year() - 2000;
                    int month = curtime.date().month();
                    int day = curtime.date().day();
                    int hour = curtime.time_of_day().hours();
                    int minutes = curtime.time_of_day().minutes();
                    int seconds = curtime.time_of_day().seconds();
                    strCommandOptions = convert::StringFormat("%02d%02d%02d%02d%02d%02d", year, month, day, hour, minutes, seconds);
                }
                mediator.PushRequest(CommandRequest("PSET", strCommandOptions, ""));
            }
            else if (strInput == "8")
            {
                // 시설코드 변경 요청
                std::string strCommandOptions = GetCommandOptions("PFCC");
                mediator.PushRequest(CommandRequest("PFCC", strCommandOptions, ""));
            }
            else if (strInput == "9")
            {
                // 측정범위변경요청
                std::string strCommandOptions = GetCommandOptions("PAST");
                if (strCommandOptions.empty()) break;
                mediator.PushRequest(CommandRequest("PAST", strCommandOptions, ""));
            }
            else if (strInput == "10")
            {
                // 방지시설 정상여부 관계정보 요청
                mediator.PushRequest(CommandRequest("PFCR", "", ""));
            }
            else if (strInput == "11")
            {
                std::string strCommandOptions = GetCommandOptions("PFRS");
                if (strCommandOptions.empty()) break;
                mediator.PushRequest(CommandRequest("PFRS", strCommandOptions, ""));
            }
            else if (strInput == "12")
            {
                // 통신서버 IP 변경요청
                std::string strCommandOptions = GetCommandOptions("PRSI");
                if (strCommandOptions.empty())
                {
                    strCommandOptions = "192.168.1.100";
                }
                unsigned char pEncHostIP[16 + 1] = { 0 };
                convert::InsertBlank(strCommandOptions, 15);
                int nEncLen = encText((unsigned char*)strCommandOptions.c_str(), pEncHostIP);
                strCommandOptions = "";
                strCommandOptions.assign((const char*)pEncHostIP);
                mediator.PushRequest(CommandRequest("PRSI", strCommandOptions, ""));
            }
            else if (strInput == "a" || strInput == "A")
            {
                std::string strCommandOptions = GetCommandOptions("PDUM");
                if (strCommandOptions.empty())
                {
                    using days = std::chrono::duration<int, std::ratio_multiply<std::ratio<24>, std::chrono::hours::period>>;
                    using years = std::chrono::duration<int, std::ratio_multiply<std::ratio<146097, 400>, days::period>>;
                    using months = std::chrono::duration<int, std::ratio_divide<years::period, std::ratio<12>>>;
                    auto start = std::chrono::system_clock::now() - days{ 1 };
                    auto end = std::chrono::system_clock::now();
                    std::time_t time_start = std::chrono::system_clock::to_time_t(start);
                    std::time_t time_end = std::chrono::system_clock::to_time_t(end);
                    tm tm_start = *localtime(&time_start);
                    tm tm_end = *localtime(&time_end);
                    strCommandOptions = convert::StringFormat("%02d%02d%02d%02d%02d%02d%02d%02d%02d%02d",
                        tm_start.tm_year + 1900 - 2000, tm_start.tm_mon + 1, tm_start.tm_mday, tm_start.tm_hour, tm_start.tm_min,
                        tm_end.tm_year - 100, tm_end.tm_mon + 1, tm_end.tm_mday, tm_end.tm_hour, tm_end.tm_min);
                }
                mediator.PushRequest(CommandRequest("PDUM", strCommandOptions, ""));

                strCommandOptions = GetCommandOptions("PFST");
                if (strCommandOptions.empty())
                {
                    BOOST_LOG_TRIVIAL(fatal) << "Can not found PFST options" << std::endl;
                    break;
                }
                mediator.PushRequest(CommandRequest("PFST", strCommandOptions, ""));
                mediator.PushRequest(CommandRequest("PCNG", "", ""));

                std::string strPasswd = GetCommandOptions("PSEP");
                convert::InsertBlank(strPasswd, 10);
                unsigned char cipherPasswd[16];
                int nLen = encText((unsigned char*)strPasswd.c_str(), cipherPasswd);
                if (nLen > 0)
                {
                    std::string strCommandOptions = "";
                    strCommandOptions.assign((const char*)cipherPasswd);
                    mediator.PushRequest(CommandRequest("PSEP", strCommandOptions, ""));
                }
                strCommandOptions = GetCommandOptions("PSET");
                if (strCommandOptions.empty())
                {
                    boost::posix_time::ptime curtime = boost::posix_time::second_clock::local_time();

                    int year = curtime.date().year() - 2000;
                    int month = curtime.date().month();
                    int day = curtime.date().day();
                    int hour = curtime.time_of_day().hours();
                    int minutes = curtime.time_of_day().minutes();
                    int seconds = curtime.time_of_day().seconds();
                    strCommandOptions = convert::StringFormat("%02d%02d%02d%02d%02d%02d", year, month, day, hour, minutes, seconds);
                }
                mediator.PushRequest(CommandRequest("PSET", strCommandOptions, ""));
                strCommandOptions = GetCommandOptions("PFCC");
                mediator.PushRequest(CommandRequest("PFCC", strCommandOptions, ""));
                strCommandOptions = GetCommandOptions("PAST");
                mediator.PushRequest(CommandRequest("PAST", strCommandOptions, ""));
                mediator.PushRequest(CommandRequest("PFCR", "", ""));
                mediator.PushRequest(CommandRequest("PVER", "", ""));
                strCommandOptions = GetCommandOptions("PRSI");
                if (strCommandOptions.empty())
                {
                    strCommandOptions = "192.168.1.100";
                }
                unsigned char pEncHostIP[16 + 1] = { 0 };
                convert::InsertBlank(strCommandOptions, 15);
                int nEncLen = encText((unsigned char*)strCommandOptions.c_str(), pEncHostIP);
                strCommandOptions = "";
                strCommandOptions.assign((const char*)pEncHostIP);
                mediator.PushRequest(CommandRequest("PRSI", strCommandOptions, ""));
                strCommandOptions = GetCommandOptions("PUPG");
                if (strCommandOptions.empty())
                {
                    std::stringstream os;
                    char type = '1';
                    std::string ftp_ip = "192.168.1.100";
                    std::string ftp_port = "22";
                    std::string path = "/download/gateway.exe";
                    std::string id = "user";
                    std::string passwd = "password";
                    std::string server_ip = "192.168.1.100";
                    // 왼쪽 정렬하고 남은 오른쪽부분은 공백문자로 패딩
                    convert::InsertBlank(ftp_ip, 40);
                    convert::InsertBlank(ftp_port, 5);
                    convert::InsertBlank(path, 50);
                    convert::InsertBlank(id, 10);
                    convert::InsertBlank(passwd, 10);
                    convert::InsertBlank(server_ip, 15);
                    os << type << ftp_ip << ftp_port << path << id << passwd << server_ip;
                    strCommandOptions = os.str();
                }
                unsigned char encData[200] = { 0 };
                nEncLen = encText((unsigned char*)strCommandOptions.c_str(), encData);
                strCommandOptions = "";
                strCommandOptions.assign((const char*)encData);
                mediator.PushRequest(CommandRequest("PUPG", strCommandOptions, ""));
                strCommandOptions = GetCommandOptions("PFRS");
                mediator.PushRequest(CommandRequest("PFRS", strCommandOptions, ""));
            }
        }
        mediator.Stop();
        mediator_thread.join();
        io_context_server.stop();
        server_thread.join();
        return nkey;
    }
    catch (std::exception& e)
    {
        std::cerr << "Exception: " << e.what() << "\n";
    }
}

int Close(HANDLE hHandle)
{
    ReleaseMutex(hHandle); // Explicitly release mutex
    CloseHandle(hHandle); // close handle before terminating
    return(1);
}

int main(int argc, char* argv[])
{
    const char szUniqueNamedMutex[] = "gwserver.exe";
    HANDLE hHandle = CreateMutex(NULL, TRUE, szUniqueNamedMutex);
    if (ERROR_ALREADY_EXISTS == GetLastError())
    {
        // Program already running somewhere
        std::cerr << "gwserver.exe already is running. This program cannot be run multiple times." << std::endl;
        return(1); // Exit program
    }

    if (argc != 4)
    {
        std::cerr << "Usage: gwserver <gwf100 ip> <gwf100 port> <local port>\n";
    }
    else
    {
        strIP = argv[1];
        strPort = argv[2];
        strLocalPort = argv[3];
    }

    if (loadIni() == false)
    {
        return Close(hHandle);
    }
    typedef boost::log::sinks::synchronous_sink<coloured_console_sink> coloured_console_sink_t;
    auto coloured_console_sink = boost::make_shared<coloured_console_sink_t>();
    boost::log::core::get()->add_sink(coloured_console_sink);

    int nKey = RunSystem();
    return Close(hHandle);
}