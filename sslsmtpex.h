#ifndef SSLSMTPEX_H
#define SSLSMTPEX_H

#include <vector>
#include <stdio.h>
#include <unistd.h>
#include <malloc.h>
#include <string>
#include <resolv.h>
#include <netdb.h>
#include <iostream>
#include <openssl/ssl.h>
#include <openssl/err.h>
// quoted
#include <iomanip>
#include <sstream>
// socket time out
#include <sys/types.h>
#include <sys/socket.h>

// fstream
#include <fstream>
#include <cerrno>
// signals errors

#define FAIL    -1

// ---- DNS PART
#include <signal.h>
#include <string>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <netinet/in.h>
#include <resolv.h>
#include <netdb.h>
#include <iostream>
#include <fstream>
#include <time.h>
#include <vector>

#include <iostream>
#include <regex>
// ip address
#include <sstream>
#include <arpa/inet.h>
// find
#include <algorithm>

#define N 4096
#define MST (-2)

using namespace std;

class sslsmtpEx
{
private:
    int Port = 25;
    std::string HostnameMX = "localhost";
public:
    sslsmtpEx(string hostnameMX, int port);
    // Create mime message and send
    int Send();
    // ssl client
    bool SendMIME(string from, string to,string mimeDATA);
    bool Send(string from, string to, string replyto, string subject, string msg, string msghtml, vector<string> files);
    int OpenConnection(const char *hostname, int port);
    void socketTimeout(int sd, int timeoutseconds);
    SSL_CTX* InitCTX(void);
    void ShowCerts(SSL* ssl);
    void sslError(SSL *ssl, int received);
    void quoted(std::string str);
    string Date(bool utc = 0);
    string fileBasename(string path);
    std::string getFileContent(const std::string& path);
    std::string get_file_contents(const char *filename);
    // file mime type
    const char* GetMimeTypeFromFileName( char* szFileExt);
    string GetFileExtension(const std::string& FileName);
    bool Contain(std::string str, std::string search);
    static const char MimeTypes[][2][128];

    // Send email to external server
    bool SendAll(string from, string to, string mimeDATA);

    // --------------- DNS PART
    bool DnsSPFvalidIP(string host, string ip);
    void DnsMX(std::string domain);
    vector<string> DnsTXT(std::string domain);

    vector<string> getMX(std::string email, int show, int logToFile);
    std::string hostnameIP(std::string hostname);
    bool validIPv4(const string& str);
    bool validIPv6(const string& str);
    vector<string> splitDelimiter(string str, string delim);

    // ------------------ BASE64
    std::string base64_encode(unsigned char const* , unsigned int len);
    std::string base64_encode(std::string str , unsigned int len);
    std::string base64_encode(std::string str);
    std::string base64_decode(std::string const& s);
    static const std::string base64_chars;
    static inline bool is_base64(unsigned char c);

};


#endif // SSLSMTPEX_H
