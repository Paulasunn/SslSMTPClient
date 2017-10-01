#include <stdio.h>
#include <unistd.h>
#include <malloc.h>
#include <string.h>
#include <sys/socket.h>
#include <resolv.h>
#include <netdb.h>
// openssl 
#include <openssl/ssl.h>
#include <openssl/err.h>

#define FAIL    -1

// apt-get install libssl-dev openssl
// g++ -o output main.cpp -lssl -lcrypto -lresolv -std=c++11

// Include client
#include <sslsmtpex.h>

using namespace std;

// main - create SSL context and connect
int main(int count, char *strings[])
{ 
    cout << "Start smtp\r\n";    
    // Attachments
    vector<string> files;
    files.push_back("file9.jpg");
    files.push_back("filek.pdf");

    sslsmtpEx smtp = sslsmtpEx("",1);
    bool mailsend1 = smtp.SendAll("<ho@breakermind.com>", "ho@qflash.pl", "<ho@breakermind.com>", "Hello =2C_czy_um=F3wisz_si=EA_ze_mn=B1=3F?=", "Wiadomosć tekstowa dla usera", "<h1>Hello from html msg.</h1>", files);
    cout << " Send email " << mailsend1 << endl;
    
    // SslSMTP smtp = SslSMTP("",25);
    // cout << smtp.Date(1) << endl;
    // smtp.Send("aspmx.l.google.com", "", "", "");
    // add files path
return 0;    
}
