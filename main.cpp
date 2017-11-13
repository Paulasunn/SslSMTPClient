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
// g++ -o start main.cpp sslsmtpex.cpp sslsmtpex.h -lssl -lcrypto -lresolv -std=c++11 -std=c++14

// Include client
#include "sslsmtpex.h"

using namespace std;

// main - create SSL context and connect
int main(int count, char *strings[])
{ 
    cout << "C++ ssl smtp send email with STARTTLS\r\n";    

    // Attachments
    vector<string> files;
    // files.push_back("file9.jpg");
    // files.push_back("filek.pdf");

    sslsmtpEx sm;
    sm.sslsmtpExSet("localhost", 25); 
    
    // get MX records for recipient
    vector<string> mx = sm.getMX("nanomoow@gmail.com",0,0);

    while(true){
        for (int i = 0; i < mx.size(); i++){
            // Set hostname from mx dns
            sm.sslsmtpExSet(mx.at(i), 25);
            cout << "Mx host: " << mx.at(i) << endl;    
            // send email            
            cout << sm.Send("your@email.xx", "nanomoow@gmail.com", "your@email.xx", "Smtp client test", "<h1>Smtp test</h1>", "<h1>Smtp test</h1>", files) << endl;
        }
        sleep(10);
    }

return 0;    
}
