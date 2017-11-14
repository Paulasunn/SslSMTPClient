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

// apt-get install libssl-dev openssl
// g++ -o start main.cpp sslsmtpex.cpp sslsmtpex.h -lssl -lresolv -lcrypto -sd=c++11 -std=c++14

// Include client
#include "sslsmtpex.h"

using namespace std;

// main - create SSL context and connect
int main(int count, char *strings[])
{ 
    cout << "C++ ssl smtp send email with STARTTLS\r\n";    

    // Add attachments to message if you want
    vector<string> files;
    // files.push_back("file9.jpg");
    // files.push_back("filek.pdf");

    // Initialize
    sslsmtpEx sm;
    sm.sslsmtpExSet("localhost", 25); 

    // EHLO hostname
    sm.heloHostname("qflash.pl");

    // Display logs
    // sm.showLogs();
    
    // get MX records from dns for recipient
    vector<string> mx = sm.getMX("nanomoow@gmail.com",0,0);

	// Send email to each mx host from recipient domain DNS ( You need send only to one server !!! )
    for (int i = 0; i < mx.size(); i++){
        
        // Set hostname from mx dns
        sm.sslsmtpExSet(mx.at(i), 25);
        cout << "Mx host: " << mx.at(i) << endl;    

        // send email
        int ok = sm.Send("email@qflash.pl", "nanomoow@gmail.com", "email@qflash.pl", "Smtp client test", "<h1>Smtp test</h1>", "<h1>Smtp test</h1>", files);

        cout << "Email has been sent : " <<  ok << endl;
        
        if(ok){
        	// if email has been sent, end loop with next mxhost
        	break;
        }            
    }
    sleep(10);

return 0;    
}
