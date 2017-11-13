
### C++ Ssl SMTP Client - SslSMTPClient
C++ ssl smtp client (send emails with attachments without local smtp server - gets mx records from email domain dns and send emails to each mx host server on port 25)

#### g++ -o start main.cpp sslsmtpex.cpp sslsmtpex.h -lssl -lcrypto -lresolv -std=c++11 -std=c++14
apt-get install libssl-dev openssl
