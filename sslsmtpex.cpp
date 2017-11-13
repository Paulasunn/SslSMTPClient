/*
* Breakermind Server (breakermind.com)
* Author: Marcin Łukaszewski
* Contact: hello@breakermind.com
* 2017 All rights reserver
* Copyrights 2017
*/

#include "sslsmtpex.h"
#include <string.h>
#include <string>
#include <iostream>

using namespace std;

const char sslsmtpEx::MimeTypes[][2][128] =
{
    {"***",    "application/octet-stream"},
    {"csv",    "text/csv"},
    {"tsv",    "text/tab-separated-values"},
    {"tab",    "text/tab-separated-values"},
    {"html",    "text/html"},
    {"htm",    "text/html"},
    {"doc",    "application/msword"},
    {"docx",    "application/vnd.openxmlformats-officedocument.wordprocessingml.document"},
    {"ods",    "application/x-vnd.oasis.opendocument.spreadsheet"},
    {"odt",    "application/vnd.oasis.opendocument.text"},
    {"rtf",    "application/rtf"},
    {"sxw",    "application/vnd.sun.xml.writer"},
    {"txt",    "text/plain"},
    {"xls",    "application/vnd.ms-excel"},
    {"xlsx",    "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet"},
    {"pdf",    "application/pdf"},
    {"ppt",    "application/vnd.ms-powerpoint"},
    {"pps",    "application/vnd.ms-powerpoint"},
    {"pptx",    "application/vnd.openxmlformats-officedocument.presentationml.presentation"},
    {"wmf",    "image/x-wmf"},
    {"atom",    "application/atom+xml"},
    {"xml",    "application/xml"},
    {"json",    "application/json"},
    {"js",    "application/javascript"},
    {"ogg",    "application/ogg"},
    {"ps",    "application/postscript"},
    {"woff",    "application/x-woff"},
    {"xhtml","application/xhtml+xml"},
    {"xht",    "application/xhtml+xml"},
    {"zip",    "application/zip"},
    {"gz",    "application/x-gzip"},
    {"rar",    "application/rar"},
    {"rm",    "application/vnd.rn-realmedia"},
    {"rmvb",    "application/vnd.rn-realmedia-vbr"},
    {"swf",    "application/x-shockwave-flash"},
    {"au",        "audio/basic"},
    {"snd",    "audio/basic"},
    {"mid",    "audio/mid"},
    {"rmi",        "audio/mid"},
    {"mp3",    "audio/mpeg"},
    {"aif",    "audio/x-aiff"},
    {"aifc",    "audio/x-aiff"},
    {"aiff",    "audio/x-aiff"},
    {"m3u",    "audio/x-mpegurl"},
    {"ra",    "audio/vnd.rn-realaudio"},
    {"ram",    "audio/vnd.rn-realaudio"},
    {"wav",    "audio/x-wave"},
    {"wma",    "audio/x-ms-wma"},
    {"m4a",    "audio/x-m4a"},
    {"bmp",    "image/bmp"},
    {"gif",    "image/gif"},
    {"jpe",    "image/jpeg"},
    {"jpeg",    "image/jpeg"},
    {"jpg",    "image/jpeg"},
    {"jfif",    "image/jpeg"},
    {"png",    "image/png"},
    {"svg",    "image/svg+xml"},
    {"tif",    "image/tiff"},
    {"tiff",    "image/tiff"},
    {"ico",    "image/vnd.microsoft.icon"},
    {"css",    "text/css"},
    {"bas",    "text/plain"},
    {"c",        "text/plain"},
    {"h",        "text/plain"},
    {"rtx",    "text/richtext"},
    {"mp2",    "video/mpeg"},
    {"mpa",    "video/mpeg"},
    {"mpe",    "video/mpeg"},
    {"mpeg",    "video/mpeg"},
    {"mpg",    "video/mpeg"},
    {"mpv2",    "video/mpeg"},
    {"mov",    "video/quicktime"},
    {"qt",    "video/quicktime"},
    {"lsf",    "video/x-la-asf"},
    {"lsx",    "video/x-la-asf"},
    {"asf",    "video/x-ms-asf"},
    {"asr",    "video/x-ms-asf"},
    {"asx",    "video/x-ms-asf"},
    {"avi",    "video/x-msvideo"},
    {"3gp",    "video/3gpp"},
    {"3gpp",    "video/3gpp"},
    {"3g2",    "video/3gpp2"},
    {"movie","video/x-sgi-movie"},
    {"mp4",    "video/mp4"},
    {"wmv",    "video/x-ms-wmv"},
    {"webm","video/webm"},
    {"m4v",    "video/x-m4v"},
    {"flv",    "video/x-flv"}
};

sslsmtpEx::sslsmtpEx(){}

void sslsmtpEx::sslsmtpExSet(std::string hostnameMX = "localhost", int port = 25)
{
    if(port > 0){
        Port = port;
    }
    HostnameMX = hostnameMX;
    cout << "ssl cleint " << HostnameMX << endl;
}

long int sslsmtpEx::microseconds(){
    struct timeval tp;
    gettimeofday(&tp, NULL);
    long int ms = tp.tv_sec * 1000 + tp.tv_usec / 1000;
    return ms;
}

int sslsmtpEx::callback1(X509_STORE_CTX *ctx, void *arg){
    if(ctx!=NULL){}
    if(arg!=NULL){}
    return 1;
}

int sslsmtpEx::callback(int x, X509_STORE_CTX *ctx){
    if(ctx!=NULL){}
    if(x!=1){}
    return 1;
}

string sslsmtpEx::replaceAll( string s, string search, string replace ) {
    for( size_t pos = 0; ; pos += replace.length() ) {
        // Locate the substring to replace
        pos = s.find( search, pos );
        if( pos == string::npos ) break;
        // Replace by erasing and inserting
        s.erase( pos, search.length() );
        s.insert( pos, replace );
    }
    return s;
}

// send mime message to server
bool sslsmtpEx::SendMIME(string from, string to, string mimeDATA, string serverHost, int msgID)
{
    // log
    string loghash = std::to_string(microseconds());
    std::ostringstream logx;

    logx << endl << "###EXSMTP###" << loghash << "###ID_" << msgID << "###" << endl;

     try{
        SSL_CTX *ctx;
        int server;
        SSL *ssl;
        char buf[8192] = {0};
        int bytes;
        char *hostname, *portnum;
        //cout << "PORT " << Port;

        ctx = InitCTX();

        // SMTP hostname and port number
        hostname = (char*)HostnameMX.c_str();
        portnum = (char*)std::to_string(Port).c_str();

        logx << "[SSL_SEND_MIME] " << hostname << " " << portnum << " " << from << endl;
                
        server = OpenConnection(hostname, atoi(portnum));
        if(server <= 0){
            logx << "[SMTP_CONNECTION_ERROR]" << endl;
            logx << "---" << loghash << "---\r\n" << endl;
            cout << logx.str();
            return 0;
        }        

        // Starttls first STARTTLS
        char buffer[8192] = {0};
        char buffer1[8192] = {0};
        std::string E1 = "ehlo ";
        E1.append(serverHost);
        E1.append(" \r\n");
        char *hello = (char*)E1.c_str();        

        memset(buffer, 0, sizeof buffer);
        buffer[0] = '\0';

        // get from server
        int valread = read(server,buffer,8192);
        logx << "[Server] [" << valread << "] " << buffer << endl;

        memset(buffer, 0, sizeof buffer);
        buffer[0] = '\0';
        
        // send helo
        send(server,hello,strlen(hello),0);
        logx << "[HELO] " << hello << endl;
        valread = read(server,buffer,8192);
        logx << "[Server] [" << valread << "] " <<  buffer << endl;
        while(!Contain(std::string(buffer), "250 ")){
            valread = read(server,buffer,8192);
        }
        /*
        int dc = 1;
        while(!Contain(std::string(buffer), "250") || Contain(std::string(buffer), ".ovh.")){
            memset(buffer, 0, sizeof buffer);
            buffer[0] = '\0';
            // send helo
            send(server,hello,strlen(hello),0);
            logx << "[HELO] " << hello << endl;
            valread = read(server,buffer,8192);
            logx << "[Server] [" << valread << "] " <<  buffer << endl;
            if(dc > 3){
                break;
            }
            dc++;
        }
        */
        
        if(!Contain(std::string(buffer), "STARTTLS")){
            logx << "[EXTERNAL_SERVER_NO_TLS] " << hostname << " " << buffer << "[CLOSING_CONNECTION]" << endl;
            logx << "---" << loghash << "---\r\n" << endl;
            cout << logx.str();
            return 0;
        }

        memset(buffer, 0, sizeof buffer);
        buffer[0] = '\0';

        // starttls
        char *hellotls = (char*)"STARTTLS\r\n";
        send(server,hellotls,strlen(hellotls),0);
        logx << "[STARTTLS] " << hellotls << endl;
        valread = read(server,buffer1,8192);
        logx << "[Server] " << valread << " " << buffer1 << endl;
        
        if(!Contain(std::string(buffer1), "220")){
            logx << "[EXTERNAL_SERVER_NOT_STARTTLS] " << hostname << " " << buffer1 << "[CLOSING_CONNECTION]" << endl;
            logx << "---" << loghash << "---\r\n" << endl;
            cout << logx.str();
            return 0;
        }

        // send with tls
        ssl = SSL_new(ctx);						// create new SSL connection
        SSL_set_fd(ssl, server);				// attach the socket descriptor

        /*
        // Disable certs verification
        SSL_set_verify(ssl, SSL_VERIFY_NONE, 0);
        SSL_set_verify_depth(ssl,0);
        SSL_CTX_set_cert_verify_callback(ctx, callback1,NULL);
        // SSL_VERIFY_PEER|SSL_VERIFY_CLIENT_ONCE SSL_VERIFY_NONE
        SSL_CTX_set_verify(ctx, SSL_VERIFY_NONE, callback);
        SSL_CTX_set_verify_depth(ctx,0);
        // SSL_CTX_set_verify_depth(0);       
        */

        // Catch errors
        sslError(ssl, 1, loghash, logx);

        if ( SSL_connect(ssl) == FAIL ){
            // ERR_print_errors_fp(stderr);            
            logx << "[TLS_SMTP_ERROR]" << endl;  
            logx << "---" << loghash << "---\r\n" << endl;
            cout << logx.str();
            return 0;
        } else {
            // char *msg = (char*)"{\"from\":[{\"name\":\"Zenobiusz\",\"email\":\"email@eee.ddf\"}]}";
            logx << "[CONNECTED_WITH_TLS] " <<  SSL_get_cipher(ssl) << " encryption " << endl;
            logx << ShowCerts(ssl) << endl;

            //buf[0] = '\0';
            //bytes = SSL_read(ssl, buf, sizeof(buf));
            //buf[bytes] = 0;
            //printf("[RECEIVED_TLS] %s\n", buf);

            //sslError(ssl, bytes);
            //cout << "ERRORNO " << errno;

            buf[0] = '\0';
            std::ostringstream f0;
            f0 << "EHLO " << serverHost << "\r\n";
            std::string f00 = f0.str();
            char *helo = (char*)f00.c_str();
            logx << "[SEND_TLS] " << helo << endl;
            SSL_write(ssl, helo, strlen(helo));
            bytes = SSL_read(ssl, buf, sizeof(buf));
            buf[bytes] = 0;
            logx << "1 [RECEIVED_TLS] " << buf << endl;
            if(!Contain(std::string(buf), "250"))return 0;


            buf[0] = '\0';
            std::ostringstream f1;
            f1 << "mail from: <" << from << ">\r\n";
            std::string f11 = f1.str();
            char *fromemail = (char*)f11.c_str();
            logx << "[SEND_TLS] " << fromemail << endl;
            SSL_write(ssl, fromemail, strlen(fromemail));
            bytes = SSL_read(ssl, buf, sizeof(buf));
            buf[bytes] = 0;
            logx << "2 [RECEIVED_TLS] " << buf << endl;
            if(!Contain(std::string(buf), "250"))return 0;


            buf[0] = '\0';
            std::string rcpt = "rcpt to: <";
            rcpt.append(to).append(">\r\n");
            char *rcpt1 = (char*)rcpt.c_str();
            logx << "[SEND_TLS] " << rcpt1 << endl;
            SSL_write(ssl, rcpt1, strlen(rcpt1));
            bytes = SSL_read(ssl, buf, sizeof(buf));
            buf[bytes] = 0;
            logx << "3 [RECEIVED_TLS] " << buf << endl;
            if(!Contain(std::string(buf), "250"))return 0;

            buf[0] = '\0';
            char *data = (char*)"DATA\r\n";
            logx << "[SEND_TLS] " << data << endl;
            SSL_write(ssl, data, strlen(data));
            bytes = SSL_read(ssl, buf, sizeof(buf));
            buf[bytes] = 0;
            logx << "4 [RECEIVED_TLS] " << buf << endl;
            if(!Contain(std::string(buf), "354"))return 0;

            mimeDATA = replaceAll(mimeDATA,"\r\n.\r\n", "");
            mimeDATA.append("\r\n.\r\n");
            char * mdata = (char*)mimeDATA.c_str();
            SSL_write(ssl, mdata, strlen(mdata));
            bytes = SSL_read(ssl, buf, sizeof(buf));
            buf[bytes] = 0;
            logx << "5 [RECEIVED_TLS] " << buf <<endl;
            if(!Contain(std::string(buf), "250"))return 0;

            char * qdata = (char*)"QUIT\r\n";
            SSL_write(ssl, qdata, strlen(qdata));
            bytes = SSL_read(ssl, buf, sizeof(buf));
            buf[bytes] = 0;
            logx << "6 [RECEIVED_TLS] " << buf << endl;
            logx << "---" << loghash << "---" << endl << endl;
            // send log
            cout << logx.str();
            if(!Contain(std::string(buf), "221"))return 1;
            
            SSL_free(ssl);
            return 1;
        }
        close(server);
        SSL_CTX_free(ctx);       
    }catch (const std::runtime_error &ee) {
            // błąd runtime 
            // std::cerr << "Runtime error: " << ee.what() << std::endl;
            logx << "[RUNTIME_ERROR] " << std::string(ee.what()) << std::endl;
            return 0;
    }catch(std::exception &e){
        logx << std::string("[CONNECTION_ERROR] ") << std::string(e.what()) << endl;
        logx << "---" << loghash << "---\r\n" << endl;
        cout << logx.str();
        return 0;
    }catch(...){
        logx << std::string("[CONNECTION_ERROR1] ") << endl;
        logx << "---" << loghash << "---\r\n" << endl;
        cout << logx.str();
        return 0;
    }
    logx << "---" << loghash << "---\r\n" << endl;
    cout << logx.str();    
    return 0;
}



// send message with attachments
bool sslsmtpEx::Send(string from, string to, string replyto, string subject, string msg, string msghtml, vector<string> files)
{
     try{
        SSL_CTX *ctx;
        int server;
        SSL *ssl;
        char buf[1024];
        int bytes;
        char *hostname, *portnum;
        //cout << "PORT " << Port;

        // SMTP hostname and port number
        hostname = (char*)HostnameMX.c_str();
        portnum = (char*)std::to_string(Port).c_str();
        //cout << "Send to server " << hostname << endl;
        //cout << "Send to server " << portnum << endl;
        
        server = OpenConnection(hostname, atoi(portnum));        
        if(server <= 0){
            cout << "COnNectiOn error " << endl;
            return 0;
        }
        // Starttls first STARTTLS
        char buffer[1024] = {0};
        char *hello = (char*)"EHLO qflash.pl\r\n";
        char *hellotls = (char*)"STARTTLS\r\n";

        int valread = read(server,buffer,8192);
        printf("Server : %s\n",buffer);
        send(server,hello,strlen(hello),0);
        printf("Hello message sent %i\n",valread);
        valread = read(server,buffer,8192);
        printf("%s\n",buffer);
        // starttls
        send(server,hellotls,strlen(hellotls),0);
        printf("STARTTLS message sent\n");
        valread = read(server,buffer,8192);
        printf("%s\n",buffer);
        // return 0;

        // send with tls
        ctx = InitCTX();
        ssl = SSL_new(ctx);						// create new SSL connection
        SSL_set_fd(ssl, server);				// attach the socket descriptor
        SSL_set_verify(ssl, SSL_VERIFY_NONE, 0);
        // SSL_CTX_set_cert_verify_callback(ctx, callback);

        cout << "Connection....smtp";


        if ( SSL_connect(ssl) == FAIL ){
            ERR_print_errors_fp(stderr);
            return 0;
        } else {
            // char *msg = (char*)"{\"from\":[{\"name\":\"Zenobiusz\",\"email\":\"email@eee.ddf\"}]}";
            printf("Connected with %s encryption\n", SSL_get_cipher(ssl));
            ShowCerts(ssl);

            //buf[0] = '\0';
            //bytes = SSL_read(ssl, buf, sizeof(buf));
            //buf[bytes] = 0;
            //printf("[RECEIVED_TLS] %s\n", buf);

            //sslError(ssl, bytes);
            //cout << "ERRORNO " << errno;

            buf[0] = '\0';
            std::ostringstream f0;
            f0 << "EHLO qflash.pl" << "\r\n";
            std::string f00 = f0.str();
            char *helo = (char*)f00.c_str();
            cout << "SEND TO SERVER " << helo << endl;
            SSL_write(ssl, helo, strlen(helo));
            bytes = SSL_read(ssl, buf, sizeof(buf));
            buf[bytes] = 0;
            printf("1 [RECEIVED_TLS] %s\n", buf);
            if(!Contain(std::string(buf), "250"))return 0;


            buf[0] = '\0';
            std::ostringstream f1;
            f1 << "mail from: <" << from << ">\r\n";
            std::string f11 = f1.str();
            char *fromemail = (char*)f11.c_str();
            cout << "SEND TO SERVER " << fromemail << endl;
            SSL_write(ssl, fromemail, strlen(fromemail));
            bytes = SSL_read(ssl, buf, sizeof(buf));
            buf[bytes] = 0;
            printf("2 [RECEIVED_TLS] %s\n", buf);
            if(!Contain(std::string(buf), "250"))return 0;


            buf[0] = '\0';
            std::string rcpt = "rcpt to: <";
            rcpt.append(to).append(">\r\n");
            char *rcpt1 = (char*)rcpt.c_str();
            cout << "SEND TO SERVER " << rcpt1 << endl;
            SSL_write(ssl, rcpt1, strlen(rcpt1));
            bytes = SSL_read(ssl, buf, sizeof(buf));
            buf[bytes] = 0;
            printf("3 [RECEIVED_TLS] %s\n", buf);
            if(!Contain(std::string(buf), "250"))return 0;

            buf[0] = '\0';
            char *data = (char*)"DATA\r\n";
            cout << "SEND TO SERVER " << data << endl;
            SSL_write(ssl, data, strlen(data));
            bytes = SSL_read(ssl, buf, sizeof(buf));
            buf[bytes] = 0;
            printf("4 [RECEIVED_TLS] %s\n", buf);
            if(!Contain(std::string(buf), "354"))return 0;

            std::string Encoding = "iso-8859-2"; // charset: utf-8, utf-16, iso-8859-2, iso-8859-1
            Encoding = "utf-8";

            std::ostringstream m;
             // m << "Date: "<< Date(1) << "\r\n";
             m << "From: " << from << "\r\n";
             m << "To: " << to << "\r\n";
             m << "Subject: =?" << Encoding << "?Q?"<< subject << "?=\r\n";
             m << "Reply-To: " << replyto << "\r\n";
             m << "Return-Path: " << from << "\r\n";             
             m << "MIME-Version: 1.0\r\n";
             m << "Content-Type: multipart/mixed; boundary=\"ToJestSeparator0000\"\r\n\r\n";
             m << "--ToJestSeparator0000\r\n";
             m << "Content-Type: multipart/alternative; boundary=\"ToJestSeparatorZagniezdzony1111\"\r\n\r\n";
             m << "--ToJestSeparatorZagniezdzony1111\r\n";
             m << "Content-Type: text/plain; charset=\"" << Encoding << "\"\r\n";
             m << "Content-Transfer-Encoding: quoted-printable\r\n\r\n";
             m << msg << "\r\n\r\n";
             m << "--ToJestSeparatorZagniezdzony1111\r\n";
             m << "Content-Type: text/html; charset=\"" << Encoding << "\"\r\n";
             m << "Content-Transfer-Encoding: quoted-printable\r\n\r\n";
             m << msghtml << "\r\n\r\n";
             m << "--ToJestSeparatorZagniezdzony1111--\r\n";
             // add atachments
             if(files.size() > 0){
                for(unsigned int i = 0;i < files.size();i++){
                    std::string path = files.at(i);
                    std::string filename = fileBasename(path);
                    std::string fc = base64_encode(get_file_contents(filename.c_str()));
                    std::string extension = GetFileExtension(filename);
                    const char *mimetype = GetMimeTypeFromFileName((char*)extension.c_str());
                    // cout << "MIME " << mimetype << endl << extension << endl;
                    // cout << "FILE CONTENT " << fc << endl;
                    m << "--ToJestSeparator0000\r\n";
                    m << "Content-Type: " << mimetype << "; name=\"" << filename << "\"\r\n";
                    m << "Content-Transfer-Encoding: base64\r\n";
                    m << "Content-Disposition: attachment; filename=\"" << filename << "\"\r\n\r\n";
                    m << fc <<"\r\n\r\n";
                }
             }
             m << "--ToJestSeparator0000--\r\n\r\n";
             m << "\r\n.\r\n";

             // create mime message string
             std::string mimemsg = m.str();
             // cout << mimemsg;

            char * mdata = (char*)mimemsg.c_str();
            SSL_write(ssl, mdata, strlen(mdata));
            bytes = SSL_read(ssl, buf, sizeof(buf));
            buf[bytes] = 0;
            printf("5 [RECEIVED_TLS] %s\n", buf);
            if(!Contain(std::string(buf), "250"))return 0;

            char * qdata = (char*)"QUIT\r\n";
            SSL_write(ssl, qdata, strlen(qdata));
            bytes = SSL_read(ssl, buf, sizeof(buf));
            buf[bytes] = 0;
            printf("6 [RECEIVED_TLS] %s\n", buf);
            if(!Contain(std::string(buf), "221"))return 0;

            SSL_free(ssl);
            return 1;
        }
        close(server);
        SSL_CTX_free(ctx);
    }catch(std::exception &e){
        return 0;
    }
}

int sslsmtpEx::OpenConnection(const char *hostname, int port)
{   
    int sd = -1;           
    sd = socket(PF_INET, SOCK_STREAM, 0);
    
    struct hostent *host; 
    struct sockaddr_in addr;
    struct in_addr **addr_list;

    // clear address
    bzero(&addr, sizeof(addr));

    // get from host or ip
    if((signed )inet_addr(hostname) == -1)
    {
        if ( (host = gethostbyname(hostname)) == NULL )
        {
            // perror(hostname);
            printf("gethostbyname() failed \n");
            // abort();
            return -1;
        }
        
        addr_list = (struct in_addr **) host->h_addr_list;
        for(int i = 0; addr_list[i] != NULL; i++)
        {
            //strcpy(ip , inet_ntoa(*addr_list[i]) );
            addr.sin_addr = *addr_list[i];
            cout << hostname << " resolved to " << inet_ntoa(*addr_list[i]) << endl;             
            inet_pton(AF_INET, inet_ntoa(*addr_list[i]), & addr.sin_addr);
            break;
        }
        // cout << "ssl cleint send open conn host " << inet_ntoa(host->h_addr) << endl;
        // set and catch timeout seconds
        socketTimeout(sd, 10);
    }else{
        addr.sin_addr.s_addr = inet_addr(hostname);
    }
    // connect
    addr.sin_family = AF_INET;
    addr.sin_port = htons(port);
    // addr.sin_addr.s_addr = *(long*)(host->h_addr);

    if (connect(sd,(struct sockaddr*)&addr,sizeof(addr))<0){
        close(sd);
        // perror(hostname);
        printf("gethostbyname() failed\n");
        return -1;
        // abort();
    }
    // cout << "ssl cleint send open conn end " << endl;
    return sd;
}

void sslsmtpEx::socketTimeout(int sd, int timeoutseconds){
    // socket time out
    struct timeval timeout;
    timeout.tv_sec = timeoutseconds;
    timeout.tv_usec = 0;

    if (setsockopt (sd, SOL_SOCKET, SO_RCVTIMEO, (char *)&timeout,sizeof(timeout)) < 0)
        cout << "[setsockopt failed]" << endl;

    if (setsockopt (sd, SOL_SOCKET, SO_SNDTIMEO, (char *)&timeout,sizeof(timeout)) < 0)
        cout << "[setsockopt failed]" << endl;
}

// InitCTX - initialize the SSL engine.
SSL_CTX* sslsmtpEx::InitCTX(void)
{   const SSL_METHOD *method;
    SSL_CTX *ctx;

    SSL_library_init();
    SSL_load_error_strings();			// Bring in and register error messages
    OpenSSL_add_all_algorithms();		// Load cryptos

    method = SSLv23_client_method();	// Create new client-method instance
    ctx = SSL_CTX_new(method);			// Create new context
    if ( ctx == NULL )
    {
        ERR_print_errors_fp(stderr);
        // abort();
    }
    return ctx;
}

// ShowCerts - print out the certificates.
string sslsmtpEx::ShowCerts(SSL* ssl)
{   X509 *cert;
    char *line;

    cert = SSL_get_peer_certificate(ssl);	// get the server's certificate
    if ( cert != NULL )
    {
        std::string log = "Server certificates:\n";
        line = X509_NAME_oneline(X509_get_subject_name(cert), 0, 0);
        log.append("Subject: ").append(line);
        free(line);							// free the malloc'ed string
        line = X509_NAME_oneline(X509_get_issuer_name(cert), 0, 0);
        log.append("\nIssuer: ").append(line);
        free(line);							// free the malloc'ed string
        X509_free(cert);					// free the malloc'ed certificate copy
        return log;
    } else {
        return "No certificates.\n";
    }
}

// Check ssl error
void sslsmtpEx::sslError1(SSL *ssl, int received){
    const int err = SSL_get_error(ssl, received);
    // const int st = ERR_get_error();
    if (err == SSL_ERROR_NONE) {
        std::cout<<"SSL_ERROR_NONE:"<<SSL_ERROR_NONE<<std::endl;
        // SSL_shutdown(ssl);
    } else if (err == SSL_ERROR_WANT_READ ) {
        std::cout<<"SSL_ERROR_WANT_READ:"<<SSL_ERROR_WANT_READ<<std::endl;
        SSL_shutdown(ssl);
        kill(getpid(), SIGKILL);
    } else if (SSL_ERROR_SYSCALL) {
        std::cout<<"SSL_ERROR_SYSCALL:"<<SSL_ERROR_SYSCALL<<std::endl;
        SSL_shutdown(ssl);
        kill(getpid(), SIGKILL);
    }
}

void sslsmtpEx::sslError(SSL *ssl, int received, string microtime, std::ostringstream &logi){
    const int err = SSL_get_error(ssl, received);
    // const int st = ERR_get_error();
    if (err == SSL_ERROR_NONE) {
        // OK send
        // std::cout<<"SSL_ERROR_NONE:"<<SSL_ERROR_NONE<<std::endl;
        // SSL_shutdown(ssl);        
    } else if (err == SSL_ERROR_WANT_READ ) {
        logi << "[SSL_ERROR_WANT_READ]" << SSL_ERROR_WANT_READ<<std::endl;
        cout << logi.str() << "--[" << microtime << "]--" << endl;
        SSL_shutdown(ssl);
        kill(getpid(), SIGKILL);
    } else if (SSL_ERROR_SYSCALL) {
        logi << errno << " Received " << received << endl;
        logi << "[SSL_ERROR_SYSCALL] "<< SSL_ERROR_SYSCALL << std::endl;
        cout << logi.str() << "--[" << microtime << "]--" << endl;
        SSL_shutdown(ssl);
        kill(getpid(), SIGKILL);
    }
}
void sslsmtpEx::quoted(string str){
    std::stringstream ss;
        std::string in = "String with spaces, and embedded \"quotes\" too";
        if(str.length() > 0){
            in = str;
        }
        std::string out;

        ss << std::quoted(in);
        std::cout << "read in     [" << in << "]\n"
                  << "stored as   [" << ss.str() << "]\n";

        ss >> std::quoted(out);
        std::cout << "written out [" << out << "]\n";
}

string sslsmtpEx::Date(bool utc){
    time_t now = time(0);
    char* dt = ctime(&now);
    if(utc){
        tm *gmtm = gmtime(&now);
        dt = asctime(gmtm);
    }
    return std::string(dt);
}

string sslsmtpEx::fileBasename(string path){
    std::string filename = path.substr(path.find_last_of("/\\") + 1);
    return filename;
    // without extension
    // std::string::size_type const p(base_filename.find_last_of('.'));
    // std::string file_without_extension = base_filename.substr(0, p);
}

std::string sslsmtpEx::getFileContent(const std::string& path)
{
  //std::ifstream file(path);
  //std::string content((std::istreambuf_iterator<char>(file)), std::istreambuf_iterator<char>());
  //return content;
    return path;
}

std::string sslsmtpEx::get_file_contents(const char *filename)
{
  std::ifstream in(filename, std::ios::in | std::ios::binary);
  if (in)
  {
    std::string contents;
    in.seekg(0, std::ios::end);
    contents.resize(in.tellg());
    in.seekg(0, std::ios::beg);
    in.read(&contents[0], contents.size());
    in.close();
    return(contents);
  }
  throw(errno);
}

bool sslsmtpEx::Contain(std::string str, std::string search){
    std::size_t found = str.find(search);
    if (found!=std::string::npos){
        return 1;
    }
    return 0;
}

std::string sslsmtpEx::GetFileExtension(const std::string& FileName)
{
    if(FileName.find_last_of(".") != std::string::npos)
        return FileName.substr(FileName.find_last_of(".")+1);
    return "";
}

const char* sslsmtpEx::GetMimeTypeFromFileName( char* szFileExt)
{
    // cout << "EXT " << szFileExt;
    for (unsigned int i = 0; i < sizeof (MimeTypes) / sizeof (MimeTypes[0]); i++)
    {
        if (strcmp(MimeTypes[i][0],szFileExt) == 0)
        {
            return MimeTypes[i][1];
        }
    }
    return MimeTypes[0][1];   //if does not match any,  "application/octet-stream" is returned
}


// -----------------------------------   DNS PART

vector<string> sslsmtpEx::getMX(std::string email, int show = 0, int logToFile = 0)
{
    string domain = "localhost";
    vector<string> em = splitDelimiter(email,"@");
    if(em.size() > 1){
        domain = em.at(em.size()-1);
    }
    vector<string> mxhosts;
    res_init();
    u_char nsbuf[N];
    //char dispbuf[N];
    ns_msg msg;
    ns_rr rr;
    int i, l;
    if(show > 0){
        // HEADER
        // printf("Domain : %s\n", std::string(domain));
        // MX RECORD
        printf("MX records : \n");
    }
    l = res_query(domain.c_str(), ns_c_any, ns_t_mx, nsbuf, sizeof(nsbuf));
    if (l < 0)
    {
      // perror(domain.c_str());
      return mxhosts;
    } else {
        #ifdef USE_PQUERY
              /* this will give lots of detailed info on the request and reply */
              res_pquery(&_res, nsbuf, l, stdout);
        #else
            /* just grab the MX answer info */
            ns_initparse(nsbuf, l, &msg);
            l = ns_msg_count(msg, ns_s_an);
            for (i = 0; i < l; i++)
            {
                ns_parserr(&msg, ns_s_an, i, &rr); // int prr = ns_parserr(&msg, ns_s_an, j, &rr);
                // priority
                char exchange[NS_MAXDNAME];
                const u_char *rdata = ns_rr_rdata(rr);
                const uint16_t pri = ns_get16(rdata);
                int len = dn_expand(nsbuf, nsbuf + 250, rdata + 2, exchange, sizeof(exchange));
                if(show > 0){
                    cout << len;
                    // priority
                    printf("Pri->%d\n", pri);
                    // hostname
                    printf("Exchange->%s\n", exchange);
                }
                mxhosts.push_back(exchange);

                if(logToFile > 0){
                    // get the current time
                    time_t rawtime;
                    tm * ptm;
                    time ( &rawtime );
                    ptm = gmtime ( &rawtime );
                    // log this information to ipaddr.log file
                    ofstream ipaddr_log("ipaddr.log", ios::app);
                    ipaddr_log << (ptm->tm_hour+MST%24) << ":" << (ptm->tm_min) << " " << domain << " " << exchange << " (" << hostnameIP(exchange) << ")" << endl;
                    ipaddr_log.close();
                }
            }
        #endif
    }
    // ---------
    return mxhosts;
}

// string delimiter
vector<string> sslsmtpEx::splitDelimiter(string str, string delim)
{
    vector<string> tokens;
    size_t prev = 0, pos = 0;
    do
    {
        pos = str.find(delim, prev);
        if (pos == string::npos) pos = str.length();
        string token = str.substr(prev, pos-prev);
        if (!token.empty()) tokens.push_back(token);
        prev = pos + delim.length();
        // cout << token << endl;
    }
    while (pos < str.length() && prev < str.length());
    return tokens;
}

// Get ip from domain name
string sslsmtpEx::hostnameIP(std::string hostname)
{
    struct hostent *he;
    struct in_addr **addr_list;
    int i;
    char ip[255];
    if ( (he = gethostbyname( (char*)hostname.c_str() ) ) == NULL)
    {
        // get the host info
        herror("gethostbyname");
        return "";
    }
    addr_list = (struct in_addr **) he->h_addr_list;
    for(i = 0; addr_list[i] != NULL; i++)
    {
        //Return the first one;
        strcpy(ip , inet_ntoa(*addr_list[i]) );
    }
    cout << std::string(ip);
    return std::string(ip);
}

// valid ip4
bool sslsmtpEx::validIPv4(const string& str)
{
    struct sockaddr_in sa;
    return inet_pton(AF_INET, str.c_str(), &(sa.sin_addr))!=0;
}

// valid ip6
bool sslsmtpEx::validIPv6(const string& str)
{
    struct sockaddr_in6 sa;
    return inet_pton(AF_INET6, str.c_str(), &(sa.sin6_addr))!=0;
}


// ---------------------------------------- BASE64

 const std::string sslsmtpEx::base64_chars =
             "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
             "abcdefghijklmnopqrstuvwxyz"
             "0123456789+/";


bool sslsmtpEx::is_base64(unsigned char c) {
  return (isalnum(c) || (c == '+') || (c == '/'));
}


std::string sslsmtpEx::base64_encode(unsigned char const* bytes_to_encode, unsigned int in_len) {
  std::string ret;
  int i = 0;
  int j = 0;
  unsigned char char_array_3[3];
  unsigned char char_array_4[4];

  while (in_len--) {
    char_array_3[i++] = *(bytes_to_encode++);
    if (i == 3) {
      char_array_4[0] = (char_array_3[0] & 0xfc) >> 2;
      char_array_4[1] = ((char_array_3[0] & 0x03) << 4) + ((char_array_3[1] & 0xf0) >> 4);
      char_array_4[2] = ((char_array_3[1] & 0x0f) << 2) + ((char_array_3[2] & 0xc0) >> 6);
      char_array_4[3] = char_array_3[2] & 0x3f;

      for(i = 0; (i <4) ; i++)
        ret += base64_chars[char_array_4[i]];
      i = 0;
    }
  }

  if (i)
  {
    for(j = i; j < 3; j++)
      char_array_3[j] = '\0';

    char_array_4[0] = ( char_array_3[0] & 0xfc) >> 2;
    char_array_4[1] = ((char_array_3[0] & 0x03) << 4) + ((char_array_3[1] & 0xf0) >> 4);
    char_array_4[2] = ((char_array_3[1] & 0x0f) << 2) + ((char_array_3[2] & 0xc0) >> 6);

    for (j = 0; (j < i + 1); j++)
      ret += base64_chars[char_array_4[j]];

    while((i++ < 3))
      ret += '=';

  }

  return ret;

}

std::string sslsmtpEx::base64_encode(std::string str, unsigned int in_len) {
  unsigned char const* bytes_to_encode = reinterpret_cast<const unsigned char*>(str.c_str());
  std::string ret;
  int i = 0;
  int j = 0;
  unsigned char char_array_3[3];
  unsigned char char_array_4[4];

  while (in_len--) {
    char_array_3[i++] = *(bytes_to_encode++);
    if (i == 3) {
      char_array_4[0] = (char_array_3[0] & 0xfc) >> 2;
      char_array_4[1] = ((char_array_3[0] & 0x03) << 4) + ((char_array_3[1] & 0xf0) >> 4);
      char_array_4[2] = ((char_array_3[1] & 0x0f) << 2) + ((char_array_3[2] & 0xc0) >> 6);
      char_array_4[3] = char_array_3[2] & 0x3f;

      for(i = 0; (i <4) ; i++)
        ret += base64_chars[char_array_4[i]];
      i = 0;
    }
  }

  if (i)
  {
    for(j = i; j < 3; j++)
      char_array_3[j] = '\0';

    char_array_4[0] = ( char_array_3[0] & 0xfc) >> 2;
    char_array_4[1] = ((char_array_3[0] & 0x03) << 4) + ((char_array_3[1] & 0xf0) >> 4);
    char_array_4[2] = ((char_array_3[1] & 0x0f) << 2) + ((char_array_3[2] & 0xc0) >> 6);

    for (j = 0; (j < i + 1); j++)
      ret += base64_chars[char_array_4[j]];

    while((i++ < 3))
      ret += '=';

  }
  return ret;
}


std::string sslsmtpEx::base64_encode(std::string str) {
  unsigned int in_len = str.length();
  unsigned char const* bytes_to_encode = reinterpret_cast<const unsigned char*>(str.c_str());
  std::string ret;
  int i = 0;
  int j = 0;
  unsigned char char_array_3[3];
  unsigned char char_array_4[4];

  while (in_len--) {
    char_array_3[i++] = *(bytes_to_encode++);
    if (i == 3) {
      char_array_4[0] = (char_array_3[0] & 0xfc) >> 2;
      char_array_4[1] = ((char_array_3[0] & 0x03) << 4) + ((char_array_3[1] & 0xf0) >> 4);
      char_array_4[2] = ((char_array_3[1] & 0x0f) << 2) + ((char_array_3[2] & 0xc0) >> 6);
      char_array_4[3] = char_array_3[2] & 0x3f;

      for(i = 0; (i <4) ; i++)
        ret += base64_chars[char_array_4[i]];
      i = 0;
    }
  }

  if (i)
  {
    for(j = i; j < 3; j++)
      char_array_3[j] = '\0';

    char_array_4[0] = ( char_array_3[0] & 0xfc) >> 2;
    char_array_4[1] = ((char_array_3[0] & 0x03) << 4) + ((char_array_3[1] & 0xf0) >> 4);
    char_array_4[2] = ((char_array_3[1] & 0x0f) << 2) + ((char_array_3[2] & 0xc0) >> 6);

    for (j = 0; (j < i + 1); j++)
      ret += base64_chars[char_array_4[j]];

    while((i++ < 3))
      ret += '=';

  }

  return ret;

}

std::string sslsmtpEx::base64_decode(std::string const& encoded_string) {
  int in_len = encoded_string.size();
  int i = 0;
  int j = 0;
  int in_ = 0;
  unsigned char char_array_4[4], char_array_3[3];
  std::string ret;

  while (in_len-- && ( encoded_string[in_] != '=') && is_base64(encoded_string[in_])) {
    char_array_4[i++] = encoded_string[in_]; in_++;
    if (i ==4) {
      for (i = 0; i <4; i++)
        char_array_4[i] = base64_chars.find(char_array_4[i]);

      char_array_3[0] = ( char_array_4[0] << 2       ) + ((char_array_4[1] & 0x30) >> 4);
      char_array_3[1] = ((char_array_4[1] & 0xf) << 4) + ((char_array_4[2] & 0x3c) >> 2);
      char_array_3[2] = ((char_array_4[2] & 0x3) << 6) +   char_array_4[3];

      for (i = 0; (i < 3); i++)
        ret += char_array_3[i];
      i = 0;
    }
  }

  if (i) {
    for (j = 0; j < i; j++)
      char_array_4[j] = base64_chars.find(char_array_4[j]);

    char_array_3[0] = (char_array_4[0] << 2) + ((char_array_4[1] & 0x30) >> 4);
    char_array_3[1] = ((char_array_4[1] & 0xf) << 4) + ((char_array_4[2] & 0x3c) >> 2);

    for (j = 0; (j < i - 1); j++) ret += char_array_3[j];
  }

  return ret;
}


/*
 char *mdata = (char*)"From: <hello@qflash.pl>\r\n"
                    "To: Breakermind <fxstareu@gmail.com>\r\n"
                    "Subject: =?iso-8859-2?Q?Hello111111=2C_czy_um=F3wisz_si=EA_ze_mn=B1=3F?=\r\n"
                    "Reply-To: m <hello@qflash.pl>\r\n"
                    "Return-Path: <hello@qflash.pl>\r\n"
                    "Date: Sat, 30 Apr 2017 19:28:29 -0300\r\n"
                    "MIME-Version: 1.0\r\n"
                    "Content-Type: multipart/mixed; boundary=\"ToJestSeparator0000\"\r\n\r\n"
                    "--ToJestSeparator0000\r\n"
                    "Content-Type: multipart/alternative; boundary=\"ToJestSeparatorZagniezdzony1111\"\r\n\r\n"
                    "--ToJestSeparatorZagniezdzony1111\r\n"
                    "Content-Type: text/plain; charset=\"iso-8859-2\"\r\n"
                    "Content-Transfer-Encoding: quoted-printable\r\n\r\n"
                    "To jest tre=B6=E6 wiadomo=B6ci.\r\n\r\n"
                    "--ToJestSeparatorZagniezdzony1111\r\n"
                    "Content-Type: text/html; charset=\"iso-8859-2\"\r\n"
                    "Content-Transfer-Encoding: quoted-printable\r\n\r\n"
                    "<BODY><FONT face=3DArial size=3D2><h1 style=\"color: #ff2222\">Co za buraki pastewniaki. HTML part color To jest tre=B6=E6 wiadomo=B6ci.</h1></FONT></BODY></HTML>\r\n\r\n"
                    "--ToJestSeparatorZagniezdzony1111--\r\n"
                    "--ToJestSeparator0000\r\n"
                    "Content-Type: image/jpeg; name=\"plik.jpg\"\r\n"
                    "Content-Transfer-Encoding: base64\r\n"
                    "Content-Disposition: attachment; filename=\"plik.jpg\"\r\n\r\n"
                    "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\r\n\r\n"
                    "--ToJestSeparator0000\r\n"
                    "Content-Type: image/jpeg; name=\"plik2.jpg\"\r\n"
                    "Content-Transfer-Encoding: base64\r\n"
                    "Content-Disposition: attachment; filename=\"plik2.jpg\"\r\n\r\n"
                    "/9j/4AAQSkZJRgABAQEASABIAAD/4gxYSUNDX1BST0ZJTEUAAQEAAAxITGlubwIQAABtbnRyUkdCIFhZWiAHzgACAAkABgAxAABhY3NwTVNGVAAAAABJRUMgc1JHQgAAAAAAAAAAAAAAAAAA9tYAAQAAAADTLUhQICAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAABFjcHJ0AAABUAAAADNkZXNjAAABhAAAAGx3dHB0AAAB8AAAABRia3B0AAACBAAAABRyWFlaAAACGAAAABRnWFlaAAACLAAAABRiWFlaAAACQAAAABRkbW5kAAACVAAAAHBkbWRkAAACxAAAAIh2dWVkAAADTAAAAIZ2aWV3AAAD1AAAACRsdW1pAAAD+AAAABRtZWFzAAAEDAAAACR0ZWNoAAAEMAAAAAxyVFJDAAAEPAAACAxnVFJDAAAEPAAACAxiVFJDAAAEPAAACAx0ZXh0AAAAAENvcHlyaWdodCAoYykgMTk5OCBIZXdsZXR0LVBhY2thcmQgQ29tcGFueQAAZGVzYwAAAAAAAAASc1JHQiBJRUM2MTk2Ni0yLjEAAAAAAAAAAAAAABJzUkdCIElFQzYxOTY2LTIuMQAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAWFlaIAAAAAAAAPNRAAEAAAABFsxYWVogAAAAAAAAAAAAAAAAAAAAAFhZWiAAAAAAAABvogAAOPUAAAOQWFlaIAAAAAAAAGKZAAC3hQAAGNpYWVogAAAAAAAAJKAAAA+EAAC2z2Rlc2MAAAAAAAAAFklFQyBodHRwOi8vd3d3LmllYy5jaAAAAAAAAAAAAAAAFklFQyBodHRwOi8vd3d3LmllYy5jaAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAABkZXNjAAAAAAAAAC5JRUMgNjE5NjYtMi4xIERlZmF1bHQgUkdCIGNvbG91ciBzcGFjZSAtIHNSR0IAAAAAAAAAAAAAAC5JRUMgNjE5NjYtMi4xIERlZmF1bHQgUkdCIGNvbG91ciBzcGFjZSAtIHNSR0IAAAAAAAAAAAAAAAAAAAAAAAAAAAAAZGVzYwAAAAAAAAAsUmVmZXJlbmNlIFZpZXdpbmcgQ29uZGl0aW9uIGluIElFQzYxOTY2LTIuMQAAAAAAAAAAAAAALFJlZmVyZW5jZSBWaWV3aW5nIENvbmRpdGlvbiBpbiBJRUM2MTk2Ni0yLjEAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAHZpZXcAAAAAABOk/gAUXy4AEM8UAAPtzAAEEwsAA1yeAAAAAVhZWiAAAAAAAEwJVgBQAAAAVx/nbWVhcwAAAAAAAAABAAAAAAAAAAAAAAAAAAAAAAAAAo8AAAACc2lnIAAAAABDUlQgY3VydgAAAAAAAAQAAAAABQAKAA8AFAAZAB4AIwAoAC0AMgA3ADsAQABFAEoATwBUAFkAXgBjAGgAbQByAHcAfACBAIYAiwCQAJUAmgCfAKQAqQCuALIAtwC8AMEAxgDLANAA1QDbAOAA5QDrAPAA9gD7AQEBBwENARMBGQEfASUBKwEyATgBPgFFAUwBUgFZAWABZwFuAXUBfAGDAYsBkgGaAaEBqQGxAbkBwQHJAdEB2QHhAekB8gH6AgMCDAIUAh0CJgIvAjgCQQJLAlQCXQJnAnECegKEAo4CmAKiAqwCtgLBAssC1QLgAusC9QMAAwsDFgMhAy0DOANDA08DWgNmA3IDfgOKA5YDogOuA7oDxwPTA+AD7AP5BAYEEwQgBC0EOwRIBFUEYwRxBH4EjASaBKgEtgTEBNME4QTwBP4FDQUcBSsFOgVJBVgFZwV3BYYFlgWmBbUFxQXVBeUF9gYGBhYGJwY3BkgGWQZqBnsGjAadBq8GwAbRBuMG9QcHBxkHKwc9B08HYQd0B4YHmQesB78H0gflB/gICwgfCDIIRghaCG4IggiWCKoIvgjSCOcI+wkQCSUJOglPCWQJeQmPCaQJugnPCeUJ+woRCicKPQpUCmoKgQqYCq4KxQrcCvMLCwsiCzkLUQtpC4ALmAuwC8gL4Qv5DBIMKgxDDFwMdQyODKcMwAzZDPMNDQ0mDUANWg10DY4NqQ3DDd4N+A4TDi4OSQ5kDn8Omw62DtIO7g8JDyUPQQ9eD3oPlg+zD88P7BAJECYQQxBhEH4QmxC5ENcQ9RETETERTxFtEYwRqhHJEegSBxImEkUSZBKEEqMSwxLjEwMTIxNDE2MTgxOkE8UT5RQGFCcUSRRqFIsUrRTOFPAVEhU0FVYVeBWbFb0V4BYDFiYWSRZsFo8WshbWFvoXHRdBF2UXiReuF9IX9xgbGEAYZRiKGK8Y1Rj6GSAZRRlrGZEZtxndGgQaKhpRGncanhrFGuwbFBs7G2MbihuyG9ocAhwqHFIcexyjHMwc9R0eHUcdcB2ZHcMd7B4WHkAeah6UHr4e6R8THz4faR+UH78f6iAVIEEgbCCYIMQg8CEcIUghdSGhIc4h+yInIlUigiKvIt0jCiM4I2YjlCPCI/AkHyRNJHwkqyTaJQklOCVoJZclxyX3JicmVyaHJrcm6CcYJ0kneierJ9woDSg/KHEooijUKQYpOClrKZ0p0CoCKjUqaCqbKs8rAis2K2krnSvRLAUsOSxuLKIs1y0MLUEtdi2rLeEuFi5MLoIuty7uLyQvWi+RL8cv/jA1MGwwpDDbMRIxSjGCMbox8jIqMmMymzLUMw0zRjN/M7gz8TQrNGU0njTYNRM1TTWHNcI1/TY3NnI2rjbpNyQ3YDecN9c4FDhQOIw4yDkFOUI5fzm8Ofk6Njp0OrI67zstO2s7qjvoPCc8ZTykPOM9Ij1hPaE94D4gPmA+oD7gPyE/YT+iP+JAI0BkQKZA50EpQWpBrEHuQjBCckK1QvdDOkN9Q8BEA0RHRIpEzkUSRVVFmkXeRiJGZ0arRvBHNUd7R8BIBUhLSJFI10kdSWNJqUnwSjdKfUrESwxLU0uaS+JMKkxyTLpNAk1KTZNN3E4lTm5Ot08AT0lPk0/dUCdQcVC7UQZRUFGbUeZSMVJ8UsdTE1NfU6pT9lRCVI9U21UoVXVVwlYPVlxWqVb3V0RXklfgWC9YfVjLWRpZaVm4WgdaVlqmWvVbRVuVW+VcNVyGXNZdJ114XcleGl5sXr1fD19hX7NgBWBXYKpg/GFPYaJh9WJJYpxi8GNDY5dj62RAZJRk6WU9ZZJl52Y9ZpJm6Gc9Z5Nn6Wg/aJZo7GlDaZpp8WpIap9q92tPa6dr/2xXbK9tCG1gbbluEm5rbsRvHm94b9FwK3CGcOBxOnGVcfByS3KmcwFzXXO4dBR0cHTMdSh1hXXhdj52m3b4d1Z3s3gReG54zHkqeYl553pGeqV7BHtje8J8IXyBfOF9QX2hfgF+Yn7CfyN/hH/lgEeAqIEKgWuBzYIwgpKC9INXg7qEHYSAhOOFR4Wrhg6GcobXhzuHn4gEiGmIzokziZmJ/opkisqLMIuWi/yMY4zKjTGNmI3/jmaOzo82j56QBpBukNaRP5GokhGSepLjk02TtpQglIqU9JVflcmWNJaflwqXdZfgmEyYuJkkmZCZ/JpomtWbQpuvnByciZz3nWSd0p5Anq6fHZ+Ln/qgaaDYoUehtqImopajBqN2o+akVqTHpTilqaYapoum/adup+CoUqjEqTepqaocqo+rAqt1q+msXKzQrUStuK4trqGvFq+LsACwdbDqsWCx1rJLssKzOLOutCW0nLUTtYq2AbZ5tvC3aLfguFm40blKucK6O7q1uy67p7whvJu9Fb2Pvgq+hL7/v3q/9cBwwOzBZ8Hjwl/C28NYw9TEUcTOxUvFyMZGxsPHQce/yD3IvMk6ybnKOMq3yzbLtsw1zLXNNc21zjbOts83z7jQOdC60TzRvtI/0sHTRNPG1EnUy9VO1dHWVdbY11zX4Nhk2OjZbNnx2nba+9uA3AXcit0Q3ZbeHN6i3ynfr+A24L3hROHM4lPi2+Nj4+vkc+T85YTmDeaW5x/nqegy6LzpRunQ6lvq5etw6/vshu0R7ZzuKO6070DvzPBY8OXxcvH/8ozzGfOn9DT0wvVQ9d72bfb794r4Gfio+Tj5x/pX+uf7d/wH/Jj9Kf26/kv+3P9t////2wBDAAMCAgMCAgMDAwMEAwMEBQgFBQQEBQoHBwYIDAoMDAsKCwsNDhIQDQ4RDgsLEBYQERMUFRUVDA8XGBYUGBIUFRT/2wBDAQMEBAUEBQkFBQkUDQsNFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBT/wgARCAAKAAoDAREAAhEBAxEB/8QAFgABAQEAAAAAAAAAAAAAAAAAAAEI/8QAFgEBAQEAAAAAAAAAAAAAAAAAAAQB/9oADAMBAAIQAxAAAAHOFs4ap//EABQQAQAAAAAAAAAAAAAAAAAAACD/2gAIAQEAAQUCH//EABQRAQAAAAAAAAAAAAAAAAAAACD/2gAIAQMBAT8BH//EABQRAQAAAAAAAAAAAAAAAAAAACD/2gAIAQIBAT8BH//EABQQAQAAAAAAAAAAAAAAAAAAACD/2gAIAQEABj8CH//EABgQAAIDAAAAAAAAAAAAAAAAAAABECFB/9oACAEBAAE/IWWbH//aAAwDAQACAAMAAAAQSS//xAAUEQEAAAAAAAAAAAAAAAAAAAAg/9oACAEDAQE/EB//xAAUEQEAAAAAAAAAAAAAAAAAAAAg/9oACAECAQE/EB//xAAZEAADAQEBAAAAAAAAAAAAAAAAAREhMXH/2gAIAQEAAT8Qp5npRSkpw//Z\r\n\r\n"
                    "--ToJestSeparator0000--\r\n\r\n"
                    ".\r\n";
*/
