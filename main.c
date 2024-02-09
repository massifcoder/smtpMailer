#include<stdio.h>
#include<stdlib.h>
#include<unistd.h>
#include<string.h>
#include<sys/types.h>
#include<arpa/inet.h>
#include<sys/socket.h>
#include<netdb.h>
#include<netinet/in.h>
#include<fcntl.h>
#include<time.h>
#include<openssl/ssl.h>
#include<openssl/err.h>

void error(const char* msg){
    perror(msg);
    exit(1);
}

char* base64_encode(const unsigned char* input, int length) {
    BIO *bio, *b64;
    BUF_MEM *bufferPtr;

    b64 = BIO_new(BIO_f_base64());
    BIO_set_flags(b64, BIO_FLAGS_BASE64_NO_NL);
    bio = BIO_new(BIO_s_mem());
    BIO_push(b64, bio);

    BIO_write(b64, input, length);
    BIO_flush(b64);

    BIO_get_mem_ptr(b64, &bufferPtr);
    char* buffer = (char*)malloc(bufferPtr->length + 1);
    memcpy(buffer, bufferPtr->data, bufferPtr->length);
    buffer[bufferPtr->length] = '\0';

    BIO_free_all(b64);

    return buffer;
}

SSL_CTX* create_ssl_context(){
    SSL_CTX* ctx = NULL;
    SSL_library_init();
    OpenSSL_add_all_algorithms();
    SSL_load_error_strings();
    ctx = SSL_CTX_new(TLS_client_method());
    if(!ctx){
        ERR_print_errors_fp(stderr);
        exit(EXIT_FAILURE);
    }
    return ctx;
};

void send_email(char* sender, char* recipient, char* subject, char* message, char* smtp_server, int smtp_port, char* smtp_username, char* smtp_password, char formatted_date[30]){
    char mime_text[1024];
    snprintf(mime_text, sizeof(mime_text),"Content-Type: text/plain; charset=\"us-ascii\" \nMIME-Version: 1.0 \nContent-Transfer-Encoding: 7bit\n");
    strncat(mime_text, "Subject: ", sizeof(mime_text) - strlen(mime_text)-1);
    strncat(mime_text, subject, sizeof(mime_text) - strlen(mime_text) -1);
    strncat(mime_text, "\nFrom: ", sizeof(mime_text) - strlen(mime_text)-1);
    strncat(mime_text, sender, sizeof(mime_text) - strlen(mime_text) -1);
    strncat(mime_text, "\nTo: ", sizeof(mime_text) - strlen(mime_text)-1);
    strncat(mime_text, recipient, sizeof(mime_text) - strlen(mime_text) -1);
    strncat(mime_text, "\nDate: ", sizeof(mime_text) - strlen(mime_text)-1);
    strncat(mime_text, formatted_date, sizeof(mime_text) - strlen(mime_text) -1);
    strncat(mime_text, "\n\n", sizeof(mime_text) - strlen(mime_text)-1);
    strncat(mime_text, message, sizeof(mime_text) - strlen(mime_text) -1);
    
    SSL_CTX* ctx;
    struct hostent* server;
    struct sockaddr_in server_address;
    SSL* ssl;

    ctx = create_ssl_context();
    
    int sockfd = socket(AF_INET, SOCK_STREAM, 0);
    if(sockfd == -1){
        error("Failed in creating connection.\n");
    }

    server = gethostbyname(smtp_server);

    if(server == NULL){
        error("Could not resolve server address.\n");
    }

    memset(&server_address, 0, sizeof(server_address));
    server_address.sin_family = AF_INET;
    server_address.sin_port = htons(smtp_port);
    memcpy(&server_address.sin_addr.s_addr, server->h_addr_list[0], server->h_length);

    if(connect(sockfd, (struct sockaddr*)&server_address, sizeof(server_address)) == -1 ){
        error("Error in creating connection.");
        exit(EXIT_FAILURE);
    }

    ssl = SSL_new(ctx);
    SSL_set_fd(ssl, sockfd);

    if(SSL_connect(ssl)!=1){
        ERR_print_errors_fp(stderr);
        SSL_free(ssl);
        close(sockfd);
        SSL_CTX_free(ctx);
        error("Error in creating ssl.\n");
        exit(EXIT_FAILURE);
    }

    char buffer[4096];
    
    int bytes_received = SSL_read(ssl, buffer, sizeof(buffer));
    buffer[bytes_received] = '\0';
    SSL_write(ssl, "EHLO smtp.google.com\r\n" , strlen("EHLO smtp.google.com\r\n"));
    bytes_received = SSL_read(ssl, buffer, sizeof(buffer));
    buffer[bytes_received] = '\0';
    SSL_write(ssl, "AUTH LOGIN\r\n" , strlen("AUTH LOGIN\r\n"));
    bytes_received = SSL_read(ssl, buffer, sizeof(buffer));
    buffer[bytes_received] = '\0';
    char* base64_encoded = base64_encode((const unsigned char*)smtp_username, strlen(smtp_username));
    char* username_to_send = (char*)malloc(strlen(base64_encoded) + 3);
    strcpy(username_to_send, base64_encoded);
    strcat(username_to_send, "\r\n");
    SSL_write(ssl, username_to_send, strlen(username_to_send));
    bytes_received = SSL_read(ssl, buffer, sizeof(buffer));
    buffer[bytes_received] = '\0';
    free(base64_encoded);
    free(username_to_send);
    char* base64_encoded_password = base64_encode((const unsigned char*)smtp_password, strlen(smtp_password));
    char* password_to_send = (char*)malloc(strlen(base64_encoded_password) + 3);
    strcpy(password_to_send, base64_encoded_password);
    strcat(password_to_send, "\r\n");
    SSL_write(ssl, password_to_send, strlen(password_to_send));
    bytes_received = SSL_read(ssl, buffer, sizeof(buffer));
    buffer[bytes_received] = '\0';
    free(base64_encoded_password);
    free(password_to_send);

    char data_to_send[256];
    snprintf(data_to_send, sizeof(data_to_send), "MAIL FROM: <%s>\r\n", sender);
    SSL_write(ssl, data_to_send, strlen(data_to_send));
    bytes_received = SSL_read(ssl, buffer, sizeof(buffer));
    buffer[bytes_received] = '\0';
    snprintf(data_to_send, sizeof(data_to_send), "RCPT TO: <%s>\r\n", recipient);
    SSL_write(ssl, data_to_send, strlen(data_to_send));
    bytes_received = SSL_read(ssl, buffer, sizeof(buffer));
    buffer[bytes_received] = '\0';
    snprintf(data_to_send, sizeof(data_to_send), "DATA\r\n");
    SSL_write(ssl, data_to_send, strlen(data_to_send));
    bytes_received = SSL_read(ssl, buffer, sizeof(buffer));
    buffer[bytes_received] = '\0';
    SSL_write(ssl, mime_text, strlen(mime_text));
    SSL_write(ssl, "\r\n.\r\n", strlen("\r\n.\r\n"));
    bytes_received = SSL_read(ssl, buffer, sizeof(buffer));
    buffer[bytes_received] = '\0';
    snprintf(data_to_send, sizeof(data_to_send), "QUIT\r\n");
    SSL_write(ssl, data_to_send, strlen(data_to_send));
    bytes_received = SSL_read(ssl, buffer, sizeof(buffer));
    buffer[bytes_received] = '\0';
    printf("\nMail Send.\n");
}

int main(int argc, char *argv[]){
    time_t t;
    struct tm *tm_info;
    time(&t);
    tm_info = localtime(&t);
    char formatted_date[30];
    strftime(formatted_date, sizeof(formatted_date), "%d %b %Y %H:%M:%S %z", tm_info);
    int smtp_port = 465;
    // char* smtp_server = "smtp.gmail.com";
    // char* sender_email = "sender_email";
    char* recipent_email = "1someshverma@gmail.com";
    char* email_subject = "Request To Submit Assignment Before Due.";
    char* email_body = "Respected Sir,\n I am Vishal Sharma. I have completed my whole syllabys and now its your turn to complete the syllabus and complete the assignment, so we can go to mam and tell them that please mark our scores and we can go to the company and tell them that we have completed our course.";
    // char* smtp_username = "username";
    // char* smtp_password = "password";
    printf("Starting mail service...\n");
    // send_email(sender_email, recipent_email, email_subject, email_body, smtp_server, smtp_port, smtp_username, smtp_password, formatted_date);
    return 0;
}