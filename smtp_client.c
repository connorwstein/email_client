#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/socket.h> //AF_INET, SOCK_STREAM, socket 
#include <strings.h> //memset 
#include <sys/types.h>
#include <netdb.h>
#include <arpa/inet.h> //inet_ntop
#include <math.h>

 #include <sasl/saslutil.h> //for SASL_OK

#include <openssl/ssl.h> //for ssl stuff
#include <openssl/err.h> //for the SSL_load_error_strings()

#define EHLO "EHLO\r\n"

typedef struct {
	int sockfd;
	SSL *ssl_sockfd;
	SSL_CTX *ssl_context;
}ssl_socket;

//Returns a socket file descriptor
int tcp_connect(char* host, char* port){
	
	int status;
	struct addrinfo info_hints; //hints as to the type of results desired from getaddrinfo (fills up the addrinfo struct for us)
	struct addrinfo *info_results; //points to results (linked list of all resolved addrinfo)

	memset(&info_hints, 0, sizeof info_hints);
	info_hints.ai_family = AF_UNSPEC; //keep it unspecified to support ipv4 and ipv6
	info_hints.ai_socktype = SOCK_STREAM; //tcp socket

	if((status = getaddrinfo(host, port, &info_hints, &info_results))!=0){
		//Non zero return value from getaddrinfo causes and error
		fprintf(stderr,"Error getting address information: %s\n",gai_strerror(status));
	}
	struct addrinfo *p=info_results; //pointer to loop through the results;
	char ipstr[INET6_ADDRSTRLEN]; //larger than ipv4 size so will use it for both

	int sockfd=-1; //if this never gets successfully assigned then will return -1;
	while(p!=NULL){
		void *addr=NULL;
        char *ipver=NULL;
        // get the pointer to the address itself,
        // different fields in IPv4 and IPv6:
        if (p->ai_family == AF_INET) { // IPv4
            struct sockaddr_in *ipv4 = (struct sockaddr_in *)p->ai_addr; //p->ai_addr is a sockaddr which can be cast to either sockaddr_in (for v4) or sockaddr_in6 (v6)
            addr = &(ipv4->sin_addr);
            ipver = "IPv4";
        } 
        else if(p->ai_family == AF_INET6) { // IPv6
            struct sockaddr_in6 *ipv6 = (struct sockaddr_in6 *)p->ai_addr;
            addr = &(ipv6->sin6_addr);
            ipver = "IPv6";
        }
        else{
        	fprintf(stderr, "Unrecognized IP address version\n");
        	goto next;
        }
        // convert the IP to a string and print it:
        inet_ntop(p->ai_family, addr, ipstr, sizeof ipstr);
        printf("Gmail server %s: %s\n", ipver, ipstr);

        //Create a socket for given infoaddr
        if((sockfd=socket(p->ai_family, p->ai_socktype, p->ai_protocol))==-1){
        	fprintf(stderr, "Unable to create socket\n");
        	goto next;
        };
        // //Bind it to the port passed into getaddrinfo, not necessary if we are a client and dont care about our local port
        // if(bind(sockfd, p->ai_addr, p->ai_addrlen)==-1){
        // 	fprintf(stderr,"Unable to bind socket\n");
        // 	goto next;
        // }
        if(connect(sockfd, p->ai_addr, p->ai_addrlen)!=-1){
        	//successful connection, do not need to check other results from getinfoaddr
        	break;
        }
        else{
        	fprintf(stderr,"Failed to connect\n");
        }
		next: p=p->ai_next; //go to next result
	}
	freeaddrinfo(info_results);
	return sockfd;
}


void ssl_init(void){
	//Initialization
	SSL_load_error_strings(); //register error strings
	SSL_library_init(); //register available ciphers
	OpenSSL_add_all_algorithms(); //link against crypto lib with -lcrypto
}

void ssl_close(ssl_socket *my_ssl_socket){
	close(my_ssl_socket->sockfd);
	SSL_shutdown(my_ssl_socket->ssl_sockfd);
	SSL_free(my_ssl_socket->ssl_sockfd);
	SSL_CTX_free(my_ssl_socket->ssl_context);
}

ssl_socket* ssl_connect(int sockfd){
	//New context saying we are a client using ssl 2 or 3
	ssl_socket *my_ssl_socket=malloc(sizeof(ssl_socket));
	my_ssl_socket->sockfd=sockfd;
	my_ssl_socket->ssl_context=SSL_CTX_new(SSLv23_client_method());
	my_ssl_socket->ssl_sockfd=SSL_new(my_ssl_socket->ssl_context);
	if(my_ssl_socket->ssl_context==NULL || my_ssl_socket->ssl_sockfd==NULL){
		ERR_print_errors_fp(stderr);
		return NULL;
	}
	if(!SSL_set_fd(my_ssl_socket->ssl_sockfd, my_ssl_socket->sockfd)){
		ERR_print_errors_fp(stderr);
		return NULL;
	};
  	// Initiate SSL handshake
  	if (SSL_connect (my_ssl_socket->ssl_sockfd) != 1){
  		ERR_print_errors_fp (stderr);
  		return NULL;
  	}
	return my_ssl_socket;
}

// Read all available text from the connection, maximum 1024 bytes
char *ssl_read(ssl_socket *my_ssl_socket)
{
	const int MAX_READ_BUF_SIZE = 1024;
	char *result= NULL;
	int bytes_received;
	char read_buffer[MAX_READ_BUF_SIZE];

	if (my_ssl_socket!=NULL)
	{
		bytes_received=SSL_read(my_ssl_socket->ssl_sockfd,read_buffer,MAX_READ_BUF_SIZE);
		//printf("Read buffer: %s\n",read_buffer);
		if(bytes_received>0){
			result=malloc(bytes_received*sizeof(char)+1); //+1 for the null byte to make a string
			memcpy(result, read_buffer,bytes_received);
			*(result+bytes_received)='\0'; //make it a string
			return result;
		}
		else{
			fprintf(stderr, "Error reading from socket, receivied %d bytes\n",bytes_received);
			return NULL;
		}
	}
	return result;
}

// int send_email(ssl_socket *my_ssl_socket){
// 	printf("Read: %s\n",ssl_read(my_ssl_socket)); //Should read smtp code 220
	
// 	char *init="EHLO\r\n";
// 	printf("%s",init);
// 	SSL_write(my_ssl_socket->ssl_sockfd,init, strlen(init));
// 	printf("Read: %s\n",ssl_read(my_ssl_socket)); //Should read smtp code 250
	
// 	char *login="AUTH PLAIN AGNvbm5vci5zdGVpbjJAZ21haWwuY29tAGdvbzFuZ0MwbiMxMg==\r\n";
// 	printf("%s",login);
// 	SSL_write(my_ssl_socket->ssl_sockfd,login, strlen(login));
// 	printf("Read: %s\n",ssl_read(my_ssl_socket));
	
// 	char *mail_from="MAIL FROM: <connor.stein2@gmail.com>\r\n";
// 	printf("%s",mail_from);
// 	SSL_write(my_ssl_socket->ssl_sockfd, mail_from, strlen(mail_from));
// 	printf("Read: %s\n", ssl_read(my_ssl_socket)); //should be 250

// 	char *to="rcpt to: <connor.stein2@gmail.com>\r\n";
// 	printf("%s",to);
// 	SSL_write(my_ssl_socket->ssl_sockfd,to, strlen(to));
// 	printf("Read: %s\n",ssl_read(my_ssl_socket)); //should be 250

// 	char *data="DATA\r\n";
// 	printf("%s",data);
// 	SSL_write(my_ssl_socket->ssl_sockfd,data, strlen(data));
// 	printf("Read: %s\n",ssl_read(my_ssl_socket)); //should be 354

// 	char *test_email="Subject: Hello World\nCommand line email baby!\r\n.\r\n";
// 	printf("%s",test_email);
// 	SSL_write(my_ssl_socket->ssl_sockfd,test_email, strlen(test_email));
// 	printf("Read: %s\n", ssl_read(my_ssl_socket)); //should be 250

// 	char *close="quit\r\n";
// 	printf("%s",close);
// 	SSL_write(my_ssl_socket->ssl_sockfd,close, strlen(close));
// 	printf("Read: %s\n", ssl_read(my_ssl_socket)); //should be 221

// 	ssl_close(my_ssl_socket);
// }

int authenticate(ssl_socket* my_ssl_socket, char* encoded_auth){
	if(encoded_auth==NULL){
		return -1;
	}
	char *read;
	if((read=ssl_read(my_ssl_socket))==NULL||strstr(read,"220")==NULL){
		printf("Fail to obtain 220 smtp code\n");
		free(read);
		return -1;
	}
	SSL_write(my_ssl_socket->ssl_sockfd,EHLO, strlen(EHLO));
	if((read=ssl_read(my_ssl_socket))==NULL||strstr(read,"250")==NULL){
		printf("Fail to obtain 250 smtp code\n");
		free(read);
		return -1;
	}
	char login[200];
	sprintf(login,"%s %s\r\n","AUTH PLAIN", encoded_auth);
	SSL_write(my_ssl_socket->ssl_sockfd,login, strlen(login));
	if((read=ssl_read(my_ssl_socket))==NULL||strstr(read,"235")==NULL){
		printf("Fail to obtain 235 smtp code when authenicating\n");
		free(read);
		return -1;
	}
	return 0;
}

char *generate_auth_plain_base64(char* email_address, char* password){
	BIO *bio, *b64;
	char message[200];
	memset(message, 0, sizeof(message));
	int email_address_length=strlen(email_address);
	int password_length=strlen(password);
	message[0]='\0'; //"\0"
	memcpy(message+1, email_address, email_address_length);//"\0emailaddress"
	message[email_address_length+1]='\0';//"\0emailaddress\0"
	memcpy(message+email_address_length+2, password, password_length); //"\0emailaddress\0password"

	int encoded_size=4*ceil((double)(email_address_length+password_length+2)/3); //note do not use strlen because there is null bytes in the string
	
	char *buffer = (char *)malloc(encoded_size+1);
	unsigned actuallength=0;
	//Note to use this link agains libsasl2 i.e. -lsasl2 when compiling
	int status=sasl_encode64(message, email_address_length+password_length+2, buffer, encoded_size+1, &actuallength);
	if(SASL_OK==status){
		//printf("successful encode: %s\n",buffer);
		return buffer;
	}
	return NULL;
}


int main(int argc, char *argv[]){

	int sockfd=tcp_connect("smtp.gmail.com", "465");
	struct timeval timeout;      
    timeout.tv_sec = 5;
    timeout.tv_usec = 0;
	if (setsockopt (sockfd, SOL_SOCKET, SO_RCVTIMEO, (char *)&timeout, sizeof(timeout)) < 0) perror("setsockopt failed\n");
	ssl_init();
	//Create SSL layer on top of TCP
	ssl_socket *my_ssl_socket=ssl_connect(sockfd);
	char *read;
	int count = 0;
	while(1){
		char email_address[100];
		memset(email_address, 0, sizeof(email_address));
		 if(count==0){
			char email_address[100];
			memset(email_address, 0, sizeof(email_address));
			char *password;
			printf("\nLogin to gmail\n");
			printf("Enter gmail address: ");
			scanf("%s",email_address);
			password=getpass("Enter gmail password: ");
			char *auth_base64=generate_auth_plain_base64(email_address ,password);
			if(authenticate(my_ssl_socket,auth_base64)==-1){
				printf("Failed to authenticate");
				count=0;
				continue;
			}
			printf("Authenication successful\n");
			free(auth_base64);
		 }
		///--- Sender address ----//
		char mail_from[200];
		sprintf(mail_from,"%s %s\r\n","MAIL FROM: ", "<connor.stein2@gmail.com>");
		//printf("%s", mail_from);
		SSL_write(my_ssl_socket->ssl_sockfd, mail_from, strlen(mail_from));
		if((read=ssl_read(my_ssl_socket))==NULL||strstr(read,"250")==NULL){
			printf("Fail to obtain 250 smtp code when sending mail from command\n");
			count++;	
			free(read);
			continue;
		}
		//-----------------------//
		//--- Receiver address---//
		char to_buf[200];
		printf(">>>> TO: ");
		scanf("%s",to_buf);
		char to[200];
		sprintf(to,"%s <%s>\r\n","RCPT TO:", to_buf);
		//printf("%s",to);
		SSL_write(my_ssl_socket->ssl_sockfd,to, strlen(to));
		if((read=ssl_read(my_ssl_socket))==NULL||strstr(read,"250")==NULL){
			printf("Failed to obtain 250 smtp code when sending rcpt to command\n"); //should be 250
			count++;	
			free(read);
			continue;
		}
		//----------------------//
		//--- Email Data ---//
		printf(">>>> COMPOSE (~ to terminate): ");
		SSL_write(my_ssl_socket->ssl_sockfd,"DATA\r\n", strlen("DATA\r\n"));
		if((read=ssl_read(my_ssl_socket))==NULL||strstr(read,"354")==NULL){
			printf("Failed to obtain 354 smtp code when sending data command\n"); //should be 250
			count++;	
			free(read);
			continue;
		}
		char data_buf[500];
		int i=0;
		int c;
		while((c=getchar())!='~'){
			data_buf[i++]=c;
		}
		char data[500];
		sprintf(data, "%s\r\n.\r\n",data_buf);
		SSL_write(my_ssl_socket->ssl_sockfd,data, strlen(data));
		if((read=ssl_read(my_ssl_socket))==NULL||strstr(read,"250")==NULL){
			printf("Failed to obtain 354 smtp code when sending data command\n"); //should be 250
			count++;	
			free(read);
			continue;
		}
		count++;
	}
	
	return 0;
}