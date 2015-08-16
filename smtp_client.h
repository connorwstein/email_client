
typedef struct {
	int sockfd;
	SSL *ssl_sockfd;
	SSL_CTX *ssl_context;
}ssl_socket;

int tcp_connect(char* host, char* port);
ssl_socket* ssl_connect(int sockfd);
void ssl_init(void);
void ssl_close(ssl_socket *my_ssl_socket);
char *ssl_read(ssl_socket *my_ssl_socket);
int authenticate(ssl_socket* my_ssl_socket, char* encoded_auth, int first_try);
char *generate_auth_plain_base64(char* email_address, char* password);
