// typedef struct {
// 	int sockfd;
// 	SSL *ssl_sockfd;
// 	SSL_CTX *ssl_context;
// }ssl_socket;

int tcp_connect(char* host, char* port);
ssl_socket* ssl_connect(int sockfd);
char *ssl_read(ssl_socket *my_ssl_socket);