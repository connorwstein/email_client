// typedef struct {
// 	int sockfd;
// 	SSL *ssl_sockfd;
// 	SSL_CTX *ssl_context;
// }ssl_socket;

int tcp_connect(char* host, char* port);
ssl_socket* ssl_connect(int sockfd);
char *ssl_read(ssl_socket *my_ssl_socket);

//--------------- Structs needed for connecting  ---------------- //
// 	struct addrinfo {
//     int              ai_flags;     // AI_PASSIVE, AI_CANONNAME, etc.
//     int              ai_family;    // AF_INET, AF_INET6, AF_UNSPEC
//     int              ai_socktype;  // SOCK_STREAM, SOCK_DGRAM
//     int              ai_protocol;  // use 0 for "any"
//     size_t           ai_addrlen;   // size of ai_addr in bytes
//     struct sockaddr *ai_addr;      // struct sockaddr_in or _in6
//     char            *ai_canonname; // full canonical hostname

//     struct addrinfo *ai_next;      // linked list, next node
// };

// struct sockaddr {
//     unsigned short    sa_family;    // address family, AF_xxx
//     char              sa_data[14];  // 14 bytes of protocol address, destination address and port number of socket
// }; 


// (IPv4 only--see struct sockaddr_in6 for IPv6)
// struct sockaddr_in {
//     short int          sin_family;  // Address family, AF_INET
//     unsigned short int sin_port;    // Port number, should be in network byte order, using htons()
//     struct in_addr     sin_addr;    // Internet address
//     unsigned char      sin_zero[8]; // Same size as struct sockadd, used to pad the structure to the length of sockaddr
// };
// (IPv4 only--see struct in6_addr for IPv6)
// Internet address (a structure for historical reasons)
// struct in_addr {
//     uint32_t s_addr; // that's a 32-bit int (4 bytes)
// };


// (IPv6 only--see struct sockaddr_in and struct in_addr for IPv4)
// struct sockaddr_in6 {
//     u_int16_t       sin6_family;   // address family, AF_INET6
//     u_int16_t       sin6_port;     // port number, Network Byte Order
//     u_int32_t       sin6_flowinfo; // IPv6 flow information
//     struct in6_addr sin6_addr;     // IPv6 address
//     u_int32_t       sin6_scope_id; // Scope ID
// };
// struct in6_addr {
//     unsigned char   s6_addr[16];   // IPv6 address
// };

//Use this if you are not sure whether it is going to be v4 or v6
// address family in the ss_family field—check this to see if it's AF_INET or AF_INET6 (for IPv4 or IPv6)
// Then you can cast it to a struct sockaddr_in or struct sockaddr_in6 if you wanna.
// 	struct sockaddr_storage {
//     sa_family_t  ss_family;     // address family

//     // all this is padding, implementation specific, ignore it:
//     char      __ss_pad1[_SS_PAD1SIZE];
//     int64_t   __ss_align;
//     char      __ss_pad2[_SS_PAD2SIZE];
// };


/* ---------   String --> struct sockaddr  --------------------- */
// struct sockaddr_in sa; // IPv4
// struct sockaddr_in6 sa6; // IPv6
// inet_pton(AF_INET, "192.0.2.1", &(sa.sin_addr)); // IPv4
// inet_pton(AF_INET6, "2001:db8:63b3:1::3490", &(sa6.sin6_addr)); // IPv6
/* -------------------------------------------------------------*/

/* ---------  struct sockaddr --> String  --------------------- */
// // IPv4:
// char ip4[INET_ADDRSTRLEN];  // space to hold the IPv4 string
// struct sockaddr_in sa;      // pretend this is loaded with something
// inet_ntop(AF_INET, &(sa.sin_addr), ip4, INET_ADDRSTRLEN);
// printf("The IPv4 address is: %s\n", ip4);
// // IPv6:
// char ip6[INET6_ADDRSTRLEN]; // space to hold the IPv6 string
// struct sockaddr_in6 sa6;    // pretend this is loaded with something
// inet_ntop(AF_INET6, &(sa6.sin6_addr), ip6, INET6_ADDRSTRLEN);
// printf("The address is: %s\n", ip6);
/* -------------------------------------------------------------*/

// //int getaddrinfo(const char *node,     // e.g. "www.example.com" or IP
 //                const char *service,  // e.g. "http" or port number
 //                const struct addrinfo *hints,
 //                struct addrinfo **res); //res is the results, linked list 
