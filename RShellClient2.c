#include <openssl/sha.h>
#include <openssl/conf.h>
#include <openssl/evp.h>
#include <openssl/err.h>

#include <time.h>
#include <stdbool.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netdb.h>
#include <arpa/inet.h>
#include <ifaddrs.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/errno.h>
#include <string.h>
#include <signal.h>
#include <sys/wait.h>
#include <sys/errno.h>


#define TYPE_SIZE		1
#define LENGTH_SIZE     2
#define ID_SIZE			16
#define MR_SIZE         1

#define BUFFER_SIZE 			4096	// used for buffer in most encryptions and decriptions
#define SHA_256_DIGEST_LENGTH 	32
#define SHA_1_DIGEST_LENGTH		20
#define PASSWORD_SIZE 			40


#define resultSz		 4096
#define	LINELEN			 128
#define MAX_PAYLOAD_SIZE 65536 // By definition of message format (for this project)
							// because payload length encoded in 16 bits (2^16) bytes
#define MAX_COMMAND_SIZE (MAX_PAYLOAD_SIZE - ID_SIZE) // We subtract the ID_SIZE 
													  // since id is embeded in payload 

#define RSHELL_REQ 		0x11
#define AUTH_CHLG 		0x12
#define AUTH_RESP 		0x13
#define AUTH_SUCCESS 	0x14
#define AUTH_FAIL 		0x15
#define RSHELL_RESULT 	0x16

// Components of message to send
char s_msgType;
short s_msgPayLength;
char s_msgId[ID_SIZE];
char *s_msgPayload;

// Components of message received
char r_msgType;
short r_msgPayLength;
char r_msgId[ID_SIZE];
char *r_msgPayload;

////////////////////////////////////////////////////////////////////////////////////
/////////////THE FOLLOWING BLOCK IS ALL CODE PROVIDED BY PROFESSOR//////////////////

int
clientsock(int UDPorTCP, const char *destination, int portN)
{
	struct hostent	*phe;		/* pointer to host information entry	*/
	struct sockaddr_in dest_addr;	/* destination endpoint address		*/
	int    sock;			/* socket descriptor to be allocated	*/

	printf("\n");
	printf("destination: %s\n", destination);
	printf("portN: %d\n", portN);


	bzero((char *)&dest_addr, sizeof(dest_addr));
	dest_addr.sin_family = AF_INET;

    /* Set destination port number */
	dest_addr.sin_port = htons(portN);

    /* Map host name to IPv4 address, does not work well for IPv6 */
	if ( (phe = gethostbyname(destination)) != 0 )
		bcopy(phe->h_addr, (char *)&dest_addr.sin_addr, phe->h_length);
	else if (inet_aton(destination, &(dest_addr.sin_addr))==0) /* invalid destination address */
		return -2;

/* version that support IPv6 
	else if (inet_pton(AF_INET, destination, &(dest_addr.sin_addr)) != 1) 
*/

    /* Allocate a socket */
	sock = socket(PF_INET, UDPorTCP, 0);
	if (sock < 0)
		return -3;

    /* Connect the socket */
	if (connect(sock, (struct sockaddr *)&dest_addr, sizeof(dest_addr)) < 0)
		return -4;


	return sock;
}
int 
clientTCPsock(const char *destination, int portN) 
{
  return clientsock(SOCK_STREAM, destination, portN);
}


int 
clientUDPsock(const char *destination, int portN) 
{
  return clientsock(SOCK_DGRAM, destination, portN);
}


void usage(char *self)
{
	fprintf(stderr, "Usage: %s destination port\n", self);
	exit(1);
}

void errmesg(char *msg)
{
	fprintf(stderr, "**** %s\n", msg);
	exit(1);

}

/*------------------------------------------------------------------------------
 * TCPrecv - read TCP socket sock w/ flag for up to buflen bytes into buf

 * return:
	>=0: number of bytes read
	<0: error
 *------------------------------------------------------------------------------
 */
int
TCPrecv(int sock, char *buf, int buflen, int flag)
{
	int inbytes, n;

	if (buflen <= 0) return 0;

  /* first recv could be blocking */
	inbytes = 0; 
	n=recv(sock, &buf[inbytes], buflen - inbytes, flag);
	if (n<=0 && n != EINTR)
		return n;

	buf[n] = 0;

#ifdef DEBUG
	printf("\tTCPrecv(sock=%d, buflen=%d, flag=%d): first read %d bytes : `%s`\n", 
			   sock, buflen, flag, n, buf);
#endif /* DEBUG */

  /* subsequent tries for for anything left available */

	for (inbytes += n; inbytes < buflen; inbytes += n)
	{ 
	 	if (recv(sock, &buf[inbytes], buflen - inbytes, MSG_PEEK|MSG_DONTWAIT)<=0) /* no more to recv */
			break;
	 	n=recv(sock, &buf[inbytes], buflen - inbytes, MSG_DONTWAIT);
		buf[n] = 0;
		
#ifdef DEBUG
		printf("\tTCPrecv(sock=%d, buflen=%d, flag=%d): subsequent read %d bytes : `%s`\n", 
			   sock, buflen, flag, n, &buf[inbytes]);
#endif /* DEBUG */

	  if (n<=0) /* no more bytes to receive */
		break;
	};

#ifdef DEBUG
		printf("\tTCPrecv(sock=%d, buflen=%d): read totally %d bytes : `%s`\n", 
			   sock, buflen, inbytes, buf);
#endif /* DEBUG */

	return inbytes;
}

int
RemoteShell(char *destination, int portN)
{
	char	buf[LINELEN+1];		/* buffer for one line of text	*/
	char	result[resultSz+1];
	int	sock;				/* socket descriptor, read count*/

	int	outchars, inchars;	/* characters sent and received	*/
	int n;

	if ((sock = clientTCPsock(destination, portN)) < 0)
		errmesg("fail to obtain TCP socket");

	while (fgets(buf, sizeof(buf), stdin)) 
	{
		buf[LINELEN] = '\0';	/* insure line null-terminated	*/
		outchars = strlen(buf);
		if ((n=write(sock, buf, outchars))!=outchars)	/* send error */
		{
#ifdef DEBUG
			printf("RemoteShell(%s, %d): has %d byte send when trying to send %d bytes to RemoteShell: `%s`\n", 
			   destination, portN, n, outchars, buf);
#endif /* DEBUG */
			close(sock);
			return -1;
		}
#ifdef DEBUG
		printf("RemoteShell(%s, %d): sent %d bytes to RemoteShell: `%s`\n", 
			   destination, portN, n, buf);
#endif /* DEBUG */

		/* Get the result */

		if ((inchars=recv(sock, result, resultSz, 0))>0) /* got some result */
		{
			result[inchars]=0;	
			fputs(result, stdout);			
		}
		if (inchars < 0)
				errmesg("socket read failed\n");
	}

	close(sock);
	return 0;
}
//////////////// END OF CODE PROVIDED BY PROFESSOR///////////////////////////////
/////////////////////////////////////////////////////////////////////////////////


int encryptWithAes(unsigned char *plain, int plainLength, unsigned char *key,
            unsigned char *iv, unsigned char *cipher)
{
    int length;
    int cipherLength;
    EVP_CIPHER_CTX *ctx;


    if(!(ctx = EVP_CIPHER_CTX_new()))
    	return -1; 


    if(1 != EVP_EncryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, key, iv))
    	return -1; 


    if(1 != EVP_EncryptUpdate(ctx, cipher, &length, plain, plainLength))
    	return -1; 

    cipherLength = length;

    if(1 != EVP_EncryptFinal_ex(ctx, cipher + length, &length))
    	return -1; 

    cipherLength += length;

    EVP_CIPHER_CTX_free(ctx);


    return cipherLength;
}


int decryptWithAes(unsigned char *cipher, int cipherLength, unsigned char *key,
            unsigned char *iv, unsigned char *plain)
{

    int length;
    int plainLength;
    EVP_CIPHER_CTX *ctx;


    if(!(ctx = EVP_CIPHER_CTX_new()))
        return -1;

    if(1 != EVP_DecryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, key, iv))
        return -1;

    if(1 != EVP_DecryptUpdate(ctx, plain, &length, cipher, cipherLength))
        return -1;
    plainLength = length;

    if(1 != EVP_DecryptFinal_ex(ctx, plain + length, &length))
        return -1;
    plainLength += length;

    EVP_CIPHER_CTX_free(ctx);

    return plainLength;
}



void cleanComponents(char option)
{
	if (option == 'r')
	{
		r_msgType = 0;
		r_msgPayLength = 0;
		r_msgId[0] = '\0';
		r_msgPayload = NULL;
	}
	else if( option == 's')
	{
		s_msgType = 0;
		s_msgPayLength = 0;
		s_msgId[0] = '\0';
		s_msgPayload = NULL;
	}
}


int sendToSocket(int socket)
{
	int bytesSent;

	bytesSent = write(socket, &s_msgType, TYPE_SIZE);
	if (bytesSent != TYPE_SIZE)
	{
		close(socket);
		return 0;
	}

	bytesSent = write(socket, &s_msgPayLength, LENGTH_SIZE);
	if (bytesSent != LENGTH_SIZE)
	{
		close(socket);
		return 0;
	}

	bytesSent = write(socket, &s_msgId, ID_SIZE);
	if (bytesSent != ID_SIZE)
	{
		close(socket);
		return 0;
	}

	bytesSent = write(socket, s_msgPayload, s_msgPayLength - ID_SIZE);
	if (bytesSent != (s_msgPayLength - ID_SIZE) )
	{
		close(socket);
		return 0;
	}

	cleanComponents('s');
	return 1;
}


int receiveFromSocket(int socket)
{
	cleanComponents('r');
	int bytesReceived;

	bytesReceived = recv(socket, &r_msgType, TYPE_SIZE, 0);
	if (bytesReceived != TYPE_SIZE)
	{
		close(socket);
		return 0;
	}

	bytesReceived = recv(socket, &r_msgPayLength, LENGTH_SIZE, 0);
	if (bytesReceived != LENGTH_SIZE)
	{
		close(socket);
		return 0;
	}

	bytesReceived = recv(socket, &r_msgId, ID_SIZE, 0);
	if (bytesReceived != ID_SIZE)
	{
		close(socket);
		return 0;
	}

	if (r_msgPayLength > ID_SIZE)
	{
        r_msgPayload = (char*)malloc( r_msgPayLength - ID_SIZE + 1);
		bytesReceived = recv(socket, r_msgPayload, (r_msgPayLength - ID_SIZE), 0);
		*(r_msgPayload + r_msgPayLength - ID_SIZE) = '\0';
		if (bytesReceived != (r_msgPayLength - ID_SIZE) )
		{
			close(socket);
			return 0;
		}

	}

	return 1;
}




/*------------------------------------------------------------------------
 * main  *------------------------------------------------------------------------
 */
int
main(int argc, char *argv[])
{
	// variables used for the duration of the running program (largest scope)
	char *destination;
	int  portN;
	unsigned char *hashPswdChars;
	unsigned char hashPswdChars2[(SHA_DIGEST_LENGTH * 2)];     // Trying w/out "\0"
	unsigned char hashPassword[SHA_DIGEST_LENGTH];
    char *rawPassword;
    char *userId;


	if (argc==5)
	{ 
		destination = argv[1];
		portN = atoi(argv[2]);
		userId = argv[3];
		rawPassword = argv[4];	// storing the password for later use  
	}
	else 
		usage(argv[0]);


	//******  Encrypting Password with SHA1 encryption *****************
	SHA_CTX ctx;
	SHA1_Init(&ctx);
	SHA1_Update(&ctx, argv[4], strlen(argv[4]));
	SHA1_Final(hashPassword, &ctx);

	int counter;
	for(counter=0; counter<SHA_DIGEST_LENGTH; counter++)
        sprintf( ((unsigned char*) &(hashPswdChars2[ counter * 2 ])), "%02x", hashPassword[ counter ] );

    hashPswdChars = (unsigned char*)malloc(41);
    memcpy(hashPswdChars, hashPswdChars2, 40);
    hashPswdChars[40] = '\0';


	//******************************************************************



	int socket  = clientTCPsock(destination, portN);	 

	printf("socket: %d\n", socket);

	if (socket < 0)
	{
		printf("\nProgram couln't obtain a socket.\n");
		exit(1);
	}
	
	cleanComponents('r');	// cleaning all variables used to 
	cleanComponents('s');	// form the messages to send and receive info

	char cmdStr[MAX_COMMAND_SIZE];

	printf("\nConnection was established with Remote Shell.\n");


	////// Now we can start waiting for user's inputs from shell command line //////


	printf("\nclient-remote-shell-prompt> ");
	// while the user/client typed in a new command
	cmdStr[0] = '\0';
	while(fgets(cmdStr, sizeof(cmdStr), stdin))
	{


		// variables that need to be declared every time there is a new shell cmd
		// comming in to hold entirely new values every time (scope of a while cycle)
		unsigned int nonce1Num;  
		char nonce1Chars[MAX_COMMAND_SIZE];
		char nonce1PlusOneChars[MAX_COMMAND_SIZE];
	
		unsigned int nonce2Num;  
		char *nonce2Chars;
		char nonce2PlusOneChars[MAX_COMMAND_SIZE];

		unsigned char *keyComponents;
		unsigned char hashKey[SHA_DIGEST_LENGTH];
		unsigned char hashKeyChars[SHA_DIGEST_LENGTH * 2];

		unsigned char *ivComponents;
		unsigned char hashIv[SHA_DIGEST_LENGTH];
		unsigned char hashIvChars[SHA_DIGEST_LENGTH * 2];

		unsigned char cipher[BUFFER_SIZE];
		unsigned char decrypted[BUFFER_SIZE];


		// if user typed in a new command
		if(strlen(cmdStr) > 1)
		{
			// storing the command for later use (getting rid of change of line character)
			cmdStr[strlen(cmdStr) -	1] = '\0';   

			//////////////////////////////////////////////////////////
			///// Setting up components for RSHELL_REQ message ///////

			// Creating our nonce1 to send it to server
			nonce1Num = rand();
			sprintf(nonce1Chars, "%u", nonce1Num);

			s_msgType = RSHELL_REQ;
			s_msgPayLength = ID_SIZE + 32;
			memcpy(s_msgId, userId, (ID_SIZE - 1));
			s_msgId[strlen(userId)] = '\0';
			s_msgPayload = nonce1Chars;
			///////////////////////////////////////////////////////////

			// printf("\nclient sent RSHELL_REQ with:\n");
			// printf("payLength: %d\n", s_msgPayLength);
			// printf("userId: %s\n", s_msgId);
			// printf("nonce1: %s\n", s_msgPayload);

			// And now sending RSHELL_REQ to server
			sendToSocket(socket);


			receiveFromSocket(socket);

			if (r_msgType == AUTH_CHLG)
			{

				// printf("\nWe got an AUTH_CHLG with:\n");
				// printf("payLength: %d\n", r_msgPayLength);
				// printf("userId: %s\n", r_msgId);
				// printf("nonce2: %s\n", r_msgPayload);
	    
				/////////////////////////////////////////////////////////////
				////// Setting up elems to create payload for AUTH_RES///////
			    // extracting the char version of nonce2 from server
				char *x;
				nonce2Chars = r_msgPayload;
				nonce2Num = strtol(nonce2Chars, &x, 10);

				// and converting it into nonce2+1 as an array of unsigned chars
			    sprintf(nonce2PlusOneChars, "%u", (nonce2Num+1) );

			    // Building key by using SHA256
			    keyComponents = hashPswdChars;
			    strcat(keyComponents, nonce1Chars);
			    strcat(keyComponents, nonce2Chars);
			    SHA256(keyComponents, strlen(keyComponents), hashKey);

				for(counter=0; counter<SHA_DIGEST_LENGTH; counter++)
			        sprintf( ((unsigned char*) &(hashKeyChars[ counter * 2 ])), "%02x", hashKey[ counter ] );

			    // Building iv by using SHA256
			    ivComponents = nonce1Chars;
			    strcat(ivComponents, nonce2Chars);
			    SHA256(ivComponents, strlen(ivComponents), hashIv);

			    // Cutting size of iv from 20 bytes to 16 bytes, while turning into a readable char array
				for(counter=0; counter<16; counter++)
			        sprintf( ((unsigned char*) &(hashIvChars[ counter * 2 ])), "%02x", hashIv[ counter ] );
	
			    // Encrypting the payload, which is  ( nonce2+1 | cmd )
			    unsigned char *plain = nonce2PlusOneChars;
			    strcat(plain, cmdStr);
			    plain[strlen(plain)] = '\0';

			    int cipherLength = encryptWithAes(plain, strlen(plain), hashKeyChars, hashIvChars, cipher);
			    ////////////////////////////////////////////////////////////////



			    //////////////////////////////////////////////////////
				///////  Constructing AUTH_RESP message  /////////////

				s_msgType = AUTH_RESP;
				s_msgPayLength = ID_SIZE + cipherLength;
				memcpy(s_msgId, userId, (ID_SIZE - 1));
				s_msgId[strlen(userId)] = '\0';
				s_msgPayload = cipher;

				// printf("\nclient sent RSHELL_RESP with:\n");
				// printf("payLength: %d\n", s_msgPayLength);
				// printf("userId: %s\n", s_msgId);
				// printf("cipher: %s\n", s_msgPayload);

			    // printf("\nhashPswdChars:  %s\n", hashPswdChars);
			    // printf("nonce1Chars:  %s\n", nonce1Chars);
			    // printf("nonce2Chars:  %s\n", nonce2Chars);
			    // printf("Key:  %s\n", hashKeyChars);
			    // printf("iv:  %s\n", hashIvChars);
			    // printf("plain:  %s\n", plain);


				sendToSocket(socket);
				////////////////////////////////////////////////////////

				receiveFromSocket(socket);

				if (r_msgType == AUTH_SUCCESS)
				{
		
					// printf("\nWe got an AUTH_SUCCESS with:\n");
					// printf("payLength: %d\n", r_msgPayLength);
					// printf("userId: %s\n", r_msgId);
					// printf("cipher: %s\n", r_msgPayload);

					int decryptedLength = decryptWithAes((unsigned char *)r_msgPayload, r_msgPayLength - ID_SIZE, hashKeyChars, hashIvChars, decrypted);
					decrypted[decryptedLength] = '\0';

					char *y;
					unsigned int nonce1PlusOne = (unsigned int) strtol(decrypted, &y, 10);
					if(nonce1PlusOne == nonce1Num+1)
						printf("\nAuthentication was Successful!\n");
								
					else
					{
						printf("\nAuthentication failed.\n");
						exit(1);
						break;
					}		

	
					receiveFromSocket(socket);
					if (r_msgType == RSHELL_RESULT)
					{

						// printf("\nWe got RSHELL_RESULT with:\n");
						// printf("payLength: %d\n", r_msgPayLength);
						// printf("userId: %s\n", r_msgId);
						// printf("results: %s\n", r_msgPayload);

						if (r_msgPayload != NULL)
							printf("\nCommand's Results: \n%s \n", r_msgPayload);
						else
							printf("\nThere was no results for your command.\n");
					}	
				}
				else if (r_msgType == AUTH_FAIL)
				{
					printf("Server could not authenticate client %s.\n", userId);
					exit(1);
				}

				printf("\nclient-remote-shell-prompt> ");

				cmdStr[0] = '\0';	// clearing the char array for a new command


			}
			else
			{
				printf("Client was expecting a AUTH_CHLG type of message.\n");
				exit(1);
			}
		}
		else
			exit(0);

	}

	exit(0);
}
