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
#define SHA_1_DIGEST_LENGTH 	20
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
//#define DEBUG

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

unsigned char *userId;


////////////////////////////////////////////////////////////////////////////////////
/////////////THE FOLLOWING BLOCK IS ALL CODE PROVIDED BY PROFESSOR//////////////////

int
serversock(int UDPorTCP, int portN, int qlen)
{
	struct sockaddr_in svr_addr;	/* my server endpoint address		*/
	int    sock;			/* socket descriptor to be allocated	*/

	if (portN<0 || portN>65535 || qlen<0)	/* sanity test of parameters */
		return -2;

	bzero((char *)&svr_addr, sizeof(svr_addr));
	svr_addr.sin_family = AF_INET;
	svr_addr.sin_addr.s_addr = INADDR_ANY;

    /* Set destination port number */
	svr_addr.sin_port = htons(portN);

    /* Allocate a socket */
	sock = socket(PF_INET, UDPorTCP, 0);
	if (sock < 0)
		return -3;

    /* Bind the socket */
	if (bind(sock, (struct sockaddr *)&svr_addr, sizeof(svr_addr)) < 0)
		return -4;

	if (UDPorTCP == SOCK_STREAM && listen(sock, qlen) < 0)
		return -5;

	return sock;
}

int 
serverTCPsock(int portN, int qlen) 
{
  return serversock(SOCK_STREAM, portN, qlen);
}

int 
serverUDPsock(int portN) 
{
  return serversock(SOCK_DGRAM, portN, 0);
}

void 
usage(char *self)
{
	fprintf(stderr, "Usage: %s port\n", self);
	exit(1);
}

void 
errmesg(char *msg)
{
	fprintf(stderr, "**** %s\n", msg);
	exit(1);

}

/*------------------------------------------------------------------------
 * reaper - clean up zombie children
 *------------------------------------------------------------------------
 */
void
reaper(int signum)
{
/*
	union wait	status;
*/

	int status;

	while (wait3(&status, WNOHANG, (struct rusage *)0) >= 0)
		/* empty */;
}

/*------------------------------------------------------------------------
 *  This is a very simplified remote shell, there are some shell command it 
	can not handle properly:

	cd
 *------------------------------------------------------------------------
 */
int
RemoteShellD(int sock)
{
#define	BUFSZ		128
#define resultSz	4096
	char cmd[BUFSZ+20];
	char result[resultSz];
	int	cc, len;
	int rc=0;
	FILE *fp;

#ifdef DEBUG
	printf("***** RemoteShellD(sock=%d) called\n", sock);
#endif

	while ((cc = read(sock, cmd, BUFSZ)) > 0)	/* received something */
	{	
		
		if (cmd[cc-1]=='\n')
			cmd[cc-1]=0;
		else cmd[cc] = 0;

#ifdef DEBUG
		printf("***** RemoteShellD(%d): received %d bytes: `%s`\n", sock, cc, cmd);
#endif

		strcat(cmd, " 2>&1");
#ifdef DEBUG
	printf("***** cmd: `%s`\n", cmd); 
#endif 
		if ((fp=popen(cmd, "r"))==NULL)	/* stream open failed */
			return -1;

		/* stream open successful */

		while ((fgets(result, resultSz, fp)) != NULL)	/* got execution result */
		{
			len = strlen(result);
			printf("***** sending %d bytes result to client: \n`%s` \n", len, result);

			if (write(sock, result, len) < 0)
			{ rc=-1;
			  break;
			}
		}
		fclose(fp);

	}

	if (cc < 0)
		return -1;

	return rc;
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
      r_msgPayload = (char*)malloc( r_msgPayLength - ID_SIZE + 1); // +1 is for '\0'
		bytesReceived = recv(socket, r_msgPayload, (r_msgPayLength - ID_SIZE), 0);
		*(r_msgPayload + r_msgPayLength - ID_SIZE) = '\0';
		if (bytesReceived != (r_msgPayLength - ID_SIZE) )
		{
			close(socket);
			free(r_msgPayload);
			return 0;
		}
	}

	return 1;
}


int getPasswordFromFile(char *fileName, char *userId, unsigned char *pwdFromF)
{	
	FILE *file;
	char *fileLine; 
	char *userFromFile;
	char *passwordFromFile;
	size_t lineLength;

	if (file = fopen(fileName, "r"))
	{   

		getline(&fileLine, &lineLength, file);
		fclose(file);

		userFromFile = strtok(fileLine, "; \n");
		passwordFromFile = strtok(NULL, "; \n");

		memcpy(pwdFromF, passwordFromFile, strlen(passwordFromFile));
		pwdFromF[strlen(pwdFromF)] = '\0';

		// if userId was not found in the userID/Password file
		if (strcmp(userId, userFromFile) != 0)
		{
			printf("Autenthication FAILED for user %s.\n", userId);
			return 0;
		}
		// else return success
		else
			return 1;
    }


	else
	{
		printf("Failed to open the file in server containing the passwords.");
		exit(1);
	}

	return 0;

}


void createResultMessage(char *command)
{
	FILE *resultFile;
	char cmdResult[resultSz];


	memset(cmdResult, 0, resultSz);

	resultFile = popen(command, "r");
	strcat(command, "2>&1");
	fread(cmdResult, resultSz, 1, resultFile);
	pclose(resultFile);

	cmdResult[strlen(cmdResult) - 1] = '\0';
	s_msgType = RSHELL_RESULT;
	s_msgPayLength = ID_SIZE + strlen(cmdResult);
	// s_msgId has to be set with userId outside this function

	if (resultFile != NULL)
		s_msgPayload = cmdResult;
	
	else
		s_msgPayload = NULL;
	
}






/*------------------------------------------------------------------------
 * main - Concurrent TCP server 
 *------------------------------------------------------------------------
 */
int
main(int argc, char *argv[])
{	
	// Variables for Connection with client
	int	 msock;			/* master server socket		*/
	int	 ssock;			/* slave server socket		*/
	int  portN;			/* port number to listen */
	struct sockaddr_in fromAddr;	/* the from address of a client	*/
	unsigned int  fromAddrLen;		/* from-address length          */

	// Variables for time calculations
	struct timeval timeOfAuth;
    struct timeval timeOfCmd;

	// Variables to store values for authentication methods that 
	// should remain the same during the whole time the program is running
	char *pwdFileName;
	int authenticated = 0;
	unsigned char *password;
	unsigned char hashPswdChars[(SHA_DIGEST_LENGTH * 2)];     // Trying w/out "\0"
	unsigned char hashPassword[SHA_DIGEST_LENGTH];
    char *rawPassword;
    char *userId;
    unsigned char passwordFromFile[BUFFER_SIZE];
    int counter;


	if (argc != 3)
		usage(argv[0]);
	else
	{
		portN = atoi(argv[1]);
		pwdFileName = argv[2];
	}

	msock = serverTCPsock(portN, 5);

	(void) signal(SIGCHLD, reaper);

	while (1) 
	{

		fromAddrLen = sizeof(fromAddr);
		ssock = accept(msock, (struct sockaddr *)&fromAddr, &fromAddrLen);
		if (ssock < 0) {
			if (errno == EINTR)
				continue;
			errmesg("accept error\n");
		}


		printf("\nConnection was made with a client.\n");

		switch (fork()) 
		{
			case 0:		/* child */
				close(msock);


				while(receiveFromSocket(ssock))
				{
					// variables that need to be declared every time there is a new request from
					// the client (to hold entirely new values every request (scope of a while cycle)
					unsigned int nonce2Num;  
					char nonce2Chars[MAX_COMMAND_SIZE];
					char nonce2PlusOneChars[MAX_COMMAND_SIZE];
				
					unsigned int nonce1Num;  
					char *nonce1Chars;
					char nonce1PlusOneChars[MAX_COMMAND_SIZE];

					unsigned char *keyComponents;
					unsigned char hashKey[SHA_DIGEST_LENGTH];
					unsigned char hashKeyChars[SHA_DIGEST_LENGTH * 2];

					unsigned char *ivComponents;
					unsigned char hashIv[SHA_DIGEST_LENGTH];
					unsigned char hashIvChars[SHA_DIGEST_LENGTH * 2];

					unsigned char cipher[BUFFER_SIZE];
					unsigned char decrypted[BUFFER_SIZE];

					unsigned char *cmdStr;


                    if (r_msgType == RSHELL_REQ)
                    {
                    	
						// printf("\nServer got RSHELL_REQ with:\n");
						// printf("payLength: %d\n", r_msgPayLength);
						// printf("userId: %s\n", r_msgId);
						// printf("nonce1: %s\n", r_msgPayload);
	    
       					// Capturing the Client's ID for future use
	    				userId = (unsigned char*)malloc( strlen(r_msgId)+1);
						memcpy(userId, r_msgId, strlen(r_msgId));
				 	    userId[strlen(r_msgId)] = '\0';

				 	    // Capturing nonce1 (and convert to int) from Client and storing it for future use
                    	nonce1Chars = (char*)malloc( (r_msgPayLength - ID_SIZE) + 1);
                    	memcpy(nonce1Chars, r_msgPayload, (r_msgPayLength - ID_SIZE));
                    	nonce1Chars[r_msgPayLength - ID_SIZE] = '\0';

						char* x;
			    		nonce1Num = (unsigned int) strtol(nonce1Chars, &x, 10); 
						// and converting it into nonce1+1 as an array of unsigned chars

		 			    sprintf(nonce1PlusOneChars, "%u", (nonce1Num+1) );
		 			    nonce1PlusOneChars[strlen(nonce1PlusOneChars)] = '\0';

			    		// Creating our nonce2 to send to client
						nonce2Num = rand();
						sprintf(nonce2Chars, "%u", nonce1Num);

						// Packing up the message to send it to client
                    	s_msgType = AUTH_CHLG;
                    	s_msgPayLength = ID_SIZE + 32;  
                    	memcpy(s_msgId, userId, ID_SIZE-1);
                    	s_msgId[strlen(userId)] = '\0';
                    	s_msgPayload = nonce2Chars;

                    	sendToSocket(ssock);

						// printf("\nWe are sending an AUTH_REQ\n");
						// printf("Sending it with nonce2: %s\n", nonce2Chars);

                    	receiveFromSocket(ssock);
                    	if(r_msgType == AUTH_RESP)
                    	{

							// printf("\nWe got a AUTH_RESP with:\n");
							// printf("payLength: %d\n", r_msgPayLength);
							// printf("userId: %s\n", r_msgId);
							// printf("cipher: %s\n\n", r_msgPayload);

                    		// if userId was found in password file
	                    	if (getPasswordFromFile(pwdFileName, userId, passwordFromFile) ) 
	                    	{

								///////////////////////////////////////////////////////////////
								////// Setting up elems to decrypt payload from AUTH_RESP ///////

							    // Building key by using SHA256
							    keyComponents = passwordFromFile;
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


							    // printf("\nhashPswdChars:  %s\n", passwordFromFile);
							    // printf("nonce1Chars:  %s\n", nonce1Chars);
							    // printf("nonce2Chars:  %s\n", nonce2Chars);
							    // printf("Key:  %s\n", hashKeyChars);
							    // printf("iv:  %s\n", hashIvChars);
							    // printf("cipher:  %s\n", r_msgPayload);
										
							    // Derypting the payload, which is  ( nonce2+1 | cmd )
							    int decryptedLength = decryptWithAes((unsigned char*)r_msgPayload, (r_msgPayLength - ID_SIZE), hashKeyChars, hashIvChars, decrypted);
							    decrypted[decryptedLength] = '\0';
							    ////////////////////////////////////////////////////////////////

							    // extracting nonce2 and command
								unsigned int nonce2PlusOneNum = (unsigned int) strtol(decrypted, &cmdStr, 10);

								// if authentication of client was successful 
							    if (nonce2PlusOneNum == nonce2Num + 1)
							    {
									printf("\nAuthentication was Successful!\n");


		                    		// creates RSHELL_SUCCESS and sends it
								    int cipherLength = encryptWithAes(nonce1PlusOneChars, strlen(nonce1PlusOneChars), hashKeyChars, hashIvChars, cipher);

		                    		s_msgType = AUTH_SUCCESS;
	                    			s_msgPayLength = ID_SIZE + cipherLength;
	                    			memcpy(s_msgId, userId, ID_SIZE-1);
			                    	s_msgId[strlen(userId)] = '\0';
	                    			s_msgPayload = cipher;
	                    			
									// printf("\nWe are sending an RSHELL_SUCCESS with:\n");
									// printf("payLength: %d\n", s_msgPayLength);
									// printf("userId: %s\n", s_msgId);
									// printf("cipher: %s\n", s_msgPayload);

	                    			sendToSocket(ssock);

	                    			// creates RSHELL_RESULT and sends it	
	                    			createResultMessage(cmdStr);
                    				memcpy(s_msgId, userId, ID_SIZE-1);
                    				s_msgId[strlen(userId)] = '\0';


	       	// 						printf("\nWe are sending RSHELL_RESULT with:\n");
									// printf("payLength: %d\n", s_msgPayLength);
									// printf("userId: %s\n", s_msgId);
									// printf("cipher: %s\n", s_msgPayload);

	                    			sendToSocket(ssock);

							    }
		                    	else
		                    	{
	                    			printf("The password provided does not match user %s in passwords file.\n", userId);

		                    		// creates RSHELL_FAIL and sends it
		                    		s_msgType = AUTH_FAIL;
	                    			s_msgPayLength = ID_SIZE;
	                    			memcpy(s_msgId, userId, ID_SIZE-1);
			                    	s_msgId[strlen(userId)] = '\0';
	                    			s_msgId[strlen(userId)] = '\0';
	                    			s_msgPayload = '\0';
	                    			sendToSocket(ssock);
		                    	}

	                    	}
	                    	else 
	                    	{
	                    		printf("The user %s was not found in passwords file.\n", userId);
	                    		// creates RSHELL_FAIL and sends it
	                    		s_msgType = AUTH_FAIL;
                    			s_msgPayLength = ID_SIZE;
                    			memcpy(s_msgId, userId, ID_SIZE-1);
		                    	s_msgId[strlen(userId)] = '\0';
                    			s_msgId[strlen(userId)] = '\0';
                    			s_msgPayload = '\0';
                    			sendToSocket(ssock);

	                    		break;
	                    	}
                    	}
                    	else
                    	{
                    		printf("This server was expecting an AUTH_RESP type of message from client.\n");
                    		break;
                    	}
                    }
                   	else
                   	{
                   		printf("This server was expecting an AUTH_REQ type of message from client.\n");
                   		break;
                   	}


				}
                close(ssock);


			default:	/* parent */
				(void) close(ssock);
				break;
			case -1:
				errmesg("fork error\n");
		}
	}
	close(msock);
}


