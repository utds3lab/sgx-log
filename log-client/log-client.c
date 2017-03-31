#include <stdio.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <string.h>


#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <errno.h>
#include <string.h>
#include <netdb.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#define PORT 7891
#define MAXSIZE 1024
#define LOCALHOST "127.0.0.1"

int main(){
  int clientSocket;
  char buffer[1024];
  struct sockaddr_in serverAddr;
  socklen_t addr_size;

  char filename[] = "log-messages.data";
  FILE *file = fopen ( filename, "r" );

  // create socket
  if ( (clientSocket = socket(PF_INET, SOCK_STREAM, 0)) == -1) {
      fprintf(stderr, "Client Socket failure!!\n");
      exit(1);
  }
  
  // Configure: Address family = Internet, port number, IP address to localhost
  serverAddr.sin_family = AF_INET;
  serverAddr.sin_port = htons(PORT);
  serverAddr.sin_addr.s_addr = inet_addr(LOCALHOST);

  // Set all bits of the padding field to 0 
  memset(serverAddr.sin_zero, '\0', sizeof serverAddr.sin_zero);  

  // Connect to server
  addr_size = sizeof serverAddr;
  connect(clientSocket, (struct sockaddr *) &serverAddr, addr_size);



  if (file != NULL) {

    while(fgets(buffer, sizeof buffer, file)!= NULL) /* read a line from a file */ {
      if ((send(clientSocket, buffer, strlen(buffer),0))== -1) {
          fprintf(stderr, "Failure Sending Message\n");
          close(clientSocket);
          exit(1);
      } else {
          printf("A new message being send: %s\n", buffer);
      }
    }

    fclose(file);
  } else {
    perror(filename);
  }

  
  // while(1) {
  //     fgets(buffer, MAXSIZE-1,stdin);

  //     if (strcmp("stop\n", buffer) == 0 )
  //       {
  //           /* code */
  //           printf("Good bye! \n");
  //           close(clientSocket);
  //           exit(0);
  //       }

  //     if ((send(clientSocket, buffer, strlen(buffer),0))== -1) {
  //         fprintf(stderr, "Failure Sending Message\n");
  //         close(clientSocket);
  //         exit(1);
  //     } else {
  //         printf("A new message being send: %s\n", buffer);
  //     }
  // }

  close(clientSocket);
  return 0;
}
