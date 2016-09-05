#include <sys/socket.h>
#include <sys/types.h>
#include <netinet/in.h>
#include <netdb.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <errno.h>
void login(int sock){
char user[10],pass[10],rec[20];	
		printf("\nUsername: ");
 		scanf("%s%*c",&user);
        send(sock, user, strlen(user), 0);        
        printf("\nPassword: ");
        scanf("%s%*c",&pass); 
        send(sock, pass, strlen(pass), 0);
        recv(sock,rec,20,0);
        printf("\n%s ",rec);
}

int main()

{

        int sock, bytes_recieved;  
        int portnum;


        char send_data[1024],recv_data[1024], ip[10],*ipptr;
        struct hostent *host;
        struct sockaddr_in server_addr;  

       // host = gethostbyname("127.0.0.1");

        if ((sock = socket(AF_INET, SOCK_STREAM, 0)) == -1) {
            perror("Socket");
            exit(1);
        }
        
         printf("\nPlease Enter Server IP:");
         fgets(ip,10,stdin);
        ipptr=ip;
        printf("\nPlease Enter Server Port #:");
		scanf("%i%*c",&portnum);
		
        server_addr.sin_family = AF_INET;     
        server_addr.sin_port = htons(portnum);   
        server_addr.sin_addr.s_addr=inet_addr(ipptr);

        bzero(&(server_addr.sin_zero),8); 

        if (connect(sock, (struct sockaddr *)&server_addr,
                    sizeof(struct sockaddr)) == -1) 
        {
            perror("Connect");
            exit(1);
        }

      printf("\nConnection Successful\n");
        
       
         
		
        

        while(1)
        {
        
          bytes_recieved=recv(sock,recv_data,1024,0);
          recv_data[bytes_recieved] = '\0';
 
          if (strcmp(recv_data , "q") == 0 || strcmp(recv_data , "Q") == 0)
          {
           close(sock);
           break;
          }

          else
           printf("\nRecieved data = %s " , recv_data);
           
         printf("\nPlease Enter Choice"); 
         printf("\nLog In: 0");
		printf("\nDisplay User List: 1");
         printf("\nSend A Message: 2");
        printf("\nSEND (q or Q to quit) : "); 
         gets(send_data);
        switch(*send_data)
		{
		case '0':
			login(sock);
          break;
      }
           
          if (strcmp(send_data , "q") != 0 && strcmp(send_data , "Q") != 0)
           send(sock,send_data,strlen(send_data), 0); 

          else
          {
           send(sock,send_data,strlen(send_data), 0);   
           close(sock);
           break;
          }
        
        }   
return 0;
}
