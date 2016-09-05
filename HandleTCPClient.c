#include <stdio.h> /* for printf() and fprintf() */
#include <sys/socket.h> /* for recv() and send() */
#include <unistd.h> /* for close() */
#include <string.h>
#include <stdbool.h>
#define RCVBUFSIZE 32 /* Size of receive buffer */
void DieWithError(char *errorMessage); /* Error handling function */
 
struct user{
char user[10];
char password[10];
}Alice,Bob;
void HandleTCPClient(int clntSocket)
{
strcpy(Alice.user, "Alice");
strcpy(Alice.password, "alice");
strcpy(Bob.user, "Bob");
strcpy(Bob.password, "bob");	
    char echoBuffer[RCVBUFSIZE]; /* Buffer for echo string */
char authen[RCVBUFSIZE];
bool Auser=false, Apass=false, Buser=false, Bpass = false,Alog=false,Blog=false;
    int recvMsgSize,comp1,comp2; /* Size of received message */






do{


    /* Receive message from client */
recv(clntSocket, echoBuffer, RCVBUFSIZE, 0);
 

comp1=strcmp(Alice.user,echoBuffer);
if(comp1==0)
Auser=true;
comp2=strcmp(Bob.user,echoBuffer);
if(comp2==0)
Buser=true;









comp1=strcmp(Alice.password,echoBuffer);
if(comp1==0)
Apass=true;
comp2=strcmp(Bob.password,echoBuffer);
if(comp2==0)
Bpass=true;











if(Alog==false&&Blog==false){
if ((Auser==true&&Apass==true)||(Buser==true&&Bpass==true)){
strcpy(authen,"Successful Login\n");
send(clntSocket,authen,RCVBUFSIZE,0);
if(Auser==true&&Apass==true){
Alog=true;
}
if(Buser==true&&Bpass==true){
Blog=true;
}
}
}





printf("Message is: %s",echoBuffer);
if(echoBuffer=="1"){
strcpy(echoBuffer,"Alice Bob");
send(clntSocket,echoBuffer,RCVBUFSIZE,0);


}


memset(echoBuffer,0,RCVBUFSIZE);

}while(echoBuffer!="6");




    close(clntSocket); /* Close client socket */
}
