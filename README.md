# cs468-challenge-response-authentication

Project Overview:

Now  you  are  asked  to  improve  the  above  client  and  server  by  implementing  a  more  secure authentication
based on  challenge  and  response  with  nonce,  user  ID  and  password.  Specifically,  you need  to  develop  two
C  programs: RShellClient2.c  and RShellServer2.c  such that  

Command "RShellServer2 Port_number  Password  File_name"  will  listen  on  the  specified Port_number  and  authenticate
the  remote  shell  command  based  on  the  SHA1  hash  of  the client’s  password  and  the  random  nonces  from
both  client  and server.  If  the  authentication  is successful,  execute  the  shell  command  and  return  the
execution result  back  to  client.  The file that stores the passwords should contain  one  or  more  line:
ID_string; hex_of_SHA1(PW).
The server will  challenge  the  client  and  use  the  shared  secret  SHA1(PW)  to  authenticate  client  request.
It will  execute the shell command requested by the client once it has successfully authenticated the client. 
  
Command "RShellClient2 Server_IP  Server_port_number  ID  Password" will read shell command from the standard input (i.e., the keyboard) and send the ID and the shell command to the server listening at the Server_port_number on Server_IP. It will exchange nonce with the server and respond to the authentication clallenge sent by server.
