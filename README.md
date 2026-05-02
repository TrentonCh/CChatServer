1. Modify inet.h to reflect the host you are currently logged into.
   Also, modify the port numbers to be used to reduce the likelihood
   of conflicting with another server.
 
2. Compile the source code using the command: make
 
3. Start the chat and directory servers in the background: ./directoryServer5 &; ./chatServer5 &
 
4. Start the client on the same or another host in the foreground: ./chatClient5
 
5. Remember to kill the server before logging off.

6. Note: Sometimes when running the directory on cougar and the client on viper when opening and closing clients fast the directory won't populate.
The error (Error: reading from directory) does not happen when the directory is on viper and the client is on cougar and is intermittent. We believe this to be a network issue outside of the code. If you continue to try to restart the client it will fix it.

Acceptable Chat Server Names:
    KSU Football
    KSU Basketball
    Puppies
    Fortnite
    KSU Compsci

Group Members (Group 8):
    Patrick Kehoe
    Kylie Phommasack
    Trenton Chrisco
    Connor Bauer

Overview
    This project extends the chat system that was developed in earlier Programming Assignments by adding
    TLS 1.3 secure communication to all components (Directory Server, Chat Server, and the Chat Client).
    Each Connection is now encrypted and authenticating using OpenSSL. All communication, including registration, listing
    chat rooms, sending messages, and receiving broadcasts, is performed securely.

    We purposefully did not limit the amount of clients. We could not find information about this within the instructions.

    We also changed MAX from 100 to 1000

    In the makefile we uncommented the line:
        LIBS	= -lcrypto -lssl
    in order to utilize this library throughout implementation.

File Structure & Purpose:
    directoryServer5:
        The directory server maintains a dynamic list of available chat rooms. 
        The responsibilites of the file are:
            - Accept TLS-secured connections from chat servers and clients
            - Verify chat server certificates using our custom CA
            - Register chat servers using: "R <topic> <port>"
            - Deregister chat servers using: "D <topic>"
            - Provide room listing using: "L"
            - Protects all communication using TLS 1.3
            - Prevents duplicate room names
            - Ensures that certificate CN matches the room topic
        The directory server is always started first and acts as the root of trust within the system.

    chatServer5:
        The chat server hosts one specific chat room topic.
        The responsibilites of the file are:
            - Load the correct certificate and key based on the topic
            - Establish TLS 1.3 connection to the Directory Server
            - Register its topic and port securely
            - Accept TLS connections from clients
            - Authenticate and complete TLS handshake for each client
            - Manage multiple active clients using select (no threads)
            - Relay user messages to all other members
            - Broadcast join/leave notifications
            - Deregister from the Directory Server when terminated
            When terminated, the chatClients will provide a message and close as well.
        Each chat server uses a certificate whose CN matches the topic name (like "KSU FOOTBALL" etc.)
        
    chatClient5:
        The chat client allows users to communciate with one another after inputting a valid chat room and user name.
        The file allows users to:
            - Connect to the Directory Server using TLS
            - Verify that the Directory Server’s certificate CN is exactly "Directory Server"
            - Retrieve list of available chat rooms
            - Enter a topic name to join (which is validated)
            - Verify that the chat server’s certificate CN matches the chosen topic
            - Send and receive broadcasted chat messages securely
            - Handle disconnects gracefully

How to Build/Run:
    1. make
    2. ./directoryServer5 &                                                 (start this in the background)
    3. ./chatServer5 "<the acceptable chat room name>" <port number> &      (this works with all chat rooms listed above, and start in background)
    4. ./chatClient5                                                        (start a client, this will provide the given chat rooms a user can join)

Requirements:
    Topic name must match one of the acceptable names
    Port must be between 49151–65536

Example Output:
1. Start the directory server
    ptkehoe@cougar:~/cis525/Project-Assignment-7$ ./directoryServer5 &
    [1] 4079484
    ptkehoe@cougar:~/cis525/Project-Assignment-7$ Directory server listening on port 57535
2. Start the chat server(s)
    ptkehoe@cougar:~/cis525/Project-Assignment-7$ ./chatServer5 "KSU Football" 57890 &
    [1] 4080791
    Using certificates: certs/ksu-football-cert.pem and certs/ksu-football-key.pem
    ptkehoe@cougar:~/cis525/Project-Assignment-7$ SSL connection established with directory server
    Directory server certificate CN: Directory Server
    Sent registration: R KSU Football 57890
    Directory server response: R KSU Football 57890

This also shows within the directory server:
    ptkehoe@cougar:~/cis525/Project-Assignment-7$ Directory server listening on port 57535
    Accepted new connection from 129.130.10.39
    SSL handshake successful
    Received message: R KSU Football 57890
    Processing registration request
    Parsed: topic='KSU Football', IP='129.130.10.39', port=57890, CN='KSU Football'
    Registered: KSU Football at 129.130.10.39:57890

I then start another chat:
    ptkehoe@cougar:~/cis525/Project-Assignment-7$ ./chatServer5 "Fortnite" 59876 &
    [1] 4082321
    Using certificates: certs/fortnite-cert.pem and certs/fortnite.pem
    ptkehoe@cougar:~/cis525/Project-Assignment-7$ SSL connection established with directory server
    Directory server certificate CN: Directory Server
    Sent registration: R Fortnite 59876
    Directory server response: R Fortnite 59876

this sends the information to the directory server as well
    Accepted new connection from 129.130.10.39
    SSL handshake successful
    Received message: R Fortnite 59876
    Processing registration request
    Parsed: topic='Fortnite', IP='129.130.10.39', port=59876, CN='Fortnite'
    Registered: Fortnite at 129.130.10.39:59876

3. Now, start a chatClient: (Terminal 1, patrick)
    ptkehoe@cougar:~/cis525/Project-Assignment-7$ ./chatClient5
    Connected to Directory Server 
    Enter the name of the chat room you want to join (ie: KSU Football): 
    Current Chat Rooms:
    Topic: KSU Football, IP: 129.130.10.39, Port: 57890
    Topic: Fortnite, IP: 129.130.10.39, Port: 59876
    Enter in the topic of the chat room that you would like to join: KSU Football
    Connected to chat server 'KSU Football'
    Enter in your name: 
    patrick kehoe
    You are the first user to join the chat.
    The user, timmy, has joined the chat
    timmy: hi there 
    hey man

then start another chatClient (terminal 2, timmy)
    tkehoe@cougar:~/cis525/Project-Assignment-7$ ./chatClient5
    Connected to Directory Server 
    Enter the name of the chat room you want to join (ie: KSU Football): 
    Current Chat Rooms:
    Topic: KSU Football, IP: 129.130.10.39, Port: 57890
    Topic: Fortnite, IP: 129.130.10.39, Port: 59876
    Enter in the topic of the chat room that you would like to join: KSU Football
    Connected to chat server 'KSU Football'
    Enter in your name: 
    timmy
    hi there     
    patrick kehoe: hey man

As you can see, patrick joined first so he was prompted with the first user message and timmy was not.

There is also a line printed in the chat server to where it shows the SSL handshake is completed with the client.

This allows no duplicate user names and only allows users to join validated chat rooms that are listed