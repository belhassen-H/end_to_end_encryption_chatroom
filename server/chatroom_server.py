import socket
import threading

# Connection Data
host = '127.0.0.1'
port = 55555

# Starting Server
server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
server.bind((host, port))
server.listen()

# Lists For Clients and Their Nicknames
clients = []
nicknames = []


# Sending Messages To All Connected Clients
def updateUserList (message):
    for client in clients:
        client.send(message.encode('ascii'))

def broadcast(message,target):
    if (target[1] in nicknames):
        clients[nicknames.index(target[1])].send(message)
    else:
        clients[nicknames.index(target[0])].send("target offline")

# Handling Messages From Clients
def handle(client):
    while True:
        try:
            # Broadcasting Messages
            message = client.recv(1024)
            #print(message)
            target = message.decode('ascii').split('\n')
            broadcast(message,target)
        except:
            # Removing And Closing Clients
            index = clients.index(client)
            clients.remove(client)
            client.close()
            nickname = nicknames[index]
            nicknames.remove(nickname)
            break

# Receiving / Listening Function
def receive():
    while True:
        # Accept Connection
        client, address = server.accept()
        print("Connected with {}".format(str(address)))

        # Request And Store Nickname
        client.send('NICK'.encode('ascii'))
        nickname = client.recv(1024).decode('ascii')
        nicknames.append(nickname)
        clients.append(client)
        userlist = 'USERSLIST:'+ ':'.join(nicknames)
        updateUserList(userlist)
        print(nicknames)
        # Print And Broadcast Nickname
        print("Nickname is {}".format(nickname))
#        broadcast("{} joined!".format(nickname).encode('ascii'))
#        client.send('Connected to server!'.encode('ascii'))

        # Start Handling Thread For Client
        thread = threading.Thread(target=handle, args=(client,))
        thread.start()

receive()
