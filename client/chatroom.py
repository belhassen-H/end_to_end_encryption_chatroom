import collections
from collections.abc import Collection
from os import name
import customtkinter as ctk
import ldap
import socket
import threading
from M2Crypto import BIO, Rand, SMIME, X509
from pika.compat import byte
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography import x509
import sys
import pika

#######chat hanndling
print("aaa:",str(sys.argv))
nickname = sys.argv[1]

credentials = pika.PlainCredentials('root','root')
connection = pika.BlockingConnection(pika.ConnectionParameters('25.1.91.86',5672,'/',credentials))
channel = connection.channel()

channel.queue_declare(queue=nickname)
# Connecting To Server
client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
client.connect(('127.0.0.1', 55555))


## decrypt
def decrypt(encmsg):
    s = SMIME.SMIME()

    # Load private key and cert.
    s.load_key('private_key.pem', 'certificate.pem')

    # Load the encrypted data.
    p7, data = SMIME.smime_load_pkcs7_bio(BIO.MemoryBuffer(encmsg))

    # Decrypt p7.
    out = s.decrypt(p7)
    return out
# Listening to Server and Sending Nickname
def receive():
    while True:
        try:
            # Receive Message From Server
            # If 'NICK' Send Nickname
            msg = client.recv(1024)
            message = msg.decode('ascii')
            users = message.split(":")
            if users[0] == 'USERSLIST':
                global onlineList
                onlineList = []
                loadOnlineList(users)
            elif message == 'NICK':
                client.send(nickname.encode('ascii'))
            else:
                #print(decrypt(msg).encode('ascii'))
                target = message.split('\n')
                for i in range(0,len(tabs)):
                    if target[0]== tabs[i][3]:
                        tabs[i][0].insert("end",'\n'+target[i]+': ' +decrypt(msg).decode('ascii'))
        except:
            # Close Connection When Error
            print("An error occured!")
            client.close()
            break



### encrpyt message
def makebuf(text):
    return BIO.MemoryBuffer(text)

def encrpyt(msg,user,target):
    msg = makebuf(msg)
    s = SMIME.SMIME()

    pos =names.index(target)
    print(pos,target)
    cert = certf[pos]
    print(cert.decode('utf-8'))

    # Load target cert to encrypt to.
    x509 = X509.load_cert_string(cert.decode('utf-8'))
    sk = X509.X509_Stack()
    sk.push(x509)
    s.set_x509_stack(sk)

    #Set cipher: 3-key triple-DES in CBC mode.
    s.set_cipher(SMIME.Cipher('des_ede3_cbc'))

    # Encrypt the buffer.
    p7 = s.encrypt(msg)
    out = BIO.MemoryBuffer()
    out.write(user+'\n')
    out.write(target+'\n')
    s.write(out, p7)
    return out


# Sending Messages To Server
def write(message,user,target):

        message = encrpyt(bytes(message, 'utf-8'),user,target)
        client.send(message.read())

# Starting Threads For Listening And Writing

def getUserCert(uid):
    LDAP_BASE_DN = "ou=users,dc=tekuplive"
    ldap_admin = 'cn=admin,dc=tekuplive'
    ldap_admin_pw = 'admin'
    user_dn = f"cn={uid},{LDAP_BASE_DN}"
    ldap_client = ldap.initialize("ldap://25.1.91.86:389")
    ldap_client.bind_s(ldap_admin, ldap_admin_pw)
    try:
        result = ldap_client.search_s(user_dn, ldap.SCOPE_BASE)
        user_certificates = result[0][1]['userCertificate;binary'][0]
        certificate = x509.load_der_x509_certificate(user_certificates,default_backend())
        crt = certificate.public_bytes(serialization.Encoding.PEM)
        return crt
    except:
        return False

#######

app = ctk.CTk()

app.geometry("1100*580")

app.grid_columnconfigure(1,weight=1)
app.grid_columnconfigure((2,3),weight=0)
app.grid_rowconfigure((0,1,2),weight=1)
#####commands
onlineList = []
names = []
certf = []
tabs = []



def addfriend():
    global onlineList
    global names
    global certf
    uid =user_entry.get()
    pos = len(onlineList)
    cert = getUserCert(uid)
    print(cert)
    if (cert !=False):
        onlineList.append(ctk.CTkButton(master=sidebar, text=uid, fg_color="transparent", anchor="w" ,command= lambda :newtab(uid)))
        onlineList[pos].grid(row=pos+1, column=0,sticky="nsew")
        names.append(uid)
        certf.append(cert)


def loadOnlineList(tab):
    global onlineList
    print(names)
    print(certf)
    for i in range(1,len(tab)):
        if tab[i] in names:
            pos = names.index(tab[i])
            print(len(onlineList))
def send_message(tabname,index):
    message = tabs[index][1].get("0.0","end")
    tabs[index][1].delete("0.0","end")
    tabs[index][0].insert("end",'\n'+'you: ' +message)
    write(message,nickname,tabname)

def newtab(tabname):
    global tabs
    tabcomp = []
    tabview.add(tabname)
    tabview.tab(tabname).grid_rowconfigure(0,weight=1)
    tabview.tab(tabname).grid_columnconfigure(0,weight=1)

    tabcomp.append( ctk.CTkTextbox(master=tabview.tab(tabname),fg_color="#36393e",))
    tabcomp[0].grid(row = 0, column=0,columnspan=2 ,sticky="nsew")
    tabcomp[0].configure(state="normal")


    tabcomp.append (ctk.CTkTextbox(master=tabview.tab(tabname),height=75,fg_color="#424549",))
    tabcomp[1].grid(row = 1, column=0 ,sticky="nsew")
    tabcomp[1].configure(state="normal")

    tabcomp.append(ctk.CTkButton(master=tabview.tab(tabname),height=75,text="send",command= lambda :send_message(tabname,tabview.index(tabname))))
    tabcomp[2].grid(row = 1 ,column = 1 ,sticky="nsew")
    #msg_list.pack(anchor="center",ipady=5,pady=(60,0))
    tabcomp.append(tabname)
    tabs.append(tabcomp)
##### side  bar frame


sidebar = ctk.CTkScrollableFrame(master=app,border_width=2)
sidebar.grid(row=0, column=0, rowspan=4, sticky="nsew")

user_entry = ctk.CTkEntry(master=sidebar, placeholder_text="Add Friend")
user_entry.grid(row=0, column=0,sticky="nsew")

testbtn = ctk.CTkButton(master=sidebar, text="Add", fg_color="transparent", anchor="w",command=addfriend)
testbtn.grid(row=0, column=1,sticky="nsew")

######### main chat frame
tabview = ctk.CTkTabview(master=app,fg_color="#7289da",border_width=2)
tabview.grid(row=0, column=1, rowspan=4 ,sticky="nsew")



receive_thread = threading.Thread(target=receive)
receive_thread.start()


#write_thread = threading.Thread(target=write)
#write_thread.start()

app.mainloop()

