
This src is structured in four main modules: 
    - Client
    - Server
    - Format (only for formatted prints with colors)

For the cryptographic solution I mainly used pycryptodome because is the main recommended library in the course.
Now, the features implemented on the system, assuming no concurrency management and all users authenticated to the server for the cryptographic solution to work.

## Module Client

The module in which the logic of the group members, or users, is. 

- As a user, you can register yourself to the server "instant messaging application". After giving a username
and password, you generate a tuple with your public key and your private key using RSA mecanism. Then, you send 
your public key to the server for it to store it, and store locally your private one. For this, I used a .bin file that is locked with the password (the only use of the password) after a login attempt. 

- As a user, you can log into the aplication, once you're registered. This is done by a "challenge" method:
    1. You request to the server a log in with a username and a password. 
    2. The server sends you a random string (os.urandom(32).hex())
    3. You hash and sign the challenge with your private key. Then send the result to the server.
    4. The server verifies with your public key with a verifier imported from "Crypto.Signature import pkcs1_15".
    5. If success, the server sends you a session token, generated with secrets.token_hex(32).
        Then you can interact with the server sending your token as an authenticated user.

    This process will be used to guarantee the value "authentication" within the system, with no needs
    of validating again autentications when exchanging information. 

- As a user, you can create a group. Once you create it, you generate for yourself as the admin of the group 
a group key (on as K_G). This is a symmetrical key, and I choose for the generation "K_G=get_random_bytes(16)".

- As a user, you can join existing groups in [constant] time. Once you request joining a certain group, the admin of it gives you through public key mecanism (RSA) the current K_G. After you receive it, you're in. Each group applies a mecanism of ratchet after each message sent or received (better explained later), so you have no access to previous messages in your new group, guaranteeing backward secrecy. 

- As a user, you can leave groups you belong to in [number of group members lineally proportional] time. This will trigger a forced group rekey, starting by the admin generating the new K_G and instantly sharing it to the current members with RSA. This guarantees forward secrecy.

- As a user, you can send messages to your group. You encrypt the message with the corresponding group-shared K_G and the server acts as a router. 

### Client polling (not cryptographic)

Each authenticated user do each 5s a recurrent polling to the server with these 4 tasks: 
    1. As a group member, fetch for messages in my groups. 
    2. As a group member, fetch for pending keys from the admin to me (whether after a leave or you as a new member)
    3. As a group admin, fetch for pending join requests to my groups, so I can share them the K_G's.
    4. As a group admin, fetch for pending leaves from my groups, so I can start the rekey process.


### Messages

Previously mentioned ratcheting mecanism is applied in the exchange of messages within a group. This works as follows:
    - As a group member, I store locally (in the diccionary auth) the tuple {K_G, seq:int} for the groups I belong. All the group members share these two values and they're updating synchronously:
        - After sending a message, K_G is ratcheted and seq+=1
        - After step 1 of Client polling, K_G is ratcheted in the receiver user and seq+=1 
    This does NOT consider extremelly concurrent cases or message disorganization for not expected network behavior.
    Ratchet is applied with:
        hasher = SHA256.new(K_G)
        next_KG = hasher.digest()[:16]

## Module Server

The server supports all this previous user requests by having a database that contains the relation of the entities Group and User (in local diccionaries). So, in all processes is exposed both the usernames and the group id's because is the minimum data the server must know to act as a router. Therefore, the server is only blind regarding keys and messages information. 


## Executing

In terminal 1, execute python -m src.server.main
In terminal 2, execute python -m src.client.user for each user 
On users' terminal a menu should blow up and you can start interacting with the mentioned options.


