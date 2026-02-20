import socket, json, struct
import base64
from src.format.printwithcolor import print_error, print_success, print_info, print_process, print_group_message,YELLOW, RESET
import src.client.keys as keys
from Crypto.Hash import SHA256
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP, AES
from Crypto.Random import get_random_bytes
from Crypto.Util.Padding import pad, unpad
from Crypto.Signature import pkcs1_15
import time, threading

HOST = "127.0.0.1"
PORT = 8000
auth = {
    "token":"", 
    "username":"", 
    "sk":"", 
    "group_keys":{} # {idgroup:{"K_G":...,"seq":...}}
}


# only reached in members, not admins
# rekey for group "idgroup" which I belong, a new key K_G (comes encripted with my PK so SK to dec)
def rekey_group(idgroup, enc_KG_data):
    print_info(enc_KG_data)
    cipher_rsa = PKCS1_OAEP.new(auth["sk"]) 
        # decryption with sk
    enc_KG_bytes = base64.b64decode(enc_KG_data["enc_KG"])
    enc_seq_bytes = base64.b64decode(enc_KG_data["enc_seq"])
    K_G = cipher_rsa.decrypt(enc_KG_bytes)
    seq_bytes = cipher_rsa.decrypt(enc_seq_bytes)
    seq = int(seq_bytes.decode("utf-8"))
        # User Update
    auth["group_keys"][idgroup] = {"K_G":K_G, "seq":seq}
    print_info(f"Key of the group {idgroup} updated by admin. Initial seq={seq}")
    
# for the group G = {"idgroup":..., "members":[{"member_i":"pk_member_i"},...]}
def generate_group_key_as_admin(G): 
    K_G, members_keys = keys.generate_group_key_as_admin(G, auth["username"]) # response = K_G, [{"enc_member_i":"enc_pki_KG"}]
    auth["group_keys"][G["idgroup"]] = {"K_G":K_G, "seq":0}
    return members_keys

# requesters={username:pk_str}
def share_group_key_as_admin(idgroup, requesters):
    pending_keys = {} # {username:{"enc_KG":...,"enc_seq":...}}
    K_G = auth["group_keys"][idgroup]["K_G"]
    seq_bytes = str(auth["group_keys"][idgroup]["seq"]).encode("utf-8")
    for username, pk_str in requesters.items():
        pk = RSA.import_key(pk_str)
        cipher_rsa = PKCS1_OAEP.new(pk)
        enc_KG = keys.encrypt_with_cipher_obj(cipher_rsa, K_G)
        enc_seq = keys.encrypt_with_cipher_obj(cipher_rsa, seq_bytes)
        pending_keys[username] = {"enc_KG":enc_KG,"enc_seq":enc_seq}
    return pending_keys

def encrypt_message_for_group(m, idgroup):
    K_G = auth["group_keys"][idgroup]["K_G"]
    cur_seq = str(auth["group_keys"][idgroup]["seq"])
    try:
            # 1. generate iv's for msg and seq
        iv_msg_bytes = get_random_bytes(16)
        iv_seq_bytes = get_random_bytes(16)
            # 2. encrypt msg and seq with CBC (with padding)
        cipher = AES.new(K_G, AES.MODE_CBC, iv=iv_msg_bytes)
        enc_msg_bytes = cipher.encrypt(pad(m.encode("utf-8"), AES.block_size))
        cipher = AES.new(K_G, AES.MODE_CBC, iv=iv_seq_bytes)
        enc_seq_bytes = cipher.encrypt(pad(cur_seq.encode("utf-8"), AES.block_size))
            # 3. convert to str
        enc_msg = base64.b64encode(enc_msg_bytes).decode("utf-8")
        enc_seq = base64.b64encode(enc_seq_bytes).decode("utf-8")
        iv_msg = base64.b64encode(iv_msg_bytes).decode("utf-8")
        iv_seq = base64.b64encode(iv_seq_bytes).decode("utf-8")
            # 4. update KG (Ratchet)
        hasher = SHA256.new(K_G)
        auth["group_keys"][idgroup]["K_G"] = hasher.digest()[:16] # 16B to AES-128
        auth["group_keys"][idgroup]["seq"] += 1
        return enc_msg, enc_seq, iv_msg, iv_seq
    except Exception:
        print_error("Encryption error.")
        return None, None, None, None

# c as enc_KG_msg. If enc_seq is not the waited one, cancel 
def receive_group_message(idgroup, enc_msg, enc_seq, iv_msg, iv_seq):
    K_G = auth["group_keys"][idgroup]["K_G"]
    try:
            # 1. convert all to bytes 
        enc_msg_bytes = base64.b64decode(enc_msg)
        enc_seq_bytes = base64.b64decode(enc_seq)
        iv_msg_bytes = base64.b64decode(iv_msg)
        iv_seq_bytes = base64.b64decode(iv_seq)
            # 2. decrypt sequence and validate if is the expected one
        cipher = AES.new(K_G, AES.MODE_CBC, iv=iv_seq_bytes)
        seq = unpad(cipher.decrypt(enc_seq_bytes), AES.block_size).decode("utf-8")
        expected_seq = auth["group_keys"][idgroup]["seq"]
        if int(seq) != expected_seq:
            print_error(f"Sequence error. Got [{seq}], expected [{expected_seq}]")
            return None, None
            # 3. decrypt message
        cipher = AES.new(K_G, AES.MODE_CBC, iv=iv_msg_bytes)
        msg = unpad(cipher.decrypt(enc_msg_bytes), AES.block_size).decode("utf-8")
            # 4. update KG (Ratchet)
        hasher = SHA256.new(K_G)
        auth["group_keys"][idgroup]["K_G"] = hasher.digest()[:16] # 16B to AES-128
        auth["group_keys"][idgroup]["seq"] += 1
        return msg

    except Exception:
        print_error("Decryption error.")
        return None, None

# only get
def request_database_status():
    response, status = send_request("/check_database", {})
    if status == 200:
        print_success(response.get("message"))

# post
def send_request(endpoint:str, data):
    if auth["token"] != "":
        data["token"] = auth["token"]
    request_data = {
        "path":endpoint,
        "body":data
    }
    try:
        payload = json.dumps(request_data).encode("utf-8")
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.settimeout(5)
            s.connect((HOST,PORT))
            # Send 
            s.sendall(struct.pack(">I", len(payload)) + payload)
            # Response
            response_header = s.recv(4)
            if not response_header:
                return None, 500
            response_len = struct.unpack(">I", response_header)[0] # 1st piece
            response_raw = b""
            while len(response_raw) < response_len:
                    chunk = s.recv(response_len - len(response_raw))
                    if not chunk:
                        break
                    response_raw += chunk
            response = json.loads(response_raw.decode("utf-8"))
            return response.get("response"), response.get("status")
    except Exception as e:
        print_error(f"Connection to server error.")
        return {"ok":False, "error":str(e)}, 500
    

# If user authenticated, look for updated keys on server (each 5s)
def background_key_ask():
    while True:
        # Only if authenticated
        if auth.get("token"):
            # Task 1: As MEMBER, fetch for messages in your groups
            response, status = send_request("/fetch_messages", {"mygroups":list(auth["group_keys"].keys())})
            if status == 200 and response.get("ok"):
                # response = {idgroup:[{sender:enc_KG_msg}]} 
                for idgroup, msg_list in response.get("messages").items():
                    for msg_data in msg_list:
                        sender = msg_data["sender"]
                        enc_KG_msg = msg_data["enc_KG_msg"]
                        enc_seq = msg_data["enc_seq"]
                        iv_msg = msg_data["iv_msg"]
                        iv_seq = msg_data["iv_seq"]
                        msg = receive_group_message(idgroup, enc_KG_msg, enc_seq, iv_msg, iv_seq)
                        print_group_message(idgroup, sender, msg)


            # Task 2: As MEMBER, recover pending keys sent to me
            response, status = send_request("/fetch_pending_keys", {})
            if status == 200 and response.get("ok"):
                new_group_keys = response.get("keys")
                print_process(f"Rekeying my groups with {new_group_keys}...")
                for idgroup, enc_KG_data in new_group_keys.items():
                    rekey_group(idgroup, enc_KG_data)

            # Task 3: As ADMIN, recover join requests to my groups
            response, status = send_request("/fetch_group_join_requests", {}) # response.requests={idgroup:{username:pk}} 
            if status == 200 and response.get("ok"):
                new_group_keys = {} # {idgroup:{username:enc_KG}}
                requests = response.get("requests")
                for idgroup, requesters in requests.items():
                    new_group_keys[idgroup] = share_group_key_as_admin(idgroup, requesters) 
                if new_group_keys:
                    print_process(f"There are new group keys to store for new group members after one join. These are: {new_group_keys}")
                    response, status = send_request("/store_new_group_keys", {"new_keys":new_group_keys})

            # Task 4: As ADMIN, recover leave requests off my groups
            response, status = send_request("/fetch_group_leave_requests", {})
            if status == 200 and response.get("ok"):
                new_group_keys = {} 
                requests = response.get("requests") # {idgroup:{username_i:pk_i}}
                for idgroup, members in requests.items(): # guaranteed the one who left is not in members
                    new_group_keys[idgroup] = generate_group_key_as_admin({"idgroup":idgroup, "members":members})
                if new_group_keys:
                    print_process(f"There are new group keys to store for new group members after one leave. These are: {new_group_keys}")
                    response, status = send_request("/store_new_group_keys", {"new_keys":new_group_keys})
            
        time.sleep(5) 

threading.Thread(target=background_key_ask, daemon=True).start()


### NO authentication needed: register & login 

def register(username, password):
    public_key, private_key = keys.generate_user_keys()
    response = send_request("/register_user", {"username":username, "public_key":public_key})
    if response is not None:
        keys.store_private_key(private_key, username, password)


def login(username, password):
    print_process("Requesting my challenge to login...")
    response, status = send_request("/get_login_challenge", {"username":username})
    if status != 200:
        print_error(response.get("error"))
        return
    
    challenge = response.get("challenge")   
    try:
        # Load secret key
        with open(f"{username}_sk.bin", "rb") as file:
            enc_key = file.read()
            auth["sk"] = RSA.import_key(enc_key, passphrase=password) # throws exception if wrong passphrase
        
        print_process("Signing the hashed challenge with my secret key and sending it...")
        hash_challenge = SHA256.new(challenge.encode("utf-8")) 
        signature = pkcs1_15.new(auth["sk"]).sign(hash_challenge)
        answer_challenge = base64.b64encode(signature).decode("utf-8")
        response, status = send_request("/login", {"username":username, "answer_challenge":answer_challenge})
        if status != 200:
            print_error(response.get("error"))
            return

        print_success("Logged in.")
        # If all was OK, proper login
        # TODO - Load group_keys

        auth["token"] = response.get("token")
        auth["username"] = username
    except Exception as e:
        print_error("Invalid credentials.")
        
### Authentication needed : create a group, join a group, leave a group, send a message

def logout():
    send_request("/logout", {})
    auth["token"] = ""
    auth["username"] = ""
    auth["sk"] = ""
    auth["group_keys"] = {}

def create_group(): # no group name required, auto generated id
    response, _ = send_request("/create_group", {})
    generate_group_key_as_admin({"idgroup":response.get("idgroup")})

def join_group():
    response, status = send_request("/list_available_groups", {})
    if status != 200:
        print_error(response.get("error"))
        return
    groups = response.get("groups")
    print("Groups available: ")
    for group in groups:
        print(f"ID: {group["id"]}, members: {group["members"]}")
    selection = int(input("ID of the group you want to join (-1 to cancel): "))
    if selection != -1:
        send_request("/join_group_request", {"idgroup":selection})

def leave_group():
    response, status = send_request("/list_user_groups", {})
    if status != 200:
        print_error(response.get("error"))
        return
    groups = response.get("groups")
    print("Groups you can leave:", groups)
    selection = int(input("ID of the group you want to leave (-1 to cancel): "))
    if selection != -1: # assuming valid group
        _, status = send_request("/leave_group", {"idgroup":selection})
        if status == 200:
            auth["group_keys"].pop(str(selection))

def send_group_message():
    response, status = send_request("/list_user_groups", {})
    if status != 200:
        print_error(response.get("error"))
        return
    groups = response.get("groups")
    print("Groups you belong to:", groups)
    selection = int(input("ID of the group you want to send a message (-1 to cancel): "))
    if selection != -1: # assuming valid group
        selection = str(selection)
        message = input("Message to send: ")
        enc_KG_msg, enc_seq, iv_msg, iv_seq = encrypt_message_for_group(message, selection)
        response, status = send_request("/store_message", {"idgroup":selection, 
                                                           "enc_KG_msg":enc_KG_msg,
                                                           "enc_seq":enc_seq,
                                                           "iv_msg":iv_msg,
                                                           "iv_seq":iv_seq})

def menu():
    if auth["token"] != "":
        header = f"\n{YELLOW}[{username}]{RESET}, what do you want to do?"
    else:
        header = "\nWhat do you want to do?"
    
    print(header)
    print("0. Exit")
    print("1. View DB status")
    if auth["token"] == "":
        print("2. Register user")
        print("3. Log in")
    else:
        print("2. Log out")
        print("3. Create group")
        print("4. Join group")
        print("5. Leave group")
        print("6. Send message to a group")
        print("7. See my session")
    
    while (opt := int(input("Option number: "))) < 0 or (opt > 7) or (opt > 3 and auth["token"] == ""):
        print("Select option within the range.")
        continue
    return opt

if __name__ == "__main__":
    opt = -1
    try:
        while opt != 0:
            opt = menu()
        # EXIT
            if opt == 0:
                print("Thank you.")
                if auth["token"]:
                    logout()
                continue
        # CHECK DATABASE IN SERVER
            elif opt == 1:
                print_info("CHECKING DATABASE STATUS IN SERVER")
                request_database_status()
        # REGISTER USER
            elif opt == 2 and auth["token"] == "":
                print_info("REGISTERING A NEW USER")
                username = input("Username: ")
                password = input("Password: ")
                register(username, password)
        # LOG OUT
            elif opt == 2 and auth["token"] != "":
                print_info("LOG OUT")
                logout()
        # LOG IN
            elif opt == 3 and auth["token"] == "":
                print_info("LOG IN")
                username = input("Username: ")
                password = input("Password: ")
                login(username, password)
        # CREATE GROUP
            elif opt == 3 and auth["token"] != "":
                print_info("CREATING GROUP")
                create_group()
        # JOIN GROUP
            elif opt == 4:
                print_info("JOINING GROUP")
                join_group()
        # LEAVE GROUP
            elif opt == 5:
                print_info("LEAVING GROUP")
                leave_group()
        # SEND MESSAGE TO A GROUP
            elif opt == 6:
                print_info("SENDING MESSAGE TO A GROUP")
                send_group_message()
        # SEE MY SESSION
            elif opt == 7 and auth["token"] != "":
                print("My Session:", auth)
    except KeyboardInterrupt:
        if auth["token"]:
            logout()


        

