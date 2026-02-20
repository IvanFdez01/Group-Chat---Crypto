from collections import defaultdict
import json, os, base64
import socket
import threading
from Crypto.Hash import SHA256
from src.format.printwithcolor import print_info, print_error, print_process, print_success
from Crypto.PublicKey import RSA
from Crypto.Signature import pkcs1_15


class RouterSocket() :
    def __init__(self, host, port, user_manager, group_manager, session_manager): 
        self.host = host
        self.port = port
        self.user_manager = user_manager
        self.group_manager = group_manager 
        self.session_manager = session_manager 
        self.pending_keys = defaultdict(dict)
        self.messages = defaultdict(dict) # {idgroup:[message]}, where message={"sender":...,"enc_KG_msg":...,"enc_seq"...,"received":[username]}}
        # Socket
        self.server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        # to check exit
        self.server_socket.settimeout(1.0)
        self.running = True

    def start(self):
        # Open server to listen
        self.server_socket.bind((self.host, self.port))
        self.server_socket.listen(5)
        print_info(f"Socket Server listening on {self.host}:{self.port}")
        while self.running:
            try:
                client_socket, _ = self.server_socket.accept()
                # for each client, a thread
                thread = threading.Thread(target=self.handle_client, args=(client_socket,))
                thread.daemon = True
                thread.start()
            except socket.timeout:
                continue
            except Exception as e:
                print_error(e)


    def close(self):
        print_info("Shutting down server...")
        self.running = False
        self.server_socket.close()

    def handle_client(self, client_socket):
        # TCP, read bytes
        try:
            while True:
                prefix_len = client_socket.recv(4)
                if not prefix_len: 
                    break
                msg_len = int.from_bytes(prefix_len, byteorder="big")
                raw_data = b""
                while len(raw_data) < msg_len:
                    chunk = client_socket.recv(msg_len - len(raw_data))
                    if not chunk:
                        break
                    raw_data += chunk
                request = json.loads(raw_data.decode("utf-8"))
                # Request
                response = self.route_request(request) #
                # Response to client
                response_data = json.dumps(response).encode("utf-8")
                header = len(response_data).to_bytes(4, byteorder="big")
                client_socket.sendall(header + response_data)

        except Exception as e:
            print_error(e)
        finally:
            client_socket.close()

            
    def route_request(self, request):
        path = request.get("path")
        body = request.get("body", {})

        print_info(f"POST REQUEST in {path}")
        print("Body:",body)

        endpoints = {
            "/check_database": self.get_database_status,
            "/register_user": self.register_user,
            "/get_login_challenge": self.get_login_challenge,
            "/login": self.login,
            "/logout": self.logout,
            "/create_group": self.create_group,
            "/join_group_request": self.join_group_request,
            "/leave_group": self.leave_group,
            "/send_message": self.send_message,
            # auxiliar
            "/list_available_groups": self.list_available_groups,
            "/list_user_groups": self.list_user_groups,
            # group request
            "/fetch_group_join_requests": self.fetch_group_join_requests,
            "/fetch_group_leave_requests": self.fetch_group_leave_requests,
            # rekeying
            "/store_new_group_keys": self.store_new_group_keys,
            "/fetch_pending_keys": self.fetch_pending_group_keys,
            # messages
            "/store_message": self.store_message,
            "/fetch_messages": self.fetch_messages,
        }
        public_endpoints = ["/check_database", "/register_user", "/get_login_challenge", "/login"]

        # session token validation
        if path not in public_endpoints: ## ¿request.get("path")?
            token = body.get("token") #
            if not token or not self.session_manager.token_valid(token):
                return {"ok": False, "error": "Invalid session"}, 401

        usecase = endpoints.get(path)
        response, status = usecase(body) ###
        return {"response": response, "status": status}



    def get_database_status(self, body):
        print("USERS: ", json.dumps(self.user_manager.get_users(), indent=4))
        print("\nGROUPS: ", json.dumps(self.group_manager.get_groups(), indent=4))
        print("\nSESSIONS: ", json.dumps(self.session_manager.get_sessions(), indent=4))
        print("\nGROUP JOIN REQUESTS: ", json.dumps(self.group_manager.get_join_requests(), indent=4))
        print("\nGROUP LEAVE REQUESTS: ", json.dumps(self.group_manager.get_leave_requests(), indent=4))
        print("\nPENDING KEYS: ", json.dumps(self.pending_keys, indent=4))
        return {"ok":True, "message":"Database status checked correctly."}, 200

    # body: username and plain password
    def register_user(self, body):
        username = body.get("username")
        public_key = body.get("public_key")
        try:
            self.user_manager.register_user(username, public_key)
            return {"ok": True, "message":f"User {username} registered succesfully.","data":{}}, 200
        except ValueError as e:
            return {"ok":False, "error":str(e)}, 400

    def get_login_challenge(self, body):
        username = body.get("username")
        challenge = os.urandom(32).hex()
        self.session_manager.set_challenge_by_username(challenge, username)
        return {"ok":True, "challenge":challenge}, 200

    # body: username and plain password
    def login(self, body):
        username = body.get("username")
        try:
            answer_challenge = body.get("answer_challenge") # b64 signature
            challenge = self.session_manager.get_challenge_by_username(username)
            hash_challenge = SHA256.new(challenge.encode("utf-8"))
            pk_user_str = self.user_manager.get_pk_user(username)
            pk_user = RSA.import_key(pk_user_str)
            verifier = pkcs1_15.new(pk_user)
            verifier.verify(hash_challenge, base64.b64decode(answer_challenge))
            print_success(f"Signature [{answer_challenge[:8]}...] verified " +
                          "against stored challenge hash [{hash_challenge.hexdigest()[:8]}...] for user '{username}'. On to login.")
            token = self.session_manager.start_session(username)
            return {"ok":True, "message":f"Logged in, {username}", "token":token}, 200
        except ValueError:
            return {"ok": False, "error": "Invalid credentials"}, 400

    # body: user token
    def logout(self, body):
        token = body.get("token")
        username = self.session_manager.get_username(token) # Only for the return
        self.session_manager.end_session(token)
        return {"ok":True, "message":f"Session ended, {username}", "data":{}}, 200

    # body: user token
    def create_group(self, body):
        username = self.session_manager.get_username(body.get("token"))
        id_group = str(self.group_manager.create_group(username)) # username as admin
        self.user_manager.add_user_to_group(username, id_group)
        return {"ok": True, "message": f"Group created with ID {id_group}", "idgroup":id_group}, 200
    

    def join_group_request(self, body):
        username = self.session_manager.get_username(body.get("token"))
        idgroup = str(body.get("idgroup"))
        admin = self.group_manager.get_admin_of_group(idgroup)
        self.group_manager.set_join_request_by_username(admin, idgroup, username)
        return {"ok":True, "message":f"Request to join group {idgroup} done."}, 200

    # body: user token and group 
    def leave_group(self, body):
        idgroup = str(body.get("idgroup"))
        username = self.session_manager.get_username(body.get("token"))
        try:
            # 1. Remove from BD user from group
            self.group_manager.leave_group(idgroup, username)
            self.user_manager.remove_user_from_group(username, idgroup)
            # 2. Store pending leave for the (new) group admin (if group still exists)
            if self.group_manager.get_group(idgroup):
                admin = self.group_manager.get_admin_of_group(idgroup)
                self.group_manager.set_leave_request_by_admin(admin, idgroup)

            return {"ok":True, "message":f"You succesfully left GROUP {idgroup}", "data":{}}, 200
        except ValueError as e:
            return {"ok":False, "error":str(e), "data":{}}, 400
        

    def send_message(self, body):
        pass
        
    # body: user token, used for joining groups
    def list_available_groups(self, body):
        groups_available = [] # groups available to join for user, [{"id":...,"members":...},...]
        username = self.session_manager.get_username(body.get("token"))
        groups = self.group_manager.get_groups()
        for idgroup, data in groups.items():
            if username not in data["members"]:
                groups_available.append({"id":idgroup, "members":len(data["members"])})
        if len(groups_available) == 0:
            return {"ok":False, "error":"You don't have groups available to join"}, 400
        return {"ok":True, "message":"You have groups available to join.", "groups":groups_available}, 200
        
    # body: user token, used for leaving group
    def list_user_groups(self, body):
        username = self.session_manager.get_username(body.get("token"))
        usergroups = self.user_manager.get_groups_by_user(username)
        print("usergroups:", usergroups)
        if not usergroups:
            return {"ok":False, "error":"You don't belong to any group"}, 400
        return {"ok":True, "message":"You belong to some groups.", "groups":usergroups}, 200
    

    def store_new_group_keys(self, body):
        admin = self.session_manager.get_username(body.get("token"))
        new_keys = body.get("new_keys")
        for idgroup, accepted in new_keys.items():
            for username, enc_KG_data in accepted.items():
                print_process(f"Storing pending key for {username} for group {idgroup}...")
                # JOin group in BD if username wasnt there
                if username not in self.group_manager.get_group_members(idgroup):
                    self.group_manager.join_group(idgroup, username)
                    self.user_manager.add_user_to_group(username, idgroup)
                    print_process(f"{username} persisted in BD...")
                # Store pending key
                self.pending_keys[username][idgroup] = enc_KG_data
                print_process(f"self.pending_keys[{username}][{idgroup}]={enc_KG_data}")                
                
        print_process(f"Stored new pending keys correctly. Pending keys are: {self.pending_keys}")
        return {"ok":True, "message":"Stored pending keys correctly."}, 200


    def fetch_pending_group_keys(self, body):
        username = self.session_manager.get_username(body.get("token"))
        user_pending_keys = {} 
        if username in self.pending_keys and self.pending_keys[username]:
            # self.pending_keys[username]={idgroup:{"encKG":.., "enc_seq":..}}
            user_pending_keys = self.pending_keys[username]
            self.pending_keys.pop(username)
            print_process(f"Sending his pending keys to {username}.")
            return {"ok":True, "message":"You have pending keys.", "keys":user_pending_keys}, 200
        return {"ok":False, "error":"No pending keys for you at the moment."}, 400

    def fetch_group_join_requests(self, body):
        response = {} # {idgroup:{username:pk} 
        admin = self.session_manager.get_username(body.get("token"))
        requests = self.group_manager.get_join_requests_by_admin(admin) # {idgroup:[username]} 
        if not requests:
            return {"ok": False, "error": "No pending join requests."}, 400
        for idgroup, requesters in requests.items():
            response[idgroup] = {} 
            for requester in requesters:
                public_key = self.user_manager.get_pk_user(requester)
                response[idgroup][requester] = public_key
        self.group_manager.remove_join_requests_by_admin(admin)
        return {"ok":True, "message":"There are join requests for you.", "requests":response}, 200
    
    def fetch_group_leave_requests(self, body):
        # 1. Consult pending_leaves
        admin = self.session_manager.get_username(body.get("token"))
        requests = self.group_manager.get_leave_requests_by_admin(admin) # {admin:[idgroup]}
        if not requests:
            return {"ok": False, "error": "No pending leave requests."}, 400
        # 2. Return in format {idgroup:{username:pk}} (searching for members and pk's)
        response = {}
        for idgroup in requests:
            response[idgroup] = {}
            members = self.group_manager.get_group_members(idgroup)
            for member in members:
                pk_member = self.user_manager.get_pk_user(member)
                response[idgroup][member] = pk_member
        self.group_manager.remove_leave_requests_by_admin(admin)
        return {"ok": True, "message": "There are join requests for you.", "requests":response}, 200



    def store_message(self, body):
        sender = self.session_manager.get_username(body.get("token"))
        print_info(body)
        idgroup = body.get("idgroup")
        enc_KG_msg = body.get("enc_KG_msg")
        enc_seq = body.get("enc_seq")
        iv_msg = body.get("iv_msg")
        iv_seq = body.get("iv_seq")
        if idgroup not in self.messages: # initialize group
            self.messages[idgroup] = []
        self.messages[idgroup].append({"sender":sender, 
                                       "enc_KG_msg":enc_KG_msg, 
                                       "enc_seq":enc_seq,
                                       "iv_msg":iv_msg,
                                       "iv_seq":iv_seq ,
                                       "received":[sender]})
        return {"ok": True, "message": "Message stored correctly."}, 200

    def fetch_messages(self, body):
        receiver = self.session_manager.get_username(body.get("token"))
        receiver_groups = body.get("mygroups") # [idgroup]
        response = {} # {idgroup:[{"sender":sender, "enc_KG_msg":enc_KG_msg}]} 
        for idgroup in receiver_groups:
            if idgroup not in self.messages: # no messages for this group
                continue
            response[idgroup] = []

            # recall self.messages format: {idgroup:[{"sender":..."enc_KG_msg":...,"enc_seq":.."received":[username]}}]}
            for message in self.messages[idgroup]:
                if receiver not in message["received"]:
                    response[idgroup].append({
                        "sender":message["sender"], 
                        "enc_KG_msg":message["enc_KG_msg"],
                        "enc_seq":message["enc_seq"],
                        "iv_msg":message["iv_msg"],
                        "iv_seq":message["iv_seq"]
                    })
                    message["received"].append(receiver)
            
            # erase the message if all the members had received it
            group_len = len(self.group_manager.get_group_members(idgroup))
            self.messages[idgroup] = [msg for msg in self.messages[idgroup] 
                                      if len(msg["received"]) < group_len]
                    
        return {"ok": True, "message": "You have unread messages.", "messages":response}, 200 


        
            
        
        
    
            