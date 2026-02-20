from src.format.printwithcolor import print_info
from src.server.usermanager import UserManager
from src.server.sessionmanager import SessionManager
from src.server.groupmanager import GroupManager
from src.server.router import RouterSocket

HOST = "127.0.0.1" # local
PORT = 8000 # listener

def run():
    user_manager = UserManager()
    session_manager = SessionManager()
    group_manager = GroupManager()
    server = RouterSocket(HOST, PORT, user_manager, group_manager, session_manager) 
    try:
        server.start()
    except KeyboardInterrupt:
        print("\nKeyboard Interrupt detected.")
    finally:    
        server.close()

if __name__ == "__main__":
    run()


