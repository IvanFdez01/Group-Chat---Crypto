
class UserManager:
    def __init__(self):
        self.users = {} # username -> {groups, public_key, pending_keys->{idgroup:enc_KG}}

    def get_user(self, username):
        return self.users[username]
    
    def get_pk_user(self, username):
        return self.users[username]["public_key"]

    def get_users(self):
        return self.users
    
    def get_groups_by_user(self, username):
        return self.users[username]["groups"]

    def register_user(self, username, public_key):
        if username in self.users:
            raise ValueError("User already exists.")
        self.users[username] = {
            "groups": [],
            "public_key": public_key
        }
        return {"ok": True, "message":f"User {username} registered succesfully.","data":{}}, 200
    
    def add_user_to_group(self, username, idgroup):
        self.users[username]["groups"].append(idgroup)

    def remove_user_from_group(self, username, idgroup):
        self.users[username]["groups"].remove(idgroup)
    