

from src.format.printwithcolor import print_process


class GroupManager:
    def __init__(self):
        self.groups = {} # {"group_id":{"admin":..., "members":[]}}
        self.join_requests = {} # {"admin": {"idgroup":[requesters]}}
        self.leave_requests = {} # {admin:[idgroup]}
        self.group_autoincrement_id = 1

    def get_join_requests(self):
        return self.join_requests

    def get_join_requests_by_admin(self, admin):
        return self.join_requests.get(admin, {})
    
    # username is the user that wants to join group idgroup
    def set_join_request_by_username(self, admin, idgroup, username):
        if admin not in self.join_requests:
            self.join_requests[admin] = {}
        if idgroup not in self.join_requests[admin]:
            self.join_requests[admin][idgroup] = []
        if username not in self.join_requests[admin][idgroup]:
            self.join_requests[admin][idgroup].append(username) 
    
    def remove_join_requests_by_admin(self, admin):
        if admin in self.join_requests:
            self.join_requests.pop(admin, None)


    def get_leave_requests(self):
        return self.leave_requests        

    def get_leave_requests_by_admin(self, admin):
        return self.leave_requests.get(admin, [])

    def set_leave_request_by_admin(self, admin, idgroup):
        if admin not in self.leave_requests:
            self.leave_requests[admin] = []
        if idgroup not in self.leave_requests[admin]:
            self.leave_requests[admin].append(idgroup)

    def remove_leave_requests_by_admin(self, admin):
        if admin in self.leave_requests:
            self.leave_requests.pop(admin, None)


    def get_group(self, idgroup):
        return self.groups.get(idgroup)

    def get_groups(self):
        return self.groups
    
    def get_admin_of_group(self, idgroup):
        return self.groups[idgroup]["admin"]

    def get_group_members(self, idgroup):
        if idgroup not in self.groups:
            return None
        return self.groups[idgroup]["members"]
    
    def is_admin_of_group(self, username, idgroup):
        return self.groups[idgroup]["admin"] == username

    def create_group(self, adminname):
        id_newgroup = str(self.group_autoincrement_id)
        self.group_autoincrement_id += 1
        self.groups[id_newgroup] = {"admin":adminname, "members":[adminname]}
        return id_newgroup
    
    def join_group(self, idgroup, username):
        if idgroup not in self.groups:
            raise ValueError("Group does not exist.")
        if username in self.get_group_members(idgroup):
            raise ValueError("You are already in the group.")
        self.groups[idgroup]["members"].append(username) ###


    def leave_group(self, idgroup, username):
        if idgroup not in self.groups:
            raise ValueError("Group does not exist.")
        if username not in self.get_group_members(idgroup):
            raise ValueError(f"You don't belong to the group {idgroup}.")
        self.groups[idgroup]["members"].remove(username)
        if not self.groups[idgroup]["members"]: # if the group is empty after the leave -> delete it
            del self.groups[idgroup]
        else: 
            if self.groups[idgroup]["admin"] == username: # admin left -> assign new admin (arbitrary)
                self.groups[idgroup]["admin"] = self.groups[idgroup]["members"][0]
        