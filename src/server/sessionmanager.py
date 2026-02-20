import secrets 

class SessionManager:
    def __init__(self):
        self.sessions = {} # token -> username
        self.challenges = {} # username -> challenge

    def get_sessions(self):
        return self.sessions
    
    def get_challenges(self):
        return self.challenges
    
    def get_challenge_by_username(self, username):
        return self.challenges.get(username)
    
    def set_challenge_by_username(self, challenge, username):
        self.challenges[username] = challenge

    def delete_challenge_by_username(self, username):
        self.challenges.pop(username)

    def start_session(self, username):
        token = secrets.token_hex(32) ##
        self.sessions[token] = username
        return token

    def end_session(self, token):
        self.sessions.pop(token, None)

    def get_username(self, token):
        return self.sessions.get(token)
    
    def token_valid(self, token):
        return token in self.sessions
    
