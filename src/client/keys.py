from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP
from Crypto.Cipher.PKCS1_OAEP import PKCS1OAEP_Cipher
from Crypto.Random import get_random_bytes
import base64

# generates assymetric public and private key 
def generate_user_keys():
    private_key = RSA.generate(2048)
    public_key = private_key.public_key().export_key().decode("utf-8")
    return public_key, private_key

# persist with passphrase the user's private key 
def store_private_key(sk, username, passphrase):
    enc_key = sk.export_key(passphrase=passphrase, pkcs=8, protection="scryptAndAES128-CBC")
    fname = f"{username}_sk.bin"
    with open(fname, "wb") as file:
        file.write(enc_key)


def encrypt_with_cipher_obj(cipher_obj:PKCS1OAEP_Cipher, m):
    c_bytes = cipher_obj.encrypt(m)
    c_str = base64.b64encode(c_bytes).decode('utf-8')
    return c_str

# input: G = {"idgroup":..., 
#             "members":[
#                   {"member_i":"pk_member_i"},...]}
def generate_group_key_as_admin(G, admin):
    K_G = get_random_bytes(16) # symmetric 16 bytes key
    if not G.get("members", {}): 
        return K_G, {}
    members_keys = {}
    for member, pk_member_server in G["members"].items():
        if member != admin:
            pk_member = RSA.import_key(pk_member_server) # server str -> obj
            cipher_rsa = PKCS1_OAEP.new(pk_member)
            # Encrypt KG and seq=0
            enc_KG_member = encrypt_with_cipher_obj(cipher_rsa, K_G)
            enc_seq = encrypt_with_cipher_obj(cipher_rsa, "0".encode("utf-8"))
            members_keys[member] = {"enc_KG":enc_KG_member, "enc_seq":enc_seq}
    return K_G, members_keys





