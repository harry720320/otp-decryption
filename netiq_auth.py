import requests
from hashlib import sha256
from typing import Dict, Optional
from dataclasses import dataclass
import urllib3

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)  # Disable SSL warnings


@dataclass
class Endpoint:
    id_hex: str
    secret: str
    name: str = "demo.endpoint"
    typ: int = 3
    desc: str = "Endpoint"
    is_trusted: bool = True
    tenant_name: str = "TOP"

class NetIQAuthenticator:
    def __init__(self, base_url: str, username: str, password: str, adminuser: str, adminpwd: str):
        self.base_url = base_url.rstrip('/')
        self.adminuser = adminuser
        self.adminpwd = adminpwd
        self.username = username
        self.password = password
        self.endpoint: Optional[Endpoint] = None
        self.endpoint_session_id: Optional[str] = None
        self.logon_process_id: Optional[str] = None

    def get_endpoint_secret_hash(self, endpoint: Endpoint, salt: str) -> str:
        salted_endpoint_id = (endpoint.id_hex + salt).encode('utf-8')
        endpoint_id_hash = sha256(salted_endpoint_id).hexdigest()
        salted_endpoint_secret = (endpoint.secret + endpoint_id_hash).encode('utf-8')
        return sha256(salted_endpoint_secret).hexdigest()

    def create_endpoint(self) -> Endpoint:
        url = f"{self.base_url}/api/v1/endpoints"
        payload = {
            "name": "demo.endpoint",
            "typ": 3,
            "desc": "Endpoint",
            "is_trusted": True,
            "tenant_name": "TOP",
            "auth_data": {
                "method_id": "PASSWORD:1",
                "user_name": self.adminuser,
                "password": self.adminpwd
            }
        }
        response = requests.post(url, json=payload, verify=False)  # Disable SSL verification
        print(response.text)
        response.raise_for_status()
        data = response.json()
        self.endpoint = Endpoint(id_hex=data['id'], secret=data['secret'])
        return self.endpoint

    def create_session(self, salt: str) -> str:
        if not self.endpoint:
            raise ValueError("Endpoint not created")
        
        url = f"{self.base_url}/api/v1/endpoints/{self.endpoint.id_hex}/sessions"
        # Calculate hash using the algorithm from hash.py
        secret_hash = self.get_endpoint_secret_hash(self.endpoint, salt)
        
        payload = {
            "salt": salt,
            "endpoint_secret_hash": secret_hash  # Now using the calculated hash instead of raw secret
        }
        response = requests.post(url, json=payload, verify=False)  # Disable SSL verification
        print(response.text)
        response.raise_for_status()
        data = response.json()
        self.endpoint_session_id = data['endpoint_session_id']
        return self.endpoint_session_id

    def start_login(self, username=None) -> Dict:
        if not self.endpoint_session_id:
            raise ValueError("Session not created")

        # Use the provided username if available, otherwise use the instance username
        login_username = username if username is not None else self.username

        url = f"{self.base_url}/api/v1/logon"
        payload = {
            "method_id": "TOTP:1",
            "user_name": login_username,
            "event": "demo",
            "endpoint_session_id": self.endpoint_session_id
        }
        print(f"Payload: {payload}")
        response = requests.post(url, json=payload, verify=False)  # Disable SSL verification
        print(response.text)
        response.raise_for_status()
        data = response.json()
        self.logon_process_id = data['logon_process_id']
        return data

    def do_login(self, totp_code: str) -> Dict:
        if not self.logon_process_id:
            raise ValueError("Login process not started")
        
        url = f"{self.base_url}/api/v1/logon/{self.logon_process_id}/do_logon"
        print(url)
        payload = {
            "response": {"answer": totp_code},
            "endpoint_session_id": self.endpoint_session_id
        }
        print(f"Payload: {payload}")
        response = requests.post(url, json=payload, verify=False)
        print(response.text)
        response.raise_for_status()
        data = response.json()
        login_session_id = data['login_session_id']
        print(login_session_id)
        
        return response.json()

    def delete_endpoint(self) -> None:
        if not self.endpoint:
            raise ValueError("No endpoint to delete")
        
        url = f"{self.base_url}/api/v1/endpoints/{self.endpoint.id_hex}"
        payload = {
            "auth_data": {
                "method_id": "PASSWORD:1",
                "user_name": self.adminuser,
                "password": self.adminpwd
            }
        }
        response = requests.delete(url, json=payload, verify=False)
        print(response.text)
        response.raise_for_status()

def main():
    # 配置信息
    BASE_URL = "https://10.0.0.4"
    ADMINUSER = "LOCAL\\admin"
    ADMINPWD = "OTS0ftware!"
    USERNAME = "universe\\demouser1"
    PASSWORD = "OTS0ftware!"
    SALT = "i-am-salt"

    # 初始化认证器
    auth = NetIQAuthenticator(BASE_URL, USERNAME, PASSWORD, ADMINUSER, ADMINPWD)

    try:
        # 1. 创建 Endpoint
        print("Creating endpoint...")
        endpoint = auth.create_endpoint()
        print(f"Endpoint created: {endpoint.id_hex}")

        # 2. 创建会话
        print("Creating session...")
        session_id = auth.create_session(SALT)
        print(f"Session created: {session_id}")

        # 3. 开始登录流程
        print("Starting login process...")
        login_result = auth.start_login()
        print(f"Login started: {login_result['status']}")

        # 4. 完成登录
        print("Completing login...")
        final_result = auth.do_login()  # Remove PASSWORD parameter
        print(f"Login result: {final_result['status']}")

        # 添加删除 endpoint 的步骤
        print("Deleting endpoint...")
        auth.delete_endpoint()
        print("Endpoint deleted successfully")

    except requests.exceptions.RequestException as e:
        print(f"Error during authentication: {str(e)}")
        # 即使认证失败也尝试删除 endpoint
        if auth.endpoint:
            try:
                print("Attempting to delete endpoint...")
                auth.delete_endpoint()
                print("Endpoint deleted successfully")
            except requests.exceptions.RequestException as delete_error:
                print(f"Failed to delete endpoint: {str(delete_error)}")

if __name__ == "__main__":
    main()