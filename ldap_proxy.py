import socket
import threading
from typing import Tuple, Optional
import logging
from ldap3 import Server, Connection, ALL, NONE
import re
from netiq_auth import NetIQAuthenticator

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# Add these configurations
NETIQ_CONFIG = {
    'BASE_URL': "https://10.0.0.4",
    'ADMINUSER': "LOCAL\\admin",
    'ADMINPWD': "OTS0ftware!",
    'SALT': "i-am-salt"
}

ADMIN_USERS = ["CN=Administrator,CN=Users,DC=universe,DC=org"]  # List of admin users that bypass TOTP

class LDAPProxy:
    # Add this at the class level, after the __init__ method
    def __init__(self, listen_host: str, listen_port: int, 
                 target_host: str, target_port: int):
        self.listen_host = listen_host
        self.listen_port = listen_port
        self.target_host = target_host
        self.target_port = target_port
        self.server_socket = None
        self.running = False
        self.netiq_auth = NetIQAuthenticator(
            NETIQ_CONFIG['BASE_URL'], 
            "", "",  # Will be set during authentication
            NETIQ_CONFIG['ADMINUSER'],
            NETIQ_CONFIG['ADMINPWD']
        )
        # Add a dictionary to track authenticated users
        self.authenticated_users = {}  # Format: {username: ldap_password}

    def start(self):
        """Start the LDAP proxy server"""
        self.server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.server_socket.bind((self.listen_host, self.listen_port))
        self.server_socket.listen(5)
        self.running = True
        
        logger.info(f"LDAP Proxy listening on {self.listen_host}:{self.listen_port}")
        logger.info(f"Forwarding to AD server {self.target_host}:{self.target_port}")

        while self.running:
            try:
                client_socket, address = self.server_socket.accept()
                logger.info(f"New connection from {address}")
                client_handler = threading.Thread(
                    target=self.handle_client,
                    args=(client_socket, address)
                )
                client_handler.start()
            except Exception as e:
                logger.error(f"Error accepting connection: {e}")

    def stop(self):
        """Stop the proxy server"""
        self.running = False
        if self.server_socket:
            self.server_socket.close()

    def handle_client(self, client_socket: socket.socket, address: Tuple[str, int]):
        """Handle individual client connections"""
        try:
            # Create direct socket connection to AD server
            ad_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            ad_socket.connect((self.target_host, self.target_port))

            while True:
                # Receive LDAP request from client
                request_data = client_socket.recv(8192)
                if not request_data:
                    break

                # Debug: Print raw request data
                logger.info(f"Received request data length: {len(request_data)}")
                
                # Try to decode and print all printable characters
                try:
                    printable_data = ''.join(chr(b) if 32 <= b <= 126 else '.' for b in request_data)
                    logger.info(f"Printable characters in request: {printable_data}")
                except Exception as e:
                    logger.error(f"Error decoding request data: {e}")

                # Check if this is a bind request
                try:
                    if request_data[0] == 0x30:  # LDAP message sequence
                        logger.info("Found LDAP message sequence")
                        
                        # Print all bytes for debugging
                        # logger.info(f"All bytes: {[hex(b) for b in request_data]}")
                        
                        # Look for bind request operation code (0x60)
                        bind_op_index = -1
                        for i in range(len(request_data)):
                            if request_data[i] == 0x60:
                                bind_op_index = i
                                logger.info(f"Found bind operation at position {i}")
                                break
                        
                        if bind_op_index > 0:  # Bind request found
                            logger.info("Found bind request!")
                            
                            # Find the DN (username) - it comes after the bind version (0x02 0x01 0x03)
                            # Look for the pattern: 0x04 (octet string) followed by length
                            dn_start = -1
                            for i in range(bind_op_index, len(request_data) - 2):
                                if request_data[i] == 0x04:  # LDAP string tag
                                    dn_length = request_data[i+1]
                                    dn_start = i + 2
                                    logger.info(f"Found DN at position {dn_start} with length {dn_length}")
                                    break
                            
                            if dn_start > 0 and dn_start + dn_length <= len(request_data):
                                username = request_data[dn_start:dn_start+dn_length].decode('utf-8', errors='replace')
                                logger.info(f"Extracted username: {username}")
                                
                                # Find password - it comes after the auth choice (0x80)
                                pwd_start = -1
                                for i in range(dn_start + dn_length, len(request_data) - 2):
                                    if request_data[i] == 0x80:  # Simple bind password tag
                                        pwd_length = request_data[i+1]
                                        pwd_start = i + 2
                                        logger.info(f"Found password at position {pwd_start} with length {pwd_length}")
                                        break
                                
                                if pwd_start > 0 and pwd_start + pwd_length <= len(request_data):
                                    password = request_data[pwd_start:pwd_start+pwd_length].decode('utf-8', errors='replace')
                                    logger.info(f"Extracted password: {'*' * len(password)}")  # Don't log actual password
                                    
                                    # Continue with bind handling...
                                    if self.handle_bind_request(username, password):
                                        logger.info("Bind authentication successful")
                                        
                                        # If this is a user that needs TOTP but has already authenticated
                                        # Modify the request to only include the LDAP password part
                                        if username in self.authenticated_users and '@' in password:
                                            ldap_pwd = password.split('@', 1)[0]
                                            logger.info(f"Removing TOTP code from authenticated user request")
                                            
                                            # Create a completely new request with the LDAP password only
                                            modified_request = bytearray(request_data)
                                            modified_request[pwd_start-1] = len(ldap_pwd)  # Update length byte
                                            
                                            # Clear the existing password and replace with LDAP password
                                            for i in range(pwd_length):
                                                if i < len(ldap_pwd):
                                                    modified_request[pwd_start+i] = ldap_pwd.encode('utf-8')[i]
                                                else:
                                                    # Pad with zeros if needed
                                                    modified_request[pwd_start+i] = 0
                                            
                                            logger.info(f"Modified request length: {len(modified_request)}")
                                            
                                            # Send the modified request to AD server
                                            ad_socket.sendall(modified_request)
                                            logger.info("Modified request sent to AD server")
                                            
                                            # Receive response from AD server
                                            response = ad_socket.recv(8192)
                                            logger.info(f"Received AD response length: {len(response)}")
                                            if len(response) > 0:
                                                logger.info(f"Response first bytes: {[hex(b) for b in response[:10]]}")
                                                # Forward the response to the client
                                                client_socket.send(response)
                                                logger.info("Response sent to client")
                                            else:
                                                logger.error("Received empty response from AD server")
                                                # Send a generic success response if AD server doesn't respond
                                                success_response = self.create_bind_success_response(request_data[1])
                                                client_socket.send(success_response)
                                                logger.info("Generic success response sent to client")
                                        else:
                                            # For normal authentication (first time with TOTP)
                                            ad_socket.sendall(request_data)
                                            logger.info("Original request sent to AD server")
                                            
                                            # Receive response from AD server
                                            response = ad_socket.recv(8192)
                                            logger.info(f"Received AD response length: {len(response)}")
                                            if len(response) > 0:
                                                logger.info(f"Response first bytes: {[hex(b) for b in response[:10]]}")
                                                # Forward the response to the client
                                                client_socket.send(response)
                                                logger.info("Response sent to client")
                                            else:
                                                logger.error("Received empty response from AD server")
                                                # Send a generic success response if AD server doesn't respond
                                                success_response = self.create_bind_success_response(request_data[1])
                                                client_socket.send(success_response)
                                                logger.info("Generic success response sent to client")
                                    else:
                                        logger.info("Bind authentication failed")
                                        failure_response = self.create_bind_failure_response(request_data[1])
                                        client_socket.send(failure_response)
                                else:
                                    logger.info("Could not locate password, forwarding request")
                                    ad_socket.sendall(request_data)
                                    response = ad_socket.recv(8192)
                                    client_socket.send(response)
                            else:
                                logger.info("Could not locate username, forwarding request")
                                ad_socket.sendall(request_data)
                                response = ad_socket.recv(8192)
                                client_socket.send(response)
                        else:
                            logger.info("Not a bind request, forwarding...")
                            ad_socket.sendall(request_data)
                            response = ad_socket.recv(8192)
                            client_socket.send(response)
                except IndexError as e:
                    logger.error(f"Error parsing LDAP message: {e}")
                    # Forward the original request if parsing fails
                    ad_socket.sendall(request_data)
                    response = ad_socket.recv(8192)
                    client_socket.send(response)

        except Exception as e:
            logger.error(f"Error handling client {address}: {e}")
        finally:
            ad_socket.close()
            client_socket.close()
            logger.info(f"Connection closed for {address}")

    def create_bind_failure_response(self, message_id: int) -> bytes:
        """Create an LDAP bind failure response"""
        # LDAP Bind Response format:
        # 0x30: Sequence
        # Length
        # Message ID
        # 0x61: Bind Response
        # Length
        # Result code (0x0A for invalid credentials)
        # Empty DN
        # Empty error message
        return bytes([
            0x30, 0x0c,  # Sequence, length
            0x02, 0x01, message_id,  # Message ID
            0x61, 0x07,  # Bind Response, length
            0x0a, 0x01, 0x31,  # Result code (49 = invalid credentials)
            0x04, 0x00,  # Empty DN
            0x04, 0x00   # Empty error message
        ])

    def create_bind_success_response(self, message_id: int) -> bytes:
        """Create an LDAP bind success response"""
        # LDAP Bind Response format:
        # 0x30: Sequence
        # Length
        # Message ID
        # 0x61: Bind Response
        # Length
        # Result code (0x00 for success)
        # Empty DN
        # Empty error message
        return bytes([
            0x30, 0x0c,  # Sequence, length
            0x02, 0x01, message_id,  # Message ID
            0x61, 0x07,  # Bind Response, length
            0x0a, 0x01, 0x00,  # Result code (0 = success)
            0x04, 0x00,  # Empty DN
            0x04, 0x00   # Empty error message
        ])

    def authenticate_with_totp(self, username: str, totp_code: str) -> bool:
        """Authenticate user with TOTP"""
        try:
            self.netiq_auth.username = username
            self.netiq_auth.password = totp_code

            # Create endpoint and session
            endpoint = self.netiq_auth.create_endpoint()
            session_id = self.netiq_auth.create_session(NETIQ_CONFIG['SALT'])

            # Start login process with username
            login_result = self.netiq_auth.start_login(username)
            
            # Override the input prompt in do_login
            final_result = self.netiq_auth.do_login(totp_code)

            # Clean up endpoint
            self.netiq_auth.delete_endpoint()

            return final_result.get('status') == 'OK'
        except Exception as e:
            logger.error(f"TOTP authentication failed: {e}")
            return False

    def handle_bind_request(self, username: str, password: str) -> bool:
        """Handle LDAP bind request with TOTP verification"""
        try:
            # Skip TOTP for admin users
            print(f"Username: {username}")
            if username in ADMIN_USERS:
                return self.ldap_authenticate(username, password)

            # Split password into LDAP password and TOTP code
            if '@' not in password:
                return False

            ldap_pwd, totp_code = password.split('@', 1)
            
            # Display TOTP code explicitly
            logger.info(f"LDAP Password: {'*' * len(ldap_pwd)}")
            logger.info(f"TOTP Code: {totp_code}")

            # Store original username for LDAP authentication
            original_username = username
            
            # Add domain prefix for TOTP authentication if not already present
            totp_username = username
            if not totp_username.startswith("universe\\") and not totp_username.startswith("CN="):
                totp_username = f"universe\\{totp_username}"
                logger.info(f"Added domain prefix for TOTP auth. Username: {totp_username}")
            
            # Check if user has already been authenticated with TOTP
            if original_username in self.authenticated_users and self.authenticated_users[original_username] == ldap_pwd:
                logger.info(f"User {original_username} already authenticated with TOTP, bypassing TOTP verification")
                # Only perform LDAP authentication with original username
                ldap_result = self.ldap_authenticate(original_username, ldap_pwd)
                return ldap_result

            # First authenticate with TOTP using prefixed username
            if not self.authenticate_with_totp(totp_username, totp_code):
                logger.error(f"TOTP authentication failed for user {totp_username}")
                return False

            # Then authenticate with LDAP using original username
            ldap_result = self.ldap_authenticate(original_username, ldap_pwd)
            
            # If both authentications succeed, store the user credentials for future bypass
            if ldap_result:
                logger.info(f"Storing successful authentication for user {original_username}")
                self.authenticated_users[original_username] = ldap_pwd
            
            return ldap_result

        except Exception as e:
            logger.error(f"Bind request handling failed: {e}")
            return False

    def ldap_authenticate(self, username: str, password: str) -> bool:
        """Perform LDAP authentication"""
        try:
            server = Server(f'ldap://{self.target_host}:{self.target_port}', get_info=NONE)
            conn = Connection(server, user=username, password=password)
            return conn.bind()
        except Exception as e:
            logger.error(f"LDAP authentication failed: {e}")
            return False

    def forward_request(self, ad_connection: Connection, request_data: bytes) -> Optional[bytes]:
        """Forward LDAP request to AD server and return response"""
        try:
            # Parse LDAP request to check if it's a bind request
            # This is a simplified example - you'll need proper LDAP message parsing
            if b'bindRequest' in request_data:
                # Extract username and password from bind request
                # This is placeholder code - implement proper LDAP message parsing
                username = "extracted_username"
                password = "extracted_password"

                if self.handle_bind_request(username, password):
                    # Return success response
                    return b"bind_success_response"
                else:
                    # Return failure response
                    return b"bind_failure_response"
            
            # For non-bind requests, forward as usual
            ad_connection.socket.sendall(request_data)
            response_data = ad_connection.socket.recv(8192)
            return response_data

        except Exception as e:
            logger.error(f"Error forwarding request: {e}")
            return None

def main():
    # Configuration
    PROXY_HOST = "0.0.0.0"  # Listen on all interfaces
    PROXY_PORT = 389        # Standard LDAP port
    AD_HOST = "10.0.0.3"
    AD_PORT = 389

    # Create and start proxy
    proxy = LDAPProxy(
        listen_host=PROXY_HOST,
        listen_port=PROXY_PORT,
        target_host=AD_HOST,
        target_port=AD_PORT
    )

    try:
        proxy.start()
    except KeyboardInterrupt:
        logger.info("Shutting down proxy server...")
        proxy.stop()
    except Exception as e:
        logger.error(f"Proxy server error: {e}")
        proxy.stop()

if __name__ == "__main__":
    main()