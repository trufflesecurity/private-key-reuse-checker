from cryptography import x509
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import ec
import hashlib, sys, os, argparse, shutil, subprocess
from urllib.parse import urlparse
import psycopg2
from prettytable import PrettyTable


FILE = 'file'
URL = 'url'

def query_certificates_by_public_key(public_key) -> list:
    '''
    Query a database of certificates by public key.
    Input: public_key (str)
    Output: certificates (list)
    '''

    # Prepare the psql command
    query = f"""
    SELECT 
        CONCAT('https://crt.sh/?q=', ID) AS "crt.sh link",
        x509_commonName(CERTIFICATE) AS "Subject Common Name (URL)",
        x509_notBefore(CERTIFICATE) AS "Not Before (Start Date)",
        x509_notAfter(CERTIFICATE) AS "Not After (End Date)"
    FROM certificate c
    WHERE digest(x509_publickey(CERTIFICATE), 'sha1') = decode('{public_key}', 'hex')
    ORDER BY x509_notBefore(CERTIFICATE) DESC NULLS LAST;
    """
    
    psql_command = [
        "psql",
        "-h", "crt.sh",
        "-p", "5432",
        "-U", "guest",
        "-d", "certwatch",
        "-c", query
    ]
    
    try:
        # Execute the psql command and capture the output
        result = subprocess.run(psql_command, capture_output=True, text=True, check=True)

        # Print the output from psql
        print(result.stdout)
    except subprocess.CalledProcessError as e:
        # Handle errors in case the command fails
        print(f"An error occurred: {e.stderr}")
        print("[i] The crt.sh database can be a little unstable. Try this again in a few minutes.")

def get_pk_fingerprint_from_cert(cert) -> str:
    '''
    Get the public key fingerprint from a certificate.
    Input: cert (cryptography.x509.Certificate)
    Output: sha1_hash (str)
    '''
    public_key = cert.public_key()
    public_key_bytes = public_key.public_bytes(
        encoding=serialization.Encoding.DER,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )
    sha1_hash = hashlib.sha1(public_key_bytes).hexdigest()
    return sha1_hash

def get_pk_fingerprint_from_public_key(public_key) -> str:
    '''
    Get the public key fingerprint from a public key.
    Input: public_key (cryptography.hazmat.primitives.asymmetric.rsa.RSAPublicKey)
    Output: sha1_hash (str)
    '''
    public_key_bytes = public_key.public_bytes(
        encoding=serialization.Encoding.DER,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )
    sha1_hash = hashlib.sha1(public_key_bytes).hexdigest()
    return sha1_hash


def get_pk_from_url(url) -> str:
    '''
    Get the public key from a URL.
    Input: url (str)
    Output: public_key (str)
    '''
    url = urlparse(url).netloc
    command = f"echo | openssl s_client -connect {url}:443 | openssl x509 -pubkey -noout"
    result = subprocess.run(
        command,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        shell=True
    )
    return result.stdout

def read_and_encode_input_file(file_path) -> bytes:
    '''
    Read the input file and encode it.
    Input: file_path (str)
    Output: bytes
    '''
    with open(file_path, 'r') as f:
        c = f.read()
        c = str.encode(c)
    return c

def is_url_or_file(path_or_url) -> str:
    '''
    Check if the input is a valid URL or file path.
    Input: path_or_url (str)
    Output: str
    '''
    # Parse the string to see if it's a valid URL
    parsed_url = urlparse(path_or_url)

    # Check if the parsed URL has a valid scheme (like 'http' or 'https') and a network location
    if parsed_url.scheme in ('http', 'https') and parsed_url.netloc:
        return URL
    # Check if it's a valid file path
    elif os.path.isfile(path_or_url):
        return FILE
    # Otherwise throw an error
    else:
        raise argparse.ArgumentTypeError(f"'{path_or_url}' is neither a valid file nor a URL. URLs require https:// or http://.")

def is_openssl_installed() -> bool:
    '''
    Check if OpenSSL is installed and accessible in the PATH.
    
    Output: bool
    '''
    # Check if openssl is in the PATH
    openssl_path = shutil.which("openssl")
    
    if openssl_path:
        try:
            # Execute 'openssl version' to ensure it's installed and accessible
            result = subprocess.run(
                ["openssl", "version"],
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True
            )
            # Check the result to determine if OpenSSL is correctly installed
            if result.returncode == 0:
                return True
        except Exception as e:
            # If there's any error, return False
            print(f"Error while checking OpenSSL: {e}")
            return False

    # If openssl is not found in the PATH or any other error occurs, return False
    return False


def is_psql_installed() -> bool:
    '''
    Check if psql is installed and accessible in the PATH.
    
    Output: bool
    '''
    # Check if psql is in the PATH
    psql_path = shutil.which("psql")
    
    if psql_path:
        try:
            # Execute 'psql --version' to ensure it's installed and accessible
            result = subprocess.run(
                ["psql", "--version"],
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True
            )
            # Check the result to determine if psql is correctly installed
            if result.returncode == 0:
                return True
        except Exception as e:
            # If there's any error, return False
            print(f"Error while checking psql: {e}")
            return False

    # If psql is not found in the PATH or any other error occurs, return False
    return False

def parse_arguments():
    '''
    Parse the command line arguments.
    Output: args (argparse.Namespace)
    '''
    parser = argparse.ArgumentParser(description="List all of the TLS certificates that have used a particular public key.", formatter_class=argparse.RawTextHelpFormatter,)
    parser.add_argument(
        'input',
        type=is_url_or_file,
        help='There are 3 input options:\n\t(1) A crt file\n\t(2) A pem file\n\t(3) A URL (requires openssl to be installed).\n\nExamples:\n\trun.py /path/to/cert.crt\n\trun.py /path/to/cert.pem\n\trun.py https://www.example.com'
    )
    return parser.parse_args()

if __name__ == "__main__":
    if not is_psql_installed():
        print("[x] psql not found in your PATH. It's needed to query the database. Please install it.")
        sys.exit(1)

    args = parse_arguments()
    sha1_hash = None

    if args.input == FILE:
        file_bytes = read_and_encode_input_file(sys.argv[1])
        try:
            cert = x509.load_pem_x509_certificate(file_bytes)
            sha1_hash = get_pk_fingerprint_from_cert(cert)
        except ValueError:
            public_key = serialization.load_pem_public_key(file_bytes)
            sha1_hash = get_pk_fingerprint_from_public_key(public_key)
    elif args.input == URL:
        if not is_openssl_installed():
            print("OpenSSL not found in your PATH. It's needed to get the public key of a URL. Either install it, or provide a file path instead.")
            sys.exit(1)
        pk = get_pk_from_url(sys.argv[1])
        if not pk:
            raise ValueError("Could not get the public key from the URL.")
        public_key = serialization.load_pem_public_key(str.encode(pk))
        sha1_hash = get_pk_fingerprint_from_public_key(public_key)
    
    print(f"SHA1 hash of the public key: {sha1_hash}")
    query_certificates_by_public_key(sha1_hash)
