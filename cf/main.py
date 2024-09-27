import hashlib
import ssl
import socket
from urllib.parse import urlparse
import psycopg2
import psycopg2.extras
import traceback
from flask import jsonify, request, render_template
from cryptography import x509
from cryptography.hazmat.primitives import serialization
import os


def query_certificates_by_public_key(public_key_sha1) -> list:
    '''
    Query the crt.sh database of certificates by public key SHA1 hash.

    Input: public_key_sha1 (str)
    Output: certificates (list)
    '''
    query = f"""
    SELECT
        CONCAT('https://crt.sh/?q=', ID) AS "crt_sh_link",
        x509_commonName(CERTIFICATE) AS "subject_common_name",
        x509_notBefore(CERTIFICATE) AS "not_before",
        x509_notAfter(CERTIFICATE) AS "not_after"
    FROM certificate c
    WHERE digest(x509_publickey(CERTIFICATE), 'sha1') = decode('{public_key_sha1}', 'hex')
    ORDER BY x509_notBefore(CERTIFICATE) DESC NULLS LAST;
    """

    print("Generated Query:")
    print(query)

    try:
        print("Attempting to connect to the database...")
        conn = psycopg2.connect(
            host="crt.sh",
            port=5432,
            database="certwatch",
            user="guest",
            password=""
        )
        print("Connection established.")

        conn.autocommit = True
        print("Autocommit set to True.")

        print("Creating cursor...")
        cur = conn.cursor()
        print("Cursor created.")

        print("Executing query...")
        cur.execute(query)
        print("Query executed.")

        print("Fetching all rows...")
        rows = cur.fetchall()
        print(f"Number of rows fetched: {len(rows)}")

        # Get the column names
        print("Fetching column names...")
        columns = [desc[0] for desc in cur.description]
        print(f"Column names: {columns}")

        # Build a list of dictionaries
        print("Building result dictionaries...")
        results = [dict(zip(columns, row)) for row in rows]

        print("Closing cursor and connection...")
        cur.close()
        conn.close()
        print("Cursor and connection closed.")

        return results
    except Exception as e:
        print(f"An error occurred: {e}")
        traceback.print_exc()
        print("[i] The crt.sh database can be a little unstable. Try this again in a few minutes.")
        raise


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

    Input: public_key (cryptography.hazmat.primitives.asymmetric.RSAPublicKey or EllipticCurvePublicKey)
    Output: sha1_hash (str)
    '''
    public_key_bytes = public_key.public_bytes(
        encoding=serialization.Encoding.DER,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )
    sha1_hash = hashlib.sha1(public_key_bytes).hexdigest()
    return sha1_hash


def main(request):
    if request.method == 'GET':
        # Return the HTML page
        return render_template('index.html')
    elif request.method == 'POST':
        # Handle form submission
        cert_data = request.form.get('certificate', '').strip()
        public_key_data = request.form.get('public_key', '').strip()

        if not cert_data and not public_key_data:
            return render_template('index.html', error='Please provide a certificate or a public key.')

        try:
            if cert_data:
                cert_data_bytes = cert_data.encode('utf-8')
                # Try to load as PEM certificate
                try:
                    cert = x509.load_pem_x509_certificate(cert_data_bytes)
                    sha1_hash = get_pk_fingerprint_from_cert(cert)
                except ValueError as e:
                    error_message = f'Invalid certificate: {str(e)}'
                    return render_template('index.html', error=error_message, certificate=cert_data, public_key=public_key_data)
            elif public_key_data:
                public_key_bytes = public_key_data.encode('utf-8')
                # Try to load as PEM public key
                try:
                    public_key = serialization.load_pem_public_key(public_key_bytes)
                    sha1_hash = get_pk_fingerprint_from_public_key(public_key)
                except ValueError as e:
                    error_message = f'Invalid public key: {str(e)}'
                    return render_template('index.html', error=error_message, certificate=cert_data, public_key=public_key_data)
            else:
                return render_template('index.html', error='Please provide a certificate or a public key.', certificate=cert_data, public_key=public_key_data)

            # Now, query the certificates
            results = query_certificates_by_public_key(sha1_hash)
            # Return the results in the HTML page
            return render_template('results.html', sha1_hash=sha1_hash, results=results, certificate=cert_data, public_key=public_key_data)
        except Exception as e:
            error_message = f'An error occurred: {str(e)}'
            return render_template('index.html', error=error_message, certificate=cert_data, public_key=public_key_data)
    else:
        return ('Method not allowed', 405)
