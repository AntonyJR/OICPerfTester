# Make calls to OIC Instance
from argparse import ArgumentParser
from base64 import b64decode
from csv import DictWriter
from datetime import datetime
from json import load, loads
from sys import stderr, stdout
from time import time
from uuid import uuid4

from jsonpath_ng import parse
from jwt import encode
from oci.config import from_file
from oci.secrets import SecretsClient
from requests import get, post
from requests.auth import AuthBase

NANOS = 1_000_000_000
MILLIS = 1_000
NANO_TO_MILLI = NANOS / MILLIS

# Config File Properties
ITERATIONS_FIELD = 'iterations'
TARGETS_FIELD = 'targets'
TARGET_NAME_FIELD = 'name'
BASE_URL_FIELD = 'baseurl'
BASIC_AUTH_SECRET_FIELD = 'secretOCID'
JWT_AUTH_SECRET_FIELD = 'jwtSecretOCID'
REQUESTS_FIELD = 'requests'
REQUEST_NAME_FIELD = 'name'
PATH_FIELD = 'path'
VERB_FIELD = 'verb'
PARAMS_FIELD = 'params'
PAYLOAD_FIELD = 'payload'
ELAPSED_FIELDS_FIELD = 'elapsedFields'
REPORT_NAME_FIELD = 'reportName'
ELAPSED_PATH_FIELD = 'elapsedPath'
INCLUDE_FIELD = 'include'

# Secret Properties
USERNAME_FIELD = 'username'
PASSWORD_FIELD = 'password'
TOKEN_URL_FIELD = 'token_url'
CLIENT_ID_FIELD = 'client_id'
CLIENT_SECRET_FIELD = 'client_secret'
SCOPES_FIELD = 'scopes'
KID_FIELD = 'kid'
SUB_FIELD = 'sub'
LIFETIME_FIELD = 'lifetime'
PRIVATE_KEY_FIELD = 'private_key'

# Auth Properties
AUTH_HEADER = 'authorization'
TOKEN_TYPE_FIELD = 'token_type'
ACCESS_TOKEN_FIELD = 'access_token'
AUTH_ENCODING = 'ascii'
EXPIRES_IN_FIELD = 'expires_in'
TOKEN_GRACE = 10


class JWTAuth(AuthBase):
    def __init__(self, token_config):
        """
        Initialize authenticator
        :param token_config: Dictionary with properties for JWT assertion
        """
        self.token_config = token_config
        self.expiry = time() - TOKEN_GRACE

    def __call__(self, r):
        """
        Update request with authentication
        :param r: request
        :return: request with authentication header
        """
        now = time()
        if now > self.expiry:
            self.token_response = get_jwt_token(self.token_config)
            self.expiry = now + self.token_response[EXPIRES_IN_FIELD] - TOKEN_GRACE
            print_error('Obtained token - expires {}'.format(
                datetime.fromtimestamp(self.expiry).strftime('%Y-%m-%d %H:%M:%S.%f')[:-3]), verbose=args.verbose)

        r.headers[AUTH_HEADER] = self.token_response[TOKEN_TYPE_FIELD] + ' ' + self.token_response[ACCESS_TOKEN_FIELD]
        return r


def print_error(output, err=False, verbose=False, end='\n'):
    """
    Print to stderr, prefixed with current datetime
    :param output: Message to output
    :param err: Boolean to indicate if this is an error and so should always be output
    :param verbose: Boolean to indicate if verbose is set, meaning that message should be output
    :param end: Newline character
    """
    if verbose or err:
        print('{}: {}'.format(datetime.now().strftime('%Y-%m-%d %H:%M:%S.%f')[:-3], output), file=stderr, end=end)


def init_oci():
    """
    Initialize OCI environment using default location for config file.
    Python OCI configuration is set up according to
    https://oracle-cloud-infrastructure-python-sdk.readthedocs.io/en/latest/configuration.html
    CLI Configuration File location is determined according to
    https://docs.oracle.com/en-us/iaas/Content/API/SDKDocs/cliconfigure.htm#Specifying_Default_Values
    :return: A config dict that can be used to create clients.
    """
    return from_file()


def get_oci_secret(oci_config, oic_secret_ocid):
    """
    Retrieve credentials from a secret using OCI Vault.
    General pattern is covered in
    https://oracle-cloud-infrastructure-python-sdk.readthedocs.io/en/latest/quickstart.html
    :param oci_config: A config dict.
    :param oic_secret_ocid: OCID of secret.
    :return: Secret converted from json.
    """
    sc = SecretsClient(oci_config)
    response = sc.get_secret_bundle(oic_secret_ocid)
    base64_secret_content = response.data.secret_bundle_content.content
    base64_secret_bytes = base64_secret_content.encode(AUTH_ENCODING)
    base64_message_bytes = b64decode(base64_secret_bytes)
    secret_content = base64_message_bytes.decode(AUTH_ENCODING)
    return loads(secret_content)


def get_jwt_assertion(kid, sub, lifetime, iss, private_key):
    """
    Create a JWT assertion
    :param kid: Key identifier
    :param sub: Subject
    :param lifetime: Duration of token
    :param iss: IDCS client id
    :param private_key: Private key relating to kid
    :return: JWT Assertion
    """
    jwt_headers = {
        # 'kid': 'OicClientCredentialsOauth'
        'kid': kid
    }
    # jwt_username = 'PMServiceAccount'
    jwt_payload = {
        "sub": sub,
        "jti": str(uuid4()),
        "iat": int(time()),
        "exp": int(time()) + lifetime,
        "iss": iss,
        "aud": "https://identity.oraclecloud.com/"
    }
    return encode(payload=jwt_payload, key=private_key, algorithm='RS256', headers=jwt_headers)


def get_jwt_token(token_config):
    """
    Obtain a token from OAuth server
    :param token_config: configuration of token
    :return: JWT token response
    """
    token_request = {
        'grant_type': 'urn:ietf:params:oauth:grant-type:jwt-bearer',
        'assertion': get_jwt_assertion(kid=token_config[KID_FIELD], sub=token_config[SUB_FIELD],
                                       lifetime=token_config[LIFETIME_FIELD], iss=token_config[CLIENT_ID_FIELD],
                                       private_key=token_config[PRIVATE_KEY_FIELD]),
        'scope': token_config[SCOPES_FIELD]
    }
    return post(token_config[TOKEN_URL_FIELD], data=token_request,
                auth=(token_config[CLIENT_ID_FIELD], token_config[CLIENT_SECRET_FIELD])).json()


def init_parser():
    """
    INitialize command line parser
    :return: Initialized parser
    """
    parser = ArgumentParser(description='Performance Test OIC Integrations')
    parser.add_argument('configFile', help='Configuration File')
    parser.add_argument('--noheader', action='store_true', help='Do not output a header for the results table')
    parser.add_argument('--verbose', action='store_true', help='Print to stderr activities')
    return parser.parse_args()


def init_config(filename):
    """
    Initialize configuration from config file
    :param filename:
    :return: config
    """
    # Load File
    with open(filename, 'r') as cf:
        root_config = load(cf)

    # Find any includes
    includes_expression = parse('$..' + INCLUDE_FIELD)
    selection = includes_expression.find(root_config)

    # Substitute includes
    for matched in selection:
        replacement = init_config(matched.value)
        matched.context.path.update(root_config, replacement)

    return root_config


if __name__ == '__main__':
    # Get configuration
    args = init_parser()
    config = init_config(args.configFile)

    # Initialize OCI config
    oci_config = init_oci()

    tests = []
    # Iterate over targets
    for target in config[TARGETS_FIELD]:
        # Initialize JWT or Basic Auth based on presence of JWT_AUTH_SECRET_FIELD
        if JWT_AUTH_SECRET_FIELD in target:
            secret = get_oci_secret(oci_config, target[JWT_AUTH_SECRET_FIELD])
            auth = JWTAuth(secret)
            auth_method = 'JWT'
        else:
            oic_credentials = get_oci_secret(oci_config, target[BASIC_AUTH_SECRET_FIELD])
            auth = (oic_credentials[USERNAME_FIELD], oic_credentials[PASSWORD_FIELD])
            auth_method = 'Basic'

        # Run test ITERATIONS_FIELD times
        print_error('Starting {} iterations on {}'.format(config[ITERATIONS_FIELD], target[BASE_URL_FIELD]),
                    verbose=args.verbose)
        for cnt in range(config[ITERATIONS_FIELD]):

            # Iterate over request list in config
            for req in config[REQUESTS_FIELD]:
                entry = {'Target': target[TARGET_NAME_FIELD], 'Auth': auth_method,
                         REQUEST_NAME_FIELD: req[REQUEST_NAME_FIELD]}
                url = target[BASE_URL_FIELD] + req[PATH_FIELD]
                params = req.get(PARAMS_FIELD, None)
                payload = req.get(PAYLOAD_FIELD, None)
                start = time()
                if req[VERB_FIELD] == 'GET':
                    resp = get(url, auth=auth, params=params)
                elif req[VERB_FIELD] == 'POST':
                    resp = post(url, auth=auth, params=params, json=payload)
                else:
                    resp = None
                elapsed = time() - start
                entry['elapsed'] = int(elapsed * 1000)
                entry['status'] = resp.status_code
                if resp.ok:
                    resp_json = resp.json()
                    for field in req[ELAPSED_FIELDS_FIELD]:
                        jsonpath = parse(field[ELAPSED_PATH_FIELD])
                        result = jsonpath.find(resp_json)
                        if len(result) > 0:
                            entry[field[REPORT_NAME_FIELD]] = int(float(result[0].value))
                        else:
                            entry[field[REPORT_NAME_FIELD]] = 'N/A'
                            print_error('Missing response field {}: {}'.format(field[ELAPSED_PATH_FIELD], resp),
                                        err=True)
                    print('😀', file=stderr, end='', flush=True)
                else:
                    print_error('Error {} returned {}'.format(url, resp.status_code), err=True)
                    for field in req[ELAPSED_FIELDS_FIELD]:
                        entry[field[REPORT_NAME_FIELD]] = 'N/A'
                    print('😞', file=stderr, end='', flush=True)
                tests.append(entry)

    # Write results in CSV format
    writer = DictWriter(stdout, list(tests[0].keys()))
    if not args.noheader:
        writer.writeheader()
    for test in tests:
        writer.writerow(test)
