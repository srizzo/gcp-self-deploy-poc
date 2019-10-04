# -*- coding: utf-8 -*-

import git
import os
import logging
import flask
import requests
import shutil

import google.oauth2.credentials
import google_auth_oauthlib.flow
import googleapiclient.discovery

logging.basicConfig(format='%(levelname)s:%(message)s', level=logging.DEBUG)
logger = logging.getLogger(__file__)

# This variable specifies the name of a file that contains the OAuth 2.0
# information for this application, including its client_id and client_secret.
from google.cloud import storage

PROJECT_DIR = os.path.dirname(os.path.abspath(__file__))

CLIENT_SECRETS_FILE = os.path.join(PROJECT_DIR, 'client_secret.json')

# This OAuth 2.0 access scope allows for full read/write access to the
# authenticated user's account and requires requests to use an SSL connection.
SCOPES = [
    # Test create Project.
    'https://www.googleapis.com/auth/cloud-platform',
    # View and manage your data across Google Cloud Platform services
    'https://www.googleapis.com/auth/cloudplatformprojects',

    # Test create AppEngine project.
    'https://www.googleapis.com/auth/appengine.admin',
    # View and manage your applications deployed on Google App Engine
    'https://www.googleapis.com/auth/cloud-platform.read-only',
    # View your data across Google Cloud Platform services
    # 'https://www.googleapis.com/auth/cloud-platform',  # View and manage your data across Google Cloud Platform services

    # Storage scopes:
    "https://www.googleapis.com/auth/devstorage.full_control",
    "https://www.googleapis.com/auth/devstorage.read_only",
    "https://www.googleapis.com/auth/devstorage.read_write",
]
API_SERVICE_NAME = 'drive'
API_VERSION = 'v2'

UNIQUE_NAME = 'test-name-here-for-gcp-3'

app = flask.Flask(__name__)
# Note: A secret key is included in the sample so that it works.
# If you use this code in your application, replace this with a truly secret
# key. See http://flask.pocoo.org/docs/0.12/quickstart/#sessions.
app.secret_key = 'REPLACE ME - this value is here as a placeholder.'


@app.route('/')
def index():
    return print_index_table()


@app.route('/testCreateProject')
def test_create_project_api_request():
    if 'credentials' not in flask.session:
        return flask.redirect('authorize')

    # Load credentials from the session.
    credentials = google.oauth2.credentials.Credentials(
        **flask.session['credentials'])

    resources = googleapiclient.discovery.build(
        'cloudresourcemanager', 'v1', credentials=credentials)

    project_body = {
        'name': UNIQUE_NAME,
        'projectId': UNIQUE_NAME
    }

    request = resources.projects().create(body=project_body)
    response = request.execute()

    flask.session['credentials'] = credentials_to_dict(credentials)

    return flask.jsonify(**response)


@app.route('/testCreateAppEngine')
def test_create_app_engine_api_request():
    if 'credentials' not in flask.session:
        return flask.redirect('authorize')

    # Load credentials from the session.
    credentials = google.oauth2.credentials.Credentials(
        **flask.session['credentials'])

    apps = googleapiclient.discovery.build(
        'appengine', 'v1', credentials=credentials)

    app_body = {
        'id': UNIQUE_NAME,
        'locationId': 'us-central'
        # https://cloud.google.com/appengine/docs/locations
    }

    request = apps.apps().create(body=app_body)
    response = request.execute()

    flask.session['credentials'] = credentials_to_dict(credentials)

    return flask.jsonify(**response)


@app.route('/testClonePublicRepo')
def test_clone_public_repo():
    if 'credentials' not in flask.session:
        return flask.redirect('authorize')

    # Load credentials from the session.
    credentials = google.oauth2.credentials.Credentials(
        **flask.session['credentials'])

    repo_dir = os.path.join(PROJECT_DIR, 'repo')

    if os.path.exists(repo_dir):
        shutil.rmtree(repo_dir)

    repo_url = 'https://github.com/markeyev/gcp-self-deploy-poc.git'

    # Clone public repo
    repo = git.Repo.clone_from(repo_url,
                               repo_dir,
                               branch='master',
                               depth=1)
    output = os.listdir(repo_dir)

    flask.session['credentials'] = credentials_to_dict(credentials)

    return flask.jsonify({'branch': str(repo.heads.master),
                          'output': str(output)})


def upload_blob(bucket_name, source_file_name, destination_blob_name,
                storage_client):
    """Uploads a file to the bucket."""
    # storage_client = storage.Client(credentials=credentials)
    # storage_client = storage.Client()
    bucket = storage_client.get_bucket(bucket_name)
    blob = bucket.blob(destination_blob_name)

    blob.upload_from_filename(source_file_name)

    logger.debug('File {} uploaded to {}.'.format(
        source_file_name,
        destination_blob_name))


def build_blob_list(dir):
    # TODO(Ivan Markeev): Drop files from .gcloudignore.
    output, dropped = [], []
    for fs_obj in os.listdir(dir):
        if fs_obj.startswith('.git'):
            continue

        fs_obj_path = os.path.join(dir, fs_obj)
        if os.path.isdir(fs_obj_path):
            output.extend(build_blob_list(fs_obj_path))
        elif os.path.isfile(fs_obj_path):
            output.append(fs_obj_path)
        else:
            dropped.append(fs_obj_path)
    logger.debug('output: {}'.format(output))
    logger.debug('dropped: {}'.format(dropped))  # symlinks, etc...
    return output


def upload_object(bucket, filename, readers, owners, service):
    logger.debug('upload_object with fn {}'.format(filename))

    # This is the request body as specified:
    # http://g.co/cloud/storage/docs/json_api/v1/objects/insert#request
    body = {
        'name': filename,
    }

    # If specified, create the access control objects and add them to the
    # request body
    if readers or owners:
        body['acl'] = []

    for r in readers:
        body['acl'].append({
            'entity': 'user-%s' % r,
            'role': 'READER',
            'email': r
        })
    for o in owners:
        body['acl'].append({
            'entity': 'user-%s' % o,
            'role': 'OWNER',
            'email': o
        })

    # Now insert them into the specified bucket as a media insertion.
    # http://g.co/dv/resources/api-libraries/documentation/storage/v1/python/latest/storage_v1.objects.html#insert
    with open(filename, 'rb') as f:
        req = service.objects().insert(
            bucket=bucket, body=body,
            # You can also just set media_body=filename, but for the sake of
            # demonstration, pass in the more generic file handle, which could
            # very well be a StringIO or similar.
            media_body=googleapiclient.http.MediaIoBaseUpload(
                f, 'application/octet-stream'))
        resp = req.execute()

    return resp


@app.route('/testRepoToBucket')
def test_upload_repo_to_bucket():
    if 'credentials' not in flask.session:
        return flask.redirect('authorize')

    # Load credentials from the session.
    credentials = google.oauth2.credentials.Credentials(
        **flask.session['credentials'])

    repo_dir = os.path.join(PROJECT_DIR, 'repo')

    if not os.path.exists(repo_dir):
        return flask.redirect('/')

    blob_list = build_blob_list(repo_dir)

    bucket_name = UNIQUE_NAME
    service = googleapiclient.discovery.build('storage', 'v1',
                                              credentials=credentials)
    try:
        req = service.buckets().get(bucket=bucket_name)
        resp = req.execute()
        # req = service.buckets().delete(bucket=bucket_name)
        # resp = req.execute()
    except googleapiclient.errors.HttpError:
        req = service.buckets().insert(project=UNIQUE_NAME,
                                       body={'name': bucket_name})
        resp = req.execute()

    # storage_client = storage.Client(credentials=credentials)
    for blob in blob_list:
        upload_object(bucket=bucket_name,
                      filename=blob.replace(repo_dir, '').lstrip('/'),
                      readers=[],
                      owners=[],
                      service=service)

        flask.session['credentials'] = credentials_to_dict(credentials)

    req = service.objects().list(bucket=bucket_name)
    resp = req.execute()
    names = [x['name'] for x in resp['items']]

    return flask.jsonify({'dirlist': blob_list, 'bucket': names})


@app.route('/authorize')
def authorize():
    # Create flow instance to manage the OAuth 2.0 Authorization Grant Flow steps.
    flow = google_auth_oauthlib.flow.Flow.from_client_secrets_file(
        CLIENT_SECRETS_FILE, scopes=SCOPES)

    # The URI created here must exactly match one of the authorized redirect URIs
    # for the OAuth 2.0 client, which you configured in the API Console. If this
    # value doesn't match an authorized URI, you will get a 'redirect_uri_mismatch'
    # error.
    flow.redirect_uri = flask.url_for('oauth2callback', _external=True)

    authorization_url, state = flow.authorization_url(
        # Enable offline access so that you can refresh an access token without
        # re-prompting the user for permission. Recommended for web server apps.
        access_type='offline',
        # Enable incremental authorization. Recommended as a best practice.
        include_granted_scopes='true')

    # Store the state so the callback can verify the auth server response.
    flask.session['state'] = state

    return flask.redirect(authorization_url)


@app.route('/oauth2callback')
def oauth2callback():
    # Specify the state when creating the flow in the callback so that it can
    # verified in the authorization server response.
    state = flask.session['state']

    flow = google_auth_oauthlib.flow.Flow.from_client_secrets_file(
        CLIENT_SECRETS_FILE, scopes=SCOPES, state=state)
    flow.redirect_uri = flask.url_for('oauth2callback', _external=True)

    # Use the authorization server's response to fetch the OAuth 2.0 tokens.
    authorization_response = flask.request.url
    flow.fetch_token(authorization_response=authorization_response)

    # Store credentials in the session.
    # ACTION ITEM: In a production app, you likely want to save these
    #              credentials in a persistent database instead.
    credentials = flow.credentials
    flask.session['credentials'] = credentials_to_dict(credentials)

    return flask.redirect(flask.url_for('index'))


@app.route('/revoke')
def revoke():
    if 'credentials' not in flask.session:
        return ('You need to <a href="/authorize">authorize</a> before ' +
                'testing the code to revoke credentials.')

    credentials = google.oauth2.credentials.Credentials(
        **flask.session['credentials'])

    revoke = requests.post(
        'https://accounts.google.com/o/oauth2/revoke',
        params={'token': credentials.token},
        headers={'content-type': 'application/x-www-form-urlencoded'})

    status_code = getattr(revoke, 'status_code')
    if status_code == 200:
        return 'Credentials successfully revoked.' + print_index_table()
    else:
        return 'An error occurred.' + print_index_table()


@app.route('/clear')
def clear_credentials():
    if 'credentials' in flask.session:
        del flask.session['credentials']
    return ('Credentials have been cleared.<br><br>' +
            print_index_table())


def credentials_to_dict(credentials):
    return {'token': credentials.token,
            'refresh_token': credentials.refresh_token,
            'token_uri': credentials.token_uri,
            'client_id': credentials.client_id,
            'client_secret': credentials.client_secret,
            'scopes': credentials.scopes}


def print_index_table():
    return ('<table>'

            '<tr><td><a href="/testCreateProject">Test a Create Project API '
            'request</a></td>'
            '<td>Submit an API request and see a formatted JSON response. '
            '    Go through the authorization flow if there are no stored '
            '    credentials for the user.</td></tr>'

            '<tr><td><a href="/testCreateAppEngine">Test a Create AppEngine API'
            ' request</a></td>'
            '<td>Submit an API request and see a formatted JSON response. '
            '    Go through the authorization flow if there are no stored '
            '    credentials for the user.</td></tr>'

            '<tr><td><a href="/testClonePublicRepo">Test Clone Public Repo'
            '</a></td>'
            '<td>&nbsp;</td></tr>'

            '<tr><td><a href="/testRepoToBucket">Test Upload Repo To Bucket'
            '</a></td>'
            '<td>&nbsp;</td></tr>'

            '<tr><td><a href="/authorize">Test the auth flow directly</a></td>'
            '<td>Go directly to the authorization flow. If there are stored '
            '    credentials, you still might not be prompted to reauthorize '
            '    the application.</td></tr>'

            '<tr><td><a href="/revoke">Revoke current credentials</a></td>'
            '<td>Revoke the access token associated with the current user '
            '    session. After revoking credentials, if you go to the test '
            '    page, you should see an <code>invalid_grant</code> error.'
            '</td></tr>'

            '<tr><td><a href="/clear">Clear Flask session credentials</a></td>'
            '<td>Clear the access token currently stored in the user session. '
            '    After clearing the token, if you <a href="/test">test the '
            '    API request</a> again, you should go back to the auth flow.'
            '</td></tr>'

            '</table>')


if __name__ == '__main__':
    # When running locally, disable OAuthlib's HTTPs verification.
    # ACTION ITEM for developers:
    #     When running in production *do not* leave this option enabled.
    os.environ['OAUTHLIB_INSECURE_TRANSPORT'] = '1'

    # Specify a hostname and port that are set as a valid redirect URI
    # for your API project in the Google API Console.
    app.run('localhost', 8080, debug=True)
