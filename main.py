import hmac
import json
import logging
import re
import sys
import traceback
from datetime import datetime
from operator import itemgetter

import boto3
import github3
import gspread
import requests
from environs import Env
from flask import Flask, request, abort
from oauth2client import crypt
from oauth2client.client import HttpAccessTokenRefreshError
from oauth2client.service_account import ServiceAccountCredentials
from zappa.async import run


logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)
logger.setLevel(logging.DEBUG)


app = Flask(__name__)


env = Env()
env.read_env()


@env.parser_for('pgp')
def pgp_parser(value):
    if value:
        return value.replace('\\n', '\n')


S3_DEPLOYMENT_BUCKET = env('S3_DEPLOYMENT_BUCKET')
SNS_TOPIC_ARN = env('SNS_TOPIC_ARN')
SLACK_API_ENDPOINT = env('SLACK_API_ENDPOINT')

with env.prefixed('DEV_DASHBOARD_'):
    DEV_DASHBOARD_CLIENT_EMAIL = env('CLIENT_EMAIL')
    DEV_DASHBOARD_PRIVATE_KEY = env.pgp('PRIVATE_KEY')
    DEV_DASHBOARD_WORKBOOK = env('WORKBOOK')
    DEV_DASHBOARD_SHEET_NAME = env('SHEET_NAME')
    DEV_DASHBOARD_GH_LOGIN_LOOKUP_SHEET_NAME = env('GH_LOGIN_LOOKUP_SHEET_NAME')

with env.prefixed('GITHUB_'):
    GITHUB_SECRET_TOKEN = env('SECRET_TOKEN')
    GITHUB_API_TOKEN = env('API_TOKEN')
    GITHUB_API_USER = env('API_USER')
    GITHUB_REPO_CREATE_RELEASE_TAG = env('REPO_CREATE_RELEASE_TAG')


@app.route('/', methods=['GET', 'POST'])
def handle_incoming_github_event():
    if request.method != 'POST':
        return 'no'

    event_type = request.headers.get('X-GitHub-Event', None)
    if event_type == 'ping':
        return json.dumps({'msg': 'pong'})

    if event_type != 'pull_request':
        return 'no'

    verify_signature(request)

    # Gather data
    try:
        event = request.get_json()
    except Exception:
        logger.error('Request parsing failed')
        abort(400)

    if not event:
        logger.error('No event to process. Make sure the content-type is json')
        abort(400)

    run(process_event, [event])
    return 'ok'


def process_event(event):
    message = create_pr_action_message(event)
    logger.info(f'Created message: {message}')
    if message:
        logger.info('Posting to Slack')
        post_slack_message(message)

    if gh_event_is_merged_pr(event):
        repo_id = str(event['repository']['id'])
        if repo_id == GITHUB_REPO_CREATE_RELEASE_TAG:
            run(create_release_tag_and_upload_s3_archive, [repo_id])
        handle_merged_pr(event)


def _get_final_minor_version():
    s3_client = boto3.client('s3')
    params = dict(Bucket=S3_DEPLOYMENT_BUCKET, Key='final_minor_version')
    try:
        obj = s3_client.get_object(**params)
    except s3_client.exceptions.ClientError:
        return
    return obj['Body'].read().decode('utf-8').strip()


def get_next_release_tag_name(tag_name):
    m = re.match(r'v(\d+)\.(\d+)\.(\d+).*', tag_name.strip())
    major, minor, patch = [int(v) for v in m.groups()]
    # TODO - handle major version increase
    final_minor_version = _get_final_minor_version()
    if tag_name == final_minor_version:
        logger.info('Detected that minor version needs to be increased')
        patch = 0
        minor += 1
    else:
        patch += 1
    next_tag_name = f'v{major:02}.{minor:02}.{patch:02}'
    return next_tag_name


def create_release_tag_and_upload_s3_archive(repo_id):
    gh = github_auth()
    repo = gh.repository_with_id(repo_id)

    latest_commit = next(repo.commits(number=1))
    latest_tag = next(repo.tags(number=1))

    # latest_commit is expected to be a merge commit. merge commits always have two parents
    # the first commit is what the original head was, before the merge
    # the second commit is the head that was merged in
    original_head_commit, merged_commit = latest_commit.parents
    # we don't need to do anything with original_head_commit. It's named so it is known
    merged_commit_sha = merged_commit['sha']

    logger.info(
        f'latest_commit={latest_commit.sha} latest_tag={latest_tag.name} '
        f'merged_commit_sha={merged_commit_sha}'
    )

    new_tag_name = get_next_release_tag_name(latest_tag.name)
    logger.info(f'new_tag_name={new_tag_name}')

    s3_client = boto3.client('s3')
    s3_client.copy_object(
        Bucket=S3_DEPLOYMENT_BUCKET,
        Key=f'releases/{new_tag_name}',
        CopySource=dict(
            Bucket=S3_DEPLOYMENT_BUCKET,
            Key=f'builds/{merged_commit_sha}',
        ),
    )

    if latest_tag.commit.sha == latest_commit.sha:
        message = 'Latest commit is already tagged. Skipping tagging'
        logger.warning(message)
        post_slack_message(message)
    else:
        repo.create_tag(
            new_tag_name,
            message='',
            sha=latest_commit.sha,
            obj_type='commit',
            tagger='',
            lightweight=True,
        )


def verify_signature(request):
    if not GITHUB_SECRET_TOKEN:
        logger.warning('Security token not specified. This is very insecure!')
        return

    hash_signature = request.headers.get('X-Hub-Signature', None)
    if not hash_signature:
        logger.error('Header X-Hub-Signature was missing and it is required')
        abort(400)
    if not hash_signature.startswith('sha1='):
        logger.error('Header X-Hub-Signature is not formatted correctly')
        abort(400)
    expected_digest = hash_signature[len('sha1='):]
    actual_digest = hmac.new(GITHUB_SECRET_TOKEN.encode(), request.data, digestmod='sha1')
    if not hmac.compare_digest(actual_digest.hexdigest(), expected_digest):
        logger.error(
            'Actual digest does not match signature. '
            'Make sure you are using the correct token.'
        )
        abort(400)


def gh_event_is_merged_pr(event):
    if event['action'] != 'closed':
        return False
    return event['pull_request']['merged']


def get_contributors(repo_owner, repo_name, pr_num):
    gh = github_auth()
    pr = gh.pull_request(repo_owner, repo_name, pr_num)
    contributors = set()
    commits = list(pr.commits())
    for c in commits:
        if c.message.startswith('Merged branch'):
            # skip merges
            continue
        author = c.commit.author['name']
        committer = c.commit.committer['name']
        if author != committer:
            # Skip cherry-picks unless the committer is Github
            if committer != 'GitHub':
                continue
        contributors.add(author)
    return contributors


def get_workbook():
    scopes = [
        'https://spreadsheets.google.com/feeds',
        'https://www.googleapis.com/auth/drive',
    ]

    signer = crypt.Signer.from_string(DEV_DASHBOARD_PRIVATE_KEY)
    credentials = ServiceAccountCredentials(
        service_account_email=DEV_DASHBOARD_CLIENT_EMAIL,
        signer=signer,
        scopes=scopes,
    )

    try:
        gc = gspread.authorize(credentials)
    except HttpAccessTokenRefreshError:
        logger.error('Invalid credentials')
        return

    try:
        book = gc.open(DEV_DASHBOARD_WORKBOOK)
    except gspread.exceptions.SpreadsheetNotFound:
        logger.error(f'Could not find workbook named {DEV_DASHBOARD_WORKBOOK}')
        return
    return book


def handle_merged_pr(event):
    book = get_workbook()
    if not book:
        return

    update_spreadsheet(book, event)
    display_current_contributions(book)


def display_current_contributions(book):
    sheet = book.worksheet('Contributions')
    now = datetime.utcnow()

    year, month = str(now.year), now.strftime('%b')
    first_col = [v.strip() for v in sheet.col_values(1)]

    try:
        year_row = first_col.index(year)
    except IndexError:
        logger.error(f'Could not find a row containing {year}')

    first_row = [v.strip() for v in sheet.row_values(1)]

    try:
        month_col = first_row.index(month)
    except IndexError:
        logger.error(f'Could not find a column containing {month}')

    try:
        total_col = first_row.index('Total')
    except IndexError:
        logger.error(f'Could not find a column containing Total')

    keys = []
    for r in first_col[year_row:]:
        if not r:
            break
        keys.append(r.split(' ')[0])

    year_total_values = [
        int(cell.value)
        for cell in sheet.range(year_row+1, total_col+1, year_row+len(keys), total_col+1)
    ]

    month_total_values = [
        int(cell.value)
        for cell in sheet.range(year_row+1, month_col+1, year_row+len(keys), month_col+1)
    ]

    all_totals = list(zip(keys, month_total_values, year_total_values))
    _, month_total, year_total = all_totals.pop(0)

    contributions = [
        f'{key} {month_value}/{year_value}'
        for key, month_value, year_value in
        sorted(all_totals, key=itemgetter(1), reverse=True)
    ]
    url = f'https://docs.google.com/spreadsheets/d/{book.id}'
    message = [
        f'<{url}|Contributions> '
        f'for {month}/{year}: {month_total}/{year_total}',
    ]
    message.append(' ~ '.join(contributions))
    post_slack_message('\n'.join(message))


def update_spreadsheet(book, event):
    pr = event['pull_request']

    merged_at = pr['merged_at'].replace('T', ' ').rstrip('Z')
    pr_url = pr['html_url']
    merged_by = pr['merged_by']['login']

    if not all([merged_at, pr_url, merged_by]):
        logger.error(f'Some meta data is missing')
        return

    contributors = get_contributors(
        repo_owner=event['repository']['owner']['login'],
        repo_name=event['repository']['name'],
        pr_num=pr['number'],
    )

    display_name = get_gh_login_display_name_mapping(book, merged_by)
    new_row = [
        merged_at,
        pr_url,
        display_name,
        '', '',
        '; '.join(sorted(contributors)),
    ]

    sheet = book.worksheet(DEV_DASHBOARD_SHEET_NAME)
    sheet.insert_row(new_row, index=2, value_input_option='USER_ENTERED')


def get_gh_login_display_name_mapping(book, gh_login):
    sheet = book.worksheet(DEV_DASHBOARD_GH_LOGIN_LOOKUP_SHEET_NAME)
    mapping = dict(zip(sheet.col_values(1), sheet.col_values(2)))
    return mapping.get(gh_login, gh_login)


def create_pr_action_message(event):
    action = event['action']
    if action not in ['opened', 'closed', 'reopened']:
        return

    if event['pull_request']['merged']:
        action = 'merged'

    sender_name = event['sender']['login']
    sender_url = event['sender']['html_url']
    repo_name = event['repository']['full_name']
    repo_url = event['repository']['html_url']
    pr_num = event['pull_request']['number']
    pr_url = event['pull_request']['html_url']
    pr_title = event['pull_request']['title']

    message = (
        f'<{sender_url}|{sender_name}> '
        f'{action} #<{pr_url}|{pr_num}> on '
        f'<{repo_url}|{repo_name}>: {pr_title}'
    )
    return message


def github_auth():
    return github3.login(GITHUB_API_USER, GITHUB_API_TOKEN)


def test_create_release():
    create_release_tag_and_upload_s3_archive(GITHUB_REPO_CREATE_RELEASE_TAG)


def test_message():
    post_slack_message('<http://google.com|Bar>')


def post_slack_message(message):
    requests.post(SLACK_API_ENDPOINT, timeout=5, json=dict(text=message))


def send_sns_message(subject, message, subject_prefix='[AWS GH PR Webhook]'):
    # remove any characters that aren't allowed
    subject = re.sub('[^a-zA-Z0-9-]+', ' ', subject)

    full_subject = f'{subject_prefix} {subject}'
    logger.info(f'send_sns_message: {full_subject}\n{message}')
    topic_arn = SNS_TOPIC_ARN
    if not topic_arn:
        logger.warning('Unable to send message because SNS_TOPIC_ARN is not set')
        return

    # subject must be < 100 characters
    limited_subject = full_subject[:99].strip()

    sns = boto3.client('sns')
    sns.publish(TopicArn=topic_arn, Message=message, Subject=limited_subject)


def get_current_exception_info():
    exc_type, exc_value, exc_traceback = sys.exc_info()

    exc_name_and_value = traceback.format_exception_only(exc_type, exc_value)
    exc_stacktrace = traceback.format_exception(exc_type, exc_value, exc_traceback)

    exc_name_and_value = ''.join(exc_name_and_value).strip()
    exc_stacktrace = ''.join(exc_stacktrace).strip()

    return exc_name_and_value, exc_stacktrace


def unhandled_exceptions(exception, event, context):
    logger = logging.getLogger(__name__)
    exc_name_and_value, exc_stacktrace = get_current_exception_info()

    # Some exception messages are across multiple lines
    # If this is the case, only use the first line
    exc_lines = exc_name_and_value.split('\n', 1)
    exception_subject = exc_lines[0].strip()

    subject = f'Unhandled exception: {exception_subject}'
    message = f'''
{exc_stacktrace}
Event:
{event}
Function: {context.function_name} {context.function_version}
AWS Request ID: {context.aws_request_id}
'''
    send_sns_message(subject=subject, message=message)
    logger.warning(f'{subject}\n{message}')
    return True  # Prevent invocation retry


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=80)
