import json
import logging
import os
import sys
import traceback

import boto3
import requests
from flask import Flask, request, abort

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)
logger.setLevel(logging.DEBUG)


app = Flask(__name__)


HIPCHAT_MSG_API_ENDPOINT = os.environ['HIPCHAT_MSG_API_ENDPOINT']
HIPCHAT_API_TOKEN = os.environ['HIPCHAT_API_TOKEN']
SNS_TOPIC_ARN = os.environ['SNS_TOPIC_ARN']


@app.route('/', methods=['GET', 'POST'])
def handle_pull_request_event():
    if request.method != 'POST':
        return 'no'

    event_type = request.headers.get('X-GitHub-Event', None)
    if event_type == 'ping':
        return json.dumps({'msg': 'pong'})

    if event_type != 'pull_request':
        return 'no'

    # Gather data
    try:
        event = request.get_json()
    except Exception:
        logger.error('Request parsing failed')
        abort(400)

    if not event:
        logger.error('No event to process. Make sure the content-type is json')
        abort(400)

    message = generate_message(event)
    if message:
        send_hipchat_message(message)

    return 'ok'


def generate_message(event):
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

    message = f'''
<a href="{sender_url}">{sender_name}</a> {action}
#<a href="{pr_url}">{pr_num}</a> on
<a href="{repo_url}">{repo_name}</a>: {pr_title}
'''
    return message


def send_hipchat_message(message):
    payload = {
        'color': 'yellow',
        'message': message,
    }
    headers = {
        'Authorization': 'Bearer {}'.format(HIPCHAT_API_TOKEN),
        'Content-Type': 'application/json',
    }
    return requests.post(
        HIPCHAT_MSG_API_ENDPOINT,
        headers=headers,
        timeout=5,
        data=json.dumps(payload),
    )


def send_sns_message(subject, message, subject_prefix='[AWS Item Monitor]'):
    full_subject = f'{subject_prefix} {subject}'
    logger.info(f'send_sns_message: {full_subject}\n{message}')
    topic_arn = SNS_TOPIC_ARN
    if not topic_arn:
        logger.warning('Unable to send message because SNS_TOPIC_ARN is not set')
        return

    # subject cannot exceed 100 characters
    limited_subject = full_subject[:100]

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

    subject = f'Unhandled exception: {exc_name_and_value}'
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
