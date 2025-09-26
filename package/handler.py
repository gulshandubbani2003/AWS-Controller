import serverless_wsgi
from one import app


def handler(event, context):
    return serverless_wsgi.handle_request(app, event, context)


