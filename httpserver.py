#!/usr/bin/env python3

from flask import Flask,request,redirect,Response
import json

app = Flask(__name__)

@app.route('/',methods=['GET', 'POST'])
@app.route('/<path:data>',methods=['GET', 'POST'])
def root(data=''):
    print(json.dumps({
        "request_line": f"{request.method} {request.full_path} {request.environ.get('SERVER_PROTOCOL')}",
        "headers": {key: value for key, value in request.headers.items()},
        "body": request.stream.read().decode('utf-8'),
        "environ": {key: str(value) for key, value in request.environ.items()}
    }, indent=4))
    return "com"

if __name__ == "__main__":
    app.run(host="::", port=8000)

