from flask import Flask, request
from flask_restful import Resource, Api
from json import dumps, loads
app = Flask(__name__)
api = Api(app)
seq = []
class Logging(Resource):
    def get(self):
        js = request.json
        print(js)
        print(js["message"])
        if js["log"] == "sequence":
            seq.append(loads(request.json["message"]))
        return {'hello': 'world'}
    def post(self):
        js = request.json
        print(js)
        if js["log"] == "sequence":
            seq.append(loads(request.json["message"]))
        print("\n###########\n")

        for item in seq:
            print(item["seq"])
        print("\n###########\n")
        return {"hello": "world"}


api.add_resource(Logging, '/')

if __name__ == '__main__':
    app.run(debug=False, port=9004)