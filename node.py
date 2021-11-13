from Crypto.Hash import SHA256
from urllib.parse import urlparse
from Crypto.Signature import pkcs1_15
from Crypto.PublicKey import RSA
from flask import Flask, jsonify, request
import os


class Pools:
    def __init__(self):
        self.nodes_pool = set()
        self.transactions_pool = []
        self.blockchain = []

    def add_node(self, address):
        parsed_url = urlparse(address)
        self.nodes_pool.add(parsed_url.netloc)

    def add_transactions(self, sender, receiver, amount, sign):
        transaction = {
            "sender": sender,
            "receiver": receiver,
            "amount": amount,
            "sign": sign
        }
        self.transactions_pool.append(transaction)

    def add_block(self, block):
        self.blockchain.append(block)

    def verify_transaction(self, public_key, data, sign):
        try:
            data = SHA256.new(data.encode())
            pub_key = RSA.import_key(public_key)
            print(pub_key)
            pkcs1_15.new(pub_key).verify(data, bytes.fromhex(sign))
            return True
        except Exception as e:
            print(e)
            return False


app = Flask(__name__)
pool = Pools()


@app.route('/add_transactions', methods=['POST'])
def add_transaction_to_pool():
    if request.method == "POST":
        json_data = request.get_json()
        if json_data['sender'] is not "Rewards":
            transaction_keys = ['sender', 'receiver', 'amount', 'sign', 'public_key']
            if not all(keys in json_data for keys in transaction_keys):
                return "Error", 400
            else:
                is_valid = pool.verify_transaction(public_key=json_data['public_key'],
                                                   data=str(json_data['receiver'] + str(json_data['amount'])),
                                                   sign=json_data['sign'])
                if is_valid:
                    pool.add_transactions(json_data['sender'], json_data['receiver'], json_data['amount'],
                                          json_data['sign'])
                else:
                    return "Invalid Transaction", 400
        else:
            transaction_keys = ['sender', 'receiver', 'amount', 'sign']
            if not all(keys in json_data for keys in transaction_keys):
                return "Error", 400
            else:
                pool.add_transactions(json_data['sender'], json_data['receiver'], json_data['amount'], None)
    return "Created", 201


@app.route('/add_nodes', methods=['POST'])
def add_nodes():
    status = 500
    if request.method == 'POST':
        data = request.get_json()
        print(data)
        if 'node' not in data:
            status = 400
        else:
            for node in data['node']:
                if data['node'] != "":
                    pool.add_node(node)
            status = 201
    return jsonify({"message": f"{status}"}), status


@app.route('/get_transactions')
def get_transactions():
    return jsonify({"message": pool.transactions_pool})


@app.route('/add_block', methods=['POST'])
def add_block_to_pool():
    if request.method == 'POST':
        data = request.get_json()
        block = data['block']
        pool.add_block(block)
    return 202


@app.route('/get_blockchain')
def get_blockchain():
    return jsonify({"chain": pool.blockchain}), 200


@app.route('/set_transaction', methods=['POST'])
def set_transactions():
    pool.transactions_pool = []
    return "Done", 200


@app.route('/get_nodes')
def get_nodes():
    response = {
        "message": list(pool.nodes_pool),
        "length": len(pool.nodes_pool)
    }
    return response, 200


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=int(os.environ.get('PORT', 2000)))
