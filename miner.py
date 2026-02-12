import socket
import time
import hashlib
import json
import sys
import random

#generated words using ChatGPT
SAMPLE_WORDS = [
    "Ambition", "Hope", "Unity", "Strength", "Peace", "Joy", "Love", "Gratitude",
    "Freedom", "Courage", "Kindness", "Patience", "Perseverance", "Compassion", "Wisdom",
    "Resilience", "Creativity", "Innovation", "Success", "Harmony", "Inspiration", "Determination",
    "Empathy", "Generosity", "Honesty", "Bravery", "Adventure", "Happiness", "Humility", "Integrity",
    "Faith", "Passion", "Achievement", "Balance", "Vision", "Prosperity", "Trust", "Opportunity",
    "Collaboration", "Friendship", "Loyalty", "Discipline", "Growth", "Commitment", "Focus", "Sacrifice",
    "Leadership", "Resourcefulness", "Effort", "Knowledge", "Action", "Mindfulness", "Respect",
    "Caring", "Supportive", "Motivated", "Committed", "Purpose", "Progress", "Tenacity", "Accountability",
    "Dedication", "Curiosity", "Openness", "Helpfulness", "Resilient", "Comfort", "Steadfast",
    "Understanding", "Forgiveness", "Giving", "Encouragement", "Teamwork", "Creativity", "Innovation",
    "Integrity", "Leadership", "Courageous", "Adaptability", "Growth", "Determined", "Balance",
    "Collaboration", "Strength", "Faithfulness", "Patience", "Belief", "Wisdom", "Resourceful",
    "Honesty", "Generosity", "Love", "Gratefulness", "Humble", "Determination", "Tenacity",
    "Innovation", "Effort", "Empathy", "Caring", "Focus", "Motivation", "Opportunity", "Empower",
    "Bravery", "Peace", "Perseverance", "Humility", "Diligence", "Inspiration", "Unity", "Strength",
    "Wisdom", "Compassion", "Success", "Trust", "Determination", "Integrity", "Knowledge", "Courage",
    "Vision", "Leadership", "Authenticity", "Forgiveness", "Loyalty", "Appreciation", "Commitment",
    "Hope", "Openness", "Growth", "Respect", "Support", "Dedication", "Empowerment", "Creativity",
    "Sincerity", "Faith", "Teamwork", "Respect", "Compassion", "Selflessness", "Mindfulness",
    "Consistency", "Achievement", "Visionary", "Progress", "Innovation", "Resilience", "Bravery",
    "Kindness", "Empathy", "Endurance", "Generosity", "Peace", "Faithfulness", "Caring", "Inspiration",
    "Unity", "Creativity", "Strength", "Joy", "Wisdom", "Focus", "Respect", "Self-care", "Openness",
    "Dedication", "Trust", "Compassion", "Hard work", "Support", "Leadership", "Courage", "Optimism",
    "Resilient", "Commitment", "Sincerity", "Vision", "Loyalty", "Innovation", "Balance", "Tenacity",
    "Self-belief", "Faith", "Kindness", "Growth", "Hope", "Self-awareness", "Ambition", "Dedication", "Trust", "Shiv",
    "Bhagat", "3010", "a3", "miner", "blockchain", "block", "chain", "hash", "hashing", "nonce", "difficulty", "proof",
    "work", "proof-of-work", "peer", "gossip", "gossiping", "consensus", "consensus", "block", "height", "heights",
    "apple", "banana", "cherry", "date", "elderberry", "fig", "grape", "honeydew", "kiwi", "lemon", "mango", "nectarine",
    "orange", "papaya", "quince", "raspberry", "strawberry", "tangerine", "watermelon", "apricot", "blackberry", "coconut",
    "dragonfruit", "eggplant", "fig", "grapefruit", "huckleberry", "imbe", "jackfruit", "kiwifruit", "lime", "mangosteen",
    "nectarine", "olive", "papaya", "quince", "raspberry", "strawberry", "tangerine", "watermelon", "yuzu", "zucchini",
    "almond", "blackberry", "cashew", "date", "elderberry", "fig", "grapefruit", "huckleberry", "imbe", "jackfruit"
]

old_message_received = []

# =======================================
# CLASS DEFINITIONS
# =======================================

# Block class to represent a mined block
class Block:
    def __init__(self, nonce, messages, previous_hash):
        """
        Initializes a new block.
        :param nonce: The nonce value used for mining.
        :param messages: List of data strings included in the block.
        :param previous_hash: Hash of the previous block in the chain.
        """
        self.minedBy = str(MY_NAME)
        self.nonce = str(nonce)
        self.messages = messages
        self.previous_hash = str(previous_hash)
        self.timestamp = int(time.time())
        self.hash = self.hash_block()

    def hash_block(self):
        """
        Generates a SHA-256 hash for the block content.
        Combines previous hash, miner name, messages, timestamp, and nonce.
        """
        hashBase = hashlib.sha256()
        lastHash = self.previous_hash
        hashBase.update(str(lastHash).encode())
        hashBase.update(str(self.minedBy).encode())
        for message in self.messages:
            hashBase.update(str(message).encode())
        hashBase.update(int(self.timestamp).to_bytes(8, 'big'))
        hashBase.update(str(self.nonce).encode())
        return hashBase.hexdigest()

def mine_block(messages, current_prev_hash, height, last_check):
    """
    Executes the Proof of Work algorithm.
    Iterates through nonce values to find a hash meeting the difficulty target.
    Checks for chain updates from the server periodically.
    :param messages: Data payload.
    :param current_prev_hash: Hash of the last known block.
    :param height: Current block height.
    :param last_check: Timestamp of the last server status check.
    """

    global old_message_received
    nonce = 0
    new_height = height
    prev_hash = current_prev_hash
    last_check_stat = last_check

    while nonce < 999999999999999999999999999999999999999: #39 digits
        # Mining logic
        block = Block(nonce, messages, prev_hash)
        block.hash = block.hash_block()
        print(f"{block.hash} - {nonce} - {new_height}")
        if block.hash[-1 * DIFFICULTY:] == '0' * DIFFICULTY:
            return block

        
        if time.time() - last_check_stat >= 30:  # Every 30s
            soc = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            soc.connect((SERVER_IP, SERVER_PORT))
            new_height, new_prev_hash, new_messages = send_stat_request(soc)
            if new_prev_hash != current_prev_hash or new_height != height or new_messages != old_message_received:
                old_message_received = new_messages
                print("-------------------------------------------------------------")
                print("New stats detected, restarting mining...")
                print("-------------------------------------------------------------")
                print(f"Previous height: {height}, previous prev_hash: {prev_hash}")
                print(f"New height: {new_height}, new prev_hash: {new_prev_hash}")
                print("-------------------------------------------------------------")
                time.sleep(3)
                prev_hash = new_prev_hash
                nonce = 0  # Reset nonce
            last_check_stat = time.time()
        nonce += 1

    return None


def request_status():
    """
    Constructs the status request payload.
    """
    return {"type": "STATS"}

def send_stat_request(soc):
    """
    Sends a stats request to the server and parses the response.
    :param soc: Active socket connection.
    """
    soc.send(json.dumps(request_status()).encode())
    data = soc.recv(1024).decode()
    data = json.loads(data)
    if not data:
        print("-------------------------------------------------------------")
        print("No data received")
        print("-------------------------------------------------------------")
        return None
    print("-------------------------------------------------------------")
    print(f"Received: \n {data}")
    print("-------------------------------------------------------------")
    return data["height"], data["hash"], data["messages"]

def start_mining(soc):
    """
    Initializes the mining process.
    Fetches current chain state, selects messages, and starts the mining loop.
    Announces successful blocks to the server.
    :param soc: Active socket connection.
    """

    global old_message_received
    print("-------------------------------------------------------------")
    print("Fetching initial stats...")
    height, prev_hash, messages = send_stat_request(soc)
    old_message_received = messages
    last_check = time.time()
    print(f"Starting mining with height: {height}, prev_hash: {prev_hash}")
    print("-------------------------------------------------------------")
    if(messages == []):
        num_words = random.randint(1, 10)
        messages = random.sample(SAMPLE_WORDS, num_words)
    print(f"Mining with messages: {messages}")
    print("-------------------------------------------------------------")
    time.sleep(3)

    # Call mine_block with the socket for stat checks
    block = mine_block(messages, prev_hash, height, last_check)

    if block is not None:
        print("-------------------------------------------------------------")
        print(f"Block mined: {block.hash}")
        announce_msg = {
            "type": "MINED_BLOCK",
            "height": height,
            "minedBy": block.minedBy,
            "nonce": block.nonce,
            "messages": block.messages,
            "hash": block.hash,
            "timestamp": block.timestamp,
        }

        soc = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        soc.connect((SERVER_IP, SERVER_PORT))
        soc.send(json.dumps(announce_msg).encode())
        print("Block announced")
        time.sleep(30)

# =======================================
# MAIN EXECUTION
# =======================================

MY_NAME = "Shiv Bhagat"
DIFFICULTY = 8
SERVER_IP = sys.argv[1] + ".cs.umanitoba.ca"
SERVER_PORT = 8106  


try:
    while True:
        soc = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        soc.connect((SERVER_IP, SERVER_PORT))
        print("Connected to server")
        start_mining(soc)
except KeyboardInterrupt:
    print("Exiting...")
finally:
    soc.close()
    print("Connection closed")
