import socket
import json
import time
import uuid
# import traceback
import hashlib
import threading
import random

from collections import Counter

# =======================================
# CLASSES
# =======================================


#For grouping the chains
class StatChain:
    def __init__(self, height, hash, peers=None):
        """
        Initializes the chain statistics group.
        :param height: Chain height.
        :param hash: Chain top hash.
        :param peers: List of peers on this chain.
        """
        self.height = height
        self.hash = hash
        self.peers = peers if peers is not None else []

    def add_peer(self, peer):
        """
        Adds a peer to the chain group.
        :param peer: Peer object to add.
        """
        self.peers.append(peer)

    def get_peers(self):
        """
        Retrieves the list of peers.
        """
        return self.peers

 # Messages   
class Message:
    def __init__(self, message_type):
        """
        Initializes the base message structure.
        :param message_type: Type of message.
        """
        self.type = message_type

    def to_json(self):
        """
        Serializes the message object to JSON.
        """
        return json.dumps(self.__dict__)
    
    def send(self, soc, addr):
        """
        Sends the message via UDP.
        :param soc: Socket object.
        :param addr: Destination address tuple.
        """
        # print(self.to_json())
        soc.sendto(self.to_json().encode(), addr)

# Messages - Subclasses 
# GOSSIP message - Sent for peer discovery, contains sender's info and a unique ID to prevent loops
class Gossip(Message):
    def __init__(self, host, port, id, name):
        """
        Constructs a Gossip message for peer discovery.
        :param host: Sender IP address.
        :param port: Sender port.
        :param id: Unique message ID.
        :param name: Sender name.
        """
        super().__init__("GOSSIP")
        self.host = host
        self.port = port
        self.id = id
        self.name = name

# Reply to the Gossip message, sent back to the sender to acknowledge receipt and share sender's info
class GossipReply(Message):
    def __init__(self, host, port, name):
        """
        Constructs a reply to a Gossip message.
        :param host: Sender IP address.
        :param port: Sender port.
        :param name: Sender name.
        """
        super().__init__("GOSSIP_REPLY")
        self.host = host
        self.port = port
        self.name = name

# STATS message - Sent to request the current blockchain status (height and top hash) from peers
class Stats(Message):
    def __init__(self):
        """
        Constructs a Stats request message.
        """
        super().__init__("STATS")
    
    
    def send(self, soc, peers):
        """
        Broadcasts the Stats request to all known peers.
        :param soc: Socket object.
        :param peers: PeerList object containing targets.
        """
        peer_list = peers.get_peers()
        for peer in peer_list:
            # print(self.to_json())
            peer = peer.get_addr()
            soc.sendto(self.to_json().encode(), peer)

# STATS_REPLY message - Sent in response to a STATS request, contains the sender's current blockchain height and top hash     
class StatsReply(Message):
    def __init__(self, height, hash):
        """
        Constructs a reply with local chain statistics.
        :param height: Current chain height.
        :param hash: Hash of the top block.
        """
        super().__init__("STATS_REPLY")
        self.height = height
        self.hash = hash

# GET_BLOCK message - Sent to request a specific block by height from peers
class GetBlock(Message):
    def __init__(self, height):
        """
        Constructs a request for a specific block.
        :param height: Height of the requested block.
        """
        super().__init__("GET_BLOCK")
        self.height = height


# GET_BLOCK_REPLY message - Sent in response to a GET_BLOCK request, contains the requested block's details if available
class GetBlockReply(Message):
    def __init__(self, height, blocks):
        """
        Constructs a reply containing block data.
        :param height: Height of the block.
        :param blocks: Dictionary containing blockchain data.
        """

        super().__init__("GET_BLOCK_REPLY")
        self.hash = blocks.get(height).get("hash")
        self.height = height
        self.messages = blocks.get(height).get("messages")
        self.minedBy = blocks.get(height).get("minedBy")
        self.nonce = blocks.get(height).get("nonce")
        self.timestamp = blocks.get(height).get("timestamp")
    

# ANNOUNCE message - Sent by miners to announce a newly mined block, contains the block's details
class Announce(Message):
    def __init__(self, height, hash, messages, mined_by, nonce, timestamp):
        """
        Constructs an announcement for a new block.
        :param height: Block height.
        :param hash: Block hash.
        :param messages: List of messages in block.
        :param mined_by: Name of miner.
        :param nonce: Proof of work nonce.
        :param timestamp: Block creation time.
        """

        super().__init__("ANNOUNCE")
        self.height = height
        self.hash = hash
        self.messages = messages
        self.minedBy = mined_by
        self.nonce = nonce
        self.timestamp = timestamp
    
    def send(self, soc, peers):
        """
        Broadcasts the announcement to all peers.
        :param soc: Socket object.
        :param peers: PeerList object.
        """

        peer_list = peers.get_peers()
        for peer in peer_list:
            peer = peer.get_addr()
            soc.sendto(self.to_json().encode(), peer)

#Messages - StatsReply - Subclass (for miners)
class MinerStats(StatsReply):
    def __init__(self, height, hash):
        """
        Constructs stats specifically for the miner.
        :param height: Current chain height.
        :param hash: Current top hash.
        """

        super().__init__(height, hash)
        self.messages = self.get_messages()
    
    def send(self, soc):
        """
        Sends data to miner via TCP.
        :param soc: TCP socket connection.
        """
        soc.send(self.to_json().encode())

    def get_messages(self):
        """
        Retrieves pending messages for the miner.
        """

        #if there are message words, send them
        if len(message_words) > 0:
            return message_words
        return []

    def get_hash(self):
        """
        Returns the block hash.
        """
        return self.hash
    
    def get_height(self):
        """
        Returns the block height.
        """
        return self.height
    
        

# Peer - Represents a peer in the network, storing its IP, port, name, and last communication timestamp
class Peer:
    def __init__(self, ip, port, name):
        """
        Initializes a peer node.
        :param ip: Peer IP address.
        :param port: Peer port.
        :param name: Peer name.
        """
        self.ip = ip
        self.port = port
        self.name = name
        self.timestamp = time.time()

    def __eq__(self, other):
        """
        Checks equality based on IP and port.
        :param other: Peer to compare.
        """
        return (self.ip == other.ip and self.port == other.port)
    
    def get_addr(self):
        """
        Returns the address tuple.
        """
        return (self.ip, self.port)
    
    def set_timestamp(self, timestamp):
        """
        Updates the last seen timestamp.
        :param timestamp: New timestamp.
        """
        self.timestamp = timestamp

    def get_name(self):
        """
        Returns the peer name.
        """
        return self.name
    
    
# PeerList - Manages the list of known peers, allowing addition, removal, retrieval, and periodic cleanup of stale peers based on last communication time
class PeerList:
    def __init__(self):
        """
        Initializes the peer list.
        """
        self.peers = []
    
    def add_peer(self, peer):
        """
        Adds a new peer to the list.
        :param peer: Peer object.
        """
        self.peers.append(peer)
    
    def remove_peer(self, peer):
        """
        Removes a peer from the list.
        :param peer: Peer object.
        """
        self.peers.remove(peer)
    
    def get_peers(self):
        """
        Returns the list of peers.
        """
        return self.peers
    
    def get_peer(self, ip, port):
        """
        Finds a peer by IP and port.
        :param ip: Target IP.
        :param port: Target port.
        """

        for peer in self.peers:
            peer_addr = peer.get_addr()
            if peer_addr[0] == ip and peer_addr[1] == port:
                return peer
        return None

    def clear(self, expiry):
        """
        Removes inactive peers.
        :param expiry: Time duration before expiration.
        """

        print("---------------------------------------------------------------------")
        for peer in self.peers[1:]:
            if time.time() - peer.timestamp >= expiry:
                self.peers.remove(peer)
                print(f"Removed peer {peer.ip}:{peer.port} - {peer.name}")
        
        if self.get_peer(WELL_KNOWN_HOST,WELL_KNOWN_PORT) is None:
            self.add_peer(WELL_KNOWN_PEER)
        print("---------------------------------------------------------------------")


# =======================================
# GLOBAL VARIABLES and CONSTANTS
# =======================================

DIFFICULTY = 8
BAD_ACTORS = []
# BAD_ACTORS = [8330, 8000]

message_words = []
    

NAME = "Shiv Bhagat"

MY_PORT = 8108
MINER_PORT = 8106

WELL_KNOWN_HOST = "130.179.28.37" #silicon.cs.umanitoba.ca
WELL_KNOWN_PORT = 8999
WELL_KNOWN_PEER = Peer(WELL_KNOWN_HOST, WELL_KNOWN_PORT, "Well Known Peer - Silicon")

track_peers = PeerList()
track_peers.add_peer(WELL_KNOWN_PEER)

my_ids = []
peers_replied = []
stat = []

blocks = {}
test_blocks = {}


max_height = -1

done_consensus = False
can_reply = False
    

# =======================================
# FUNCTIONS
# =======================================


def receive_message():
    """
    Processes incoming UDP packets and routes based on type.
    """
    try:
        data, addr = soc.recvfrom(1024)
        message = json.loads(data.decode())
        #print(message)
    
        if message is None:
            return
        
        #to be removed
        if addr[1] in BAD_ACTORS:
            return
        
        message_type = message.get("type")

        # Handle GOSSIP message
        if message_type == "GOSSIP":
            gossip_host = message.get("host")
            gossip_port = message.get("port")
            gossip_name = message.get("name")
            gossip_id = message.get("id")

            # print(f'Received GOSSIP message from {gossip_host}:{gossip_port} - {gossip_name}')
            #To be removed
            if gossip_port in BAD_ACTORS:
                return
            
            if gossip_id not in peers_replied:
                GossipReply(MY_IP, MY_PORT, NAME).send(soc, (gossip_host, gossip_port))
                peers_replied.append(gossip_id)
                print(f"Sent GOSSIP_REPLY to {gossip_host}:{gossip_port} - {gossip_name}")

                peer = Peer(gossip_host, gossip_port, gossip_name)
                peers_list = track_peers.get_peers()
                if peer not in peers_list:
                    track_peers.add_peer(peer)
                    print(f"Added peer {gossip_host}:{gossip_port} - {gossip_name}")
                else :
                    #update timestamp
                    track_peers.get_peer(gossip_host, gossip_port).set_timestamp(time.time())



        elif message_type == "NEW_WORD":
            print(f'Received NEW_WORD message from {addr[0]}:{addr[1]}')
            print(f'New Word: {message.get("word")}')
            message_words.append(message.get("word"))

        # Handle STAT_REPLY message
        elif message_type == "STATS_REPLY":
            print(f'Received STATS_REPLY from {addr[0]}:{addr[1]}')

            if message.get("hash") is None or not message.get("hash").endswith('0' * DIFFICULTY) or message.get("height") is None or message.get("height") < 0 or isinstance(message.get("height"), int) is False:
                return

            if (addr[0], addr[1]) not in [(peer_ip, peer_port) for peer_ip, peer_port, _ in stat]:
                stat.append((addr[0], addr[1], message))

        elif message_type == "GET_BLOCK_REPLY":
            print(f'\nReceived GET_BLOCK_REPLY from {addr[0]}:{addr[1]}\n{json.dumps(message, indent=2)}')
            block_hash = message.get("hash")
            if block_hash is not None and message.get("height") is not None and message.get("messages") is not None and message.get("minedBy") is not None and message.get("nonce") is not None and message.get("timestamp") is not None and block_hash.endswith('0' * DIFFICULTY) and message.get("height") >= 0 and isinstance(message.get("height"), int):
                height = int(message.get("height"))
                #only add the block if it is not already in the chain
                if height not in blocks:
                    test_blocks[height] = message

        elif message_type == "CONSENSUS":
            print("---------------------------------------------------------------------")
            print("Forced CONSENSUS Received")
            consensus()

        elif message_type == "GET_BLOCK":
            if (can_reply):
                if(message.get("height") is not None and isinstance(message.get("height"), int) and message.get("height") >= 0 and message.get("height") in blocks):
                    height = message.get("height")
                    GetBlockReply(height, blocks).send(soc, addr)
                    print(f"Sent GET_BLOCK reply to {addr[0]}:{addr[1]} - Height {height}")

        elif message_type == "STATS":
            if (can_reply):
                max_height = max(blocks.keys())
                StatsReply(max_height + 1, blocks.get(max_height).get("hash")).send(soc, addr)
                print(f"Sent STATS reply to {addr[0]}:{addr[1]}")

        elif message_type == "ANNOUNCE":
            if (can_reply):
                print(f"Received ANNOUNCE message from {addr[0]}:{addr[1]} - {message['minedBy']}")
                handle_announce(message)

        elif message_type == "MINED_BLOCK":
            print(f"Received MINED_BLOCK message from miner: {addr[0]}:{addr[1]} - {message['minedBy']}")
            Announce(message["height"], message["hash"], message["messages"], message["minedBy"], message["nonce"], message["timestamp"]).send(soc, track_peers)
            handle_announce(message)

    
    except socket.error as e:
        pass

    except json.JSONDecodeError as e:
        print("Error decoding JSON")
        print(f"Message: {data.decode()} - {addr}")
        # traceback.print_exc()
        print(e)

    except Exception as e:
        print(e)



def stat_peers():
    """
    Broadcasts stats request to all peers.
    """

    print("---------------------------------------------------------------------")
    print("SENDING - STATS")
    Stats().send(soc, track_peers)
    print(f"Sent STATS message to :\n{[peer.get_addr() for peer in track_peers.get_peers()]}")
    print("---------------------------------------------------------------------")

def sort_chain(stat):
    """
    Sorts chains to find the majority hash.
    :param stat: List of stats replies.
    """

    if not stat:
        return None

    max_height = max([s[2]["height"] for s in stat])
    longest_chain = [s for s in stat if s[2]["height"] == max_height]

    #count hash of longest chain
    hash_count = Counter(s[2]["hash"] for s in longest_chain)
    majority_hash = hash_count.most_common(1)[0][0]

    peers_associated = []
    for s in longest_chain:
        if s[2]["hash"] == majority_hash:
            peers_associated.append((s[0], s[1]))

    return StatChain(max_height, majority_hash, peers_associated)

#remove when not in use
def group_chains(stat):
    """
    Groups peers based on their chain height and hash.
    :param stat: List of stats replies.
    """

    chains = {}
    for s in stat:
        #none check
        if s[2] is None or s[2]["height"] is None or s[2]["hash"] is None:
            continue
        
        height = s[2]["height"]
        hash = s[2]["hash"]
        peer = (s[0], s[1])

        if height not in chains:
            chains[height] = {}

        if hash not in chains[height]:
            chains[height][hash] = []

        chains[height][hash].append(peer)

    sorted_chains = []
    for height in sorted(chains.keys(), reverse=True):
        for hash, peers in chains[height].items():
            sorted_chains.append(StatChain(height, hash, peers))

    return sorted_chains

def fetch_blocks(chains):
    """
    Attempts to download blocks from the best chain.
    :param chains: List of StatChain objects.
    """
    for chain in chains:
        test_blocks.clear()
        test_blocks.update(blocks)

        print(f"Selected peers: {chain.get_peers()}, height: {chain.height}, hash: {chain.hash}")
        peer_height = chain.height - 1
        peers = chain.get_peers()
        num_peers = len(peers)
        
        
        retries = 60 
        retry_interval = 1
        for attempt in range(retries):
            print(f"Attempt {attempt + 1}/{retries} for chain height {chain.height}")
            print("---------------------------------------------------------------------")

            current = 0
            for height in range(peer_height, -1, -1):
                if height not in test_blocks:
                    peer = peers[current % num_peers]
                    try:
                        GetBlock(height).send(soc, peer)
                        print(f"Sent request for block at height {height} to peer {peer}")
                        current += 1
                    except Exception as e:
                        print(f"Error sending request for block at height {height} to peer {peer}: {e}")
                        # traceback.print_exc()
                        continue
            
            # Wait for blocks to be received for this attempt
            start_time = time.time()
            while time.time() - start_time < retry_interval:
                receive_message()
                if len(test_blocks) >= chain.height:
                    break

            if len(test_blocks) >= chain.height:
                break

        #wait for 2s after trials  
        while time.time() - start_time < 2:
            receive_message()
            
   
        
        # Validate the chain after all retries or successful completion\

        if validate_chain(test_blocks, chain.height):
            print(f"Chain validated with height {chain.height}")
            blocks.update(test_blocks)
            print("---------------------------------------------------------------------")
            return chain.height #chain height from stat (already +1)
        else:
            test_blocks.clear()
            print(f"Chain with height {chain.height} is invalid or incomplete, moving to the next chain")
            print("---------------------------------------------------------------------")
    
    print("No valid chain found")
    return None


def do_consensus(stat):
    """
    Executes the consensus logic.
    :param stat: List of stats replies.
    """
    print("---------------------------------------------------------------------")
    print("CONSENSUS")
    stat_chain = group_chains(stat)
    # print(f"Selected peers: {stat_chain.get_peers()}")
    
    if not stat_chain:
        print("No consensus")
        return
    
    max_height = fetch_blocks(stat_chain)
    return max_height



def consensus():
    """
    Manages the consensus loop.
    """
    done_consensus = False
    can_reply = False
    done_stat = False
    process_time = time.time()
    while not done_consensus:
        if time.time() - process_time >= 0 and not done_stat:
            #get stats from peers
            stat_peers()
            process_time = time.time()
            done_stat = True

        receive_message()

        if time.time() - process_time >= 5 and len(stat) > 0:
            
            show_stats(stat)
            max_height = do_consensus(stat)
            if max_height:
                done_consensus = True
                can_reply = True

    return (max_height, can_reply, done_consensus) 
            

def show_stats(stat):
    """
    Prints stats received from peers.
    :param stat: List of stats replies.
    """
    print("---------------------------------------------------------------------")
    print("STATS")
    for s in stat:
        print(f"Peer: {s[0]}:{s[1]} - Height: {s[2]['height']} - Hash: {s[2]['hash']}")
    print("---------------------------------------------------------------------")

def validate_chain(blocks, max_height):
    """
    Validates the blockchain integrity.
    :param blocks: Dictionary of blocks.
    :param max_height: Maximum height to check.
    """
    print("---------------------------------------------------------------------")
    
    if(len(blocks) < max_height):
        print("Blockchain is invalid")
        return False
    
    previous_hash = None
    for height in range(max(blocks.keys())):
        block = blocks[height]

        if block is None:
            print(f"Block at height {height} is missing")
            return False

        new_hash = calculate_hash(block, previous_hash)

        if new_hash != block["hash"]:
            print(f"Blockchain is invalid at height {height}")
            print(f"Expected: {block['hash']}, Got: {new_hash}")
            return False
        
        #check for difficulty
        if not new_hash.endswith('0' * DIFFICULTY):
            print(f"Block does not meet difficulty requirements: {new_hash}")
            return False

        previous_hash = new_hash
        
    print("Blockchain is valid")
    return True


def calculate_hash(block, prev_hash):
    """
    Computes SHA-256 hash for a block.
    :param block: Block data to hash.
    :param prev_hash: Hash of the previous block.
    """

    m = hashlib.sha256()
    if prev_hash:
        m.update(prev_hash.encode())
    m.update(str(block["minedBy"]).encode())
    for msg in block["messages"]:
        m.update(str(msg).encode())
    m.update(int(block["timestamp"]).to_bytes(8, 'big'))
    m.update(str(block["nonce"]).encode())

    return m.hexdigest()

def validate_new_block(announced_block, prev_hash):
    """
    Validates a single new block.
    :param announced_block: The new block to check.
    :param prev_hash: Hash of the previous block.
    """

    hashBase = hashlib.sha256()

    hashBase.update(prev_hash.encode())

    hashBase.update(announced_block['minedBy'].encode())

    for m in announced_block['messages']:
        hashBase.update(m.encode())

    hashBase.update(announced_block['timestamp'].to_bytes(8, 'big'))

    hashBase.update(announced_block['nonce'].encode())

    recalculated_hash = hashBase.hexdigest()

    if recalculated_hash != announced_block['hash']:
        print(f"Block hash mismatch! Expected: {announced_block['hash']}, Got: {recalculated_hash}")
        return False

    # Check proof-of-work difficulty
    if not recalculated_hash.endswith('0' * DIFFICULTY):
        print(f"Block does not meet difficulty requirements: {recalculated_hash}")
        return False

    print(f"Block is valid: {recalculated_hash}")
    return True


def handle_announce(announced_block):
    """
    Processes an announced block and updates the chain.
    :param announced_block: The block to process.
    """

    global max_height
    current_height = len(blocks) - 1
    announced_block_height = announced_block['height']
    
    if announced_block_height != current_height + 1:
        print(f"Announced block height {announced_block['height']} is not valid. Expected {current_height + 1}.")
        return False

    top_block = blocks[current_height]
    prev_hash = top_block['hash']
    new_hash = validate_new_block(announced_block, prev_hash)

    if not new_hash:
        return False
    
    blocks[announced_block_height] = announced_block
    max_height = announced_block_height

    #remove the words of the message from the list if they are in the block
    for word in announced_block['messages']:
        if word in message_words:
            message_words.remove(word)
            
    print(f"Block added to the chain: \n {announced_block}")

    return True


# =======================================
# MINER THREADING
# =======================================

#create miner socket
miner_soc = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
miner_soc.bind(("", MINER_PORT))
miner_soc.setblocking(False)
miner_soc.listen(5)
MINER_IP = socket.gethostbyname(socket.gethostname())
print("---------------------------------------------------------------------")
print(f"Miner Socket created {MINER_IP}:{MINER_PORT} - TCP")


#use threading to handle multiple miners
def handle_miner(miner_soc):
    """
    Accepts connections from miners.
    :param miner_soc: The miner socket.
    """
    while True:
        try:
            conn, addr = miner_soc.accept()
            receive_miner_msg(conn, addr)
        except socket.error as e:
            pass
        except json.JSONDecodeError as e:
            print("Error decoding JSON")
            # traceback.print_exc()
            print(e)
        except Exception as e:
            print(e)
            # traceback.print_exc()

def receive_miner_msg(conn, addr):
    """
    Reads messages from the miner connection.
    :param conn: Connection object.
    :param addr: Address tuple.
    """
    global old_message
    try:
        data = conn.recv(1024).decode()
        data = json.loads(data)
        print("---------------------------------------------------------------------")
        print(f"Received MINER message from {addr[0]}:{addr[1]}")
        print(data)

        miner_msg_type = data.get("type")
        if miner_msg_type == "STATS":
            max_height = max(blocks.keys())
            print(f"Height: {max_height + 1}")
            MinerStats(max_height + 1, blocks.get(max_height).get("hash")).send(conn)
            print(f"Sent STATS reply to miner - {addr[0]}:{addr[1]}")

        elif miner_msg_type == "MINED_BLOCK":
            Announce(data["height"], data["hash"], data["messages"], data["minedBy"], data["nonce"], data["timestamp"]).send(soc, track_peers)
            handle_announce(data)
        print("---------------------------------------------------------------------")
        

    except socket.error as e:
        pass
    except json.JSONDecodeError as e:
        print("Error decoding JSON")
        # traceback.print_exc()
        print(e)
    except Exception as e:
        print(e)
        # traceback.print_exc()
    finally:
        conn.close()



# =======================================
# MAIN LOOP
# ===========================================

#create a socket object
soc = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
soc.bind(("", MY_PORT))
soc.setblocking(False)
MY_IP = socket.gethostbyname(socket.gethostname())
print(f"Server Socket created {MY_IP}:{MY_PORT} - UDP")
print("---------------------------------------------------------------------\n")
last_gossip_time = 0
last_consensus_time = time.time() - (90 + 90 + 40 + 60) #after 20s
last_block_stat = 0
last_clear_check = time.time()


have_chain = False
start_time = time.time()

EXPIRY = 80


threading.Thread(target=handle_miner, args=(miner_soc,), daemon=True).start()

try:
    while True:

        #regossip every 60s seconds - 1 min
        if time.time() - last_gossip_time >= 60:
            id = str(uuid.uuid4())
            peers_replied.append(id)
            peer_list = track_peers.get_peers()
            peers_to_send = [WELL_KNOWN_PEER] + random.sample(peer_list[1:], min(2, len(peer_list) - 1))
            print("---------------------------------------------------------------------")
            for peer in peers_to_send:
                peer_addr = peer.get_addr()
                peer_name = peer.get_name()
                Gossip(MY_IP, MY_PORT, id, NAME).send(soc, peer_addr)
                print(f"Sent GOSSIP message to {peer_addr[0]}:{peer_addr[1]} - {peer_name}")
            last_gossip_time = time.time()
            print("---------------------------------------------------------------------")

        #clear peers every 80s
        if time.time() - last_clear_check >= EXPIRY:
            track_peers.clear(EXPIRY)
            last_clear_check = time.time()
            #print the list of peers
            print("---------------------------------------------------------------------")
            print("PEERS")
            for peer in track_peers.get_peers():
                print(f"{peer.ip}:{peer.port} - {peer.name}")
            print("---------------------------------------------------------------------")

        receive_message()

        if time.time() - last_consensus_time >= 300:
            stat = []
            max_height,can_reply,done_consensus = consensus()
            last_consensus_time = time.time()




        if time.time() - last_block_stat >= 60:
            print("---------------------------------------------------------------------")
            print(f"BLOCKS: {len(blocks)} of {max_height}")
            print("---------------------------------------------------------------------")
            last_block_stat = time.time()

    
except KeyboardInterrupt:
    print("Exiting...")

except Exception as e:
    print(e)
    # traceback.print_exc()

finally:
    soc.close()
    print("Socket closed")
