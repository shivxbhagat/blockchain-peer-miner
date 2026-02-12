NAME: Shiv Bhagat

## NOTES

Make sure to conver `peer.txt` to `peer.py` and `miner.txt` to `miner.py` before running the code.

The Peer (`peer.py`) acts as a decentralized node that maintains the blockchain state and handles all network communication. It uses UDP for peer-to-peer gossip and chain synchronization, ensuring all nodes reach consensus on the longest valid chain. It also opens a TCP server to listen for local miners, validating their work and broadcasting successful blocks to the rest of the network.

The Miner (`miner.py`) is a standalone worker script that performs the Proof-of-Work (PoW) algorithm. It continuously hashes block candidates with a changing nonce until it finds a hash with 8 leading zeros (the difficulty target). It periodically checks with the Peer to ensure it is mining on the latest block and submits valid blocks back to the Peer via TCP for propagation.

## Port Assignments - Aviary UNIX/LINUX servers at UofM

#### 8106: Miner Port

#### 8108: Peer Port

Blockchain Peer will connect with port 8108 for global peers and port 8106 for miner clients

```zsh
$python3 peer.py
```

commands after starting the server

- `ctrl + c` : quit the server

Miner client requires 1 args:

1. bird name of peer's connected host, eg: hawk

```zsh
$python3 miner.py hawk
```

commands after starting the miner

- `ctrl + c` : quit the miner

## Breakdown of Peer Code

### Joining

##### Send GOSSIP to join network. Repeat GOSSIP message every minute, sent to up to 3 of your known peers (send to fewer if you don't have 3 peers).

Line : 908
Initially I set time to time.time() to send the fist gossip in while loop
Peer sends gossip message every 60s. Well known peer - silicon is fixed. Other 2 are selected randomly from the list of available peers.

#### Reply to GOSSIP message with GOSSIP-REPLY

Line: 408 - check full function
Replies the GOSSIP mesage with GOSSIP-REPLY, iff the id mentioned in the peer is not available in the list of ids replied. Else it will igore the gossip message.

#### Clean up peers that have not sent GOSSIP messages (note to students: consider writing where and how you do this in your readme)

Line: Class PeerList - 278 and Period check - 924
Created Peer and PeerList class to make this work and use the classes for other purpose. Whenever a new peer is encountered it my peer will add the Peer to the PeerList. Whenever a new peer is added, it will add a timestamp to the Peer. Or if the peer already exists, it will update the timestamp.
My peer will check after every 80 seconds for removing peers that are inactive by calling PeerList.clear() function.

### Building chain

#### Collect blocks in a load-balanced and concurrent way (not one block at a time)

Line: loadbalance = 580, function = 556 (`fetch_blocks(chain)`)
My peer will ask for blocks in a roundrobin style. Will collect the blocks and after 1s it will check and ask remaining blocks. This process will take 60s - 60 trys and move to validating chain.

#### Verify entire chain

Line: function = 556 (`fetch_blocks(chain)`) and function = 680 (`verify_chain(chain)`)
Simple verification
Use `verify_chain` function to verify the chain. It will check the hash of the block, and also check the hash of the previous block, and also check the height of the block.

#### Add new block to top of chain on ANNOUNCE

Line: 771 = function `handle_announce`
My peer will validate the block first, if its valid, it will add to the top of the chain.

### Consensus

#### Send STATS to all known peers, collect results

Line: 490, 429 ....
My Peer will send stats to all available known peers, and collect the stats ! It will reject any hash < DIFF, in the process of collection

#### Choose longest chain (Ties break on which is the majority), or longest chain (ties break on majority). Write in README where this code is and 2 sentences on how it works- what data structure do you use, give an example.

Line: 525 (grouping) and 556 (selection)
The chain selection groups STATS replies into a nested dictionary `chains[height][hash] -> [peers]`, then converts that into a list of `StatChain` entries sorted by height descending in `group_chains()` and tried in order by `fetch_blocks()`. For example, if replies contain height 10 with hashes A and B and height 9 with hash C, it will attempt height 10 (A then B in insertion order), and only if those chains fail validation will it move on to height 9.

#### After fetching a valid chain become a peer - GET_BLOCK and STATS function

Line: 452-468
My Peer have `can_reply` varible which is initially set to false, it will not reply to GET_BLOCK , STATS and also will not handle ANNOUNCE, as my chain is not the longest chain, if handles the announce, it will automatically reject.

### Discussion

It takes around 1~2 min if the chain selected is the valid in the first try.
For example , there are 3 chains 2 invalid, and 2 of them have priority, and last priority as per height is of 3rd chain which is valid, it will take approximately 3~4 minutes to synchronize the chain.

Consensus Code
Initial Consensus and Periodic Consensus = 936
Force Consensus = 447

My asking for STATs and collecting them is part of consensus. As this process will only get triggered when consensus is triggered (forced or periodical). After collecting stats, it will group chains with StatChain Class and then sort the chain with height, hash, peers. I made separated StatChain class for this. If chain with max height will be priority, if tie breaks, then priority is set to max(count of peers). Line : 550 where sorting takes place
Then the code will ask for the blocks starting from 1st grouped chain to end, validing through out the process. Once Validated it will stop the process, and becomes the peer.
Consensus is done every 5 min. For re-consensus, it will copy blocks from the validated chain to a temporary chain, and collect remaining blocks and replace the original chain if validated.
If the peer with highest height did not reply to my stat request, it will get ignored and will probably get to that chain when the peer replies during further consensus rounds.

Cleaning up peers is done using Peer and PeerList Class after every 80s.

There is a `BAD_ACTORS`constant in `peer.py`, line: 340, to add bad actors that were send unusal messages and wrong stuff in getblock replies.
For example : adding '' in start and end of words. Like: 'test', where required is test.
Can remove or ports from the`BAD_ACTORS` constant.

Also I have used threads only for miners. Line: 903
`threading.Thread(target=handle_miner, args=(miner_soc,), daemon=True).start()`
where the target function is only for handle_miner()

I have mined few blocks, on silicon's network - Name : Shiv Bhagat. Only use miner when done consensus, to avoid failures.
There is no error check for this.
Miner will continuously bring stats every 30s to check if there is change in the height or messages
