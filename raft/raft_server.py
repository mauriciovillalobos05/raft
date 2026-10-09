import rpyc
from rpyc.utils.server import ThreadedServer
from raft.IRaftActions import IRaftActions
from raft.raft_structure import RaftStructure
from raft.raft_state import RaftState
import random
from raft.raft_websocket_manager import WebSocketManager
import asyncio
import concurrent.futures
import traceback
import datetime
import json
import threading
import time
from raft.vote_arguments import VoteArguments
from raft.health_check_arguments import HealthCheckArguments
from rpyc.utils.classic import obtain #To change the netref to dict


class Raft(IRaftActions):
    """A Raft node that implements `IRaftActions` and holds a `RaftStructure`.

    For now methods are placeholders; the structure is stored on
    `self.raft_terms` and exposed to tests via RPC methods.
    """
    def __init__(self, node_id, peers_config=None, logs_file_path="raft_logs.jsonl", state_machine_applier=None):
        # initialize raft structure with sensible defaults
        self._killed = False
        
        # ADDED: Thread safety lock for concurrent RPC access
        self.lock = threading.Lock()
        
        #ADDED: Websocker manager to sync it with the UI
        self.ws_manager = WebSocketManager.get_ws_manager()
            
        # ADDED: State machine applier (for applying committed log entries to KV store)
        self.state_machine_applier = state_machine_applier
        
        self.raft_terms: RaftStructure = RaftStructure(
            id=node_id,
            current_term=0,
            voted_for=-1,  # -1 means no vote cast in current term
            logs_file_path=logs_file_path,
            last_log_index=0,
            last_log_term=0,  # ADDED
            peers=peers_config if peers_config else {},
            state=RaftState.follower,
            logs=[],  # ADDED
            commit_index=-1,  # ADDED: Highest log index committed
            last_applied=-1   # ADDED: Highest log index applied to state machine
        )
        
        # Load persistent state from disk if it exists - what if the server has crashed and it has restarted
        self._load_persistent_state()
        
        #Recover in-memory state machine after loading persistent state
        self._recover_state_machine_from_log()
        
        # ADDED: For leader log tracking
        self.next_index = {}        # Index of next log entry to send to each peer
        self.match_index = {}       # Index of highest replicated log entry on each peer
    
        # Initialize for all peers
        for peer_id in (peers_config if peers_config else {}).keys():
            self.next_index[peer_id] = 0  # Start at my last log index
            self.match_index[peer_id] = -1
    
        # ADDED: Heartbeat timer thread
        self.heartbeat_timer_event = threading.Event()
        self.heartbeat_thread = threading.Thread(target=self._heartbeat_ticker, daemon=True)
        self.election_timer_event = threading.Event()
        self.timer_thread = threading.Thread(target=self._ticker, args=(), daemon=True)
        
        # ADDED: For leader election tracking
        self.vote_count = 0 #To calculate the peer count for leader election -> check it against the majority
        self.received_votes = {} # To track the peer id response for leader election
    
    """Start the election timer thread"""
    def start_raft_node(self):
        self.timer_thread.start()
        self.heartbeat_thread.start()
    
    def add_peer_connections(self, peers_config):
        """Set up peer connections after node initialization"""
        self.raft_terms.peers = peers_config
    
    def reset_election_timer(self):
        """
        Signals the ticker to stop sleeping/waiting immediately
        and restart the countdown.
        """
        # Setting the event interrupts the 'wait' call in the ticker() loop
        if self.raft_terms.state != RaftState.leader:
            self.election_timer_event.set()
    
    #Main method -> a thread is invoked and it is run as a daemon to check for the timeout
    #If the event set function is called within the time, then election timer is reset again
    #If the election timer is fired, then it initiates for the leader election voting
    def _ticker(self):
        
        while not self.killed():
            
            # 1. Clear the event flag for the next cycle
            self.election_timer_event.clear()
            
            # 2. Randomize the timeout duration for the next cycle
            # We must do this before we start waiting
            new_timeout_ms = random.uniform(5000, 10000)
            self.raft_terms.election_timer = new_timeout_ms / 1000.0 # To yield the new timeout in ms and not in seconds
            
            print(f"[Node {self.raft_terms.id}] Ticker waiting for up to {self.raft_terms.election_timer:.3f}s...")
            
            # 3. Wait using event.wait(timeout)
            # it returns TRUE if set() was called -> if the health check function is reached before the timeout then the set is invoked
            # by another thread, or FALSE if the timeout was reached naturally.
            heartbeat_received = self.election_timer_event.wait(timeout=self.raft_terms.election_timer)
            
            #Before asking for the vote check if the node is active
            #Checking the worst scenarios first
            if self.killed():
                break
            
            #Check if the leader invokes the health check up
            #If the events occurs then we have to again reset the timer for the election timeout
            if heartbeat_received:
                continue
            
             # ← ADD THIS CHECK: Don't start election if we're leader!
            with self.lock:
                if self.raft_terms.state == RaftState.leader:
                    continue  # ← Skip election, just loop again
            
            # Election timeout fired -> start leader election
            print(f"[Node {self.raft_terms.id}] Election timeout! Starting election...")
            self.request_vote()
    
    # -----------------------------
    # Append log entries
    # -----------------------------
    
    def append_log_entries(self, command):
        
        """
        PHASE 2: LOG REPLICATION - Client write request
        Raft Paper §5.3
        
        1. Only leader accepts writes
        2. Append to leader's log
        3. Replicate to followers (via send_health_checks)
        4. When majority replicates, advance commitIndex
        5. When commitIndex > lastApplied, apply to state machine
        """
        
        try:
            
            with self.lock:
                
                # Rule 1: Only leader accepts writes
                if self.raft_terms.state != RaftState.leader:
                    
                    return {
                        "success": False,
                        "error": "NOT_LEADER",
                        "leader_hint": self._get_current_leader_id(),
                        "message": f"Node {self.raft_terms.id} is not the leader"
                    }
                
                # Rule 2: Append to own log immediately
                log_entry = {
                    "term": self.raft_terms.current_term,
                    "command": str(command) if not isinstance(command, str) else command
                }

                self.raft_terms.logs.append(log_entry)
                log_index = len(self.raft_terms.logs) - 1  # Calculate index from position
                self.raft_terms.last_log_index = len(self.raft_terms.logs) - 1
                self.raft_terms.last_log_term = self.raft_terms.current_term
                self.match_index[self.raft_terms.id] = log_index
                self.next_index[self.raft_terms.id] = len(self.raft_terms.logs)
            
                # Rule 3: Persist to disk immediately (required by Raft)
                self._persist_log_entry(log_entry)
                
                print(f"[Node {self.raft_terms.id}] Leader appended log entry at index {log_index}: '{log_entry['command'][:50]}...'")
                
            try:
                # ← FIX: Get the loop from WebSocketManager (which has the running loop)
                loop = self.ws_manager.event_loop
                
                if loop is None:
                    print(f"[Node {self.raft_terms.id}] ERROR: WebSocketManager event_loop not initialized!")
                    return
                
                if not loop.is_running():
                    print(f"[Node {self.raft_terms.id}] ERROR: Event loop is not running!")
                    return
                
                # Now schedule the coroutine on the running loop
                asyncio.run_coroutine_threadsafe(
                    self.ws_manager.broadcast_log_entry(
                        node_id=self.raft_terms.id,
                        log_entry=log_entry["command"],
                        log_index=self.raft_terms.last_log_index,
                    ),
                    loop,
                )
                
                # Rule 4: Return to client
                # Client can:
                # - Poll to check if committed
                # - Or just wait (entries will be replicated in background)
                return {
                    "success": True,
                    "index": log_index,
                    "term": self.raft_terms.current_term,
                    "message": "Appended to leader log, waiting for replication"
                }
        
            except Exception as e:
                print(f"[Node {self.raft_terms.id}] WebSocket broadcast error: {e}")
                traceback.print_exc()  # Print full traceback for debugging
                return {
                    "success": False,
                    "error": "WEBSOCKET_ERROR",
                    "message": str(e)
                }
                
        except Exception as e:
            print(f"[Node {self.raft_terms.id}] Error appending log entry: {e}")
            return {
                "success": False,
                "error": "INTERNAL_ERROR",
                "message": str(e)
            }
    
    def _persist_log_entry(self, log_entry):
        """Persist a single log entry to the LOG file (append-only)"""
        try:
            # Calculate index from current log length
            log_index = len(self.raft_terms.logs) - 1
            
            # Write to SEPARATE log file
            with open(self.raft_terms.logs_file_path, 'a') as f:
                entry = {
                    "index": log_index,
                    "term": log_entry["term"],
                    "command": log_entry["command"]
                }
                f.write(json.dumps(entry) + '\n')  # Add newline for readability
                
        except Exception as e:
            print(f"[Node {self.raft_terms.id}] Error persisting log entry: {e}")
        
    def read_log(self, index):
        
        """
        PHASE 2: LOG REPLICATION - Client read request
        Raft Paper §5.3
        
        - Leaders can read from uncommitted logs (linearizable reads)
        - Followers must read from committed logs only (for consistency)
        
        Returns:
            dict: {
                "success": bool,
                "entry": dict (if found),
                "committed": bool (if entry is committed),
                "error": str (if not found)
            }
        """
        
        with self.lock:
            
            # Check if index exists in logs
            if index < 0 or index >= len(self.raft_terms.logs):
                return {
                    "success": False,
                    "error": "INDEX_OUT_OF_RANGE",
                    "message": f"Index {index} not found in logs"
                }
            
            log_entry = self.raft_terms.logs[index]
            is_committed = index <= self.raft_terms.commit_index
            
            # Follower rule: Only return committed entries
            if self.raft_terms.state != RaftState.leader and not is_committed:
                return {
                    "success": False,
                    "error": "NOT_COMMITTED",
                    "message": f"Entry at index {index} is not yet committed"
                }
            
            # Return the log entry
            return {
                "success": True,
                "entry": log_entry,
                "committed": is_committed,
                "index": index
            }
    
    def get_leader_info(self):
        """Get current leader information for client routing."""
        with self.lock:
            return {
                "node_id": self.raft_terms.id,
                "state": self.raft_terms.state.name,
                "term": self.raft_terms.current_term,
                "leader_id": self._get_current_leader_id()
            }
    
    def _get_current_leader_id(self):
        """Get the current leader's ID (if known)."""
        # In RAFT, followers don't explicitly track the leader
        # But we can infer it from recent heartbeats
        # For now, return None if we're not the leader
        if self.raft_terms.state == RaftState.leader:
            return self.raft_terms.id
        return None
    
    # -----------------------------
    # Phase 1: Leader Election
    # -----------------------------
    
    def request_vote(self):
        
        """
        PHASE 1: LEADER ELECTION - RequestVote RPC sender
        Raft Paper §5.2
        
        Executed when election timeout fires:
        1. Increment currentTerm
        2. Transition to CANDIDATE
        3. Vote for self
        4. Send RequestVote RPCs to all peers in PARALLEL
        5. If majority votes: become LEADER
        6. If discover higher term or another leader: become FOLLOWER
        """
        
        with self.lock:
            # Step 1: Increment term
            self.raft_terms.current_term += 1
            
            # Step 2: Become candidate
            self.raft_terms.state = RaftState.candidate
            
            # Step 3: Vote for self
            self.raft_terms.voted_for = self.raft_terms.id
            self.vote_count = 1
            self.received_votes = {self.raft_terms.id: True}
            
            print(f"[Node {self.raft_terms.id}] Starting election for term {self.raft_terms.current_term}")
            
            # Step 4: Persist state BEFORE sending RPCs
            self._persist_state()
            
            #Reset election timer when becoming candidate
            self.reset_election_timer()
        
            # Prepare RequestVote arguments
            vote_arguments = VoteArguments(
                candidate_id=self.raft_terms.id,
                current_term=self.raft_terms.current_term,
                last_log_index=self.raft_terms.last_log_index,
                last_log_term=self.raft_terms.last_log_term
            )
            
            # Get peers snapshot
            peers = dict(self.raft_terms.peers)
        
        try:
            # ← FIX: Get the loop from WebSocketManager (which has the running loop)
            loop = self.ws_manager.event_loop
            
            if loop is None:
                print(f"[Node {self.raft_terms.id}] ERROR: WebSocketManager event_loop not initialized!")
                return
            
            if not loop.is_running():
                print(f"[Node {self.raft_terms.id}] ERROR: Event loop is not running!")
                return
            
            # Now schedule the coroutine on the running loop
            asyncio.run_coroutine_threadsafe(
                self.ws_manager.broadcast_vote_request(
                    node_id=self.raft_terms.id,
                    current_term=self.raft_terms.current_term,
                    last_log_index=self.raft_terms.last_log_index,
                    last_log_term=self.raft_terms.last_log_term,
                ),
                loop,
            )
            
        except Exception as e:
            print(f"[Node {self.raft_terms.id}] WebSocket broadcast error: {e}")
            traceback.print_exc()  # Print full traceback for debugging
    
        # Step 5: Send RequestVote RPCs in PARALLEL
        with concurrent.futures.ThreadPoolExecutor(max_workers=len(peers)) as executor:
            futures = []
            for peer_id, peer_value in peers.items():
                if peer_id == self.raft_terms.id:
                    continue
                
                future = executor.submit(self._send_vote_request_to_peer, peer_id, peer_value, vote_arguments)
                futures.append(future)
            
            concurrent.futures.wait(futures)
    
        # Step 6: Count votes AFTER all threads finish
        won_election = False  # ← Flag
        
        with self.lock:
            total_servers = len(self.raft_terms.peers) + 1
            majority = (total_servers // 2) + 1
            
            print(f"[Node {self.raft_terms.id}] Election result: {self.vote_count}/{total_servers} votes (need {majority})")
            
            # Step 7: Check if we won
            if self.vote_count >= majority and self.raft_terms.state == RaftState.candidate:
                print(f"[Node {self.raft_terms.id}] WON ELECTION for term {self.raft_terms.current_term}!")
                
                self.raft_terms.state = RaftState.leader
                self._persist_state()
                
                # Initialize leader state
                for peer_id in self.raft_terms.peers.keys():
                    if peer_id != self.raft_terms.id:
                        self.next_index[peer_id] = len(self.raft_terms.logs)
                        self.match_index[peer_id] = -1
                
                # Initialize OWN matchIndex
                self.match_index[self.raft_terms.id] = len(self.raft_terms.logs) - 1
                
                won_election = True  # ← Set flag

        # Broadcast that entries are now committed to the followers
        try:
            loop = self.ws_manager.event_loop
            if loop and loop.is_running():
                asyncio.run_coroutine_threadsafe(
                    self.ws_manager.broadcast_election_result(
                        node_id=self.raft_terms.id,
                        election_result=won_election,
                        voted_by=list(self.received_votes.keys()),
                        current_term = self.raft_terms.current_term,
                        last_log_index= vote_arguments.last_log_index,
                        last_log_term = vote_arguments.last_log_term,
                    ),
                    loop,
                )
        except Exception as e:
            print(f"[Node {self.raft_terms.id}] Error broadcasting: {e}")
            
        # Step 8: Send immediate heartbeat OUTSIDE the lock
        if won_election:
            print(f"[Node {self.raft_terms.id}] Sending immediate heartbeat to establish leadership")
            self.send_health_checks()
    
    def handle_request_vote(self, vote_arguments: VoteArguments):
        
        """
        PHASE 1: LEADER ELECTION - RequestVote RPC receiver
        Raft Paper §5.2, §5.4
        
        Called when another node requests our vote
        Decision rules:
        1. Reject if candidate's term < currentTerm
        2. If candidate's term > currentTerm: update term, become follower
        3. Grant vote if:
            - Haven't voted in this term OR already voted for this candidate
            - Candidate's log is at least as up-to-date as receiver's log
        """
        
        with self.lock:
            
            print(f"[Node {self.raft_terms.id}] Received RequestVote from Node {vote_arguments.candidate_id} (term {vote_arguments.current_term})")
            
            # Rule 1: Reject stale term
            if vote_arguments.current_term < self.raft_terms.current_term:
                print(f"[Node {self.raft_terms.id}] Rejected (stale term)")
                return False
            
            # Rule 2: If RPC term > currentTerm: update term and become follower
            if vote_arguments.current_term > self.raft_terms.current_term:
                print(f"[Node {self.raft_terms.id}] Higher term detected, updating to {vote_arguments.current_term}")
                self.raft_terms.current_term = vote_arguments.current_term
                self.raft_terms.state = RaftState.follower
                self.raft_terms.voted_for = -1  # Clear vote in new term
            
            # Rule 3: Check if we can grant vote
            can_vote = (
                self.raft_terms.voted_for == -1 or 
                self.raft_terms.voted_for == vote_arguments.candidate_id
            )
            
            # Rule 4: Check if candidate's log is up-to-date (§5.4.1)
            log_is_current = self._is_log_up_to_date(
                vote_arguments.last_log_term,
                vote_arguments.last_log_index
            )
            
            # Grant vote if both conditions met
            if can_vote and log_is_current:
                self.raft_terms.voted_for = vote_arguments.candidate_id
                self._persist_state()  # Persist vote before responding
                self.reset_election_timer()  # Reset our own election timeout
                print(f"[Node {self.raft_terms.id}] GRANTED vote to Node {vote_arguments.candidate_id} for term {vote_arguments.current_term}")
                
                # Broadcast vote response from followers to leader
                try:
                    loop = self.ws_manager.event_loop
                    if loop and loop.is_running():
                        asyncio.run_coroutine_threadsafe(
                            self.ws_manager.broadcast_vote_response(
                                node_id=self.raft_terms.id,
                                voted_for = vote_arguments.candidate_id,
                                current_term = self.raft_terms.current_term,
                                last_log_index= vote_arguments.last_log_index,
                                last_log_term = vote_arguments.last_log_term,
                            ),
                            loop,
                        )
                except Exception as e:
                    print(f"[Node {self.raft_terms.id}] Error broadcasting: {e}")
                    
                return True
            else:
                print(f"[Node {self.raft_terms.id}] REJECTED vote from Node {vote_arguments.candidate_id} (can_vote={can_vote}, log_current={log_is_current})")
                
                # Broadcast vote response from followers to leader
                try:
                    loop = self.ws_manager.event_loop
                    if loop and loop.is_running():
                        asyncio.run_coroutine_threadsafe(
                            self.ws_manager.broadcast_vote_response(
                                node_id=self.raft_terms.id,
                                voted_for = -1,
                                current_term = self.raft_terms.current_term,
                                last_log_index= vote_arguments.last_log_index,
                                last_log_term = vote_arguments.last_log_term,
                            ),
                            loop,
                        )
                except Exception as e:
                    print(f"[Node {self.raft_terms.id}] Error broadcasting: {e}")
                    
                return False
    
    # -----------------------------
    # Phase 2: Log Replication
    # -----------------------------
    
    def _heartbeat_ticker(self):
        
        """
        PHASE 2: LOG REPLICATION - Heartbeat loop (leader only)
        Raft Paper §5.2
        
        Leader sends periodic heartbeats (AppendEntries with no entries)
        to maintain authority and prevent elections
        
        Frequency: 100ms (much less than election timeout of 300-500ms)
        """
        
        while not self.killed():
            
            # Only leader sends heartbeats
            with self.lock:
                is_leader = (self.raft_terms.state == RaftState.leader)
            
            if is_leader:
                self.send_health_checks()
            
            # Wait 3 seconds before next heartbeat
            # This is MUCH shorter than election timeout
            # to prevent followers from timing out
            self.heartbeat_timer_event.wait(timeout=3)
    
    def send_health_checks(self):
        
        """
        PHASE 2: LOG REPLICATION - AppendEntries RPC sender
        Raft Paper §5.3
        
        Leader sends AppendEntries RPCs to all followers:
        - If no new entries: heartbeat (prevents election)
        - If new entries: replication (with consistency check)
        
        For each follower:
        1. Prepare entries starting from nextIndex[follower]
        2. Include prevLogIndex/prevLogTerm for consistency check
        3. Send RPC in parallel
        4. On success: update matchIndex, try to advance commitIndex
        5. On failure: decrement nextIndex and retry
        """
        with self.lock:
            
            # Only leader sends AppendEntries
            if self.raft_terms.state != RaftState.leader:
                return
            
            # ADDED: Collect followers list for WebSocket broadcast
            followers = [peer_id for peer_id in self.raft_terms.peers.keys() if peer_id != self.raft_terms.id]
            
            peers = dict(self.raft_terms.peers)
        
        try:
            # ← FIX: Get the loop from WebSocketManager (which has the running loop)
            loop = self.ws_manager.event_loop
            
            if loop is None:
                print(f"[Node {self.raft_terms.id}] ERROR: WebSocketManager event_loop not initialized!")
                return
            
            if not loop.is_running():
                print(f"[Node {self.raft_terms.id}] ERROR: Event loop is not running!")
                return
            
            # Now schedule the coroutine on the running loop
            asyncio.run_coroutine_threadsafe(
                self.ws_manager.broadcast_heartbeat(
                    leader_id=self.raft_terms.id,
                    current_term=self.raft_terms.current_term,
                    last_log_index=self.raft_terms.last_log_index,
                    last_log_term=self.raft_terms.last_log_term,
                    followers=followers,
                    peer_responses={},
                ),
                loop,
            )
            
        except Exception as e:
            print(f"[Node {self.raft_terms.id}] WebSocket broadcast error: {e}")
            traceback.print_exc()  # Print full traceback for debugging
            
        # Send to all peers IN PARALLEL
        with concurrent.futures.ThreadPoolExecutor(max_workers=len(peers)) as executor:
            for peer_id, peer_value in peers.items():
                if peer_id == self.raft_terms.id:
                    continue
                
                # Submit heartbeat task
                executor.submit(self._send_health_check_to_peer, peer_id, peer_value)
    
    def handle_health_check_request(self, health_check_arguments: HealthCheckArguments):
        
        """
        PHASE 2: LOG REPLICATION - AppendEntries RPC receiver
        Raft Paper §5.3
        
        Called when leader (or candidate) sends AppendEntries
        
        Consistency check:
        1. Reject if term < currentTerm
        2. If term >= currentTerm: reset election timer, become follower
        3. Check if log contains entry at prevLogIndex with prevLogTerm
        4. If match: append new entries, update commitIndex
        5. If no match: return failure (leader will decrement nextIndex)
        """
        
        with self.lock:
            
            print(f"[Node {self.raft_terms.id}] Received AppendEntries from Node {health_check_arguments.leader_id} (term {health_check_arguments.current_term})")
            
            # Rule 1: Reject stale term
            if health_check_arguments.current_term < self.raft_terms.current_term:
                return {"success": False, "term": self.raft_terms.current_term}
            
            # Rule 2: Valid leader discovered -> reset timer and become follower
            if health_check_arguments.current_term >= self.raft_terms.current_term:
                self.raft_terms.current_term = health_check_arguments.current_term
                self.raft_terms.state = RaftState.follower
                self._persist_state()
                self.reset_election_timer()
            
            # Rule 3: Log consistency check
            # Check if we have an entry at prevLogIndex matching prevLogTerm
            if health_check_arguments.prev_log_index >= 0:
                # prevLogIndex is -1 for first entry
                if health_check_arguments.prev_log_index >= len(self.raft_terms.logs):
                    # We're missing entries
                    print(f"[Node {self.raft_terms.id}] Log too short (have {len(self.raft_terms.logs)}, need {health_check_arguments.prev_log_index + 1})")
                    return {"success": False, "term": self.raft_terms.current_term}
                
                prev_entry_local = obtain(self.raft_terms.logs[health_check_arguments.prev_log_index])
                prev_term = int(prev_entry_local["term"])
                
                if prev_term != health_check_arguments.prev_log_term:
                    # Term mismatch -> delete conflicting entry and all that follow
                    print(f"[Node {self.raft_terms.id}] Log conflict at index {health_check_arguments.prev_log_index}")
                    self.raft_terms.logs = self.raft_terms.logs[:health_check_arguments.prev_log_index]
                    self._truncate_log_file(health_check_arguments.prev_log_index)
                    return {"success": False, "term": self.raft_terms.current_term}
            
            # Rule 4: Append new entries (if any)
            if health_check_arguments.entries:
                # Delete any conflicting entries and append new ones
                insert_index = health_check_arguments.prev_log_index + 1
                self.raft_terms.logs = self.raft_terms.logs[:insert_index]
                self._truncate_log_file(insert_index)  
                
                for i, entry_ref in enumerate(health_check_arguments.entries):
                    if isinstance(entry_ref, dict):
                        plain_entry = entry_ref
                    else:
                        plain_entry = obtain(entry_ref)
            
                    clean_entry = {
                        "term": int(plain_entry["term"]),
                        "command": str(plain_entry["command"])
                    }
                    self.raft_terms.logs.append(clean_entry)
                    
                    #Persist to disk immediately (RAFT requirement)
                    self._persist_log_entry(clean_entry)
                    
                    # Calculate the log index for this entry
                    log_idx = health_check_arguments.prev_log_index + i + 1
                    
                    # Broadcast immediately (so UI shows entry as soon as appended) -> followers
                    try:
                        loop = self.ws_manager.event_loop
                        if loop and loop.is_running():
                            asyncio.run_coroutine_threadsafe(
                                self.ws_manager.broadcast_log_entry(
                                    node_id=self.raft_terms.id,
                                    log_entry=clean_entry["command"],
                                    log_index=log_idx,
                                ),
                                loop,
                            )
                    except Exception as e:
                        print(f"[Node {self.raft_terms.id}] Broadcast error: {e}")
                
                # Update metadata
                if self.raft_terms.logs:
                    self.raft_terms.last_log_index = len(self.raft_terms.logs) - 1
                    self.raft_terms.last_log_term = self.raft_terms.logs[-1]["term"]
                
                print(f"[Node {self.raft_terms.id}] Follower appended {len(health_check_arguments.entries)} entries (now have {len(self.raft_terms.logs)} total)")
            
            # Rule 5: Update commitIndex
            if health_check_arguments.leader_commit > self.raft_terms.commit_index:
                old_commit = self.raft_terms.commit_index
                self.raft_terms.commit_index = min(
                    health_check_arguments.leader_commit,
                    len(self.raft_terms.logs) - 1
                )
                self._persist_state()
                
                # Broadcast that entries are now committed to the followers
                try:
                    loop = self.ws_manager.event_loop
                    if loop and loop.is_running():
                        asyncio.run_coroutine_threadsafe(
                            self.ws_manager.broadcast_entries_committed(
                                node_id=self.raft_terms.id,
                                committed_until_index= self.raft_terms.commit_index,
                                current_term=self.raft_terms.current_term,
                            ),
                            loop,
                        )
                except Exception as e:
                    print(f"[Node {self.raft_terms.id}] Error broadcasting: {e}")
                    
                print(f"[Node {self.raft_terms.id}] Updated commitIndex: {old_commit} -> {self.raft_terms.commit_index}")
                # Apply newly committed entries to state machine
                self._apply_committed_entries()
            
            return {"success": True, "term": self.raft_terms.current_term}
    
    def _apply_committed_entries(self):
        """
        Apply all committed but not yet applied log entries to state machine.
        Called when commitIndex > lastApplied
        """
        while self.raft_terms.last_applied < self.raft_terms.commit_index:
            self.raft_terms.last_applied += 1
            log_entry = self.raft_terms.logs[self.raft_terms.last_applied]
            
            print(f"[Node {self.raft_terms.id}] Applying entry {self.raft_terms.last_applied} to state machine: '{log_entry['command'][:50]}...'")
            
            # Apply to state machine using the applier
            if self.state_machine_applier:
                try:
                    result = self.state_machine_applier.apply(log_entry["command"])
                    
                    # Broadcast that entry was applied
                    try:
                        loop = self.ws_manager.event_loop
                        if loop and loop.is_running():
                            asyncio.run_coroutine_threadsafe(
                                self.ws_manager.broadcast_kv_store_update(
                                    node_id=self.raft_terms.id,
                                    log_index=self.raft_terms.last_applied,
                                    log_entry=log_entry,
                                    result=result,
                                ),
                                loop,
                            )
                    except Exception as e:
                        print(f"[Node {self.raft_terms.id}] Error broadcasting: {e}")
                    
                except Exception as e:
                    print(f"[Node {self.raft_terms.id}] Error applying to state machine: {e}")
    
    def _send_health_check_to_peer(self, peer_id, peer_value):
        """Send AppendEntries RPC to a single peer (NO CALLBACK)"""
        conn = None
        try:
            time.sleep(6)
            with self.lock:
                #check if the node is still the leader before sending the heartbeat
                if self.raft_terms.state != RaftState.leader:
                    return
                # Prepare entries to send (from nextIndex[peer] onwards)
                next_idx = self.next_index[peer_id]
                prev_log_index = next_idx - 1
                prev_log_term = 0
                
                if prev_log_index >= 0 and prev_log_index < len(self.raft_terms.logs):
                    prev_entry = self.raft_terms.logs[prev_log_index]
                    prev_log_term = int(prev_entry["term"])
                
                # Get entries from nextIndex onwards (empty list for heartbeat)
                entries = []
                if next_idx < len(self.raft_terms.logs):
                    entries = [self.raft_terms.logs[next_idx]]
                
                # Prepare RPC arguments
                health_check_args = HealthCheckArguments(
                    current_term=self.raft_terms.current_term,
                    leader_id=self.raft_terms.id,
                    prev_log_index=prev_log_index,
                    prev_log_term=prev_log_term,
                    entries=entries,
                    leader_commit=self.raft_terms.commit_index
                )
            
            conn = rpyc.connect(
                peer_value["host"],
                peer_value["port"],
                config={"allow_public_attrs": True, "instantiate_remote_objects": True}
            )

            result = conn.root.exposed_send_health_check_request(health_check_args)
            
            # after getting `result`:
            try:
                success = result['success'] if result and result['success'] else False
                loop = self.ws_manager.event_loop
                
                if loop and loop.is_running():
                    asyncio.run_coroutine_threadsafe(
                        self.ws_manager.broadcast_peer_response(
                        leader_id=self.raft_terms.id,
                        peer_id=peer_id,
                        success=success,
                        result=result,
                        ),
                        loop,
                    )
            except Exception as e:
                print(f"[Node {self.raft_terms.id}] WebSocket peer response broadcast error: {e}")
            
            with self.lock:
                
                if result is None:
                    return

                if result['term'] > self.raft_terms.current_term:
                    self.raft_terms.current_term = result["term"]
                    self.raft_terms.state = RaftState.follower
                    self.raft_terms.voted_for = -1
                    return 

                # If success=False: follower's log doesn't match
                if not result['success']:
                    # Decrement nextIndex[peer] and retry next time
                    if self.next_index[peer_id] > 0:
                        self.next_index[peer_id] -= 1
                        print(f"[Node {self.raft_terms.id}] Log mismatch with Node {peer_id}, decrementing nextIndex to {self.next_index[peer_id]}")

                    return

                # If success=True: follower accepted the entries
                # Update matchIndex and nextIndex for this peer
                
                if len(health_check_args.entries) > 0:
                    new_match_index = health_check_args.prev_log_index + len(health_check_args.entries)
                    self.match_index[peer_id] = new_match_index
                    self.next_index[peer_id] = new_match_index + 1
                
                    print(f"[Node {self.raft_terms.id}] Node {peer_id} replicated entries up to index {new_match_index}")
                
                    # Check if we can advance commitIndex
                    # commitIndex = highest index replicated on majority
                    self._try_advance_commit_index()
                
                else:
                    if not entries:
                        print(
                            f"HEARTBEAT leader={self.raft_terms.id} "
                            f"follower={peer_id} "
                            f"time={time.monotonic():.9f}"
                            f"Raft State = {self.raft_terms.state.name}"
                        )
                    # Just a heartbeat, no new entries sent
                    # Don't update matchIndex/nextIndex
                    pass
            
        except Exception as e:
            # Peer is down or unreachable - do nothing
            # Retry happens on next heartbeat cycle (100ms later)
            print(f"[Node {self.raft_terms.id}] Heartbeat to Node {peer_id} failed: {e}")
        finally:
            if conn:
                try:
                    conn.close()
                except:
                    pass
                
    def _truncate_log_file(self, keep_up_to_index):
        """
        Truncate log file to only keep entries [0, keep_up_to_index)
        
        Args:
            keep_up_to_index: Keep entries from index 0 to keep_up_to_index-1
                            (e.g., keep_up_to_index=2 keeps entries 0,1)
        """
        try:
            log_file = self.raft_terms.logs_file_path
            
            # Read all existing entries
            existing_entries = []
            try:
                with open(log_file, 'r') as f:
                    for line in f:
                        line = line.strip()
                        if line:
                            existing_entries.append(line)
            except FileNotFoundError:
                # No file yet, nothing to truncate
                return
            
            # Keep only entries up to keep_up_to_index
            entries_to_keep = existing_entries[:keep_up_to_index]
            
            # Rewrite file with only kept entries
            with open(log_file, 'w') as f:
                for entry_line in entries_to_keep:
                    f.write(entry_line + '\n')
            
            print(f"[Node {self.raft_terms.id}] Truncated log file to {keep_up_to_index} entries")
            
        except Exception as e:
            print(f"[Node {self.raft_terms.id}] Error truncating log file: {e}")
    
    def _try_advance_commit_index(self):
        
        """
        LEADER ONLY: Check if we can advance commitIndex
        commitIndex = highest index replicated on majority of servers
        Raft Paper §5.3
        """
        
        if self.raft_terms.state != RaftState.leader:
            return

        # Count how many servers have replicated each log index
        # Start from the end of the log and work backwards
        for index in range(len(self.raft_terms.logs) - 1, self.raft_terms.commit_index, -1):
            
            replicated_count = 1 # Count self
            
            for peer_id in self.raft_terms.peers.keys():
                if peer_id == self.raft_terms.id:
                    continue
                    
                if self.match_index.get(peer_id, 0) >= index:
                    replicated_count += 1
            
            #  FIX: Include self in total_servers calculation
            total_servers = len(self.raft_terms.peers) + 1  # +1 for self
            majority = (total_servers // 2) + 1
            
            # Only commit entries from current term (§5.4.2)
            if replicated_count >= majority and self.raft_terms.logs[index].get("term") == self.raft_terms.current_term:
                old_commit = self.raft_terms.commit_index
                self.raft_terms.commit_index = index
                
                # Broadcast that entries are now committed
                try:
                    loop = self.ws_manager.event_loop
                    if loop and loop.is_running():
                        asyncio.run_coroutine_threadsafe(
                            self.ws_manager.broadcast_entries_committed(
                                node_id=self.raft_terms.id,
                                committed_until_index=index,
                                current_term=self.raft_terms.current_term,
                            ),
                            loop,
                        )
                except Exception as e:
                    print(f"[Node {self.raft_terms.id}] Error broadcasting: {e}")
                    
                print(f"[Node {self.raft_terms.id}] Advanced commitIndex: {old_commit} -> {index} (replicated on {replicated_count}/{total_servers} servers)")
            
                # Apply newly committed entries
                self._apply_committed_entries()
                
                # Persist state change
                self._persist_state()
                
                break
            
            
    def _send_vote_request_to_peer(self, peer_id, peer_value, vote_arguments):
        """Send RequestVote RPC to a peer (NO CALLBACK)"""
        conn = None
        try:
            print(f"[Node {self.raft_terms.id}] Sending RequestVote to Node {peer_id}")
            
            conn = rpyc.connect(
                peer_value["host"],
                peer_value["port"],
                config={"allow_public_attrs": True, "instantiate_remote_objects": True}
            )
            result = conn.root.exposed_send_vote_request(vote_arguments)
            
            print(f"[Node {self.raft_terms.id}] RPC to Node {peer_id}: {result}")
            
            # Update vote count if granted
            if result:
                with self.lock:
                    self.vote_count += 1
                    self.received_votes[peer_id] = True
        
        except Exception as e:
            print(f"[Node {self.raft_terms.id}] RPC to Node {peer_id} failed: {e}")
        finally:
            if conn:
                try:
                    conn.close()
                except:
                    pass
    
    def _is_log_up_to_date(self, candidate_last_term: int, candidate_last_index: int) -> bool:
        """
        ADDED: Check if candidate's log is at least as up-to-date as receiver's log
        Raft Paper §5.4.1: Comparing logs by (lastLogTerm, lastLogIndex)
        """
        receiver_last_term = self.raft_terms.last_log_term
        receiver_last_index = self.raft_terms.last_log_index
        
        # If last terms differ, higher term is more up-to-date
        if candidate_last_term != receiver_last_term:
            return candidate_last_term > receiver_last_term
        
        # If last terms are same, higher index is more up-to-date
        return candidate_last_index >= receiver_last_index
    
    def _persist_state(self):
        """
        Persist currentTerm and votedFor to disk before responding to RPCs
        Raft Paper: "Persistent state (updated on stable storage before responding to RPCs)"
        
        Simple append-only log format (one JSON object per line) -> id, current_term, voted_for
        """
        try:
            state_file = f"raft_node_{self.raft_terms.id}_state.json"
            state = {
                "node_id": self.raft_terms.id,
                "current_term": self.raft_terms.current_term,
                "voted_for": self.raft_terms.voted_for,
                "commit_index": self.raft_terms.commit_index,
                "last_applied": self.raft_terms.last_applied
            }
        
            # Overwrite entire state file
            with open(state_file, 'w') as f:
                json.dump(state, f, indent=2)
        
        except Exception as e:
            print(f"[Node {self.raft_terms.id}] Error persisting state: {e}")
    
    def _recover_state_machine_from_log(self):
        """
        RECOVERY METHOD: Called during startup to rebuild in-memory state machine
        by replaying all committed entries from the persistent log.
        
        This ensures that after a node crash/restart, the KV store is populated
        with all data that was committed before the crash.
        
        Raft Paper: State machine is deterministic, so replaying the same entries
        in the same order always produces the same state.
        """
        
        with self.lock:
            print(f"[Node {self.raft_terms.id}] Rebuilding state machine from committed log entries...")
            print(f"[Node {self.raft_terms.id}] Loaded state: commit_index={self.raft_terms.commit_index}, last_applied={self.raft_terms.last_applied}")
            
            # Safety check: commit_index should never be less than last_applied
            if self.raft_terms.commit_index < self.raft_terms.last_applied:
                print(f"[Node {self.raft_terms.id}] WARN: commit_index < last_applied (corruption?)")
                self.raft_terms.last_applied = self.raft_terms.commit_index
            
            # Replay all committed entries
            entries_replayed = 0
            
            # Don't skip any - the in-memory state machine is empty and needs to be rebuilt
            # The last_applied value from disk is just metadata; we need to rebuild the state machine
            
            for index in range(0, self.raft_terms.commit_index + 1):
                # Bounds check
                if index >= len(self.raft_terms.logs):
                    print(f"[Node {self.raft_terms.id}] WARN: commit_index ({self.raft_terms.commit_index}) exceeds log length ({len(self.raft_terms.logs)})")
                    break
                
                log_entry = self.raft_terms.logs[index]
                
                # Apply this entry to state machine
                # We must rebuild the entire state machine
                if self.state_machine_applier and log_entry and "command" in log_entry:
                    try:
                        self.state_machine_applier.apply(log_entry["command"])
                        self.raft_terms.last_applied = index
                        entries_replayed += 1
                        
                        print(f"[Node {self.raft_terms.id}] Replayed entry {index}: {log_entry['command'][:60]}...")
                        
                    except Exception as e:
                        print(f"[Node {self.raft_terms.id}] Error replaying entry {index}: {e}")
                        import traceback
                        traceback.print_exc()
            
            print(f"[Node {self.raft_terms.id}] Recovery complete: {entries_replayed} entries replayed")
            print(f"[Node {self.raft_terms.id}] State machine state: last_applied={self.raft_terms.last_applied}, commit_index={self.raft_terms.commit_index}")
                    
    def _load_persistent_state(self):
        """
        Load persistent state from TWO separate files:
        1. State file: current_term, voted_for, commit_index, last_applied
        2. Log file: all log entries (append-only)
        """
        
        # ===== PART 1: Load STATE file =====
        state_file = f"raft_node_{self.raft_terms.id}_state.json"
        
        try:
            with open(state_file, 'r') as f:
                state = json.load(f)
                self.raft_terms.current_term = state.get('current_term', 0)
                self.raft_terms.voted_for = state.get('voted_for', -1)
                self.raft_terms.commit_index = state.get('commit_index', -1)
                self.raft_terms.last_applied = state.get('last_applied', -1)
                
                print(f"[Node {self.raft_terms.id}] ✅ Recovered state: term={self.raft_terms.current_term}, voted_for={self.raft_terms.voted_for}")
                
        except FileNotFoundError:
            print(f"[Node {self.raft_terms.id}] No state file found, starting fresh (term=0)")
            
        except Exception as e:
            print(f"[Node {self.raft_terms.id}] ❌ Error loading state: {e}")
        
        
        # ===== PART 2: Load LOG file =====
        log_file = self.raft_terms.logs_file_path  # e.g., raft_node_A_log.jsonl
        
        try:
            with open(log_file, 'r') as f:
                self.raft_terms.logs = []  # Clear existing logs
                
                for line_num, line in enumerate(f):
                    line = line.strip()
                    if not line:
                        continue  # Skip empty lines
                    
                    try:
                        entry = json.loads(line)
                        
                        # Reconstruct log entry as plain dict (not netref)
                        log_entry = {
                            "term": int(entry["term"]),
                            "command": str(entry["command"])
                        }
                        
                        self.raft_terms.logs.append(log_entry)
                        
                    except json.JSONDecodeError as e:
                        print(f"[Node {self.raft_terms.id}] ⚠️  Skipping corrupted log line {line_num}: {e}")
                        continue
                
                # Update metadata after loading all logs
                if self.raft_terms.logs:
                    self.raft_terms.last_log_index = len(self.raft_terms.logs) - 1
                    self.raft_terms.last_log_term = self.raft_terms.logs[-1]["term"]
                    print(f"[Node {self.raft_terms.id}] ✅ Recovered {len(self.raft_terms.logs)} log entries (last_index={self.raft_terms.last_log_index})")
                else:
                    self.raft_terms.last_log_index = -1
                    self.raft_terms.last_log_term = 0
                    print(f"[Node {self.raft_terms.id}] No log entries found")
                    
        except FileNotFoundError:
            print(f"[Node {self.raft_terms.id}] No log file found, starting with empty log")
            self.raft_terms.logs = []
            self.raft_terms.last_log_index = -1
            self.raft_terms.last_log_term = 0
            
        except Exception as e:
            print(f"[Node {self.raft_terms.id}] ❌ Error loading logs: {e}")
            self.raft_terms.logs = []
        
    
    def killed(self):
        # A simple check for a killed state (using a lock might be safer in real code)
        return self._killed
    
    def kill(self):
        # A simple check for a killing a node
        self._killed = True