#!/usr/bin/env python3
"""
RAFT Resilience Tests - Full Version with Cluster Access

This version has full access to the RaftCluster and can test internal RAFT state.

Usage:
    Terminal 1: python start_cluster_with_test_hook.py
    Terminal 2: python test_raft_resilience_with_cluster.py
"""

if __name__ == "__main__":
    from security.launcher import ensure_launched
    ensure_launched("start_cluster_test_inmem_raft_reslience")

import time
import sys
import pathlib

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent.parent))

from inmem.kv_client import KVClient
import start_cluster_test_hook

class RaftResilienceTestFull:
    """Full RAFT resilience tests with cluster access"""
    
    def __init__(self, cluster, cluster_config):
        self.cluster = cluster
        self.cluster_config = cluster_config
        self.client = KVClient(cluster_config)
        self.passed = 0
        self.failed = 0
    
    def print_separator(self, title=""):
        """Print visual separator"""
        if title:
            print(f"\n{'='*75}")
            print(f"  {title}")
            print(f"{'='*75}\n")
        else:
            print(f"{'='*75}\n")
    
    def print_result(self, test_name, passed):
        """Print test result"""
        if passed:
            print(f"{'✅ PASSED':20} {test_name}")
            self.passed += 1
        else:
            print(f"{'❌ FAILED':20} {test_name}")
            self.failed += 1
    
    def print_cluster_state(self, title="CLUSTER STATE"):
        """Pretty print cluster state"""
        print(f"\n{title}:")
        print("-" * 75)
        for node_id in sorted(self.cluster.nodes.keys()):
            node = self.cluster.nodes[node_id]
            print(f"\nNode {node_id}:")
            print(f"  State:           {node.raft_terms.state.name.upper()}")
            print(f"  Term:            {node.raft_terms.current_term}")
            print(f"  Commit Index:    {node.raft_terms.commit_index}")
            print(f"  Last Applied:    {node.raft_terms.last_applied}")
            print(f"  Last Log Index:  {node.raft_terms.last_log_index}")
            print(f"  Log Length:      {len(node.raft_terms.logs)}")
    
    # ========================================================================
    # HELPER FUNCTIONS
    # ========================================================================
    
    def get_leader(self):
        """Get current leader node ID"""
        for nid, n in self.cluster.nodes.items():
            if n.raft_terms.state.name == "leader":
                return nid
        return None
    
    def get_followers(self):
        """Get list of follower node IDs"""
        return [nid for nid, n in self.cluster.nodes.items() 
                if n.raft_terms.state.name == "follower"]
    
    def verify_single_leader(self):
        """Verify exactly one leader exists"""
        leaders = [nid for nid, n in self.cluster.nodes.items() 
                  if n.raft_terms.state.name == "leader"]
        return len(leaders) == 1
    
    def verify_log_consistency(self, up_to_index=None):
        """Verify all nodes have same logs"""
        leader_id = self.get_leader()
        if not leader_id:
            return False
        
        leader_logs = self.cluster.nodes[leader_id].raft_terms.logs
        max_index = up_to_index if up_to_index else len(leader_logs)
        
        for node_id, node in self.cluster.nodes.items():
            node_logs = node.raft_terms.logs
            for i in range(min(max_index, len(leader_logs))):
                if i >= len(node_logs):
                    return False
                if leader_logs[i].get("command") != node_logs[i].get("command"):
                    return False
        
        return True
    
    def verify_no_split_brain(self):
        """Verify only one leader in multiple snapshots"""
        for _ in range(3):
            leaders = [nid for nid, n in self.cluster.nodes.items() 
                      if n.raft_terms.state.name == "leader"]
            if len(leaders) != 1:
                return False
            time.sleep(1)
        return True
    
    def verify_commit_index_invariant(self):
        """Verify commit_index <= last_log_index"""
        for node_id, node in self.cluster.nodes.items():
            if node.raft_terms.commit_index > node.raft_terms.last_log_index:
                return False
        return True
    
    def verify_terms_monotonic(self, initial_terms):
        """Verify terms never decrease"""
        for node_id, node in self.cluster.nodes.items():
            if node.raft_terms.current_term < initial_terms[node_id]:
                return False
        return True
    
    # ========================================================================
    # TEST CASES
    # ========================================================================
    
    def test_1_normal_operation(self):
        """TEST 1: Normal Operation - Write and replicate"""
        self.print_separator("TEST 1: Normal Operation")
        
        print("Step 1: Verify initial state...")
        leader = self.get_leader()
        print(f"  Leader: Node {leader}")
        
        print("\nStep 2: Write 3 KV entries...")
        for i in range(3):
            result = self.client.set(
                key=f"test:normal_{i}",
                field="value",
                value=f"data_{i}",
                timestamp=1000 + i,
                ttl=None
            )
            status = "✅" if result['success'] else "❌"
            print(f"  {status} SET test:normal_{i}")
        
        print("\nStep 3: Wait for replication...")
        time.sleep(10)
        
        print("\nStep 4: Verify invariants...")
        passed = all([
            self.verify_single_leader(),
            self.verify_log_consistency(),
            self.verify_commit_index_invariant(),
        ])
        
        self.print_result("Normal Operation", passed)
        self.print_cluster_state("After normal writes")
        return passed
    
    
    def test_2_leader_crash_election(self):
        """TEST 2: Leader Crash - Verify new leader elected"""
        self.print_separator("TEST 2: Leader Crash & New Leader Election")
        
        leader_id = self.get_leader()
        print(f"Current leader: Node {leader_id}")
        
        print(f"\nCrashing leader Node {leader_id}...")
        self.cluster.nodes[leader_id].kill()
        time.sleep(10)
        
        print("Waiting for new leader election (10 seconds)...")
        for i in range(10):
            new_leader = self.get_leader()
            if new_leader and new_leader != leader_id:
                print(f"✅ New leader elected: Node {new_leader} at t={i+1}s")
                break
            time.sleep(1)
        
        time.sleep(5)
        
        new_leader = self.get_leader()
        passed = new_leader is not None and new_leader != leader_id
        
        self.print_result("Leader Crash Detection & Re-election", passed)
        self.print_cluster_state(f"After leader {leader_id} crashed")
        return passed
    
    
    def test_3_follower_crash_continues(self):
        """TEST 3: Follower Crash - System continues"""
        self.print_separator("TEST 3: Follower Crash - System Continues")
        
        followers = self.get_followers()
        if not followers:
            print("❌ No followers available (unexpected)")
            return False
        
        follower_id = followers[0]
        print(f"Crashing follower: Node {follower_id}")
        self.cluster.nodes[follower_id].kill()
        time.sleep(1)
        
        print(f"\nWriting data while Node {follower_id} is down...")
        for i in range(2):
            result = self.client.set(
                key=f"test:fol_crash_{i}",
                field="value",
                value=f"data_{i}",
                timestamp=3000 + i,
                ttl=None
            )
            status = "✅" if result['success'] else "❌"
            print(f"  {status} SET test:fol_crash_{i}")
        
        time.sleep(10)
        
        # Verify still have leader
        leader = self.get_leader()
        passed = leader is not None
        
        self.print_result("System Continues Without Follower", passed)
        self.print_cluster_state(f"After follower {follower_id} crashed")
        return passed
    
    def test_4_no_split_brain(self):
        """TEST 4: Split Brain Prevention"""
        self.print_separator("TEST 4: Split Brain Prevention")
        
        print("Monitoring for split brain (multiple leaders)...")
        print("-" * 75)
        
        passed = self.verify_no_split_brain()
        
        if passed:
            print("No split brain detected in 3 snapshots ✅")
        else:
            print("Split brain detected! ❌")
        
        self.print_result("No Split Brain Occurs", passed)
        return passed
    
    def test_5_commit_index_advancement(self):
        """TEST 5: Commit Index Advances"""
        self.print_separator("TEST 5: Commit Index Advancement")
        
        leader = self.get_leader()
        initial_commit = self.cluster.nodes[leader].raft_terms.commit_index
        print(f"Initial commit_index (Leader {leader}): {initial_commit}")
        
        print("\nWriting 4 entries...")
        for i in range(4):
            result = self.client.set(
                key=f"test:commit_{i}",
                field="value",
                value=f"data_{i}",
                timestamp=5000 + i,
                ttl=None
            )
            status = "✅" if result['success'] else "❌"
            print(f"  {status} SET test:commit_{i}")
        
        print("\nWaiting for replication...")
        time.sleep(18)
        
        final_commit = self.cluster.nodes[leader].raft_terms.commit_index
        print(f"Final commit_index (Leader {leader}): {final_commit}")
        
        passed = final_commit > initial_commit
        
        self.print_result("Commit Index Advances on Writes", passed)
        return passed
    
    
    def test_6_log_replication(self):
        """TEST 6: Log Replication to All Nodes"""
        self.print_separator("TEST 6: Log Replication")
        
        print("Writing entries...")
        for i in range(3):
            result = self.client.set(
                key=f"test:replicate_{i}",
                field="value",
                value=f"replicate_data_{i}",
                timestamp=6000 + i,
                ttl=None
            )
            status = "✅" if result['success'] else "❌"
            print(f"  {status} SET test:replicate_{i}")
        
        print("\nWaiting for replication...")
        time.sleep(15)
        
        print("\nLog lengths across nodes:")
        log_lengths = {}
        for node_id, node in self.cluster.nodes.items():
            log_len = len(node.raft_terms.logs)
            log_lengths[node_id] = log_len
            print(f"  Node {node_id}: {log_len} entries")
        
        unique_lengths = set(log_lengths.values())
        passed = len(unique_lengths) == 1
        
        self.print_result("Logs Replicated to All Nodes", passed)
        return passed
    
    def test_7_state_machine_consistency(self):
        """TEST 7: State Machine Consistency"""
        self.print_separator("TEST 7: State Machine Consistency")
        
        print("Writing entry...")
        result = self.client.set(
            key="test:sm_consistency",
            field="value",
            value="all_nodes_match",
            timestamp=7000,
            ttl=None
        )
        print(f"  {'✅' if result['success'] else '❌'} SET test:sm_consistency")
        
        time.sleep(5)
        
        print("\nReading from all nodes:")
        values = {}
        for node_id in self.cluster.nodes.keys():
            result = self.client.get(
                key="test:sm_consistency",
                field="value",
                timestamp=7000,
                node_id=node_id
            )
            if result['success']:
                value = result.get('value', 'NOT_FOUND')
            else:
                value = 'ERROR'
            values[node_id] = value
            print(f"  Node {node_id}: {value}")
        
        unique_values = set(v for v in values.values() if v != 'ERROR')
        passed = len(unique_values) == 1
        
        self.print_result("State Machines Consistent Across Nodes", passed)
        return passed
    
    
    def test_8_term_monotonicity(self):
        """TEST 8: Terms Increase Monotonically"""
        self.print_separator("TEST 8: Term Monotonicity")
        
        initial_terms = {nid: n.raft_terms.current_term for nid, n in self.cluster.nodes.items()}
        print(f"Initial terms: {initial_terms}")
        
        print("Waiting 10 seconds...")
        time.sleep(10)
        
        final_terms = {nid: n.raft_terms.current_term for nid, n in self.cluster.nodes.items()}
        print(f"Final terms:   {final_terms}")
        
        passed = self.verify_terms_monotonic(initial_terms)
        
        self.print_result("Terms Increase Monotonically", passed)
        return passed
    
    def test_9_commit_index_invariant(self):
        """TEST 9: Commit Index Invariant"""
        self.print_separator("TEST 9: Commit Index <= Last Log Index (Invariant)")
        
        print("Checking invariant on all nodes:")
        print("-" * 75)
        
        all_valid = True
        for node_id, node in self.cluster.nodes.items():
            commit = node.raft_terms.commit_index
            last_log = node.raft_terms.last_log_index
            valid = commit <= last_log
            status = "✅" if valid else "❌"
            print(f"  {status} Node {node_id}: commit_index({commit}) <= last_log_index({last_log})")
            all_valid = all_valid and valid
        
        self.print_result("Commit Index Invariant Maintained", all_valid)
        return all_valid
    
    def test_10_leader_stability(self):
        """TEST 10: Leader Stability"""
        self.print_separator("TEST 10: Leader Stability")
        
        initial_leader = self.get_leader()
        print(f"Initial leader: Node {initial_leader}")
        
        print("Monitoring leadership for 15 seconds...")
        leaders = [initial_leader]
        
        for i in range(15):
            current_leader = self.get_leader()
            if current_leader != leaders[-1]:
                leaders.append(current_leader)
                print(f"  t={i+1}s: Leadership changed to Node {current_leader}")
            time.sleep(1)
        
        passed = len(leaders) == 1
        
        if passed:
            print(f"Leader remained stable: {leaders[0]}")
        else:
            print(f"Leader changed multiple times: {leaders}")
        
        self.print_result("Leader Stability (No Unnecessary Elections)", passed)
        return passed

def main():
    """Run all tests"""
    
    print("\n" + "="*75)
    print("  RAFT RESILIENCE TEST SUITE (WITH CLUSTER ACCESS)")
    print("="*75)
    
    # Try to import cluster from test hook
    cluster = start_cluster_test_hook.start_cluster_for_tests()
    cluster_config = start_cluster_test_hook.CLUSTER_CONFIG
    print('port', start_cluster_test_hook.WEBSOCKET_PORT)
    
    # Wait for cluster stability
    print("\n⏳ Waiting for cluster to stabilize (5 seconds)...")
    time.sleep(20)
    
    try:
        tester = RaftResilienceTestFull(cluster, cluster_config)
        
        # Run tests
        tester.test_1_normal_operation()
        tester.test_4_no_split_brain()
        tester.test_5_commit_index_advancement()
        tester.test_6_log_replication()
        tester.test_7_state_machine_consistency()
        tester.test_8_term_monotonicity()
        tester.test_9_commit_index_invariant()
        tester.test_10_leader_stability()
        
        # Tests that modify cluster state
        tester.test_2_leader_crash_election() #PASSIVE NODE FAILURE -> CAN STILL RESPOND TO RPC CALL BUT NOT TAKE PART IN ELECTIONS / HEARBEAT
        tester.test_3_follower_crash_continues()
        
        # Print summary
        tester.print_separator("TEST SUMMARY")
        
        total = tester.passed + tester.failed
        print(f"\nTests Passed: {tester.passed}/{total}")
        print(f"Tests Failed: {tester.failed}/{total}")
        
        if tester.failed == 0:
            print("\n🎉 ALL TESTS PASSED!")
        else:
            print(f"\n⚠️  {tester.failed} tests failed")
        
        print("\n" + "="*75)
        
    except KeyboardInterrupt:
        print("\n\nTest interrupted by user")
    except Exception as e:
        print(f"\n\nTest failed with error: {e}")
        import traceback
        traceback.print_exc()


if __name__ == "__main__":
    main()