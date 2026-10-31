import React, { useState, useEffect, useRef } from 'react';
import { motion as Motion } from 'framer-motion';

const nodeCoords = {
  A: { x: 80, y: 100 },
  B: { x: 280, y: 100 },
  C: { x: 180, y: 240 },
};

const RaftVisualizationWithWebSocket = ({ onSessionEnd }) => {
  // Logs per node
  const [nodeLogEntries, setNodeLogEntries] = useState({
    A: [],
    B: [],
    C: [],
  });

  // Base RAFT state
  const [activeMessage, setActiveMessage] = useState(null);
  const [leaderId, setLeaderId] = useState(null);
  const [currentTerm, setCurrentTerm] = useState(null);
  const [lastLogIndex, setLastLogIndex] = useState(null);
  const [lastLogTerm, setLastLogTerm] = useState(null);
  const [followers, setFollowers] = useState([]);
  const [, setPeerResponses] = useState({});
  const [connectionStatus, setConnectionStatus] = useState('disconnected');
  const [lastHeartbeatTime, setLastHeartbeatTime] = useState(null);
  const [, setDebugMessages] = useState([]);
  // NEW: Election state
  const [electionInProgress, setElectionInProgress] = useState(false);
  const [candidateNodes, setCandidateNodes] = useState([]); // ['A', 'B']
  const [electionTerm, setElectionTerm] = useState(null);
  const [voteRequests, setVoteRequests] = useState([]); // [{ from: 'A', to: 'B', id: '...' }]
  const [votesReceived, setVotesReceived] = useState({}); // { 'A': ['B', 'C'], 'B': ['A'] }
  const [electionWinner, setElectionWinner] = useState(null);
  const [showElectionAnimation, setShowElectionAnimation] = useState(false);

  const wsRef = useRef(null);

  const addDebug = (msg) => {
    console.log(`[DEBUG] ${msg}`);
    setDebugMessages((prev) => [...prev.slice(-4), msg]);
  };

  // The HTTPS login cookie authenticates this same-origin WebSocket.
  useEffect(() => {
    let stopped = false;
    let timer;
    const connect = () => {
      const socket = new WebSocket(`wss://${window.location.host}/ws`);
      wsRef.current = socket;
      socket.onopen = () => setConnectionStatus('connected');
      socket.onmessage = (event) => handleWebSocketMessage(JSON.parse(event.data));
      socket.onerror = () => setConnectionStatus('error');
      socket.onclose = (event) => {
        setConnectionStatus('disconnected');
        if (stopped) return;
        if (event.code === 1008 || event.code === 1006) onSessionEnd();
        else timer = setTimeout(connect, 3000);
      };
    };
    connect();
    return () => {
      stopped = true;
      clearTimeout(timer);
      wsRef.current?.close();
    };
    // Message handlers use functional state updates.
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, []);

  const handleWebSocketMessage = (message) => {
    try {
      switch (message.type) {
        case 'heartbeat':
          handleHeartbeat(message);
          break;
        case 'peer_response':
          handlePeerResponse(message);
          break;
        case 'node_state_change':
          handleNodeStateChange(message);
          break;
        case 'log_entry':
          handleLogEntry(message);
          break;
        case 'entries_committed':
          handleEntriesCommitted(message);
          break;
        case 'entry_applied':
          break;
        // NEW: Election message handlers
        case 'vote_request':
          handleVoteRequest(message);
          break;
        case 'vote_response':
          handleVoteResponse(message);
          break;
        case 'election_result':
          handleElectionResult(message);
          break;
        default:
          addDebug(`Unknown message type: ${message.type}`);
      }
    } catch (e) {
      addDebug(`Handler error: ${e.message}`);
    }
  };

  const handleHeartbeat = (message) => {
    const {
      leader_id,
      current_term,
      last_log_index,
      last_log_term,
      followers: hbFollowers,
      timestamp,
    } = message;

    setLeaderId(leader_id || null);
    setCurrentTerm(current_term ?? null);
    setLastLogIndex(last_log_index ?? null);
    setLastLogTerm(last_log_term ?? null);
    setFollowers(Array.isArray(hbFollowers) ? hbFollowers : []);
    setLastHeartbeatTime(timestamp ? new Date(timestamp) : new Date());

    const newResponses = {};
    (hbFollowers || []).forEach((f) => {
      newResponses[f] = { success: null, term: null, matchIndex: null };
    });
    setPeerResponses(newResponses);

    if (leader_id) {
      setActiveMessage({ type: 'heartbeat', leader_id });
      setTimeout(() => setActiveMessage(null), 1500);
    }
  };

  const handlePeerResponse = (message) => {
    const { leader_id, peer_id, success, term, timestamp } = message;
    if (!peer_id || !leader_id) {
      addDebug('peer_response missing fields');
      return;
    }

    setPeerResponses((prev) => ({
      ...prev,
      [peer_id]: {
        success: success,
        term: term,
        timestamp: timestamp
      },
    }));

    if (success) {
      setActiveMessage({
        type: 'peer_response',
        from: peer_id,
        to: leader_id,
      });
      setTimeout(() => setActiveMessage(null), 1500);
    }
  };

  const handleNodeStateChange = (message) => {
    const { node_id, new_state, current_term } = message;
    if (new_state === 'leader') {
      setLeaderId(node_id);
      if (current_term != null) setCurrentTerm(current_term);
    }
  };

  const handleLogEntry = (message) => {
    const { node_id, log_index, committed } = message;
    if (!node_id || log_index == null) {
      addDebug('log_entry missing fields');
      return;
    }

    addDebug(`Log index ${log_index} on Node ${node_id}`);

    setNodeLogEntries((prev) => ({
      ...prev,
      [node_id]: [
        ...prev[node_id],
        {
          id: log_index,
          value: `Index ${log_index}`,
          committed: !!committed,
        },
      ],
    }));
  };

  const handleEntriesCommitted = (message) => {
    try {
      const { committed_until_index } = message;
      addDebug(`Entries committed up to index ${committed_until_index}`);

      setNodeLogEntries((prev) => {
        const updated = {};

        ['A', 'B', 'C'].forEach((nId) => {
          updated[nId] = prev[nId].map((entry) => {
            if (entry.id <= committed_until_index && !entry.committed) {
              return { ...entry, committed: true };
            }
            return entry;
          });
        });

        return updated;
      });
    } catch (e) {
      addDebug(`Error in handleEntriesCommitted: ${e.message}`);
    }
  };

  const handleVoteRequest = (message) => {
    const { node_id, current_term } = message;

    addDebug(`Vote request from Node ${node_id} for term ${current_term}`);

    // Mark node as candidate
    setCandidateNodes((prev) => {
      const set = new Set(prev);
      set.add(node_id);
      return Array.from(set);
    });

    setElectionInProgress(true);
    setElectionTerm(current_term);

    // Animate vote requests to all other nodes
    const targetNodes = ['A', 'B', 'C'].filter((n) => n !== node_id);
    const newRequests = targetNodes.map((target) => ({
      from: node_id,
      to: target,
      id: `vreq-${node_id}-${target}-${Date.now()}`,
    }));

    setVoteRequests(newRequests);

    // Clear animation after 1.5s
    setTimeout(() => setVoteRequests([]), 1500);
  };

  const handleVoteResponse = (message) => {
    const { node_id, voted_for, current_term } = message;

    // -1 means rejected
    if (voted_for === -1) {
      addDebug(`Node ${node_id} rejected vote in term ${current_term}`);
      return;
    }

    addDebug(`Node ${node_id} voted for Node ${voted_for} in term ${current_term}`);

    // Track votes
    setVotesReceived((prev) => ({
      ...prev,
      [voted_for]: [...(prev[voted_for] || []), node_id],
    }));

    // Animate response
    setActiveMessage({
      type: 'vote_response',
      from: node_id,
      to: voted_for,
    });
    setTimeout(() => setActiveMessage(null), 1000);
  };

  const handleElectionResult = (message) => {
    const { node_id, election_result, current_term } = message;

    if (!election_result) {
      addDebug(`Node ${node_id} did not win election in term ${current_term}`);
      return;
    }

    addDebug(`Node ${node_id} WON ELECTION in term ${current_term}!`);

    // Update state
    setElectionWinner(node_id);
    setLeaderId(node_id);
    setCurrentTerm(current_term);
    setShowElectionAnimation(true);

    // Clear candidates
    setCandidateNodes([]);

    // Clear election state after animation
    setTimeout(() => {
      setElectionInProgress(false);
      setVotesReceived({});
      setShowElectionAnimation(false);
      setElectionWinner(null);
    }, 2500);
  };

  const nodeColors = {
    leader: { gradient: 'linear-gradient(135deg, #f97316 0%, #ef4444 100%)', shadow: 'rgba(249, 115, 22, 0.5)' },
    candidate: { gradient: 'linear-gradient(135deg, #a855f7 0%, #f59e0b 100%)', shadow: 'rgba(168, 85, 247, 0.7)' },
    follower: { gradient: 'linear-gradient(135deg, #3b82f6 0%, #06b6d4 100%)', shadow: 'rgba(59, 130, 246, 0.5)' },
  };

  // Get node state: CANDIDATE > LEADER > FOLLOWER
  const getNodeState = (nodeId) => {
    if (candidateNodes.includes(nodeId)) return 'CANDIDATE';
    if (leaderId === nodeId) return 'LEADER';
    return 'FOLLOWER';
  };

  return (
    <div
      style={{
        width: '100%',
        minHeight: '100vh',
        background:
          'linear-gradient(135deg, #0f172a 0%, #1e293b 50%, #0f172a 100%)',
        padding: '2rem',
        fontFamily: 'system-ui, Avenir, Helvetica, Arial, sans-serif',
        color: '#f1f5f9',
        display: 'flex',
        flexDirection: 'column',
      }}
    >
      {/* Header */}
      <div
        style={{
          marginBottom: '2rem',
          display: 'flex',
          justifyContent: 'space-between',
          alignItems: 'center',
        }}
      >
        <div>
          <h1
            style={{
              fontSize: '2.5rem',
              fontWeight: 'bold',
              margin: '0 0 0.5rem 0',
            }}
          >
            RAFT Consensus Visualization
          </h1>
          <p
            style={{
              color: '#cbd5e1',
              margin: 0,
              fontSize: '0.95rem',
            }}
          >
            Real-time leader election, heartbeats, and consensus
          </p>
        </div>
        <div
          style={{
            display: 'flex',
            flexDirection: 'column',
            alignItems: 'flex-end',
            gap: '0.5rem',
          }}
        >
          <div
            style={{
              display: 'flex',
              alignItems: 'center',
              gap: '0.75rem',
              fontSize: '12px',
            }}
          >
            <div
              style={{
                width: '12px',
                height: '12px',
                borderRadius: '50%',
                background:
                  connectionStatus === 'connected'
                    ? '#10b981'
                    : connectionStatus === 'error'
                      ? '#ef4444'
                      : '#f59e0b',
                animation:
                  connectionStatus === 'connected' ? 'pulse 2s infinite' : 'none',
              }}
            />
            <span>{connectionStatus.toUpperCase()}</span>
          </div>
          {lastHeartbeatTime && (
            <div style={{ fontSize: '10px', color: '#64748b' }}>
              Last heartbeat: {lastHeartbeatTime.toLocaleTimeString()}
            </div>
          )}
        </div>
      </div>

      {/* NEW: Election Tracker Panel */}
      {electionInProgress && (
        <Motion.div
          initial={{ opacity: 0, y: -20 }}
          animate={{ opacity: 1, y: 0 }}
          exit={{ opacity: 0, y: -20 }}
          style={{
            background: 'rgba(168, 85, 247, 0.1)',
            border: '2px solid rgba(168, 85, 247, 0.6)',
            borderRadius: '12px',
            padding: '1.5rem',
            marginBottom: '2rem',
            backdropFilter: 'blur(10px)',
          }}
        >
          <h2
            style={{
              fontSize: '1.2rem',
              fontWeight: '700',
              margin: '0 0 1rem 0',
              color: '#a855f7',
            }}
          >
            Leader Election in Progress (Term {electionTerm})
          </h2>
          <div
            style={{
              display: 'grid',
              gridTemplateColumns: 'repeat(auto-fit, minmax(180px, 1fr))',
              gap: '1.5rem',
            }}
          >
            {candidateNodes.map((candidate) => {
              const votes = votesReceived[candidate] || [];
              const total_nodes = 3;
              const majority = Math.floor((total_nodes / 2) + 1);

              return (
                <div
                  key={candidate}
                  style={{
                    background: 'rgba(15, 23, 42, 0.8)',
                    border: '1px solid rgba(168, 85, 247, 0.4)',
                    borderRadius: '10px',
                    padding: '1.25rem',
                  }}
                >
                  <div
                    style={{
                      color: '#a855f7',
                      fontWeight: '800',
                      fontSize: '1.2rem',
                      marginBottom: '0.75rem',
                    }}
                  >
                    Candidate {candidate}
                  </div>

                  {/* Vote progress bar */}
                  <div style={{ marginBottom: '0.75rem' }}>
                    <div
                      style={{
                        fontSize: '11px',
                        color: '#cbd5e1',
                        marginBottom: '0.4rem',
                      }}
                    >
                      Votes: {votes.length}/{total_nodes} (Need {majority})
                    </div>
                    <div
                      style={{
                        width: '100%',
                        height: '6px',
                        background: 'rgba(71, 85, 105, 0.3)',
                        borderRadius: '3px',
                        overflow: 'hidden',
                      }}
                    >
                      <Motion.div
                        initial={{ width: 0 }}
                        animate={{ width: `${(votes.length / total_nodes) * 100}%` }}
                        transition={{ duration: 0.5 }}
                        style={{
                          height: '100%',
                          background:
                            votes.length >= majority
                              ? 'linear-gradient(90deg, #10b981, #34d399)'
                              : 'linear-gradient(90deg, #a855f7, #d946ef)',
                        }}
                      />
                    </div>
                  </div>

                  {/* Voters list */}
                  {votes.length > 0 && (
                    <div
                      style={{
                        fontSize: '11px',
                        color: '#10b981',
                        fontWeight: '600',
                      }}
                    >
                      From: {votes.join(', ')}
                    </div>
                  )}
                </div>
              );
            })}
          </div>
        </Motion.div>
      )}

      {/* Node Visualization + Logs */}
      <div
        style={{
          display: 'grid',
          gridTemplateColumns: '1fr 2fr',
          gap: '2rem',
          marginBottom: '2rem',
        }}
      >
        {/* Node Visualization */}
        <div
          style={{
            background: 'rgba(30, 41, 59, 0.8)',
            border: '1px solid rgba(71, 85, 105, 0.4)',
            borderRadius: '12px',
            padding: '2rem',
            backdropFilter: 'blur(10px)',
            display: 'flex',
            flexDirection: 'column',
          }}
        >
          <h3
            style={{
              fontSize: '1.1rem',
              fontWeight: '700',
              marginTop: 0,
              marginBottom: '1.5rem',
            }}
          >
            Node Network (Term {currentTerm ?? '-'})
          </h3>

          <div
            style={{
              position: 'relative',
              flex: 1,
              minHeight: '300px',
              marginBottom: '1.5rem',
            }}
          >
            <svg
              width="100%"
              height="100%"
              viewBox="0 0 400 320"
              style={{ position: 'absolute', inset: 0 }}
            >
              {/* Static connections */}
              <line
                x1={nodeCoords.A.x}
                y1={nodeCoords.A.y}
                x2={nodeCoords.B.x}
                y2={nodeCoords.B.y}
                stroke="#475569"
                strokeWidth="1"
                strokeDasharray="3,3"
              />
              <line
                x1={nodeCoords.A.x}
                y1={nodeCoords.A.y}
                x2={nodeCoords.C.x}
                y2={nodeCoords.C.y}
                stroke="#475569"
                strokeWidth="1"
                strokeDasharray="3,3"
              />
              <line
                x1={nodeCoords.B.x}
                y1={nodeCoords.B.y}
                x2={nodeCoords.C.x}
                y2={nodeCoords.C.y}
                stroke="#475569"
                strokeWidth="1"
                strokeDasharray="3,3"
              />

              {/* NEW: Vote requests (candidate asking for votes) */}
              {voteRequests.map((req) => (
                <Motion.line
                  key={req.id}
                  x1={nodeCoords[req.from].x}
                  y1={nodeCoords[req.from].y}
                  x2={nodeCoords[req.to].x}
                  y2={nodeCoords[req.to].y}
                  stroke="#f59e0b"
                  strokeWidth="2"
                  strokeDasharray="5,5"
                  initial={{ pathLength: 0, opacity: 0.8 }}
                  animate={{ pathLength: 1, opacity: 1 }}
                  transition={{ duration: 1 }}
                />
              ))}

              {/* Heartbeats */}
              {activeMessage?.type === 'heartbeat' &&
                leaderId &&
                followers.map((f) => (
                  <Motion.line
                    key={`hb-${f}`}
                    x1={nodeCoords[leaderId].x}
                    y1={nodeCoords[leaderId].y}
                    x2={nodeCoords[f].x}
                    y2={nodeCoords[f].y}
                    stroke="#06b6d4"
                    strokeWidth="2"
                    initial={{ pathLength: 0, opacity: 0.8 }}
                    animate={{ pathLength: 1, opacity: 0 }}
                    transition={{ duration: 1.5 }}
                  />
                ))}

              {activeMessage?.type === 'heartbeat' && leaderId && (
                <Motion.circle
                  cx={nodeCoords[leaderId].x}
                  cy={nodeCoords[leaderId].y}
                  r={60}
                  fill="none"
                  stroke="#06b6d4"
                  strokeWidth="2"
                  initial={{ r: 60, opacity: 0.8 }}
                  animate={{ r: 90, opacity: 0 }}
                  transition={{ duration: 1.5, ease: 'easeOut' }}
                />
              )}

              {/* Vote responses (voters responding to candidate) */}
              {activeMessage?.type === 'vote_response' &&
                nodeCoords[activeMessage.from] &&
                nodeCoords[activeMessage.to] && (
                  <Motion.line
                    x1={nodeCoords[activeMessage.from].x}
                    y1={nodeCoords[activeMessage.from].y}
                    x2={nodeCoords[activeMessage.to].x}
                    y2={nodeCoords[activeMessage.to].y}
                    stroke="#10b981"
                    strokeWidth="3"
                    strokeDasharray="5,5"
                    initial={{ pathLength: 0 }}
                    animate={{ pathLength: 1 }}
                    transition={{ duration: 0.6 }}
                  />
                )}

              {/* NEW: Election won animation */}
              {showElectionAnimation && electionWinner && (
                <Motion.circle
                  cx={nodeCoords[electionWinner].x}
                  cy={nodeCoords[electionWinner].y}
                  r={50}
                  fill="none"
                  stroke="#10b981"
                  strokeWidth="3"
                  initial={{ r: 50, opacity: 1 }}
                  animate={{ r: 130, opacity: 0 }}
                  transition={{ duration: 1.5 }}
                />
              )}

              {/* Nodes A, B, C */}
              {['A', 'B', 'C'].map((nodeId) => {
                const state = getNodeState(nodeId);
                const color =
                  state === 'LEADER'
                    ? nodeColors.leader
                    : state === 'CANDIDATE'
                      ? nodeColors.candidate
                      : nodeColors.follower;
                const coords = nodeCoords[nodeId];

                return (
                  <g key={`node-${nodeId}`}>
                    <Motion.circle
                      cx={coords.x}
                      cy={coords.y}
                      r={50}
                      fill={color.gradient}
                      animate={
                        state === 'CANDIDATE'
                          ? {
                            filter: [
                              `drop-shadow(0 4px 12px ${color.shadow})`,
                              `drop-shadow(0 4px 20px ${color.shadow})`,
                              `drop-shadow(0 4px 12px ${color.shadow})`,
                            ],
                          }
                          : {
                            filter: `drop-shadow(0 4px 12px ${color.shadow})`,
                          }
                      }
                      transition={
                        state === 'CANDIDATE'
                          ? { duration: 1, repeat: Infinity }
                          : { duration: 0 }
                      }
                    />
                    <text
                      x={coords.x}
                      y={coords.y - 5}
                      textAnchor="middle"
                      fill="white"
                      fontSize="20"
                      fontWeight="bold"
                    >
                      Node {nodeId}
                    </text>
                    <text
                      x={coords.x}
                      y={coords.y + 15}
                      textAnchor="middle"
                      fill="white"
                      fontSize="11"
                      fontWeight="600"
                    >
                      {state}
                    </text>
                  </g>
                );
              })}
            </svg>
          </div>

          {/* Leader info */}
          <div
            style={{
              background: 'rgba(15, 23, 42, 0.6)',
              border: '1px solid rgba(71, 85, 105, 0.3)',
              borderRadius: '8px',
              padding: '1rem',
            }}
          >
            <div
              style={{
                fontSize: '10px',
                fontWeight: '700',
                color: '#64748b',
                marginBottom: '0.75rem',
                textTransform: 'uppercase',
              }}
            >
              Leader Info
            </div>
            <div
              style={{
                display: 'flex',
                flexDirection: 'column',
                gap: '0.5rem',
                fontSize: '11px',
                color: '#cbd5e1',
              }}
            >
              <div>
                Leader: <strong>{leaderId ?? '-'}</strong>
              </div>
              <div>
                Term: <strong>{currentTerm ?? '-'}</strong>
              </div>
              <div>
                Last Log:{' '}
                <strong>
                  Index {lastLogIndex ?? '-'}, Term {lastLogTerm ?? '-'}
                </strong>
              </div>
            </div>
          </div>
        </div>

        {/* Logs per node */}
        <div
          style={{
            display: 'grid',
            gridTemplateColumns: 'repeat(3, 1fr)',
            gap: '1rem',
          }}
        >
          {['A', 'B', 'C'].map((nodeId) => (
            <div
              key={`log-${nodeId}`}
              style={{
                background: 'rgba(30, 41, 59, 0.8)',
                border: '1px solid rgba(71, 85, 105, 0.4)',
                borderRadius: '12px',
                padding: '1.5rem',
                backdropFilter: 'blur(10px)',
                display: 'flex',
                flexDirection: 'column',
              }}
            >
              <h3
                style={{
                  fontSize: '1rem',
                  fontWeight: '700',
                  marginTop: 0,
                  marginBottom: '1rem',
                  color:
                    getNodeState(nodeId) === 'LEADER'
                      ? '#fed7aa'
                      : getNodeState(nodeId) === 'CANDIDATE'
                        ? '#d946ef'
                        : '#bfdbfe',
                }}
              >
                Node {nodeId} Log
              </h3>
              <div
                style={{
                  flex: 1,
                  display: 'flex',
                  flexDirection: 'column',
                  gap: '0.75rem',
                  overflowY: 'auto',
                  maxHeight: '400px',
                }}
              >
                {nodeLogEntries[nodeId] && nodeLogEntries[nodeId].length === 0 ? (
                  <div
                    style={{
                      color: '#64748b',
                      fontSize: '12px',
                      fontStyle: 'italic',
                    }}
                  >
                    No entries yet...
                  </div>
                ) : nodeLogEntries[nodeId] ? (
                  nodeLogEntries[nodeId].map((log, idx) => (
                    <Motion.div
                      key={`${nodeId}-log-${log.id}-${idx}`}
                      initial={{ opacity: 0, x: -20 }}
                      animate={{ opacity: 1, x: 0 }}
                      transition={{ duration: 0.4 }}
                      style={{
                        padding: '0.75rem',
                        borderRadius: '6px',
                        fontSize: '11px',
                        fontFamily: 'monospace',
                        background: log.committed
                          ? 'rgba(16, 185, 129, 0.15)'
                          : 'rgba(245, 158, 11, 0.15)',
                        border: log.committed
                          ? '1px solid rgba(16, 185, 129, 0.4)'
                          : '1px solid rgba(245, 158, 11, 0.4)',
                        color: log.committed ? '#10b981' : '#f59e0b',
                        display: 'flex',
                        justifyContent: 'space-between',
                        alignItems: 'center',
                        wordBreak: 'break-word',
                      }}
                    >
                      <span style={{ flex: 1 }}>
                        {log.value || 'Empty entry'}
                      </span>
                      {log.committed && (
                        <span
                          style={{
                            fontSize: '9px',
                            marginLeft: '0.5rem',
                            whiteSpace: 'nowrap',
                          }}
                        >
                          ✓
                        </span>
                      )}
                    </Motion.div>
                  ))
                ) : null}
              </div>
            </div>
          ))}
        </div>
      </div>


      {/* Legend */}
      <div
        style={{
          marginTop: 'auto',
          display: 'grid',
          gridTemplateColumns: 'repeat(auto-fit, minmax(200px, 1fr))',
          gap: '1rem',
          fontSize: '11px',
          paddingTop: '1.5rem',
          borderTop: '1px solid rgba(71, 85, 105, 0.3)',
        }}
      >
        <div
          style={{
            display: 'flex',
            alignItems: 'center',
            gap: '0.75rem',
            color: '#cbd5e1',
          }}
        >
          <div
            style={{
              width: '12px',
              height: '12px',
              borderRadius: '50%',
              background: 'linear-gradient(135deg, #f97316, #ef4444)',
            }}
          />
          Leader Node
        </div>
        <div
          style={{
            display: 'flex',
            alignItems: 'center',
            gap: '0.75rem',
            color: '#cbd5e1',
          }}
        >
          <div
            style={{
              width: '12px',
              height: '12px',
              borderRadius: '50%',
              background: 'linear-gradient(135deg, #a855f7, #f59e0b)',
            }}
          />
          Candidate (Running for election)
        </div>
        <div
          style={{
            display: 'flex',
            alignItems: 'center',
            gap: '0.75rem',
            color: '#cbd5e1',
          }}
        >
          <div
            style={{
              width: '12px',
              height: '12px',
              borderRadius: '50%',
              background: 'linear-gradient(135deg, #3b82f6, #06b6d4)',
            }}
          />
          Follower Node
        </div>
        <div
          style={{
            display: 'flex',
            alignItems: 'center',
            gap: '0.75rem',
            color: '#cbd5e1',
          }}
        >
          <div style={{ width: '12px', height: '2px', background: '#06b6d4' }} />
          Heartbeat (Cyan)
        </div>
        <div
          style={{
            display: 'flex',
            alignItems: 'center',
            gap: '0.75rem',
            color: '#cbd5e1',
          }}
        >
          <div style={{ width: '12px', height: '2px', background: '#f59e0b' }} />
          Vote Request (Orange)
        </div>
        <div
          style={{
            display: 'flex',
            alignItems: 'center',
            gap: '0.75rem',
            color: '#cbd5e1',
          }}
        >
          <div style={{ width: '12px', height: '2px', background: '#10b981' }} />
          Vote Response (Green)
        </div>
      </div>

      <style>{`
        @keyframes pulse {
          0%, 100% { opacity: 1; }
          50% { opacity: 0.5; }
        }
      `}</style>
    </div>
  );
};

function App() {
  const [authenticated, setAuthenticated] = useState(false);
  const [error, setError] = useState('');
  const login = async (event) => {
    event.preventDefault();
    const form = event.currentTarget;
    const values = new FormData(form);
    try {
      const response = await fetch('/auth/login', {
        method: 'POST', credentials: 'same-origin',
        headers: { Authorization: `Basic ${btoa(`${values.get('username')}:${values.get('password')}`)}` },
      });
      if (!response.ok) throw new Error('Sign-in failed');
      form.reset();
      setError('');
      setAuthenticated(true);
    } catch {
      setError('Sign-in failed. Check your credentials and connection.');
    }
  };
  const logout = async () => {
    await fetch('/auth/logout', { method: 'POST', credentials: 'same-origin' });
    setAuthenticated(false);
  };
  if (!authenticated) return (
    <main style={{ maxWidth: 360, margin: '10vh auto', padding: 24 }}>
      <h1>Raft telemetry</h1>
      <form onSubmit={login} style={{ display: 'grid', gap: 12 }}>
        <label>Username <input name="username" autoComplete="username" required /></label>
        <label>Password <input name="password" type="password" autoComplete="current-password" required /></label>
        <button type="submit">Sign in</button>
        <p role="alert">{error}</p>
      </form>
    </main>
  );
  return <><button onClick={logout}>Sign out</button>
    <RaftVisualizationWithWebSocket onSessionEnd={() => setAuthenticated(false)} /></>;
}

export default App;