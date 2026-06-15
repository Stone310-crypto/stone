// ── Auth ──────────────────────────────────────────────────────────────────────

// Server signup/login response
export interface AuthResponse {
  id: string;
  name: string;
  api_key: string;
  wallet_address: string;
  session_token?: string;
  phrase?: string;
  message?: string;
  error?: string;
  discord_id?: string;
  discord_username?: string;
}

export interface ChallengeResponse {
  challenge: string;
  expires_in?: number;
}

export interface VerifyUser {
  id: string;
  name: string;
  wallet_address: string;
  account_type?: string;
  api_key: string;
  session_token: string;
}

export interface VerifyChallengeResponse {
  session_token: string;
  expires_in: number;
  user: VerifyUser;
}

// ── Health / Node ──────────────────────────────────────────────────────────────

export interface HealthResponse {
  status: string;
  node_id: string;
  role: string;
  block_height: number;
  latest_hash: string;
  network: string;
}

// ── Wallet ────────────────────────────────────────────────────────────────────

export interface WalletBalanceResponse {
  address: string;
  balance: string;
  nonce: number;
}

export interface TokenSupplyResponse {
  supply: SupplyInfo;
}

export interface SupplyInfo {
  network: string;
  total_supply: string;
  circulating_supply: string;
  mempool_pending: number;
  accounts: number;
}

export interface TokenTransaction {
  tx_id: string;
  tx_type: string;
  from: string;
  to: string;
  amount: string;
  fee: string;
  memo: string;
  timestamp: number;
  block_index?: number;
}

export interface TokenHistoryResponse {
  transactions: TokenTransaction[];
}

export interface TokenSendRequest {
  from: string;
  to: string;
  amount: string;
  memo?: string;
  signature: string;
  nonce: number;
}

export interface TokenSendResponse {
  success: boolean;
  tx_id?: string;
  message?: string;
}

// ── Staking ───────────────────────────────────────────────────────────────────

export interface StakingInfoResponse {
  total_staked: string;
  reward_pool: string;
  apy_pct: number;
  stakers_count: number;
}

export interface StakerInfoResponse {
  staker: StakerDetail;
}

export interface StakerDetail {
  address: string;
  staked_amount: string;
  pending_reward: string;
  staked_since: number;
}

// ── Mining ────────────────────────────────────────────────────────────────────

export interface MiningStatusResponse {
  mining: MiningInfo;
}

export interface MiningInfo {
  is_mining: boolean;
  throttle_pct: number;
  blocks_mined: number;
  active_miners: number;
  current_difficulty: number;
  mining_wallet?: string;
  chain: MiningChainInfo;
  network: MiningNetworkInfo;
  token: MiningTokenInfo;
}

export interface MiningChainInfo {
  block_height: number;
  latest_hash: string;
  total_documents: number;
}

export interface MiningNetworkInfo {
  total_peers: number;
  trusted_peers: number;
}

export interface MiningTokenInfo {
  total_supply: string;
  circulating_supply: string;
}

// ── Blocks ────────────────────────────────────────────────────────────────────

export interface Block {
  index: number;
  hash: string;
  previous_hash: string;
  timestamp: number;
  document_count: number;
  transaction_count: number;
  validator_pub_key: string;
  chat_batch_count?: number;
}

export interface BlockListResponse {
  blocks: Block[];
  total: number;
  page: number;
  page_size: number;
}

export interface BlockTransaction {
  tx_id: string;
  tx_type: string;
  from: string;
  to: string;
  amount: string;
  memo: string;
}

export interface BlockDetailResponse {
  block: Block;
  transactions: BlockTransaction[];
  document_count: number;
}

// ── Chat ──────────────────────────────────────────────────────────────────────

export interface ConversationSummary {
  peer_wallet: string;
  peer_name?: string;
  last_message: string;
  last_message_at: number;
  unread_count: number;
}

export interface ChatConversationsResponse {
  conversations: ConversationSummary[];
}

export interface ChatEntry {
  // server fields (stone::chat::ChatEntry serialization)
  msg_id?: string;
  id?: string;
  from_wallet?: string;
  sender_wallet?: string;
  sender_name?: string;
  from_name?: string;
  encrypted_content?: string;
  content?: string;
  nonce?: string;
  timestamp: number;
  is_own?: boolean;
  type?: string;
  amount?: string;
}

export interface ChatMessagesResponse {
  messages: ChatEntry[];
  peer_name?: string;
}

export interface ChatResolveResult {
  wallet: string;
  username: string;
  user_id?: string;
}

export interface ChatResolveResponse {
  result: ChatResolveResult;
}

export interface ContactRequestDetail {
  id: string;
  from_wallet: string;
  from_name: string;
  created_at: number;
}

export interface ContactRequestsResponse {
  requests: ContactRequestDetail[];
}

// ── Groups ────────────────────────────────────────────────────────────────────

export interface GroupSummary {
  group_id: string;
  name: string;
  member_count: number;
  last_message?: string;
  last_message_at?: number;
  unread_count: number;
}

export interface GroupListResponse {
  groups: GroupSummary[];
}

export interface GroupMessage {
  id: string;
  sender_wallet: string;
  sender_name?: string;
  content: string;
  timestamp: number;
  is_own: boolean;
}

export interface GroupMessagesResponse {
  messages: GroupMessage[];
  group_name: string;
}

// ── Announcements ─────────────────────────────────────────────────────────────

export interface PollOption {
  id: string;
  label: string;
  votes: number;
}

export interface AnnouncementEntry {
  id: string;
  title: string;
  body: string;
  author: string;
  created_at: number;
  reactions?: Record<string, number>;
  votes?: { up: number; down: number };
  poll_options?: PollOption[];
}

export interface AnnouncementListResponse {
  announcements: AnnouncementEntry[];
}

// ── Games ─────────────────────────────────────────────────────────────────────

export interface OnChainGame {
  game_id: string;
  name: string;
  description?: string;
  owner_wallet: string;
  verified: boolean;
  created_at: number;
  icon_url?: string;
  player_count?: number;
}

export interface GameResponse {
  games: OnChainGame[];
}

export interface GameCoinBalanceResponse {
  game_id: string;
  wallet: string;
  balance: string;
}

export interface GamingPoolStatus {
  game_id: string;
  pool_balance: string;
  configured: boolean;
  daily_limit?: string;
}

// ── Documents ─────────────────────────────────────────────────────────────────

export interface DocumentEntry {
  doc_id: string;
  filename: string;
  size: number;
  uploaded_at: number;
  owner_wallet: string;
  block_index?: number;
  version: number;
}

export interface DocumentListResponse {
  documents: DocumentEntry[];
  total: number;
}

// ── Session (local) ───────────────────────────────────────────────────────────

export interface Session {
  sessionToken: string;
  apiKey: string;
  userId: string;
  walletAddress: string;
  username: string;
  phrase?: string;
}

// ── Settings (local) ──────────────────────────────────────────────────────────

export interface NodeSettings {
  nodeUrl: string;
  label?: string;
}
