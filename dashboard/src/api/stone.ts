import { apiFetch } from "./client";
import { loadSession } from "../store/session";
import type {
  AuthResponse,
  ChallengeResponse,
  VerifyChallengeResponse,
  HealthResponse,
  WalletBalanceResponse,
  TokenSupplyResponse,
  TokenHistoryResponse,
  TokenSendRequest,
  TokenSendResponse,
  StakingInfoResponse,
  StakerInfoResponse,
  MiningStatusResponse,
  BlockListResponse,
  BlockDetailResponse,
  ChatConversationsResponse,
  ChatMessagesResponse,
  ChatResolveResponse,
  ContactRequestsResponse,
  GroupListResponse,
  GroupMessagesResponse,
  AnnouncementListResponse,
  AnnouncementEntry,
  GameResponse,
  GameCoinBalanceResponse,
  GamingPoolStatus,
  DocumentListResponse,
} from "../types/api";

// ── Auth ──────────────────────────────────────────────────────────────────────

export const auth = {
  signup: (name: string) =>
    apiFetch<AuthResponse>("/api/v1/auth/signup", {
      method: "POST", body: JSON.stringify({ name }), skipAuth: true,
    }),
  login: (phrase: string) =>
    apiFetch<AuthResponse>("/api/v1/auth/login", {
      method: "POST", body: JSON.stringify({ phrase }), skipAuth: true,
    }),
  challenge: (walletAddress: string) =>
    apiFetch<ChallengeResponse>("/api/v1/auth/challenge", {
      method: "POST", body: JSON.stringify({ wallet_address: walletAddress }), skipAuth: true,
    }),
  verify: (walletAddress: string, signature: string) =>
    apiFetch<VerifyChallengeResponse>("/api/v1/auth/verify", {
      method: "POST", body: JSON.stringify({ wallet_address: walletAddress, signature }), skipAuth: true,
    }),
  discord: (code: string, redirectUri: string) =>
    apiFetch<AuthResponse>("/api/v1/auth/discord", {
      method: "POST", body: JSON.stringify({ code, redirect_uri: redirectUri }), skipAuth: true,
    }),
  qrCreate: () =>
    apiFetch<{ login_token: string; expires_in: number }>("/api/v1/auth/qr/create", {
      method: "POST", body: "{}", skipAuth: true,
    }),
  qrStatus: (token: string) =>
    apiFetch<{ status: string; session_token?: string; api_key?: string; phrase?: string; user?: any }>(
      `/api/v1/auth/qr/status/${token}`, { skipAuth: true }),
};

// ── Node ──────────────────────────────────────────────────────────────────────

export const node = {
  health: () => apiFetch<HealthResponse>("/api/v1/health", { skipAuth: true }),
};

// ── Wallet ────────────────────────────────────────────────────────────────────

export const wallet = {
  balance: (address: string) =>
    apiFetch<WalletBalanceResponse>(`/api/v1/wallet/${address}/balance`),
  supply: () => apiFetch<TokenSupplyResponse>("/api/v1/token/supply"),
  history: (address: string) =>
    apiFetch<TokenHistoryResponse>(`/api/v1/token/history/${address}`),
  send: (req: TokenSendRequest) =>
    apiFetch<TokenSendResponse>("/api/v1/token/send", {
      method: "POST", body: JSON.stringify(req),
    }),
  /// send-authenticated requires the mnemonic (phrase) in the body as proof of ownership.
  /// We read it from the session (saved in localStorage after login/signup).
  sendAuthenticated: (to: string, amount: string) => {
    const session = loadSession();
    const mnemonic = session?.phrase ?? "";
    console.log("[wallet] sendAuthenticated: mnemonic.len=", mnemonic.length);
    return apiFetch<{ success: boolean }>("/api/v1/token/send-authenticated", {
      method: "POST", body: JSON.stringify({ to, amount, mnemonic }),
    });
  },
};

// ── Staking ───────────────────────────────────────────────────────────────────

export const staking = {
  info: () => apiFetch<StakingInfoResponse>("/api/v1/staking/info"),
  stakerInfo: (address: string) =>
    apiFetch<StakerInfoResponse>(`/api/v1/staking/staker/${address}`),
  stake: (amount: string, signature: string, nonce: number) =>
    apiFetch("/api/v1/mining/stake", {
      method: "POST", body: JSON.stringify({ amount, signature, nonce }),
    }),
  unstake: (amount: string, signature: string, nonce: number) =>
    apiFetch("/api/v1/mining/unstake", {
      method: "POST", body: JSON.stringify({ amount, signature, nonce }),
    }),
};

// ── Mining ────────────────────────────────────────────────────────────────────

export const mining = {
  status: () => apiFetch<MiningStatusResponse>("/api/v1/mining/status").catch(() => null),
};

// ── Blocks ────────────────────────────────────────────────────────────────────

export const blocks = {
  list: (page = 0, pageSize = 25) =>
    apiFetch<BlockListResponse>(`/api/v1/blocks?page=${page}&page_size=${pageSize}`),
  detail: (index: number) =>
    apiFetch<BlockDetailResponse>(`/api/v1/blocks/${index}`),
};

// ── Chat ──────────────────────────────────────────────────────────────────────

export const chat = {
  conversations: () => apiFetch<ChatConversationsResponse>("/api/v1/chat/conversations"),
  messages: (peerWallet: string, limit = 50) =>
    apiFetch<ChatMessagesResponse>(`/api/v1/chat/messages/${peerWallet}?limit=${limit}`),
  send: (to: string, content: string, mnemonic: string) => {
    const encrypted_content = btoa(unescape(encodeURIComponent(content)));
    const nonceBytes = crypto.getRandomValues(new Uint8Array(12));
    const nonce = btoa(String.fromCharCode(...nonceBytes));
    return apiFetch("/api/v1/chat/send", {
      method: "POST", body: JSON.stringify({ to, mnemonic, encrypted_content, nonce }),
    });
  },
  resolve: (identifier: string) =>
    apiFetch<ChatResolveResponse>(`/api/v1/chat/resolve/${identifier}`),
  contactRequests: () => apiFetch<ContactRequestsResponse>("/api/v1/chat/contacts/requests"),
  acceptRequest: (id: string) => apiFetch(`/api/v1/chat/contacts/requests/${id}/accept`, { method: "POST" }),
  declineRequest: (id: string) => apiFetch(`/api/v1/chat/contacts/requests/${id}/decline`, { method: "POST" }),
  sendCoins: (to: string, amount: string, memo?: string) =>
    apiFetch("/api/v1/chat/send-coins", {
      method: "POST", body: JSON.stringify({ to, amount, memo }),
    }),
  requestCoins: (from: string, amount: string, memo?: string) =>
    apiFetch("/api/v1/chat/request-coins", {
      method: "POST", body: JSON.stringify({ from, amount, memo }),
    }),
};

// ── Groups ────────────────────────────────────────────────────────────────────

export const groups = {
  list: () => apiFetch<GroupListResponse>("/api/v1/chat/groups"),
  messages: (groupId: string, limit = 50) =>
    apiFetch<GroupMessagesResponse>(`/api/v1/chat/groups/${groupId}/messages?limit=${limit}`),
  send: (groupId: string, content: string) => {
    const encrypted_content = btoa(unescape(encodeURIComponent(content)));
    return apiFetch(`/api/v1/chat/groups/${groupId}/send`, {
      method: "POST", body: JSON.stringify({ content: encrypted_content }),
    });
  },
  create: (name: string, members: string[]) =>
    apiFetch("/api/v1/chat/groups", {
      method: "POST", body: JSON.stringify({ name, members }),
    }),
};

// ── Announcements ─────────────────────────────────────────────────────────────

export const announcements = {
  list: () => apiFetch<AnnouncementListResponse>("/api/v1/announcements"),
  detail: (id: string) => apiFetch<{ announcement: AnnouncementEntry }>(`/api/v1/announcements/${id}`),
  react: (id: string, emoji: string) =>
    apiFetch(`/api/v1/announcements/${id}/react`, {
      method: "POST", body: JSON.stringify({ emoji }),
    }),
  vote: (id: string, direction: "up" | "down") =>
    apiFetch(`/api/v1/announcements/${id}/vote`, {
      method: "POST", body: JSON.stringify({ direction }),
    }),
};

// ── Games ─────────────────────────────────────────────────────────────────────

export const games = {
  list: () => apiFetch<GameResponse>("/api/v1/games"),
  verified: () => apiFetch<GameResponse>("/api/v1/games/verified"),
  coinBalance: (gameId: string, wallet: string) =>
    apiFetch<GameCoinBalanceResponse>(`/api/v1/games/${gameId}/coins/${wallet}`),
  poolStatus: (gameId: string) =>
    apiFetch<GamingPoolStatus>(`/api/v1/sdk/owner/gaming-pool/status?game_id=${gameId}`),
};

// ── Organization / Servers ────────────────────────────────────────────────────

export const orgs = {
  list: () => apiFetch<{ orgs: any[] }>("/api/v1/orgs"),
  create: (name: string) => apiFetch("/api/v1/orgs/create", { method: "POST", body: JSON.stringify({ name }) }),
  detail: (orgId: string) => apiFetch(`/api/v1/orgs/${orgId}`),
  invite: (orgId: string) => apiFetch(`/api/v1/orgs/${orgId}/invite`, { method: "POST" }),
  createCategory: (orgId: string, name: string) => apiFetch(`/api/v1/orgs/${orgId}/categories`, { method: "POST", body: JSON.stringify({ name }) }),
  createChannel: (orgId: string, name: string, categoryId: string, type: string) => apiFetch(`/api/v1/orgs/${orgId}/channels`, { method: "POST", body: JSON.stringify({ name, category_id: categoryId, type }) }),
  sendMessage: (orgId: string, channelId: string, encryptedContent: string, nonce: string) =>
    apiFetch(`/api/v1/orgs/${orgId}/chat`, { method: "POST", body: JSON.stringify({ channel_id: channelId, encrypted_content: encryptedContent, nonce }) }),
  getMessages: (orgId: string, channelId: string) =>
    apiFetch<{ channel_id: string, messages: Array<{ msg_id: string; sender_wallet: string; sender_name: string; content: string; timestamp: number }> }>(`/api/v1/orgs/${orgId}/chat/${channelId}`),
  leave: (orgId: string) => apiFetch(`/api/v1/orgs/${orgId}/leave`, { method: "POST" }),
  acceptInvite: (inviteId: string) => apiFetch(`/api/v1/orgs/invites/${inviteId}/accept`, { method: "POST" }),
  myInvites: () => apiFetch<{ invites: any[] }>("/api/v1/orgs/invites"),
};

// ── Documents ─────────────────────────────────────────────────────────────────

export const documents = {
  list: (page = 0) =>
    apiFetch<DocumentListResponse>(`/api/v1/documents?page=${page}&page_size=20`),
  search: (q: string) =>
    apiFetch<DocumentListResponse>(`/api/v1/documents/search?q=${encodeURIComponent(q)}`),
  delete: (docId: string) => apiFetch(`/api/v1/documents/${docId}`, { method: "DELETE" }),
};