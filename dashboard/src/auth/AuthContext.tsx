import {
  createContext,
  useContext,
  useState,
  useCallback,
  useEffect,
  type ReactNode,
} from "react";
import type { Session } from "../types/api";
import { loadSession, saveSession, clearSession } from "../store/session";
import { auth as authApi } from "../api/stone";
import { signChallenge } from "./bip39";

// ── Session builder ───────────────────────────────────────────────────────────

async function buildSessionFromLoginResponse(
  apiKey: string,
  walletAddress: string,
  userId: string,
  username: string,
  phrase?: string,
  sessionTokenOverride?: string,
): Promise<Session> {
  let sessionToken = sessionTokenOverride ?? apiKey; // prefer server-issued token

  if (!sessionTokenOverride && phrase) {
    try {
      const challengeRes = await authApi.challenge(walletAddress);
      const sig = await signChallenge(challengeRes.challenge, phrase);
      const verifyRes = await authApi.verify(walletAddress, sig);
      sessionToken = verifyRes.session_token;
    } catch {
      // challenge-response not available or failed — use apiKey as token
    }
  }

  return { sessionToken, apiKey, userId, walletAddress, username, phrase };
}

// ── Context ───────────────────────────────────────────────────────────────────

export interface AuthState {
  session: Session | null;
  /** Login with 12-word phrase */
  login: (phrase: string) => Promise<void>;
  /** Signup with username — returns the new mnemonic phrase (show once!) */
  signup: (username: string) => Promise<string>;
  /** Login via Discord OAuth code */
  loginDiscord: (code: string) => Promise<void>;
  /** Apply an already-resolved session (e.g. from QR polling) */
  applySession: (s: Session) => void;
  /** Store phrase post-login (for QR / Discord users who need it for chat) */
  storePhrase: (phrase: string) => void;
  logout: () => void;
}

const AuthContext = createContext<AuthState | null>(null);

export function AuthProvider({ children }: { children: ReactNode }) {
  const [session, setSession] = useState<Session | null>(() => loadSession());

  // ── Listen for deep-link (stonechain://auth/discord?code=XXX) ─────────────
  useEffect(() => {
    let cleanup: (() => void) | undefined;

    import("@tauri-apps/plugin-deep-link")
      .then(({ onOpenUrl }) => {
        const unlisten = onOpenUrl((urls) => {
          for (const url of urls) {
            try {
              const parsed = new URL(url);
              if (
                parsed.protocol === "stonechain:" &&
                parsed.hostname === "auth" &&
                parsed.pathname === "/discord"
              ) {
                const code = parsed.searchParams.get("code");
                if (code) {
                  void handleDiscordCode(code);
                }
              }
            } catch {}
          }
        });
        cleanup = () => { void unlisten.then((fn) => fn()); };
      })
      .catch(() => { /* deep-link not available in browser preview */ });

    return () => cleanup?.();
  // eslint-disable-next-line react-hooks/exhaustive-deps
  }, []);

  async function handleDiscordCode(code: string) {
    const REDIRECT = "https://www.unrooted.dev/management/login/discord/callback";
    const res = await authApi.discord(code, REDIRECT);
    const s = await buildSessionFromLoginResponse(
      res.api_key,
      res.wallet_address,
      res.id,
      res.name,
    );
    saveSession(s);
    setSession(s);
  }

  const login = useCallback(async (phrase: string) => {
    const res = await authApi.login(phrase);
    const s = await buildSessionFromLoginResponse(
      res.api_key,
      res.wallet_address,
      res.id,
      res.name,
      phrase,
      res.session_token,
    );
    saveSession(s);
    setSession(s);
  }, []);

  const signup = useCallback(async (username: string): Promise<string> => {
    const res = await authApi.signup(username);
    const phrase = res.phrase ?? "";
    const s = await buildSessionFromLoginResponse(
      res.api_key,
      res.wallet_address,
      res.id,
      res.name,
      phrase,
      res.session_token,
    );
    saveSession(s);
    setSession(s);
    return phrase;
  }, []);

  const loginDiscord = useCallback(async (code: string) => {
    await handleDiscordCode(code);
  // eslint-disable-next-line react-hooks/exhaustive-deps
  }, []);

  const applySession = useCallback((s: Session) => {
    saveSession(s);
    setSession(s);
  }, []);

  const storePhrase = useCallback((phrase: string) => {
    setSession((prev) => {
      if (!prev) return prev;
      const updated = { ...prev, phrase };
      saveSession(updated);
      return updated;
    });
  }, []);

  const logout = useCallback(() => {
    clearSession();
    setSession(null);
  }, []);

  return (
    <AuthContext.Provider value={{ session, login, signup, loginDiscord, applySession, storePhrase, logout }}>
      {children}
    </AuthContext.Provider>
  );
}

export function useAuth(): AuthState {
  const ctx = useContext(AuthContext);
  if (!ctx) throw new Error("useAuth must be inside AuthProvider");
  return ctx;
}
