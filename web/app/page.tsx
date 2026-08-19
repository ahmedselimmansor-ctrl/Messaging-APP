"use client";

import { useState } from "react";
import { useRouter } from "next/navigation";
import { APIError, sendCode, signIn, type SendCodeResult } from "@/lib/api";

/**
 * Sign-in: phone, then code, then a display name if the account is new.
 *
 * The server tells us whether the phone is registered in the send-code
 * response, so the name field only appears when it is actually needed.
 */
export default function SignInPage() {
  const router = useRouter();

  const [step, setStep] = useState<"phone" | "code">("phone");
  const [phone, setPhone] = useState("");
  const [code, setCode] = useState("");
  const [displayName, setDisplayName] = useState("");
  const [challenge, setChallenge] = useState<SendCodeResult | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);

  async function onSendCode(e: React.FormEvent) {
    e.preventDefault();
    setError(null);
    setBusy(true);
    try {
      const result = await sendCode(phone.trim());
      setChallenge(result);
      setStep("code");
    } catch (err) {
      setError(describe(err));
    } finally {
      setBusy(false);
    }
  }

  async function onSignIn(e: React.FormEvent) {
    e.preventDefault();
    if (!challenge) return;
    setError(null);
    setBusy(true);
    try {
      await signIn({
        challenge_id: challenge.challenge_id,
        code: code.trim(),
        display_name: challenge.registered ? undefined : displayName.trim(),
      });
      router.push("/chat");
    } catch (err) {
      setError(describe(err));
    } finally {
      setBusy(false);
    }
  }

  return (
    <main style={{ maxWidth: 380, margin: "12vh auto", padding: 24 }}>
      <h1 style={{ fontSize: 24, marginBottom: 4 }}>Sign in</h1>
      <p style={{ color: "var(--text-dim)", marginTop: 0 }}>
        {step === "phone"
          ? "We will send a verification code by SMS."
          : `Enter the ${challenge?.code_length}-digit code we sent to ${phone}.`}
      </p>

      {step === "phone" ? (
        <form onSubmit={onSendCode} style={{ display: "grid", gap: 12 }}>
          <input
            type="tel"
            inputMode="tel"
            autoComplete="tel"
            placeholder="+201234567890"
            value={phone}
            onChange={(e) => setPhone(e.target.value)}
            required
          />
          <button type="submit" disabled={busy || phone.trim().length < 8}>
            {busy ? "Sending…" : "Send code"}
          </button>
        </form>
      ) : (
        <form onSubmit={onSignIn} style={{ display: "grid", gap: 12 }}>
          <input
            inputMode="numeric"
            autoComplete="one-time-code"
            placeholder="12345"
            value={code}
            onChange={(e) => setCode(e.target.value)}
            required
            autoFocus
          />
          {!challenge?.registered && (
            <input
              placeholder="Your name"
              value={displayName}
              onChange={(e) => setDisplayName(e.target.value)}
              required
            />
          )}
          <button type="submit" disabled={busy || code.trim().length === 0}>
            {busy ? "Verifying…" : "Sign in"}
          </button>
          <button
            type="button"
            className="secondary"
            onClick={() => { setStep("phone"); setCode(""); setError(null); }}
          >
            Use a different number
          </button>
        </form>
      )}

      {error && (
        <p role="alert" style={{ color: "var(--danger)", marginTop: 16 }}>
          {error}
        </p>
      )}
    </main>
  );
}

function describe(err: unknown): string {
  if (err instanceof APIError) {
    // A flood-wait carries the exact backoff; showing it beats a generic
    // "try again later" the user cannot act on.
    if (err.isRateLimited && err.body.retry_after) {
      return `Too many attempts. Try again in ${err.body.retry_after} seconds.`;
    }
    return err.body.message;
  }
  return err instanceof Error ? err.message : "Something went wrong.";
}
