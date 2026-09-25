// Verdent fork: usage accounting (Document 3, §K).
// Per-connection tracker instruments the relay loop, accumulates byte counts
// in memory, and flushes idempotent usage events to the Control Plane's
// ingest endpoint on an interval OR a size threshold, whichever comes first.
// Every event carries (connectionId, sequenceNumber) — enforced unique
// server-side, so a retried flush is a no-op, never an accumulate.

import { getGlobals } from '@settings';
import { getNodeSecret } from '@settings/users';

const FLUSH_INTERVAL_MS = 30_000;   // ~30s — Document 3: every 30-60s
const FLUSH_THRESHOLD_BYTES = 1024 * 1024;  // or a few MB, whichever first

export interface UsageEvent {
    configId: string;
    connectionId: string;
    sequenceNumber: number;
    bytesUp: number;
    bytesDown: number;
    windowStartedAt: string;   // ISO
    reportedAt: string;        // ISO
}

export class UsageTracker {
    public readonly configId: string;
    public readonly connectionId: string;
    public sequenceNumber = 0;
    public bytesUp = 0;
    public bytesDown = 0;
    public windowStartedAt = Date.now();
    public closed = false;

    private flushing = false;
    private flushQueued = false;
    private lastFlushAt = Date.now();

    constructor(configId: string, private env: Env, private ctx: ExecutionContext) {
        this.configId = configId;
        this.connectionId = crypto.randomUUID();
    }

    public trackUp(bytes: number) {
        if (this.closed) return;
        this.bytesUp += bytes;
        this.maybeFlush();
    }

    public trackDown(bytes: number) {
        if (this.closed) return;
        this.bytesDown += bytes;
        this.maybeFlush();
    }

    // Called on connection close: final flush via ctx.waitUntil, covering
    // whatever accumulated since the last periodic flush (Document 3, #2).
    public async close() {
        if (this.closed) return;
        this.closed = true;

        if (this.pendingBytes() === 0) return;

        await this.flush();
    }

    private pendingBytes(): number {
        return this.bytesUp + this.bytesDown;
    }

    private maybeFlush() {
        if (this.flushing || this.closed) return;

        const elapsed = Date.now() - this.lastFlushAt;
        const pending = this.pendingBytes();

        if (elapsed >= FLUSH_INTERVAL_MS || pending >= FLUSH_THRESHOLD_BYTES) {
            this.scheduleFlush();
        }
    }

    private scheduleFlush() {
        if (this.flushing || this.flushQueued || this.closed) return;
        this.flushQueued = true;
        this.lastFlushAt = Date.now();
        this.ctx.waitUntil(this.flush().catch(error =>
            console.error('Usage flush failed (queued):', error)
        ));
    }

    public async flush(): Promise<void> {
        if (this.flushing) {
            this.flushQueued = true;
            return;
        }

        this.flushing = true;
        this.flushQueued = false;

        // Snapshot the slice. The counters are NOT cleared yet — see the
        // success branch below for why clearing here loses bytes.
        const bytesUp = this.bytesUp;
        const bytesDown = this.bytesDown;
        const windowStartedAt = this.windowStartedAt;

        if (bytesUp === 0 && bytesDown === 0) {
            this.flushing = false;
            return;
        }

        const event: UsageEvent = {
            configId: this.configId,
            connectionId: this.connectionId,
            // The number this slice WILL have. It is only committed on
            // success (see below): a retry must reuse the same number so the
            // server's (connectionId, sequenceNumber) key can recognise it.
            // Advancing it up front would make every retry look like new
            // traffic and double-count the same bytes.
            sequenceNumber: this.sequenceNumber + 1,
            bytesUp,
            bytesDown,
            windowStartedAt: new Date(windowStartedAt).toISOString(),
            reportedAt: new Date().toISOString()
        };

        try {
            await postUsageEvent(this.env, event);

            // ONLY now is this slice safe to drop. Clearing before the await
            // (as this did) meant a failed POST destroyed the bytes: the
            // counters were already back at 0, so the "next flush retries"
            // comment was never true and the traffic was simply lost. Every
            // Redis blip would have handed customers free bandwidth.
            //
            // Subtract rather than assign: traffic keeps arriving during the
            // await, and those bytes belong to the NEXT window.
            this.sequenceNumber = event.sequenceNumber;
            this.bytesUp -= bytesUp;
            this.bytesDown -= bytesDown;
            this.windowStartedAt = Date.now();
            this.lastFlushAt = Date.now();
        } catch (error) {
            // Never crash the relay on accounting failure. The slice is kept
            // AND the sequence number is not advanced, so the retry resends
            // the identical (connectionId, sequenceNumber) pair. If the first
            // POST actually landed and only the response was lost, the server
            // sees the duplicate key and drops it — no double count. If it
            // never landed, the retry records it once. Either way the bytes
            // are counted exactly once, which is only true because the number
            // is stable across retries.
            console.error('Usage flush failed, bytes retained for retry:', error);
            this.lastFlushAt = Date.now();
        } finally {
            this.flushing = false;
            // A flush requested while this one was in flight has not run yet;
            // without this it would wait for the next track() call, which on
            // an idle connection never comes.
            if (this.flushQueued && this.pendingBytes() > 0 && !this.closed) {
                this.flushQueued = false;
                this.scheduleFlush();
            }
        }
    }
}

// ----------------------------------------------------------------------------
// HTTP + HMAC signing
// ----------------------------------------------------------------------------
// Headers (Document 5, "Node-to-Control-Plane auth" + replay protection):
//   x-verdent-timestamp  ms epoch, validated server-side within a short window
//   x-verdent-nonce      random hex, unique per request
//   x-verdent-signature  hex(HMAC-SHA256(nodeSecret, `${nodeId}.${ts}.${nonce}.${body}`))

async function postUsageEvent(env: Env, event: UsageEvent): Promise<void> {
    const { nodeId, verdentUrl } = getGlobals();
    const nodeSecret = await getNodeSecret(env);

    if (!nodeSecret) {
        throw new Error('nodeSecret missing from KV — usage events cannot be signed');
    }

    const body = JSON.stringify(event);
    const timestamp = String(Date.now());
    const nonce = crypto.randomUUID().replace(/-/g, '');
    const signature = await hmacHex(nodeSecret, `${nodeId}.${timestamp}.${nonce}.${body}`);

    const res = await fetch(`${verdentUrl}/internal/nodes/${nodeId}/usage`, {
        method: 'POST',
        headers: {
            'content-type': 'application/json',
            'x-verdent-node-id': nodeId,
            'x-verdent-timestamp': timestamp,
            'x-verdent-nonce': nonce,
            'x-verdent-signature': signature
        },
        body
    });

    if (!res.ok) {
        throw new Error(`Ingest endpoint returned ${res.status}`);
    }
}

export async function hmacHex(secret: string, message: string): Promise<string> {
    const encoder = new TextEncoder();
    const key = await crypto.subtle.importKey(
        'raw', encoder.encode(secret), { name: 'HMAC', hash: 'SHA-256' }, false, ['sign']
    );
    const mac = await crypto.subtle.sign('HMAC', key, encoder.encode(message));
    return Array.from(new Uint8Array(mac), b => b.toString(16).padStart(2, '0')).join('');
}
