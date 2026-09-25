import { getGlobals } from '@settings';
import { getUserByUuid } from '@settings/users';
import { isValidUUID } from '@common';
import { UsageTracker } from '@usage/usage';
import { incrSession, decrSession } from '@usage/sessions';
import {
    safeCloseTcpSocket,
    handleTCPOutBound,
    makeReadableWebSocketStream,
    WS_READY_STATE_OPEN
} from '@protocols/common';

// Verdent fork (Document 1, "BPB Fork Scope" #1, #2): the credential check is
// no longer an equality test against one global UUID — it is a map lookup
// against this Node's KV-backed `proxyUsers` map, written by the Control
// Plane. On match, the resolved configId drives steps 3-4 (usage accounting,
// session admission). On no match, the socket is closed — this is also,
// structurally, the revocation check.

export async function VlOverWSHandler(request: Request, env: Env, ctx: ExecutionContext): Promise<Response> {
    const webSocketPair = new WebSocketPair();
    const [client, webSocket] = Object.values(webSocketPair);
    webSocket.accept();
    webSocket.binaryType = 'arraybuffer';

    let address = '';
    let portWithRandomLog = '';

    const log = (info: string, event?: string) => {
        console.log(`[${address}:${portWithRandomLog}] ${info}`, event || '');
    };

    const earlyDataHeader = request.headers.get('sec-websocket-protocol') || '';
    const readableWebSocketStream = makeReadableWebSocketStream(webSocket, earlyDataHeader, log);

    let remoteSocketWapper: { value: Socket | null } = { value: null };
    let udpStreamWrite: any = null;
    let isDns = false;

    let tracker: UsageTracker | null = null;
    let userConfigId: string | null = null;
    let admitted = false;

    const finalize = async () => {
        if (admitted && userConfigId) await decrSession(env, userConfigId, ctx);
        if (tracker) await tracker.close();
    };

    const writableStream = new WritableStream({
        async write(chunk) {
            if (isDns && udpStreamWrite) {
                return udpStreamWrite(chunk);
            }

            if (remoteSocketWapper.value) {
                const writer = remoteSocketWapper.value.writable.getWriter();
                await writer.write(chunk);
                writer.releaseLock();
                if (tracker) tracker.trackUp(chunk.byteLength);
                return;
            }

            const parsed = await parseVlHeader(chunk, env, ctx, log);

            address = parsed.addressRemote ?? '';
            portWithRandomLog = `${parsed.portRemote ?? 443}--${Math.random()} ${parsed.isUDP ? 'udp ' : 'tcp '} `;

            if (parsed.hasError || !parsed.configId) {
                throw new Error(parsed.message);
            }

            // Verdent fork: concurrent-session admission (Document 1 #5).
            // It happens HERE, after every parse-time rejection above, so the
            // increment and the `admitted` flag that owns the matching
            // decrement are set in one place and cannot drift. Over the limit,
            // refuse cleanly — a client-recognizable close, not a silent hang.
            const admittedNow = await incrSession(
                env,
                parsed.configId,
                parsed.deviceLimit ?? 1,
                ctx
            );

            if (!admittedNow) {
                log('device limit reached');
                throw new Error('device limit reached');
            }

            // Resolution + admission succeeded — open this connection's ledger
            // slice. `admitted` is what finalize() gates the decrement on, so
            // it must be set for every path that incremented, including the
            // UDP rejection below.
            admitted = true;
            userConfigId = parsed.configId;
            tracker = new UsageTracker(parsed.configId, env, ctx);

            const VLResponseHeader = new Uint8Array([parsed.VLVersion![0], 0]);
            const rawClientData = chunk.slice(parsed.rawDataIndex!);

            if (parsed.isUDP) {
                if (parsed.portRemote === 53) {
                    isDns = true;
                    const { write } = await handleUDPOutBound(webSocket, VLResponseHeader, log, tracker);
                    udpStreamWrite = write;
                    await udpStreamWrite(rawClientData);
                    return;
                } else {
                    throw new Error('UDP proxy only enable for DNS which is port 53');
                }
            }

            handleTCPOutBound(
                remoteSocketWapper,
                parsed.addressRemote ?? '',
                parsed.portRemote ?? 443,
                rawClientData,
                webSocket,
                VLResponseHeader,
                log,
                tracker
            );
        },
        close() {
            safeCloseTcpSocket(remoteSocketWapper.value);
            ctx.waitUntil(finalize());
        },
        abort(reason) {
            log(`readableWebSocketStream is abort`, JSON.stringify(reason));
            ctx.waitUntil(finalize());
        },
    });

    readableWebSocketStream
        .pipeTo(writableStream)
        .catch(error => {
            log('readableWebSocketStream pipeTo error', error);
            safeCloseTcpSocket(remoteSocketWapper.value);
            ctx.waitUntil(finalize());
        });

    return new Response(null, {
        status: 101,
        webSocket: client,
    });
}

interface VlParsed {
    hasError: boolean;
    message?: string;
    addressRemote?: string;
    portRemote?: number;
    rawDataIndex?: number;
    VLVersion?: Uint8Array;
    isUDP?: boolean;
    configId?: string;
    deviceLimit?: number;
}

async function parseVlHeader(
    VLBuffer: ArrayBuffer,
    env: Env,
    ctx: ExecutionContext,
    log: Function
): Promise<VlParsed> {
    if (VLBuffer.byteLength < 24) {
        return { hasError: true, message: 'invalid data' };
    }

    const VLVersion = new Uint8Array(VLBuffer.slice(0, 1));
    const slicedBuffer = new Uint8Array(VLBuffer.slice(1, 17));
    const slicedBufferString = stringify(slicedBuffer);

    // Verdent fork: multi-tenant credential lookup (revocation included
    // structurally — a disabled/removed credential closes the socket here).
    const user = await getUserByUuid(env, slicedBufferString);

    if (!user) {
        log('invalid user');
        return { hasError: true, message: 'invalid user' };
    }

    // Verdent fork: admission is NOT done here. parseVlHeader returns the
    // resolved identity and every parse-time rejection happens before the
    // caller increments — see the write handler. Incrementing here and then
    // returning an error (a malformed address, an unsupported command) left
    // the slot charged with nobody owning the refund.

    const optLength = new Uint8Array(VLBuffer.slice(17, 18))[0];
    const command = new Uint8Array(VLBuffer.slice(18 + optLength, 18 + optLength + 1))[0];
    let isUDP = false;

    if (command === 1) {
    } else if (command === 2) {
        isUDP = true;
    } else {
        return {
            hasError: true,
            message: `command ${command} is not supported, command 01-tcp,02-udp,03-mux`,
        };
    }

    const portIndex = 18 + optLength + 1;
    const portBuffer = VLBuffer.slice(portIndex, portIndex + 2);
    const portRemote = new DataView(portBuffer).getUint16(0);

    let addressIndex = portIndex + 2;
    const addressBuffer = new Uint8Array(VLBuffer.slice(addressIndex, addressIndex + 1));
    const addressType = addressBuffer[0];
    let addressLength = 0;
    let addressValueIndex = addressIndex + 1;
    let addressValue = '';

    switch (addressType) {
        case 1:
            addressLength = 4;
            addressValue = new Uint8Array(VLBuffer.slice(addressValueIndex, addressValueIndex + addressLength)).join('.');
            break;

        case 2:
            addressLength = new Uint8Array(VLBuffer.slice(addressValueIndex, addressValueIndex + 1))[0];
            addressValueIndex += 1;
            addressValue = new TextDecoder().decode(VLBuffer.slice(addressValueIndex, addressValueIndex + addressLength));
            break;

        case 3: {
            addressLength = 16;
            const dataView = new DataView(VLBuffer.slice(addressValueIndex, addressValueIndex + addressLength));
            const ipv6 = [];

            for (let i = 0; i < 8; i++) {
                ipv6.push(dataView.getUint16(i * 2).toString(16));
            }

            addressValue = ipv6.join(':');
            break;
        }
        default:
            return {
                hasError: true,
                message: `invalid addressType is ${addressType}`,
            };
    }

    if (!addressValue) {
        return {
            hasError: true,
            message: `addressValue is empty, addressType is ${addressType}`,
        };
    }

    return {
        hasError: false,
        addressRemote: addressValue,
        portRemote,
        rawDataIndex: addressValueIndex + addressLength,
        VLVersion,
        isUDP,
        configId: user.configId,
        deviceLimit: user.deviceLimit ?? 1,
    };
}

function unsafeStringify(arr: Uint8Array, offset = 0) {
    const byteToHex: string[] = [];

    for (let i = 0; i < 256; ++i) {
        byteToHex.push((i + 256).toString(16).slice(1));
    }

    return (
        byteToHex[arr[offset + 0]] +
        byteToHex[arr[offset + 1]] +
        byteToHex[arr[offset + 2]] +
        byteToHex[arr[offset + 3]] +
        '-' +
        byteToHex[arr[offset + 4]] +
        byteToHex[arr[offset + 5]] +
        '-' +
        byteToHex[arr[offset + 6]] +
        byteToHex[arr[offset + 7]] +
        '-' +
        byteToHex[arr[offset + 8]] +
        byteToHex[arr[offset + 9]] +
        '-' +
        byteToHex[arr[offset + 10]] +
        byteToHex[arr[offset + 11]] +
        byteToHex[arr[offset + 12]] +
        byteToHex[arr[offset + 13]] +
        byteToHex[arr[offset + 14]] +
        byteToHex[arr[offset + 15]]
    ).toLowerCase();
}

function stringify(arr: Uint8Array, offset = 0) {
    const uuid = unsafeStringify(arr, offset);

    if (!isValidUUID(uuid)) {
        throw TypeError('Stringified UUID is invalid');
    }

    return uuid;
}

async function handleUDPOutBound(
    webSocket: WebSocket,
    VLResponseHeader: Uint8Array<ArrayBuffer>,
    log: Function,
    tracker: UsageTracker | null = null
) {
    let isVLHeaderSent = false;

    const transformStream = new TransformStream({
        start(_controller) { },
        transform(chunk, controller) {
            for (let index = 0; index < chunk.byteLength;) {
                const lengthBuffer = chunk.slice(index, index + 2);
                const udpPakcetLength = new DataView(lengthBuffer).getUint16(0);
                const udpData = new Uint8Array(chunk.slice(index + 2, index + 2 + udpPakcetLength));
                index = index + 2 + udpPakcetLength;
                controller.enqueue(udpData);
            }
        },
        flush(_controller) { },
    });

    transformStream.readable
        .pipeTo(
            new WritableStream({
                async write(chunk) {
                    // Verdent fork: the DNS leg is billed like any other leg.
                    // This path relayed every query and answer without ever
                    // touching the tracker, so a customer could push all their
                    // traffic through in-tunnel DNS and the plan's quota would
                    // never move — under-billing on exactly the path the
                    // gaming profile's "antisanction DNS" promise sells.
                    // Counted here as the upstream query, matching the TCP
                    // leg's trackUp in common.ts.
                    if (tracker) tracker.trackUp(chunk.byteLength);

                    // Verdent fork: resolve through the Node's configured DoH
                    // endpoint, not a hardcoded one. This is the DNS path the
                    // Tier A "antisanction DNS" gaming promise rides on, so a
                    // profile's doh_endpoint has to reach it or the promise is
                    // decoration. Trailing query params are stripped: this
                    // request carries a raw dns-message body, not a ?name=.
                    const { dohUrl } = getGlobals();
                    const dnsEndpoint = (dohUrl || 'https://cloudflare-dns.com/dns-query').split('?')[0];
                    const resp = await fetch(dnsEndpoint, {
                        method: 'POST',
                        headers: {
                            'content-type': 'application/dns-message',
                        },
                        body: chunk
                    });

                    const dnsQueryResult = await resp.arrayBuffer();
                    const udpSize = dnsQueryResult.byteLength;

                    // Downstream leg: the resolver's answer, counted only when
                    // a response actually arrived, so a failed lookup is not
                    // billed to the customer.
                    if (tracker) tracker.trackDown(udpSize);

                    const udpSizeBuffer = new Uint8Array([(udpSize >> 8) & 0xff, udpSize & 0xff]);

                    if (webSocket.readyState === WS_READY_STATE_OPEN) {
                        log(`doh success and dns message length is ${udpSize}`);

                        if (isVLHeaderSent) {
                            webSocket.send(await new Blob([udpSizeBuffer, dnsQueryResult]).arrayBuffer());
                        } else {
                            webSocket.send(await new Blob([VLResponseHeader, udpSizeBuffer, dnsQueryResult]).arrayBuffer());
                            isVLHeaderSent = true;
                        }
                    }
                },
            })
        )
        .catch((error) => {
            log('dns udp has error' + error);
        });

    const writer = transformStream.writable.getWriter();

    return {
        async write(chunk: ArrayBuffer) {
            await writer.write(chunk);
        },
    };
}
