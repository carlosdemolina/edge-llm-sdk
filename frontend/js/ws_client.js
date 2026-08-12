/**
 * WebSocket telemetry client (see docs/ARCHITECTURE.md).
 *
 * Auto-reconnects with exponential backoff + jitter on any drop (server
 * restart, network blip, etc.). `onStatusChange` is
 * called with one of "connected" | "disconnected" | "reconnecting" so the
 * UI can distinguish "just dropped" from "actively retrying" instead of a
 * flat connected/disconnected boolean.
 */

const WS_RECONNECT_BASE_MS = 1000;
const WS_RECONNECT_MAX_MS = 30000;

function connectTelemetry(onMessage, onStatusChange) {
  const protocol = window.location.protocol === "https:" ? "wss:" : "ws:";
  const url = `${protocol}//${window.location.host}/ws/telemetry`;

  let socket = null;
  let reconnectAttempt = 0;
  let reconnectTimer = null;
  let closedByCaller = false;

  function scheduleReconnect() {
    if (closedByCaller) return;
    // Full jitter: a random delay in [0, backoff] avoids every open tab
    // hammering the server in lockstep after a shared outage, and caps out
    // at WS_RECONNECT_MAX_MS so a long outage still retries at a sane pace.
    const backoff = Math.min(WS_RECONNECT_MAX_MS, WS_RECONNECT_BASE_MS * 2 ** reconnectAttempt);
    reconnectAttempt += 1;
    onStatusChange("reconnecting");
    reconnectTimer = setTimeout(open, Math.random() * backoff);
  }

  function open() {
    socket = new WebSocket(url);

    socket.onopen = () => {
      reconnectAttempt = 0;
      onStatusChange("connected");
    };

    socket.onmessage = (event) => {
      let data;
      try {
        data = JSON.parse(event.data);
      } catch (err) {
        console.error("ws_client: failed to parse telemetry message", err);
        return;
      }
      onMessage(data);
    };

    socket.onclose = () => {
      console.warn("ws_client: telemetry connection closed");
      onStatusChange("disconnected");
      scheduleReconnect();
    };

    socket.onerror = (err) => {
      // A failed/dropped connection always fires onclose right after this,
      // so reconnection scheduling stays there rather than being duplicated
      // here.
      console.error("ws_client: telemetry connection error", err);
    };
  }

  open();

  return {
    close() {
      closedByCaller = true;
      if (reconnectTimer !== null) clearTimeout(reconnectTimer);
      if (socket) socket.close();
    },
  };
}

