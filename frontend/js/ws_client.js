/**
 * Minimal WebSocket telemetry client (see docs/DESIGN_SPEC.md, Phase 6).
 *
 * Deliberately has NO auto-reconnect/backoff logic yet: a dropped
 * connection just flips the status to "disconnected" and logs to the
 * console. Robust reconnection is explicitly deferred to Phase 10
 * (hardening), per the implementation plan's own phase split.
 */

function connectTelemetry(onMessage, onStatusChange) {
  const protocol = window.location.protocol === "https:" ? "wss:" : "ws:";
  const url = `${protocol}//${window.location.host}/ws/telemetry`;

  const socket = new WebSocket(url);

  socket.onopen = () => {
    onStatusChange(true);
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
    onStatusChange(false);
  };

  socket.onerror = (err) => {
    console.error("ws_client: telemetry connection error", err);
  };

  return socket;
}
