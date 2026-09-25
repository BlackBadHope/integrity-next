// Host-supplied admission binds the exact offer. No provider key reaches JS.
// Browser timers are cleanup, NOT a provider-enforced duration/spend limit.
export function createVoiceClient({admit, audioElement, onStatus = () => {}}) {
  if (typeof admit !== "function") throw new Error("Host admission is required");
  let generation = 0, stream = null, peer = null, controller = null, timer = null;
  const stop = () => {
    generation += 1;
    controller?.abort(); controller = null;
    clearTimeout(timer); timer = null;
    stream?.getTracks().forEach(track => track.stop()); stream = null;
    peer?.close(); peer = null;
    if (audioElement) audioElement.srcObject = null;
    onStatus("stopped");
  };
  const start = async () => {
    stop();
    const epoch = generation;
    const current = () => generation === epoch;
    controller = new AbortController();
    const signal = controller.signal;
    timer = setTimeout(() => {
      if (current()) { stop(); onStatus("setup-timeout-no-automatic-retry"); }
    }, 30000);
    let acquired = null;
    try {
      onStatus("requesting-microphone");
      acquired = await navigator.mediaDevices.getUserMedia({audio: true});
      if (!current()) { acquired.getTracks().forEach(track => track.stop()); return; }
      stream = acquired;
      const pc = new RTCPeerConnection();
      peer = pc;
      pc.ontrack = ({streams}) => {
        if (current() && audioElement) {
          audioElement.srcObject = streams[0];
          Promise.resolve(audioElement.play()).catch(() => {
            if (current()) onStatus("playback-needs-user-click");
          });
        }
      };
      stream.getTracks().forEach(track => pc.addTrack(track, stream));
      // Required data channel; incoming events are NOT forwarded to any tools.
      pc.createDataChannel("oai-events");
      const offer = await pc.createOffer();
      if (!current()) return;
      await pc.setLocalDescription(offer);
      if (!current()) return;
      const offerBytes = new TextEncoder().encode(offer.sdp);
      const digest = new Uint8Array(await crypto.subtle.digest("SHA-256", offerBytes));
      if (!current()) return;
      const offerSha256 = "sha256:" + Array.from(digest, b => b.toString(16).padStart(2, "0")).join("");
      onStatus("awaiting-exact-admission");
      const authorization = await admit({offerSha256, offer: offer.sdp, signal});
      if (!current()) return;
      if (!authorization || !authorization.requestId || !authorization.bearer || !authorization.csrf)
        throw new Error("Exact admission unavailable");
      const response = await fetch("/voice/session", {
        method: "POST", credentials: "same-origin", cache: "no-store", redirect: "error", signal,
        headers: {"Content-Type": "application/sdp", "Authorization": "Bearer " + authorization.bearer,
          "X-Integrity-CSRF": authorization.csrf, "X-Integrity-Request": authorization.requestId},
        body: offer.sdp
      });
      if (!response.ok) throw new Error("Session was not established; do not retry automatically");
      if (response.headers.get("content-type")?.split(";", 1)[0] !== "application/sdp")
        throw new Error("Invalid answer type");
      const reader = response.body.getReader();
      const chunks = []; let length = 0;
      try {
        while (true) {
          const {value, done} = await reader.read();
          if (done) break;
          length += value.length;
          if (length > 65536) { await reader.cancel(); throw new Error("Answer too large"); }
          chunks.push(value);
        }
      } finally { reader.releaseLock(); }
      const bytes = new Uint8Array(length); let offset = 0;
      for (const chunk of chunks) { bytes.set(chunk, offset); offset += chunk.length; }
      const answer = new TextDecoder("utf-8", {fatal: true}).decode(bytes);
      if (!answer.startsWith("v=0")) throw new Error("Invalid answer");
      if (!current()) return;
      await pc.setRemoteDescription({type: "answer", sdp: answer});
      if (!current()) return;
      onStatus("connected-unverified");
      clearTimeout(timer);
      timer = setTimeout(stop, 60000);
    } catch (error) {
      if (current()) { stop(); onStatus("failed-no-automatic-retry"); }
      if (error?.name !== "AbortError") throw new Error("Voice session failed; outcome may be unknown");
    }
  };
  return {start, stop};
}
