#!/usr/bin/env node
// Capture server: spawn tshark and stream simplified fields via Server-Sent Events
// Falls back to `cap` (optional native module) if tshark is unavailable.
//$env:TSHARK_PATH='C:\Program Files\Wireshark\tshark.exe'
// >> npm run capture -- 8
const http = require("http");
const { spawn } = require("child_process");

const PORT = process.env.PORT || 4000;
// Allow passing interface as first arg or via IFACE env
const INTERFACE = process.argv[2] || process.env.IFACE || "Wi-Fi";

// Allow overriding tshark binary via env or --tshark-path <path>
function resolveTsharkBin() {
  if (process.env.TSHARK_PATH) return process.env.TSHARK_PATH;
  const idx = process.argv.indexOf("--tshark-path");
  if (idx !== -1 && process.argv.length > idx + 1) return process.argv[idx + 1];
  return "tshark";
}
const TSHARK_BIN = resolveTsharkBin();

function createTsharkArgs(iface) {
  // Request many common fields so we can build a Wireshark-like details object
  return [
    "-i",
    iface,
    "-l",
    "-T",
    "fields",
    // frame
    "-e",
    "frame.number",
    "-e",
    "frame.time_relative",
    "-e",
    "frame.len",
    "-e",
    "frame.cap_len",
    // ethernet
    "-e",
    "eth.src",
    "-e",
    "eth.dst",
    // ip
    "-e",
    "ip.src",
    "-e",
    "ip.dst",
    "-e",
    "ip.proto",
    // tcp/udp
    "-e",
    "tcp.srcport",
    "-e",
    "tcp.dstport",
    "-e",
    "tcp.flags",
    "-e",
    "udp.srcport",
    "-e",
    "udp.dstport",
    // application-layer
    "-e",
    "http.request.method",
    "-e",
    "http.request.uri",
    "-e",
    "dns.qry.name",
    // generic
    "-e",
    "frame.protocols",
    "-e",
    "_ws.col.Info",
    // raw hex payload when available
    "-e",
    "data.data",
    "-E",
    "header=y",
    "-E",
    "separator=\t",
  ];
}

const server = http.createServer((req, res) => {
  if (req.url !== "/events") {
    res.writeHead(404, { "Content-Type": "text/plain" });
    return res.end("Not found");
  }

  res.writeHead(200, {
    "Content-Type": "text/event-stream",
    "Cache-Control": "no-cache",
    Connection: "keep-alive",
    "Access-Control-Allow-Origin": "*",
  });
  res.write("\n");

  console.log(`Client connected, starting capture on interface ${INTERFACE}`);

  const args = createTsharkArgs(INTERFACE);
  let tshark;
  try {
    tshark = spawn(TSHARK_BIN, args);
  } catch (e) {
    tshark = null;
  }

  if (tshark) {
    let firstLine = true;
    let headers = [];
    tshark.stdout.setEncoding("utf8");
    tshark.stdout.on("data", (chunk) => {
      const lines = chunk.split(/\r?\n/);
      for (let line of lines) {
        if (!line) continue;
        // header row
        if (firstLine) {
          headers = line.trim().split("\t");
          firstLine = false;
          continue;
        }
        const parts = line.trim().split("\t");
        const obj = {};
        for (let i = 0; i < headers.length; i++) {
          obj[headers[i]] = parts[i] || "";
        }

        // Build details object similar to Wireshark tree
        const details = {};
        // Frame
        details.frame = {
          title: `Frame ${obj["frame.number"] || ""}: ${
            obj["frame.len"] || ""
          } bytes on wire`,
          fields: [
            `Arrival Time: ${obj["frame.time_relative"] || ""}`,
            `Frame Length: ${obj["frame.len"] || ""} bytes`,
            `Capture Length: ${obj["frame.cap_len"] || ""} bytes`,
            `Frame Number: ${obj["frame.number"] || ""}`,
            `Protocols in frame: ${obj["frame.protocols"] || ""}`,
          ],
        };

        // Ethernet
        if (obj["eth.src"] || obj["eth.dst"]) {
          details.ethernet = {
            title: "Ethernet II",
            fields: [
              `Destination: ${obj["eth.dst"] || ""}`,
              `Source: ${obj["eth.src"] || ""}`,
            ],
          };
        }

        // IP
        if (obj["ip.src"] || obj["ip.dst"]) {
          details.ipv4 = {
            title: "Internet Protocol",
            fields: [
              `Source Address: ${obj["ip.src"] || ""}`,
              `Destination Address: ${obj["ip.dst"] || ""}`,
              `Protocol: ${obj["ip.proto"] || ""}`,
            ],
          };
        }

        // TCP
        if (obj["tcp.srcport"] || obj["tcp.dstport"]) {
          details.tcp = {
            title: "Transmission Control Protocol",
            fields: [
              `Source Port: ${obj["tcp.srcport"] || ""}`,
              `Destination Port: ${obj["tcp.dstport"] || ""}`,
              `Flags: ${obj["tcp.flags"] || ""}`,
            ],
          };
        }

        // UDP
        if (obj["udp.srcport"] || obj["udp.dstport"]) {
          details.udp = {
            title: "User Datagram Protocol",
            fields: [
              `Source Port: ${obj["udp.srcport"] || ""}`,
              `Destination Port: ${obj["udp.dstport"] || ""}`,
            ],
          };
        }

        // Application layer: HTTP/DNS
        if (obj["http.request.method"] || obj["http.request.uri"]) {
          details.application = {
            title: "HTTP",
            fields: [
              `Method: ${obj["http.request.method"] || ""}`,
              `URI: ${obj["http.request.uri"] || ""}`,
            ],
          };
        }
        if (obj["dns.qry.name"]) {
          details.dns = {
            title: "DNS",
            fields: [`Query: ${obj["dns.qry.name"]}`],
          };
        }

        const pkt = {
          id: obj["frame.number"] ? Number(obj["frame.number"]) : null,
          time: obj["frame.time_relative"] || "0.000000",
          timestamp: Date.now(),
          source: obj["ip.src"] || "",
          destination: obj["ip.dst"] || "",
          protocol: obj["frame.protocols"] || "",
          length: obj["frame.len"] ? Number(obj["frame.len"]) : 0,
          info: obj["_ws.col.Info"] || "",
          raw: obj["data.data"] || "",
          details,
        };
        res.write("data: " + JSON.stringify(pkt) + "\n\n");
      }
    });

    tshark.stderr.on("data", (d) =>
      console.error("tshark stderr:", d.toString())
    );

    tshark.on("error", (err) => {
      console.error("Failed to start tshark:", err.message);
      res.write(
        "data: " +
          JSON.stringify({
            error:
              "tshark failed: " +
              err.message +
              ". Provide a full path via TSHARK_PATH or --tshark-path",
          }) +
          "\n\n"
      );
      startCapFallback(res, INTERFACE);
    });
  } else {
    startCapFallback(res, INTERFACE);
  }

  req.on("close", () => {
    console.log("Client disconnected, stopping capture");
    try {
      if (tshark) tshark.kill();
    } catch (e) {}
    try {
      if (capInstance && typeof capInstance.close === "function")
        capInstance.close();
    } catch (e) {}
    res.end();
  });
});

// Try binding to requested port, otherwise increment
let startPort = Number(PORT) || 4000;
const MAX_ATTEMPTS = 50;
function tryListen(port, attempt = 0) {
  server.once("error", (err) => {
    if (err && err.code === "EADDRINUSE" && attempt < MAX_ATTEMPTS) {
      console.warn(`Port ${port} in use, trying ${port + 1}...`);
      tryListen(port + 1, attempt + 1);
    } else {
      console.error("Failed to bind port:", err);
      process.exit(1);
    }
  });
  server.once("listening", () => {
    const addr = server.address();
    const p = typeof addr === "object" && addr ? addr.port : port;
    console.log(`Capture server listening on http://localhost:${p}/events`);
    console.log(
      "Tshark args example:",
      TSHARK_BIN,
      createTsharkArgs(INTERFACE).join(" ")
    );
    if (TSHARK_BIN !== "tshark") {
      console.log(`Using tshark binary: ${TSHARK_BIN}`);
    }
  });
  server.listen(port);
}
tryListen(startPort);

// cap fallback
let capInstance = null;
function startCapFallback(res, ifaceName) {
  let Cap;
  try {
    Cap = require("cap").Cap;
  } catch (e) {
    console.error("cap missing:", e.message);
    res.write(
      "data:" +
        JSON.stringify({ error: "cap module missing: " + e.message }) +
        "\n\n"
    );
    return;
  }
  const { decoders } = require("cap");
  const PROTOCOL = decoders.PROTOCOL;

  const devices = Cap.deviceList ? Cap.deviceList() : [];
  if (!devices.length) {
    res.write(
      "data:" + JSON.stringify({ error: "No capture devices found" }) + "\n\n"
    );
    return;
  }
  let device = devices.find(
    (d) =>
      d.name.includes(ifaceName) ||
      (d.description && d.description.includes(ifaceName))
  );
  if (!device) device = devices[0];

  try {
    const c = new Cap();
    capInstance = c;
    const filter = "";
    const bufSize = 10 * 1024 * 1024;
    const buffer = Buffer.alloc(65535);
    const linkType = c.open(device.name, filter, bufSize, buffer);
    c.setMinBytes && c.setMinBytes(0);
    console.log("cap fallback capturing on", device.name, linkType);
    c.on("packet", function (nbytes, trunc) {
      try {
        let src = "",
          dst = "",
          proto = "";
        try {
          if (linkType === "ETHERNET") {
            const ret = decoders.Ethernet(buffer);
            if (ret.info.type === PROTOCOL.ETHERNET.IPV4) {
              const ip = decoders.IPV4(buffer, ret.offset);
              src = ip.info.srcaddr;
              dst = ip.info.dstaddr;
              proto = ip.info.protocol;
            }
          }
        } catch (e) {}
        const pkt = {
          id: null,
          time: (Date.now() / 1000).toFixed(6),
          source: src,
          destination: dst,
          protocol: String(proto),
          length: nbytes,
          info: trunc ? "truncated" : "raw",
          raw: buffer.slice(0, nbytes).toString("hex"),
        };
        res.write("data: " + JSON.stringify(pkt) + "\n\n");
      } catch (err) {
        console.error("cap packet error", err);
      }
    });
  } catch (err) {
    console.error("cap open failed", err);
    res.write(
      "data:" +
        JSON.stringify({ error: "cap open failed: " + (err.message || err) }) +
        "\n\n"
    );
  }
}
