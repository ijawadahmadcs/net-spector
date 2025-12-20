"use client";
import React, { useState, useEffect, useRef } from "react";
import {
  Play,
  Square,
  Pause,
  Trash2,
  Download,
  Search,
  Filter,
  Wifi,
  Activity,
  Settings,
  BarChart3,
  Network,
  Info,
  Database,
} from "lucide-react";

const NetSpector = () => {
  const [packets, setPackets] = useState<any[]>([]);
  const [selectedPacket, setSelectedPacket] = useState<any>(null);
  const [filter, setFilter] = useState("");
  const [appliedFilter, setAppliedFilter] = useState("");
  const [searchTerm, setSearchTerm] = useState("");
  const [showStats, setShowStats] = useState(false);
  const [showSettings, setShowSettings] = useState(false);
  const [captureSpeed, setCaptureSpeed] = useState(1000);
  const [maxPackets, setMaxPackets] = useState(1000);
  const [networkInterface, setNetworkInterface] = useState("eth0");
  const [promiscuousMode, setPromiscuousMode] = useState(false);
  const [useLiveCapture, setUseLiveCapture] = useState(false);
  const [captureServerUrl, setCaptureServerUrl] = useState(
    "http://localhost:4000"
  );
  const [autoScroll, setAutoScroll] = useState(true);
  const [showWelcome, setShowWelcome] = useState(true);
  const [startTime, setStartTime] = useState(0);
  const [capturing, setCapturing] = useState(false);
  const [paused, setPaused] = useState(false);
  const [expandAll, setExpandAll] = useState(false);
  const [showRawJson, setShowRawJson] = useState(false);

  const captureInterval = useRef<NodeJS.Timeout | null>(null);
  const packetId = useRef(1);
  const listEndRef = useRef<HTMLTableRowElement | null>(null);
  const listContainerRef = useRef<HTMLDivElement>(null);
  const startTimeRef = useRef<number | null>(null);
  const eventSourceRef = useRef<EventSource | null>(null);

  const protocolColors: Record<string, string> = {
    TCP: "bg-blue-100 text-blue-800 border-blue-300",
    UDP: "bg-green-100 text-green-800 border-green-300",
    HTTP: "bg-purple-100 text-purple-800 border-purple-300",
    DNS: "bg-yellow-100 text-yellow-800 border-yellow-300",
    ARP: "bg-orange-100 text-orange-800 border-orange-300",
    ICMP: "bg-red-100 text-red-800 border-red-300",
    HTTPS: "bg-indigo-100 text-indigo-800 border-indigo-300",
    SSH: "bg-pink-100 text-pink-800 border-pink-300",
    FTP: "bg-cyan-100 text-cyan-800 border-cyan-300",
    SMTP: "bg-teal-100 text-teal-800 border-teal-300",
    IMAP: "bg-lime-100 text-lime-800 border-lime-300",
    POP3: "bg-amber-100 text-amber-800 border-amber-300",
  };

  const buildDetails = (pkt: any) => {
    const src = pkt.source || "";
    const dst = pkt.destination || "";
    const len = pkt.length || 0;
    const arrival =
      pkt.time || (pkt.timestamp ? new Date(pkt.timestamp).toISOString() : "");
    const proto = pkt.protocol || "";
    const info = pkt.info || "";
    const rawDetails = pkt.details || {};

    const details: Record<string, { title: string; fields: string[] }> = {};

    // Parse protocol chain
    const protoParts = proto.split(":").filter(Boolean);

    // Frame - Prefer server-provided details if available
    if (rawDetails.frame?.fields && Array.isArray(rawDetails.frame.fields)) {
      details.frame = {
        title: rawDetails.frame.title || `${pkt.id || ""} ${len} `,
        fields: rawDetails.frame.fields,
      };
    } else {
      const frameFields: string[] = [];
      if (arrival) frameFields.push(`Arrival Time: ${arrival}`);
      if (len) frameFields.push(`Frame Length: ${len} bytes`);
      if (len) frameFields.push(`Capture Length: ${len} bytes`);
      if (pkt.id) frameFields.push(`Frame Number: ${pkt.id}`);
      if (proto) frameFields.push(`Protocols in frame: ${proto}`);

      if (frameFields.length > 0) {
        details.frame = {
          title: `${pkt.id || ""} ${len} `,
          fields: frameFields,
        };
      }
    }

    // Ethernet - Only show if we have ethernet data
    const ethernetFields: string[] = [];

    if (
      rawDetails.ethernet?.fields &&
      Array.isArray(rawDetails.ethernet.fields)
    ) {
      ethernetFields.push(...rawDetails.ethernet.fields);
    } else {
      if (rawDetails["eth.dst"])
        ethernetFields.push(`Destination: ${rawDetails["eth.dst"]}`);
      if (rawDetails["eth.src"])
        ethernetFields.push(`Source: ${rawDetails["eth.src"]}`);
    }

    if (protoParts.includes("eth") || protoParts.includes("ethertype")) {
      if (rawDetails["eth.type"]) {
        ethernetFields.push(`Type: ${rawDetails["eth.type"]}`);
      } else if (protoParts[1]) {
        const etherTypeMap: Record<string, string> = {
          ipv4: "IPv4 (0x0800)",
          ip: "IPv4 (0x0800)",
          ipv6: "IPv6 (0x86dd)",
          arp: "ARP (0x0806)",
        };
        const nextProto = protoParts[1];
        if (etherTypeMap[nextProto]) {
          ethernetFields.push(`Type: ${etherTypeMap[nextProto]}`);
        }
      }
    }

    if (ethernetFields.length > 0) {
      details.ethernet = {
        title: rawDetails.ethernet?.title || "",
        fields: ethernetFields,
      };
    }

    // ARP - Only show if ARP is in protocol chain
    if (protoParts.includes("arp")) {
      const arpFields: string[] = [];

      if (rawDetails.arp?.fields) {
        arpFields.push(...rawDetails.arp.fields);
      } else {
        arpFields.push(`Hardware type: Ethernet (1)`);
        arpFields.push(`Protocol type: IPv4 (0x0800)`);
        arpFields.push(`Hardware size: 6`);
        arpFields.push(`Protocol size: 4`);

        if (info.includes("Probe")) {
          arpFields.push(`Opcode: ARP Probe (1)`);
        } else if (info.includes("Reply")) {
          arpFields.push(`Opcode: ARP Reply (2)`);
        } else if (info.includes("Request")) {
          arpFields.push(`Opcode: ARP Request (1)`);
        }

        const arpMatch = info.match(/Who has ([\d.]+)\?/);
        if (arpMatch) arpFields.push(`Target IP address: ${arpMatch[1]}`);
      }

      if (arpFields.length > 0) {
        details.arp = {
          title: "Address Resolution Protocol",
          fields: arpFields,
        };
      }
    }

    // IPv6 - Only show if IPv6 is in protocol chain
    if (protoParts.includes("ipv6")) {
      const ipv6Fields: string[] = [];

      if (rawDetails.ipv6?.fields) {
        ipv6Fields.push(...rawDetails.ipv6.fields);
      } else {
        ipv6Fields.push(`Version: 6`);
        if (rawDetails["ipv6.tclass"])
          ipv6Fields.push(`Traffic Class: ${rawDetails["ipv6.tclass"]}`);
        if (rawDetails["ipv6.flow"])
          ipv6Fields.push(`Flow Label: ${rawDetails["ipv6.flow"]}`);

        const payloadLen = Math.max(0, len - 40);
        if (payloadLen > 0)
          ipv6Fields.push(`Payload Length: ${payloadLen} bytes`);

        if (protoParts.includes("hopopts")) {
          ipv6Fields.push(`Next Header: Hop-by-Hop Option (0)`);
        } else if (protoParts.includes("icmpv6")) {
          ipv6Fields.push(`Next Header: ICMPv6 (58)`);
        } else if (protoParts.includes("udp")) {
          ipv6Fields.push(`Next Header: UDP (17)`);
        } else if (protoParts.includes("tcp")) {
          ipv6Fields.push(`Next Header: TCP (6)`);
        }

        if (rawDetails["ipv6.hlim"]) {
          ipv6Fields.push(`Hop Limit: ${rawDetails["ipv6.hlim"]}`);
        }
      }

      if (src) ipv6Fields.push(`Source Address: ${src}`);
      if (dst) ipv6Fields.push(`Destination Address: ${dst}`);

      if (ipv6Fields.length > 2) {
        details.ipv6 = {
          title: rawDetails.ipv6?.title || "Internet Protocol Version 6",
          fields: ipv6Fields,
        };
      }
    }

    // IPv4 - Only show if IPv4 is in protocol chain (and not IPv6)
    if (
      (protoParts.includes("ip") || protoParts.includes("ipv4")) &&
      !protoParts.includes("ipv6")
    ) {
      const ipv4Fields: string[] = [];

      if (rawDetails.ipv4?.fields) {
        ipv4Fields.push(...rawDetails.ipv4.fields);
      } else {
        ipv4Fields.push(`Version: 4`);
        if (rawDetails["ip.hdr_len"]) {
          ipv4Fields.push(`Header Length: ${rawDetails["ip.hdr_len"]}`);
        } else {
          ipv4Fields.push(`Header Length: 20 bytes`);
        }

        const totalLen = rawDetails["ip.len"] || Math.max(0, len - 14);
        if (totalLen) ipv4Fields.push(`Total Length: ${totalLen}`);

        if (rawDetails["ip.id"])
          ipv4Fields.push(`Identification: ${rawDetails["ip.id"]}`);
        if (rawDetails["ip.ttl"])
          ipv4Fields.push(`Time to Live: ${rawDetails["ip.ttl"]}`);
        if (rawDetails["ip.proto"])
          ipv4Fields.push(`Protocol: ${rawDetails["ip.proto"]}`);
      }

      if (src) ipv4Fields.push(`Source Address: ${src}`);
      if (dst) ipv4Fields.push(`Destination Address: ${dst}`);

      if (ipv4Fields.length > 0) {
        details.ipv4 = {
          title: rawDetails.ipv4?.title || "Internet Protocol Version 4",
          fields: ipv4Fields,
        };
      }
    }

    // ICMPv6 - Only show if ICMPv6 is in protocol chain
    if (protoParts.includes("icmpv6")) {
      const icmpv6Fields: string[] = [];

      if (rawDetails.icmpv6?.fields) {
        icmpv6Fields.push(...rawDetails.icmpv6.fields);
      } else {
        if (info.includes("Neighbor Solicitation")) {
          icmpv6Fields.push(`Type: Neighbor Solicitation (135)`);
          icmpv6Fields.push(`Code: 0`);
          const nsMatch = info.match(/for ([\da-f:]+)/i);
          if (nsMatch) icmpv6Fields.push(`Target Address: ${nsMatch[1]}`);
        } else if (info.includes("Neighbor Advertisement")) {
          icmpv6Fields.push(`Type: Neighbor Advertisement (136)`);
          icmpv6Fields.push(`Code: 0`);
          const naMatch = info.match(/([a-f0-9:]+) \(ovr\) is at ([\da-f:]+)/i);
          if (naMatch) {
            icmpv6Fields.push(`Target Address: ${naMatch[1]}`);
            icmpv6Fields.push(`Target Link-layer Address: ${naMatch[2]}`);
          }
        } else if (info.includes("Router Solicitation")) {
          icmpv6Fields.push(`Type: Router Solicitation (133)`);
          icmpv6Fields.push(`Code: 0`);
        } else if (info.includes("Router Advertisement")) {
          icmpv6Fields.push(`Type: Router Advertisement (134)`);
          icmpv6Fields.push(`Code: 0`);
        } else if (info.includes("Multicast Listener Report")) {
          icmpv6Fields.push(`Type: Multicast Listener Report (143)`);
          icmpv6Fields.push(`Code: 0`);
          const mlrMatch = info.match(/v(\d+)/);
          if (mlrMatch) icmpv6Fields.push(`Version: ${mlrMatch[1]}`);
        } else if (info.includes("Echo")) {
          icmpv6Fields.push(
            `Type: Echo ${info.includes("Reply") ? "Reply" : "Request"} (${
              info.includes("Reply") ? "129" : "128"
            })`
          );
          icmpv6Fields.push(`Code: 0`);
        }

        if (rawDetails["icmpv6.checksum"]) {
          icmpv6Fields.push(`Checksum: ${rawDetails["icmpv6.checksum"]}`);
        }
      }

      if (icmpv6Fields.length > 0) {
        details.icmpv6 = {
          title:
            rawDetails.icmpv6?.title || "Internet Control Message Protocol v6",
          fields: icmpv6Fields,
        };
      }
    }

    // TCP - Only show if TCP is in protocol chain
    if (protoParts.includes("tcp")) {
      const tcpFields: string[] = [];

      if (rawDetails.tcp?.fields) {
        tcpFields.push(...rawDetails.tcp.fields);
      } else {
        // Parse from info field if available
        const portMatch = info.match(/(\d+)\s*(?:→|â†'|->|\u2192)\s*(\d+)/);
        if (portMatch) {
          tcpFields.push(`Source Port: ${portMatch[1]}`);
          tcpFields.push(`Destination Port: ${portMatch[2]}`);
        } else if (rawDetails["tcp.srcport"]) {
          tcpFields.push(`Source Port: ${rawDetails["tcp.srcport"]}`);
          tcpFields.push(`Destination Port: ${rawDetails["tcp.dstport"]}`);
        }

        if (rawDetails["tcp.seq"])
          tcpFields.push(`Sequence Number: ${rawDetails["tcp.seq"]}`);
        if (rawDetails["tcp.ack"])
          tcpFields.push(`Acknowledgment Number: ${rawDetails["tcp.ack"]}`);
        if (rawDetails["tcp.hdr_len"])
          tcpFields.push(`Header Length: ${rawDetails["tcp.hdr_len"]}`);

        const flagsMatch = info.match(/\[(.*?)\]/);
        if (flagsMatch) {
          tcpFields.push(`Flags: ${flagsMatch[1]}`);
        } else if (rawDetails["tcp.flags"]) {
          tcpFields.push(`Flags: ${rawDetails["tcp.flags"]}`);
        }

        if (rawDetails["tcp.window_size"])
          tcpFields.push(`Window Size: ${rawDetails["tcp.window_size"]}`);
        if (rawDetails["tcp.checksum"])
          tcpFields.push(`Checksum: ${rawDetails["tcp.checksum"]}`);
        if (rawDetails["tcp.urgent_pointer"])
          tcpFields.push(`Urgent Pointer: ${rawDetails["tcp.urgent_pointer"]}`);
      }

      if (tcpFields.length > 0) {
        details.tcp = {
          title: rawDetails.tcp?.title || "Transmission Control Protocol",
          fields: tcpFields,
        };
      }
    }

    // UDP - Only show if UDP is in protocol chain
    if (protoParts.includes("udp")) {
      const udpFields: string[] = [];

      if (rawDetails.udp?.fields) {
        udpFields.push(...rawDetails.udp.fields);
      } else {
        if (rawDetails["udp.srcport"]) {
          udpFields.push(`Source Port: ${rawDetails["udp.srcport"]}`);
          udpFields.push(`Destination Port: ${rawDetails["udp.dstport"]}`);
        }

        if (rawDetails["udp.length"]) {
          udpFields.push(`Length: ${rawDetails["udp.length"]}`);
        } else {
          udpFields.push(`Length: ${len}`);
        }

        if (rawDetails["udp.checksum"])
          udpFields.push(`Checksum: ${rawDetails["udp.checksum"]}`);
      }

      if (udpFields.length > 0) {
        details.udp = {
          title: rawDetails.udp?.title || "User Datagram Protocol",
          fields: udpFields,
        };
      }
    }

    // LLMNR - Only show if present
    if (protoParts.includes("llmnr")) {
      const llmnrFields: string[] = [];

      if (rawDetails.llmnr?.fields) {
        llmnrFields.push(...rawDetails.llmnr.fields);
      } else {
        const txIdMatch = info.match(/0x[0-9a-f]+/i);
        if (txIdMatch) llmnrFields.push(`Transaction ID: ${txIdMatch[0]}`);

        llmnrFields.push(`Flags: Standard Query`);

        const queryMatch = info.match(/ANY\s+(\S+)/i);
        if (queryMatch) {
          llmnrFields.push(`Queries: ${queryMatch[1]}`);
          llmnrFields.push(`Query Type: ANY`);
        }
      }

      if (llmnrFields.length > 0) {
        details.llmnr = {
          title: "Link-Local Multicast Name Resolution",
          fields: llmnrFields,
        };
      }
    }

    // mDNS - Only show if present
    if (protoParts.includes("mdns")) {
      const mdnsFields: string[] = [];

      if (rawDetails.mdns?.fields) {
        mdnsFields.push(...rawDetails.mdns.fields);
      } else {
        const txIdMatch = info.match(/0x[0-9a-f]+/i);
        if (txIdMatch) mdnsFields.push(`Transaction ID: ${txIdMatch[0]}`);

        mdnsFields.push(`Flags: Standard Query`);

        const queryMatch = info.match(/ANY\s+([^,]+)/);
        if (queryMatch) {
          mdnsFields.push(`Query: ${queryMatch[1]}`);
          mdnsFields.push(`Query Type: ANY (255)`);
        }

        if (info.includes('"QU"')) {
          mdnsFields.push(`QU Flag: Set (Unicast response requested)`);
        }
      }

      if (mdnsFields.length > 0) {
        details.mdns = {
          title: "Multicast DNS",
          fields: mdnsFields,
        };
      }
    }

    // DNS - Show if present (prefer provided title/fields)
    if (
      (protoParts.includes("dns") || rawDetails.dns?.fields) &&
      rawDetails.dns?.fields
    ) {
      details.dns = {
        title: rawDetails.dns.title || "DNS",
        fields: rawDetails.dns.fields,
      };
    }

    // HTTP/HTTPS - Only show if present
    if (protoParts.includes("http") || protoParts.includes("https")) {
      const appFields: string[] = [];

      if (rawDetails.http?.fields) {
        appFields.push(...rawDetails.http.fields);
      } else {
        const methodMatch = info.match(
          /^(GET|POST|PUT|DELETE|PATCH|HEAD|OPTIONS)\s+(.+?)\s/i
        );
        if (methodMatch) {
          appFields.push(`Request Method: ${methodMatch[1]}`);
          appFields.push(`Request URI: ${methodMatch[2]}`);
        }

        if (info.includes("Host:")) {
          const hostMatch = info.match(/Host:\s*([^\s,]+)/i);
          if (hostMatch) appFields.push(`Host: ${hostMatch[1]}`);
        }
      }

      if (appFields.length > 0) {
        const title = protoParts.includes("https")
          ? "HTTPS Request"
          : "HTTP Request";
        details.application = {
          title: title,
          fields: appFields,
        };
      }
    }

    // Generic Application Data - Only show if present
    if (rawDetails.application?.fields && !details.application) {
      details.application = {
        title: rawDetails.application.title || "Application Data",
        fields: rawDetails.application.fields,
      };
    }

    return details;
  };

  const getPrimaryProtocol = (p: string | undefined) => {
    if (!p) return "";
    const parts = String(p)
      .toLowerCase()
      .split(/[:\s,]+/)
      .filter(Boolean);

    const preferredOrder = [
      "http",
      "https",
      "dns",
      "tcp",
      "udp",
      "icmp",
      "icmpv6",
      "ipv4",
      "ip",
      "ipv6",
      "arp",
      "mdns",
      "llmnr",
    ];

    for (const proto of preferredOrder) {
      if (parts.includes(proto)) return proto.toUpperCase();
    }

    // Fallback: pick the last meaningful part (ignore generic 'data')
    const last = [...parts].reverse().find((x) => x !== "data");
    return (last || parts[parts.length - 1] || p).toUpperCase();
  };

  const copyText = async (text: string) => {
    try {
      await navigator.clipboard.writeText(text);
    } catch (e) {
      console.warn("Clipboard copy failed", e);
    }
  };

  useEffect(() => {
    const style = document.createElement("style");
    style.textContent = `
        details > summary { list-style: none; }
        details > summary::-webkit-details-marker { display: none; }
        details > summary > span:first-child {
          transition: transform 0.2s;
          display: inline-block;
        }
        details[open] > summary > span:first-child {
          transform: rotate(90deg);
        }
      `;
    document.head.appendChild(style);
    return () => {
      if (style.parentNode) style.parentNode.removeChild(style);
    };
  }, []);

  // No dummy packet generation: UI maps real capture JSON provided by the capture server.
  // Helper to convert raw hex string into 16-byte lines for the hex viewer.
  const toHexFromUnknown = (raw: any): string => {
    try {
      if (!raw) return "";

      // Array of byte numbers
      if (Array.isArray(raw)) {
        return raw
          .map((b) => {
            const n = Number(b) & 0xff;
            return n.toString(16).padStart(2, "0");
          })
          .join("");
      }

      const s = String(raw).trim();

      // Try base64 heuristic
      const looksBase64 =
        /^[A-Za-z0-9+/=]+$/.test(s) && s.length % 4 === 0 && /[+/=]/.test(s);
      if (looksBase64) {
        try {
          const bin = atob(s);
          let hex = "";
          for (let i = 0; i < bin.length; i++) {
            hex += bin.charCodeAt(i).toString(16).padStart(2, "0");
          }
          if (hex) return hex;
        } catch (_) {
          // fallthrough to hex-only cleanup
        }
      }

      // Remove all non-hex chars (handles spaces, colons, newlines)
      return s.replace(/[^0-9a-fA-F]/g, "");
    } catch {
      return "";
    }
  };

  const convertRawToLines = (raw: any) => {
    const hex = toHexFromUnknown(raw);
    if (!hex) return [];
    const bytes: string[] = [];
    for (let i = 0; i < hex.length; i += 2) {
      bytes.push(hex.substr(i, 2));
    }
    const lines: string[] = [];
    for (let i = 0; i < bytes.length; i += 16) {
      lines.push(bytes.slice(i, i + 16).join(" "));
    }
    return lines;
  };

  const startCapture = () => {
    setCapturing(true);
    setPaused(false);
    setShowWelcome(false);
    const now = Date.now();
    setStartTime(now);
    startTimeRef.current = now;

    if (useLiveCapture) {
      try {
        const url = captureServerUrl.replace(/\/+$/, "") + "/events";
        const es = new EventSource(url);
        eventSourceRef.current = es;
        es.onmessage = (ev) => {
          try {
            const data = JSON.parse(ev.data);
            if (data.error) {
              console.error("capture server error:", data.error);
              return;
            }
            // Accept multiple payload shapes from server
            const rawInput =
              data.raw ?? data.data ?? data.payload ?? data.bytes ?? "";
            const rawHex = toHexFromUnknown(rawInput);
            const lengthFromRaw = rawHex ? Math.ceil(rawHex.length / 2) : 0;
            const proto = getPrimaryProtocol(data.protocol || "");
            const pkt = {
              id: data.id != null ? Number(data.id) : packetId.current++,
              time:
                data.time ||
                (startTimeRef.current
                  ? ((Date.now() - startTimeRef.current) / 1000).toFixed(6)
                  : "0.000000"),
              timestamp: data.timestamp || Date.now(),
              source: data.source || data.src || "",
              destination: data.destination || data.dst || "",
              protocol: proto || (rawHex ? "RAW" : ""),
              length: data.length || lengthFromRaw || 0,
              info: data.info || "",
              hexData:
                data.hexData && data.hexData.length
                  ? data.hexData
                  : convertRawToLines(rawHex),
              raw: rawHex,
              details: data.details || {},
            };
            setPackets((prev) => {
              const next = [...prev, pkt];
              if (next.length > maxPackets) return next.slice(-maxPackets);
              return next;
            });
          } catch (e) {
            console.error("Failed to parse capture event", e);
          }
        };
        es.onerror = (e) => {
          console.error("EventSource error", e);
        };
      } catch (e) {
        console.error("Failed to open EventSource", e);
        setCapturing(false);
      }
    } else {
      // No dummy/simulated data: when live capture is disabled, do not generate packets.
      // User should enable 'Use Live Capture' and point to a running capture server.
      console.warn(
        "Live capture is disabled — enable Use Live Capture to receive packets."
      );
    }
  };

  const stopCapture = () => {
    setCapturing(false);
    setPaused(false);
    if (captureInterval.current) clearInterval(captureInterval.current);
    if (eventSourceRef.current) {
      eventSourceRef.current.close();
      eventSourceRef.current = null;
    }
  };

  const pauseCapture = () => {
    if (paused) {
      startCapture(); // reuse logic
      setPaused(false);
    } else {
      if (eventSourceRef.current) {
        eventSourceRef.current.close();
        eventSourceRef.current = null;
      }
      setPaused(true);
    }
  };

  const clearPackets = () => {
    setPackets([]);
    setSelectedPacket(null);
    packetId.current = 1;
    setStartTime(0);
    startTimeRef.current = null;
  };

  const exportPackets = () => {
    const data = filteredPackets
      .map(
        (p) =>
          `${p.id},${p.time},${p.source},${p.destination},${p.protocol},${p.length},${p.info}`
      )
      .join("\n");
    const blob = new Blob(
      [`No,Time,Source,Destination,Protocol,Length,Info\n${data}`],
      { type: "text/csv" }
    );
    const url = URL.createObjectURL(blob);
    const a = document.createElement("a");
    a.href = url;
    a.download = `netspector_${Date.now()}.csv`;
    a.click();
  };

  const applyFilter = () => setAppliedFilter(filter);

  const filterPacket = (p: any, filterStr: string) => {
    if (!filterStr) return true;
    const lower = filterStr.toLowerCase();
    return (
      p.protocol.toLowerCase().includes(lower) ||
      p.source.toLowerCase().includes(lower) ||
      p.destination.toLowerCase().includes(lower) ||
      p.info.toLowerCase().includes(lower)
    );
  };

  const filteredPackets = packets.filter((p) => filterPacket(p, appliedFilter));
  const searchedPackets = filteredPackets.filter((p) => {
    if (!searchTerm) return true;
    const term = searchTerm.toLowerCase();
    return (
      p.id.toString().includes(term) ||
      p.source.toLowerCase().includes(term) ||
      p.destination.toLowerCase().includes(term) ||
      p.protocol.toLowerCase().includes(term) ||
      p.info.toLowerCase().includes(term)
    );
  });

  useEffect(() => {
    return () => {
      if (captureInterval.current) clearInterval(captureInterval.current);
      if (eventSourceRef.current) {
        try {
          eventSourceRef.current.close();
        } catch (e) {}
        eventSourceRef.current = null;
      }
    };
  }, []);

  useEffect(() => {
    if (autoScroll && listContainerRef.current) {
      listContainerRef.current.scrollTop =
        listContainerRef.current.scrollHeight;
    }
  }, [searchedPackets, autoScroll]);

  const stats = {
    total: packets.length,
    displayed: searchedPackets.length,
    protocols: packets.reduce((acc: any, p: any) => {
      acc[p.protocol] = (acc[p.protocol] || 0) + 1;
      return acc;
    }, {}),
    captureDuration: startTime
      ? ((Date.now() - startTime) / 1000).toFixed(1)
      : "0.0",
  };

  const detailsForRender = selectedPacket ? buildDetails(selectedPacket) : {};

  // Build concise Info column text from provided details
  const buildRowInfo = (pkt: any) => {
    try {
      const d = pkt?.details || {};

      // DNS query summary
      if (d.dns?.fields && Array.isArray(d.dns.fields)) {
        const q = d.dns.fields.find((f: string) => f.startsWith("Query:"));
        if (q) return `DNS ${q}`; // e.g., "DNS Query: example.com"
      }

      // HTTP summary
      if (d.http?.fields && Array.isArray(d.http.fields)) {
        const method = d.http.fields.find((f: string) =>
          f.toLowerCase().startsWith("method:")
        );
        const uri = d.http.fields.find((f: string) =>
          f.toLowerCase().startsWith("uri:")
        );
        if (method || uri) {
          const m = method ? method.split(": ")[1] : "";
          const u = uri ? uri.split(": ")[1] : "";
          return `HTTP ${m} ${u}`.trim();
        }
      }

      // TCP summary with flags
      if (d.tcp?.fields && Array.isArray(d.tcp.fields)) {
        const sp = d.tcp.fields.find((f: string) =>
          f.toLowerCase().startsWith("source port:")
        );
        const dp = d.tcp.fields.find((f: string) =>
          f.toLowerCase().startsWith("destination port:")
        );
        const fl = d.tcp.fields.find((f: string) =>
          f.toLowerCase().startsWith("flags:")
        );
        const srcPort = sp ? sp.split(": ")[1] : "";
        const dstPort = dp ? dp.split(": ")[1] : "";

        let flagsLabel = "";
        if (fl) {
          const val = fl.split(": ")[1] || "";
          if (/^0x/i.test(val)) {
            const n = parseInt(val, 16);
            const bits: string[] = [];
            if (n & 0x01) bits.push("FIN");
            if (n & 0x02) bits.push("SYN");
            if (n & 0x04) bits.push("RST");
            if (n & 0x08) bits.push("PSH");
            if (n & 0x10) bits.push("ACK");
            if (n & 0x20) bits.push("URG");
            if (n & 0x40) bits.push("ECE");
            if (n & 0x80) bits.push("CWR");
            if (bits.length) flagsLabel = `[${bits.join(", ")}]`;
          } else if (val) {
            flagsLabel = val.startsWith("[") ? val : `[${val}]`;
          }
        }

        if (srcPort || dstPort || flagsLabel) {
          return `${srcPort} → ${dstPort} ${flagsLabel}`.trim();
        }
      }

      // UDP summary
      if (d.udp?.fields && Array.isArray(d.udp.fields)) {
        const sp = d.udp.fields.find((f: string) =>
          f.toLowerCase().startsWith("source port:")
        );
        const dp = d.udp.fields.find((f: string) =>
          f.toLowerCase().startsWith("destination port:")
        );
        const srcPort = sp ? sp.split(": ")[1] : "";
        const dstPort = dp ? dp.split(": ")[1] : "";
        if (srcPort || dstPort) return `${srcPort} → ${dstPort}`.trim();
      }

      // Fallback to provided info or empty
      return pkt.info || "";
    } catch (e) {
      return pkt?.info || "";
    }
  };

  const getSectionIcon = (key: string) => {
    switch (key) {
      case "frame":
        return { Icon: Info, className: "text-blue-600" };
      case "ethernet":
        return { Icon: Activity, className: "text-gray-600" };
      case "ipv4":
      case "ipv6":
        return { Icon: Network, className: "text-green-600" };
      case "tcp":
        return { Icon: Settings, className: "text-red-600" };
      case "udp":
        return { Icon: Settings, className: "text-indigo-600" };
      case "dns":
      case "mdns":
        return { Icon: Search, className: "text-purple-600" };
      case "application":
        return { Icon: Database, className: "text-teal-600" };
      default:
        return { Icon: Info, className: "text-gray-500" };
    }
  };

  return (
    <div className="min-h-screen flex flex-col bg-gray-100">
      {/* Welcome Overlay */}
      {showWelcome && (
        <div className="fixed inset-0 bg-gradient-to-br from-blue-50 to-purple-50 flex items-center justify-center z-50">
          <div className="bg-white rounded-xl shadow-2xl p-8 max-w-2xl mx-4">
            <div className="mb-6 text-center">
              <div className="flex items-center justify-center gap-3 mb-3">
                <Wifi className="w-8 h-8 text-blue-500" />
                <h2 className="text-2xl font-bold">Welcome to NetSpector</h2>
              </div>
              <p className="text-gray-600">
                Capture and inspect network traffic in real time.
              </p>
            </div>

            <div className="space-y-4 text-gray-700">
              <div className="flex items-start gap-3">
                <Info className="w-5 h-5 text-blue-500 mt-0.5" />
                <p>
                  Enable <strong>Use Live Capture</strong> in Settings and start
                  the capture.
                </p>
              </div>
              <div className="flex items-start gap-3">
                <Database className="w-5 h-5 text-green-500 mt-0.5" />
                <p>Click any row to view protocol details and hex.</p>
              </div>
            </div>

            <button
              onClick={() => setShowWelcome(false)}
              className="w-full mt-6 bg-blue-600 text-white py-3 rounded-lg font-bold hover:bg-blue-700"
            >
              Start Exploring
            </button>
          </div>
        </div>
      )}

      {/* Settings Modal */}
      {showSettings && (
        <div className="fixed inset-0 bg-black bg-opacity-50 flex items-center justify-center z-60">
          <div className="bg-white rounded-lg p-6 max-w-md mx-4 shadow-2xl">
            <div className="flex items-center justify-between mb-4">
              <h3 className="text-xl font-bold flex items-center gap-2">
                <Settings className="w-5 h-5" />
                Capture Settings
              </h3>
              <button
                onClick={() => setShowSettings(false)}
                className="text-gray-500"
              >
                ✕
              </button>
            </div>
            <div className="space-y-4">
              <div>
                <label className="block text-sm font-semibold mb-2">
                  Network Interface
                </label>
                <select
                  value={networkInterface}
                  onChange={(e) => setNetworkInterface(e.target.value)}
                  className="w-full border rounded px-3 py-2"
                >
                  <option value="eth0">Ethernet (eth0)</option>
                  <option value="wlan0">WiFi (wlan0)</option>
                  <option value="lo">Loopback (lo)</option>
                </select>
              </div>
              <div className="flex items-center justify-between mt-3">
                <label className="text-sm font-semibold">
                  Use Live Capture (local)
                </label>
                <div className="flex items-center gap-2">
                  <input
                    type="text"
                    value={captureServerUrl}
                    onChange={(e) => setCaptureServerUrl(e.target.value)}
                    className="border rounded px-2 py-1 w-48"
                  />
                  <button
                    onClick={() => setUseLiveCapture(!useLiveCapture)}
                    className={`px-3 py-1 rounded ${
                      useLiveCapture ? "bg-green-500 text-white" : "bg-gray-200"
                    }`}
                  >
                    {useLiveCapture ? "ON" : "OFF"}
                  </button>
                </div>
              </div>
              <div>
                <label className="block text-sm font-semibold mb-2">
                  Capture Speed (ms): {captureSpeed}
                </label>
                <input
                  type="range"
                  min="100"
                  max="3000"
                  value={captureSpeed}
                  onChange={(e) => setCaptureSpeed(Number(e.target.value))}
                  className="w-full"
                />
              </div>
              <div>
                <label className="block text-sm font-semibold mb-2">
                  Max Packets: {maxPackets}
                </label>
                <input
                  type="range"
                  min="100"
                  max="10000"
                  step="100"
                  value={maxPackets}
                  onChange={(e) => setMaxPackets(Number(e.target.value))}
                  className="w-full"
                />
              </div>
              <div className="flex items-center justify-between">
                <label className="text-sm font-semibold">
                  Promiscuous Mode
                </label>
                <button
                  onClick={() => setPromiscuousMode(!promiscuousMode)}
                  className={`px-4 py-2 rounded ${
                    promiscuousMode ? "bg-green-500 text-white" : "bg-gray-200"
                  }`}
                >
                  {promiscuousMode ? "ON" : "OFF"}
                </button>
              </div>
            </div>
            <div className="mt-4 flex justify-end">
              <button
                onClick={() => setShowSettings(false)}
                className="px-4 py-2 bg-blue-600 text-white rounded"
              >
                Close
              </button>
            </div>
          </div>
        </div>
      )}

      {/* Statistics Modal */}
      {showStats && (
        <div className="fixed inset-0 bg-black bg-opacity-50 flex items-center justify-center z-60">
          <div className="bg-white rounded-lg p-6 max-w-3xl mx-4 shadow-2xl max-h-[80vh] overflow-auto">
            <div className="flex items-center justify-between mb-4">
              <h3 className="text-xl font-bold flex items-center gap-2">
                <BarChart3 className="w-5 h-5" /> Network Statistics
              </h3>
              <button
                onClick={() => setShowStats(false)}
                className="text-gray-500"
              >
                ✕
              </button>
            </div>
            <div className="grid grid-cols-2 md:grid-cols-5 gap-4 mb-6">
              <div className="bg-blue-50 p-4 rounded-lg">
                <div className="text-sm text-gray-600">Total Packets</div>
                <div className="text-2xl font-bold text-blue-600">
                  {stats.total}
                </div>
              </div>
              <div className="bg-purple-50 p-4 rounded-lg">
                <div className="text-sm text-gray-600">Displayed</div>
                <div className="text-2xl font-bold text-purple-600">
                  {stats.displayed}
                </div>
              </div>
              <div className="bg-indigo-50 p-4 rounded-lg">
                <div className="text-sm text-gray-600">Capture Duration</div>
                <div className="text-2xl font-bold text-indigo-600">
                  {stats.captureDuration}s
                </div>
              </div>
            </div>
            <h4 className="font-semibold mb-3">Protocol Distribution</h4>
            <div className="space-y-2">
              {Object.entries(stats.protocols as Record<string, number>)
                .sort((a, b) => (b[1] as number) - (a[1] as number))
                .map(([protocol, count]) => {
                  const pct = (
                    (count / Math.max(stats.total, 1)) *
                    100
                  ).toFixed(1);
                  return (
                    <div key={protocol} className="mb-2">
                      <div className="flex justify-between text-sm mb-1">
                        <span className="font-semibold">{protocol}</span>
                        <span>
                          {count} ({pct}%)
                        </span>
                      </div>
                      <div className="w-full bg-gray-200 rounded-full h-2">
                        <div
                          className="h-2 rounded-full bg-blue-500"
                          style={{ width: `${pct}%` }}
                        />
                      </div>
                    </div>
                  );
                })}
            </div>
            <div className="mt-4 flex justify-end">
              <button
                onClick={() => setShowStats(false)}
                className="px-4 py-2 bg-blue-600 text-white rounded"
              >
                Close
              </button>
            </div>
          </div>
        </div>
      )}

      {/* Top Action Bar */}
      <div className="bg-gradient-to-r from-gray-800 to-gray-900 text-white px-6 py-3 flex items-center justify-between shadow-lg">
        <div className="flex items-center gap-5">
          <Wifi className="w-8 h-8 text-blue-400" />
          <div>
            <h1 className="text-2xl font-bold">NetSpector</h1>
            <p className="text-sm text-gray-400 hidden md:block">
              Network Protocol Analyzer
            </p>
          </div>
        </div>

        <div className="flex items-center gap-3">
          <button
            onClick={startCapture}
            disabled={capturing}
            className="p-2.5 rounded-lg bg-green-600 hover:bg-green-700 disabled:opacity-50 transition"
            title="Start"
          >
            <Play className="w-5 h-5" />
          </button>
          <button
            onClick={stopCapture}
            disabled={!capturing}
            className="p-2.5 rounded-lg bg-red-600 hover:bg-red-700 disabled:opacity-50"
            title="Stop"
          >
            <Square className="w-5 h-5" />
          </button>
          <button
            onClick={pauseCapture}
            disabled={!capturing}
            className={`p-2.5 rounded-lg disabled:opacity-50 ${
              paused
                ? "bg-yellow-400 hover:bg-yellow-500"
                : "bg-yellow-600 hover:bg-yellow-700"
            }`}
            title={paused ? "Resume" : "Pause"}
          >
            {paused ? (
              <Play className="w-5 h-5" />
            ) : (
              <Pause className="w-5 h-5" />
            )}
          </button>
          <button
            onClick={clearPackets}
            className="p-2.5 rounded-lg bg-gray-600 hover:bg-gray-700"
            title="Clear"
          >
            <Trash2 className="w-5 h-5" />
          </button>
          <button
            onClick={exportPackets}
            className="p-2.5 rounded-lg bg-blue-600 hover:bg-blue-700"
            title="Export CSV"
          >
            <Download className="w-5 h-5" />
          </button>
          <button
            onClick={() => setShowStats(true)}
            className="p-2.5 rounded-lg bg-purple-600 hover:bg-purple-700"
            title="Statistics"
          >
            <BarChart3 className="w-5 h-5" />
          </button>
          <button
            onClick={() => setShowSettings(true)}
            className="p-2.5 rounded-lg bg-indigo-600 hover:bg-indigo-700"
            title="Settings"
          >
            <Settings className="w-5 h-5" />
          </button>

          <div className="ml-6 flex items-center gap-4">
            <div className="bg-gray-700 px-4 py-1.5 rounded-lg flex items-center gap-2">
              <Activity className="w-4 h-4 text-white" />
              <span className="font-mono font-bold text-white">
                {packets.length}
              </span>
            </div>
            {capturing && (
              <div className="w-3 h-3 bg-green-500 rounded-full animate-pulse" />
            )}
            <button
              onClick={() => {
                console.debug("NetSpector: open settings (toolbar)");
                setShowSettings(true);
              }}
              className={`px-3 py-1.5 text-xs rounded border ${
                autoScroll
                  ? "bg-blue-600 border-blue-700"
                  : "bg-gray-700 border-gray-600"
              }`}
            >
              Auto: {autoScroll ? "ON" : "OFF"}
            </button>
          </div>
        </div>
      </div>

      {/* Filter Bar */}
      <div className="bg-gray-100 px-6 py-3 flex items-center gap-4 border-b">
        <Filter className="w-5 h-5 text-gray-600" />
        <input
          type="text"
          value={filter}
          onChange={(e) => setFilter(e.target.value)}
          onKeyDown={(e) => e.key === "Enter" && applyFilter()}
          placeholder="Display filter (e.g., tcp, http, dns, 192.168)"
          className="flex-1 px-4 py-2 border rounded-lg focus:outline-none focus:ring-2 focus:ring-blue-500"
        />
        <button
          onClick={applyFilter}
          className="px-5 py-2 bg-blue-600 text-white rounded-lg hover:bg-blue-700"
        >
          Apply
        </button>
        <button
          onClick={() => {
            setFilter("");
            setAppliedFilter("");
          }}
          className="px-5 py-2 bg-gray-600 text-white rounded-lg hover:bg-gray-700"
        >
          Clear
        </button>

        <div className="flex items-center gap-2">
          <Search className="w-5 h-5 text-gray-600" />
          <input
            type="text"
            value={searchTerm}
            onChange={(e) => setSearchTerm(e.target.value)}
            placeholder="Search..."
            className="px-4 py-2 border rounded-lg w-64 focus:outline-none focus:ring-2 focus:ring-blue-500"
          />
        </div>
      </div>

      {/* Main Layout */}
      <div className="flex-1 flex flex-col overflow-hidden">
        {/* Packet List - Top 60% */}
        <div
          ref={listContainerRef}
          className="flex-1 overflow-auto bg-white"
          style={{ maxHeight: "60vh" }}
        >
          <table className="w-full text-sm">
            <thead className="bg-gradient-to-r from-gray-200 to-gray-300 sticky top-0 z-10 shadow-sm">
              <tr>
                <th className="px-4 py-3 text-left font-bold">No.</th>
                <th className="px-4 py-3 text-left font-bold">Time (s)</th>
                <th className="px-4 py-3 text-left font-bold">Source</th>
                <th className="px-4 py-3 text-center font-bold">→</th>
                <th className="px-4 py-3 text-left font-bold">Destination</th>
                <th className="px-4 py-3 text-left font-bold">Protocol</th>
                <th className="px-4 py-3 text-right font-bold">Length</th>
                <th className="px-4 py-3 text-left font-bold">Info</th>
              </tr>
            </thead>
            <tbody>
              {searchedPackets.map((packet: any) => (
                <tr
                  key={packet.id}
                  onClick={() => setSelectedPacket(packet)}
                  className={`cursor-pointer hover:bg-blue-50 border-b transition ${
                    selectedPacket?.id === packet.id
                      ? "bg-blue-100 border-l-4 border-l-blue-600"
                      : ""
                  }`}
                >
                  <td className="px-4 py-2 font-semibold">{packet.id}</td>
                  <td className="px-4 py-2 font-mono text-xs text-gray-600">
                    {packet.time}
                  </td>
                  <td className="px-4 py-2 font-mono text-blue-700">
                    {packet.source}
                  </td>
                  <td className="px-4 py-2 text-center text-gray-400">→</td>
                  <td className="px-4 py-2 font-mono text-green-700">
                    {packet.destination}
                  </td>
                  <td className="px-4 py-2">
                    <span
                      className={`px-2.5 py-1 rounded text-xs font-bold border ${
                        protocolColors[packet.protocol] || "bg-gray-300"
                      }`}
                    >
                      {packet.protocol}
                    </span>
                  </td>
                  <td className="px-4 py-2 text-right font-mono">
                    {packet.length}
                  </td>
                  <td className="px-4 py-2 text-gray-700">
                    {buildRowInfo(packet)}
                  </td>
                </tr>
              ))}
              <tr ref={listEndRef}>
                <td colSpan={8} />
              </tr>
            </tbody>
          </table>

          {searchedPackets.length === 0 && (
            <div className="flex flex-col items-center justify-center h-full text-gray-500">
              <Network className="w-20 h-20 mb-4" />
              <p className="text-xl font-semibold">
                {packets.length === 0
                  ? "No packets captured"
                  : "No packets match filter"}
              </p>
              <p className="mt-2">
                {packets.length === 0
                  ? "Click Start to begin"
                  : "Adjust your filter"}
              </p>
            </div>
          )}
        </div>

        {/* Bottom Panel: Details (2/3) + Hex (1/3) */}
        <div className="flex flex-1 min-h-0 bg-gray-50 border-t">
          {/* Packet Details - 2/3 */}
          <div className="w-2/3 min-w-0 overflow-y-auto bg-white border-r flex-shrink-0">
            {selectedPacket ? (
              <div className="p-6">
                {/* Header */}
                <div className="mb-5">
                  <h3 className="text-lg font-bold flex items-center gap-2">
                    <Info className="w-5 h-5 text-blue-600" />
                    Packet Details #{selectedPacket.id}
                  </h3>

                  <div className="mt-3 grid grid-cols-1 lg:grid-cols-2 gap-4">
                    {/* Source → Destination */}
                    <div className="flex flex-wrap items-center gap-3 text-sm">
                      <span className="font-mono text-gray-600">
                        {selectedPacket.time}s
                      </span>

                      <span className="font-mono text-blue-700">
                        {selectedPacket.source}
                      </span>

                      <span className="text-gray-400">→</span>

                      <span className="font-mono text-green-700">
                        {selectedPacket.destination}
                      </span>
                    </div>

                    {/* Meta Info */}
                    <div className="flex flex-wrap items-center gap-3 lg:justify-end text-sm">
                      <span
                        className={`px-2 py-1 rounded text-xs font-semibold border ${
                          protocolColors?.[selectedPacket.protocol] ??
                          "bg-gray-200 text-gray-700"
                        }`}
                      >
                        {selectedPacket.protocol}
                      </span>

                      <span className="text-gray-600">
                        {selectedPacket.length} bytes
                      </span>

                      <span className="text-gray-500 truncate max-w-xs">
                        {selectedPacket.info}
                      </span>
                    </div>
                  </div>
                </div>

                {/* Controls */}
                <div className="flex items-center justify-between mb-3">
                  <div className="text-xs text-gray-500">
                    Sections: {Object.keys(detailsForRender ?? {}).length}
                  </div>
                  <div className="flex items-center gap-2">
                    <button
                      onClick={() => setExpandAll((v) => !v)}
                      className={`px-3 py-1 text-xs rounded border ${
                        expandAll
                          ? "bg-blue-600 border-blue-700 text-white"
                          : "bg-gray-100 border-gray-300 text-gray-800"
                      }`}
                      title={expandAll ? "Collapse All" : "Expand All"}
                    >
                      {expandAll ? "Collapse All" : "Expand All"}
                    </button>
                    <button
                      onClick={() => setShowRawJson((v) => !v)}
                      className={`px-3 py-1 text-xs rounded border ${
                        showRawJson
                          ? "bg-purple-600 border-purple-700 text-white"
                          : "bg-gray-100 border-gray-300 text-gray-800"
                      }`}
                    >
                      {showRawJson ? "Hide Raw JSON" : "Show Raw JSON"}
                    </button>
                  </div>
                </div>

                {/* Raw JSON */}
                {showRawJson && (
                  <div className="mb-4 p-3 bg-gray-50 border rounded">
                    <pre className="text-xs overflow-auto max-h-64">
                      {JSON.stringify(selectedPacket.details || {}, null, 2)}
                    </pre>
                  </div>
                )}

                {/* Protocol Details */}
                <div className="mt-4">
                  {Object.keys(detailsForRender ?? {}).length > 0 ? (
                    <div
                      className="space-y-3"
                      style={{ overflowAnchor: "none" }}
                    >
                      {Object.entries(detailsForRender).map(
                        ([key, section]) => (
                          <details
                            key={key}
                            className="border rounded"
                            open={expandAll}
                          >
                            <summary className="px-4 py-2 bg-gray-100 cursor-pointer font-semibold flex justify-between items-center">
                              <span className="flex items-center gap-2">
                                {(() => {
                                  const { Icon, className } =
                                    getSectionIcon(key);
                                  return (
                                    <Icon className={`w-4 h-4 ${className}`} />
                                  );
                                })()}
                                <span className="sr-only">{section.title}</span>
                              </span>

                              {Array.isArray(section.fields) && (
                                <span className="text-xs text-gray-500">
                                  {section.fields.length} fields
                                </span>
                              )}
                            </summary>

                            <div className="p-4 bg-white text-sm">
                              <div className="space-y-1">
                                {Array.isArray(section.fields) &&
                                  section.fields.map((field, i) => {
                                    const [label, ...rest] = field.split(": ");
                                    const value = rest.join(": ");

                                    return rest.length ? (
                                      <div
                                        key={i}
                                        className="grid grid-cols-12 items-center gap-3"
                                      >
                                        <span className="col-span-4 text-gray-700 font-medium truncate">
                                          {label}
                                        </span>
                                        <span className="col-span-7 font-mono text-blue-700 truncate">
                                          {value}
                                        </span>
                                        <button
                                          className="col-span-1 text-xs px-2 py-1 bg-gray-100 border rounded hover:bg-gray-200"
                                          onClick={() =>
                                            copyText(value || field)
                                          }
                                        >
                                          Copy
                                        </button>
                                      </div>
                                    ) : (
                                      <div
                                        key={i}
                                        className="flex items-center justify-between gap-3"
                                      >
                                        <span className="font-mono text-gray-700 truncate">
                                          {field}
                                        </span>
                                        <button
                                          className="text-xs px-2 py-1 bg-gray-100 border rounded hover:bg-gray-200"
                                          onClick={() => copyText(field)}
                                        >
                                          Copy
                                        </button>
                                      </div>
                                    );
                                  })}
                              </div>
                            </div>
                          </details>
                        )
                      )}
                    </div>
                  ) : (
                    <div className="p-4 bg-gray-50 rounded border text-sm text-gray-600">
                      No parsed details available for this packet.
                    </div>
                  )}
                </div>
              </div>
            ) : (
              /* Empty State */
              <div className="flex items-center justify-center h-full text-gray-400">
                <div className="text-center">
                  <Info className="w-16 h-16 mx-auto mb-3 opacity-60" />
                  <p className="text-lg">Select a packet to view details</p>
                </div>
              </div>
            )}
          </div>

          {/* Hex Dump - 1/3 */}
          <div className="w-1/3 overflow-auto bg-gray-900 text-green-400 font-mono text-xs flex-shrink-0 min-w-0">
            {selectedPacket ? (
              <div className="p-5">
                <div className="text-white mb-4 flex items-center gap-3">
                  <Database className="w-5 h-5" />
                  <span className="font-bold">
                    Hex View ({selectedPacket.length} bytes)
                  </span>
                </div>
                {(() => {
                  const lines =
                    selectedPacket.hexData && selectedPacket.hexData.length > 0
                      ? selectedPacket.hexData
                      : convertRawToLines(selectedPacket.raw);
                  if (!lines || lines.length === 0) {
                    return (
                      <div className="text-gray-400">
                        No payload available to render.
                      </div>
                    );
                  }
                  return lines.map((line: string, idx: number) => (
                    <div
                      key={idx}
                      className="hover:bg-gray-800 py-1 px-3 rounded"
                    >
                      <span className="text-gray-500 select-none mr-4">
                        {(idx * 16).toString(16).padStart(4, "0")}
                      </span>
                      <span className="mr-8">{line}</span>
                      <span className="text-blue-400">
                        {line
                          .split(" ")
                          .map((b) =>
                            b
                              ? parseInt(b, 16) >= 32 && parseInt(b, 16) <= 126
                                ? String.fromCharCode(parseInt(b, 16))
                                : "."
                              : ""
                          )
                          .join("")}
                      </span>
                    </div>
                  ));
                })()}
              </div>
            ) : (
              <div className="flex items-center justify-center h-full text-gray-500">
                <div className="text-center">
                  <Database className="w-20 h-20 mx-auto mb-4" />
                  <p className="text-xl">Select packet for hex view</p>
                </div>
              </div>
            )}
          </div>
        </div>
      </div>

      {/* Status Bar */}
      <div className="bg-gradient-to-r from-gray-800 to-gray-900 text-white px-6 py-2 text-xs flex items-center justify-between">
        <div className="flex items-center gap-8">
          <span>
            Total: <strong>{stats.total}</strong>
          </span>
          <span>
            Displayed: <strong>{stats.displayed}</strong>
          </span>
          <span>
            Duration: <strong>{stats.captureDuration}s</strong>
          </span>
          {appliedFilter && (
            <span className="bg-blue-600 px-3 py-1 rounded">
              Filter: {appliedFilter}
            </span>
          )}
        </div>
        <div className="flex gap-3">
          {Object.entries(stats.protocols)
            .sort((a: any, b: any) => b[1] - a[1])
            .slice(0, 8)
            .map(([p, c]: [string, any]) => (
              <span
                key={p}
                className={`px-3 py-1 rounded font-bold ${
                  protocolColors[p] || "bg-gray-600"
                }`}
              >
                {p}: {c}
              </span>
            ))}
        </div>
      </div>
    </div>
  );
};

export default NetSpector;
