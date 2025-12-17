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
  AlertCircle,
  Info,
  Database,
  Clock,
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
  const [autoScroll, setAutoScroll] = useState(true);
  const [showWelcome, setShowWelcome] = useState(true);
  const [startTime, setStartTime] = useState(0);
  const [capturing, setCapturing] = useState(false);
  const [paused, setPaused] = useState(false);

  const captureInterval = useRef<NodeJS.Timeout | null>(null);
  const packetId = useRef(1);
  const listEndRef = useRef<HTMLDivElement>(null);
  const listContainerRef = useRef<HTMLDivElement>(null);
  const startTimeRef = useRef<number | null>(null);

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
    return () => document.head.removeChild(style);
  }, []);

  const generatePacket = () => {
    const protocols = [
      "TCP",
      "UDP",
      "HTTP",
      "DNS",
      "ARP",
      "ICMP",
      "HTTPS",
      "SSH",
      "FTP",
      "SMTP",
      "IMAP",
      "POP3",
    ];
    const protocol = protocols[Math.floor(Math.random() * protocols.length)];

    const sourceIP = promiscuousMode
      ? `${Math.floor(Math.random() * 223) + 1}.${Math.floor(
          Math.random() * 255
        )}.${Math.floor(Math.random() * 255)}.${Math.floor(
          Math.random() * 255
        )}`
      : `192.168.1.${Math.floor(Math.random() * 254) + 1}`;

    const destIPs = [
      "8.8.8.8",
      "1.1.1.1",
      "192.168.1.1",
      "10.0.0.1",
      "142.250.190.14",
      "13.107.42.14",
    ];
    const destIP = destIPs[Math.floor(Math.random() * destIPs.length)];

    const length = Math.floor(Math.random() * 1446) + 54;

    const relativeTime = startTimeRef.current
      ? ((Date.now() - startTimeRef.current) / 1000).toFixed(6)
      : "0.000000";

    const bytes = Array.from({ length }, () => Math.floor(Math.random() * 256));
    const hexData: string[] = [];
    for (let i = 0; i < length; i += 16) {
      const lineBytes = bytes.slice(i, i + 16);
      const hex = lineBytes
        .map((b) => b.toString(16).padStart(2, "0"))
        .join(" ");
      hexData.push(hex.padEnd(47, " "));
    }

    const details = generateProtocolDetails(protocol, sourceIP, destIP, length);

    return {
      id: packetId.current++,
      time: relativeTime,
      timestamp: Date.now(),
      source: sourceIP,
      destination: destIP,
      protocol,
      length,
      info: generateInfo(protocol),
      hexData,
      details,
    };
  };

  const generateFlags = (protocol: string) => {
    if (protocol === "TCP") {
      const flags = ["SYN", "ACK", "PSH", "FIN", "RST", "URG"];
      return flags[Math.floor(Math.random() * flags.length)];
    }
    return null;
  };

  const generateProtocolDetails = (
    protocol: string,
    src: string,
    dst: string,
    len: number
  ) => {
    const macSrc = Array(6)
      .fill(0)
      .map(() =>
        Math.floor(Math.random() * 256)
          .toString(16)
          .padStart(2, "0")
      )
      .join(":");
    const macDst = Array(6)
      .fill(0)
      .map(() =>
        Math.floor(Math.random() * 256)
          .toString(16)
          .padStart(2, "0")
      )
      .join(":");

    const now = new Date();
    const arrivalTime =
      now.toLocaleString("en-US", { hour12: false }) +
      `.${now.getMilliseconds().toString().padStart(3, "0")}`;

    const details: Record<string, { title: string; fields: string[] }> = {
      frame: {
        title: `Frame ${packetId.current}: ${len} bytes on wire`,
        fields: [
          `Arrival Time: ${arrivalTime}`,
          `Frame Length: ${len} bytes`,
          `Capture Length: ${len} bytes`,
          `Frame Number: ${packetId.current}`,
          "Protocols in frame: eth:ip:tcp",
        ],
      },
      ethernet: {
        title: "Ethernet II",
        fields: [
          `Destination: ${macDst}`,
          `Source: ${macSrc}`,
          "Type: IPv4 (0x0800)",
        ],
      },
      ipv4: {
        title: "Internet Protocol Version 4",
        fields: [
          "Version: 4",
          "Header Length: 20 bytes",
          "Total Length: " + (len - 14),
          "Identification: 0x" + Math.floor(Math.random() * 65535).toString(16),
          "Time to Live: " + Math.floor(Math.random() * 128 + 64),
          "Protocol: " + protocol,
          "Source Address: " + src,
          "Destination Address: " + dst,
        ],
      },
    };

    if (
      ["TCP", "HTTP", "HTTPS", "SSH", "FTP", "SMTP", "IMAP", "POP3"].includes(
        protocol
      )
    ) {
      details.tcp = {
        title: "Transmission Control Protocol",
        fields: [
          "Source Port: " + Math.floor(Math.random() * 40000 + 1024),
          "Destination Port: " +
            [80, 443, 22, 21, 25, 143, 110][Math.floor(Math.random() * 7)],
          "Sequence Number: " + Math.floor(Math.random() * 4294967295),
          "Acknowledgment Number: " + Math.floor(Math.random() * 4294967295),
          "Flags: 0x018 (PSH, ACK)",
          "Window Size: " + Math.floor(Math.random() * 65535),
        ],
      };
    } else if (protocol === "UDP" || protocol === "DNS") {
      details.udp = {
        title: "User Datagram Protocol",
        fields: [
          "Source Port: " + Math.floor(Math.random() * 65535),
          "Destination Port: " + [53, 123][Math.floor(Math.random() * 2)],
          "Length: " + (len - 34),
        ],
      };
    }

    if (protocol === "HTTP" || protocol === "HTTPS") {
      details.application = {
        title: protocol + " Request",
        fields: [
          "Request Method: " + ["GET", "POST"][Math.floor(Math.random() * 2)],
          "Request URI: /" +
            ["", "api/data", "login"][Math.floor(Math.random() * 3)],
          "Host: " + dst,
        ],
      };
    }

    return details;
  };

  const generateInfo = (protocol: string) => {
    const infos: Record<string, string[]> = {
      TCP: ["[SYN]", "[SYN, ACK]", "[ACK]", "[PSH, ACK]", "[FIN, ACK]"],
      UDP: ["DNS Query", "NTP Request"],
      HTTP: ["GET / HTTP/1.1", "POST /login"],
      DNS: ["Standard query A example.com"],
      ARP: ["Who has 192.168.1.1?"],
      ICMP: ["Echo (ping) request"],
      HTTPS: ["Application Data", "Client Hello"],
      SSH: ["SSH-2.0-OpenSSH"],
      FTP: ["USER anonymous"],
      SMTP: ["EHLO mail.example.com"],
      IMAP: ["LOGIN user pass"],
      POP3: ["STAT"],
    };
    return (
      infos[protocol]?.[Math.floor(Math.random() * infos[protocol].length)] ||
      "Data"
    );
  };

  const startCapture = () => {
    setCapturing(true);
    setPaused(false);
    setShowWelcome(false);
    const now = Date.now();
    setStartTime(now);
    startTimeRef.current = now;
    captureInterval.current = setInterval(() => {
      const packet = generatePacket();
      setPackets((prev) => {
        const next = [...prev, packet];
        if (next.length > maxPackets) return next.slice(-maxPackets);
        return next;
      });
    }, captureSpeed);
  };

  const stopCapture = () => {
    setCapturing(false);
    setPaused(false);
    if (captureInterval.current) clearInterval(captureInterval.current);
  };

  const pauseCapture = () => {
    if (paused) {
      startCapture(); // reuse logic
      setPaused(false);
    } else {
      if (captureInterval.current) clearInterval(captureInterval.current);
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

  return (
    <div className="h-screen flex flex-col bg-gradient-to-br from-gray-50 to-gray-100">
      {/* Welcome Modal */}
      {showWelcome && (
        <div className="fixed inset-0 bg-black/50 flex items-center justify-center z-50">
          <div className="bg-white rounded-lg p-8 max-w-2xl shadow-2xl">
            <div className="flex items-center gap-4 mb-6">
              <Wifi className="w-10 h-10 text-blue-600" />
              <h2 className="text-3xl font-bold">NetSpector</h2>
            </div>
            <p className="text-lg mb-6">
              Browser-based Wireshark-like Network Analyzer (Simulation)
            </p>
            <div className="bg-blue-50 p-4 rounded mb-6">
              <p className="text-sm">
                This is a <strong>simulation</strong> for educational purposes.
                Real packet capture requires native tools.
              </p>
            </div>
            <button
              onClick={() => setShowWelcome(false)}
              className="w-full bg-blue-600 text-white py-3 rounded-lg font-bold hover:bg-blue-700"
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
              {Object.entries(stats.protocols)
                .sort((a, b) => b[1] - a[1])
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
                  <td className="px-4 py-2 text-gray-700">{packet.info}</td>
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
          <div className="w-2/3 overflow-auto bg-white border-r">
            {selectedPacket ? (
              <div className="p-6">
                <h3 className="text-xl font-bold mb-5 flex items-center gap-3">
                  <Info className="w-6 h-6 text-blue-600" />
                  Packet Details #{selectedPacket.id}
                </h3>
                {Object.entries(selectedPacket.details).map(
                  ([key, section]: [string, any]) => (
                    <details
                      key={key}
                      open
                      className="mb-4 border rounded-lg shadow-sm"
                    >
                      <summary className="cursor-pointer font-semibold py-3 px-5 bg-blue-50 hover:bg-blue-100 flex items-center gap-3">
                        <span className="text-blue-600 text-lg">▶</span>
                        {section.title}
                      </summary>
                      <div className="p-5 bg-gray-50 border-t">
                        {section.fields.map((field: string, i: number) => {
                          const parts = field.split(": ");
                          return parts.length >= 2 ? (
                            <div key={i} className="py-1.5 text-sm">
                              <span className="font-medium text-gray-800">
                                {parts[0]}:
                              </span>
                              <span className="ml-4 font-mono text-blue-700">
                                {parts.slice(1).join(": ")}
                              </span>
                            </div>
                          ) : (
                            <div key={i} className="py-1.5 text-sm font-mono">
                              {field}
                            </div>
                          );
                        })}
                      </div>
                    </details>
                  )
                )}
              </div>
            ) : (
              <div className="flex items-center justify-center h-full text-gray-400">
                <div className="text-center">
                  <Info className="w-20 h-20 mx-auto mb-4" />
                  <p className="text-xl">Select a packet to view details</p>
                </div>
              </div>
            )}
          </div>

          {/* Hex Dump - 1/3 */}
          <div className="w-1/3 overflow-auto bg-gray-900 text-green-400 font-mono text-xs">
            {selectedPacket ? (
              <div className="p-5">
                <div className="text-white mb-4 flex items-center gap-3">
                  <Database className="w-5 h-5" />
                  <span className="font-bold">
                    Hex View ({selectedPacket.length} bytes)
                  </span>
                </div>
                {selectedPacket.hexData.map((line: string, idx: number) => (
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
                ))}
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
