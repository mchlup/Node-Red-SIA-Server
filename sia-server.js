const net = require("net");
const crc = require("crc");
const fs = require("fs");
const crypto = require("crypto");

module.exports = function (RED) {

    // ================================
    // Konfigurační node
    // ================================
    function SiaServerConfigNode(n) {
        RED.nodes.createNode(this, n);
        this.name = n.name;
        this.port = parseInt(n.port) || 10000;
        this.password = n.password || "";
        this.account = n.account || "";
        this.allowedEvents = (n.allowedEvents || "").split(",").map(s => s.trim()).filter(s => s);
        try {
            this.zoneMap = n.zoneMap ? JSON.parse(n.zoneMap) : {};
        } catch(err) {
            this.zoneMap = {};
        }
        this.useAes = n.useAes || false;
        this.aesKey = n.aesKey || "";
        this.reconnectInterval = parseInt(n.reconnectInterval) || 10;
        this.allowedUsers = (n.allowedUsers || "").split(",").map(s => s.trim()).filter(s => s);
        this.language = n.language || "en";
        this.autoRespondPolling = n.autoRespondPolling || true;
        // Výchozí šablona: odpověď na polling musí být "P#<account>"
        this.pollResponseTemplate = n.pollResponseTemplate || "P#${account}";
    }
    RED.nodes.registerType("sia-server-config", SiaServerConfigNode);

    // ================================
    // Hlavní node
    // ================================
    function SiaServerNode(config) {
        RED.nodes.createNode(this, config);

        const nodeConfig = RED.nodes.getNode(config.config);
        if (!nodeConfig) {
            this.error("Není přiřazen žádný konfigurační node!");
            return;
        }

        const node = this;
        const port = nodeConfig.port;
        const defaultAccount = nodeConfig.account;
        const allowedEvents = nodeConfig.allowedEvents;
        const zoneMap = nodeConfig.zoneMap;
        const useAes = nodeConfig.useAes;
        const aesKey = nodeConfig.aesKey;
        const reconnectInterval = nodeConfig.reconnectInterval;
        const allowedUsers = nodeConfig.allowedUsers;
        const language = nodeConfig.language;
        const autoRespondPolling = nodeConfig.autoRespondPolling;
        const pollResponseTemplate = nodeConfig.pollResponseTemplate;
        const debugMode = config.debugMode || true;
        const rawOutput = config.rawOutput || true;

        let clientSockets = [];
        let server = null;

        // Lokalizační zprávy (CS/EN)
        const messages = {
            en: {
                BA: "Burglary Alarm",
                BF: "Fire Alarm",
                GC: "Armed Away",
                GP: "Armed Present",
                BD: "Bypass Disable",
                PD: "Power Failure",
                POLL: "Polling Frame",
                UNAUTHORIZED: "Unauthorized user",
                NO_CONNECTION: "No connection to panel"
            },
            cs: {
                BA: "Poplach vloupání",
                BF: "Požární poplach",
                GC: "Připnuto z domova",
                GP: "Připnuto v objektu",
                BD: "Bypass vypnutý",
                PD: "Výpadek napájení",
                POLL: "Pollingový rámec",
                UNAUTHORIZED: "Nepovolený uživatel",
                NO_CONNECTION: "Není připojena ústředna"
            }
        };

        // ================================
        // Spuštění TCP serveru
        // ================================
        function startServer() {
            server = net.createServer((socket) => {
                clientSockets.push(socket);
                socket.setEncoding("utf8");
                node.log(`Klient připojen: ${socket.remoteAddress}:${socket.remotePort}`);
                node.status({ fill: "green", shape: "dot", text: `Připojeno od ${socket.remoteAddress}` });

                socket.on("data", (data) => {
                    let frames = data.split("\r\n").filter(x => x.trim().length > 0);
                    for (let frame of frames) {
                        node.log(`Přijato (raw): ${frame}`);
                        let sia = tryParseSia(frame, defaultAccount);
                        if (sia.valid) {
                            // === Polling („F#…“) ===
                            if (sia.protocol === "GATEWAY-POLL") {
                                sia.localizedMessage = localize("POLL", sia.account);

                                // Odeslat polling-ack („P#<account>“) pokud je autoRespondPolling
                                if (autoRespondPolling) {
                                    let resp = pollResponseTemplate.replace("${account}", sia.account);
                                    socket.write(resp + "\r\n");
                                    node.log(`Odesílám polling ack: ${resp}`);
                                }

                                // Pošle do prvního výstupu objekt s polling daty
                                node.send([{
                                    payload: sia,
                                    raw: frame,
                                    account: sia.account,
                                    timestamp: new Date().toISOString()
                                }, null]);
                                continue;
                            }

                            // === Standardní SIA-DCS (DC-09) ===
                            if (sia.protocol === "SIA-DCS") {
                                // Filtrace povolených eventů (pokud je vyplněno)
                                if (allowedEvents.length && !allowedEvents.includes(sia.event)) {
                                    node.log(`Ignoruji událost ${sia.event}`);
                                    continue;
                                }
                                // Odeslat ACK
                                let ack = buildAck(sia.sequence, sia.account);
                                node.log(`Odesílám ACK: ${ack.trim()}`);
                                socket.write(ack);
                            }
                            // === Contact-ID (ADM-CID) – neodesíláme ACK, pouze zpracujeme ===

                            // Mapování zóny (pokud existuje)
                            if (sia.zone && zoneMap[sia.zone]) {
                                sia.zoneName = zoneMap[sia.zone];
                            }
                            // Lokalizace
                            sia.localizedMessage = localize(sia.event, sia.zone);
                            // Logování do souboru
                            logEvent(sia);
                            // Pošleme do prvního výstupu
                            node.send([{
                                payload: sia,
                                raw: frame,
                                account: sia.account,
                                timestamp: new Date().toISOString()
                            }, null]);

                        } else {
                            // === Špatný formát / CRC / neznámý formát ===
                            node.warn(`Chyba parsování: ${sia.error}`);
                            if (sia.protocol === "SIA-DCS") {
                                let nak = buildNak(sia.sequence);
                                node.log(`Odesílám NAK: ${nak.trim()}`);
                                socket.write(nak);
                            }
                            if (rawOutput || debugMode) {
                                node.send([null, {
                                    error: sia.error,
                                    raw: frame,
                                    timestamp: new Date().toISOString()
                                }]);
                            }
                            node.status({ fill: "yellow", shape: "ring", text: `"${sia.error}"` });
                            setTimeout(() => node.status({}), 3000);
                        }
                    }
                });

                socket.on("close", () => {
                    node.log(`Klient odpojen: ${socket.remoteAddress}`);
                    clientSockets = clientSockets.filter(s => s !== socket);
                    node.send([null, {
                        event: "disconnect",
                        ip: socket.remoteAddress,
                        timestamp: new Date().toISOString()
                    }]);
                    node.status({ fill: "red", shape: "ring", text: "Odpojeno" });
                });

                socket.on("error", (err) => {
                    node.error(`Socket error: ${err.message}`);
                    node.send([null, {
                        error: err.message,
                        timestamp: new Date().toISOString()
                    }]);
                    node.status({ fill: "red", shape: "ring", text: "Chyba socketu" });
                    clientSockets = clientSockets.filter(s => s !== socket);
                    socket.destroy();
                    // Po reconnectInterval sekundách restartujeme server
                    setTimeout(() => {
                        try {
                            startServer();
                        } catch(e) {
                            node.error("Nepovedlo se restartovat server: " + e.message);
                        }
                    }, reconnectInterval * 1000);
                });
            });

            server.listen(port, () => {
                node.log(`SIA server naslouchá na portu ${port}`);
                node.status({ fill: "green", shape: "dot", text: `Naslouchá na portu ${port}` });
            });

            server.on("error", (err) => {
                node.error("Chyba při spouštění serveru: " + err.message);
                node.status({ fill: "red", shape: "ring", text: "Nelze otevřít port" });
                setTimeout(() => {
                    try {
                        startServer();
                    } catch(e) {
                        node.error("Nepovedlo se restartovat server: " + e.message);
                    }
                }, reconnectInterval * 1000);
            });
        }

        startServer();

        // ================================
        // Při vypnutí node
        // ================================
        this.on("close", () => {
            if (server) server.close();
            clientSockets.forEach(s => s.destroy());
            clientSockets = [];
            node.status({});
            node.log("SIA server ukončen");
        });

        // ================================
        // Zpracování vstupu (ARM / DISARM / CUSTOM)
        // ================================
        node.on("input", (msg) => {
            try {
                if (!msg.payload || typeof msg.payload !== "object") {
                    throw new Error("Očekávám objekt s akcí (action) a parametry.");
                }
                let cmd = msg.payload.action;
                let userCode = msg.payload.code || "";
                // Kontrola oprávnění pro ARM / DISARM
                if ((cmd === "ARM" || cmd === "DISARM")
                    && allowedUsers.length
                    && !allowedUsers.includes(userCode)) {
                    throw new Error(localize("UNAUTHORIZED", ""));
                }
                let destAccount = msg.payload.account || defaultAccount;
                let partition   = msg.payload.partition || "";
                let customFrame = msg.payload.customFrame || "";
                if (clientSockets.length === 0) {
                    throw new Error(localize("NO_CONNECTION", ""));
                }
                let socket = clientSockets[0];
                let frameToSend = "";

                if (cmd === "ARM" || cmd === "DISARM") {
                    let actionCode = (cmd === "ARM") ? "AR" : "DA";
                    let body = `[${actionCode}|${partition}]${userCode}`;
                    frameToSend = `SIA-DCS 00 "${body}"\r\n`;
                } else if (cmd === "CUSTOM") {
                    if (!customFrame) {
                        throw new Error("Pro CUSTOM musíte dodat customFrame.");
                    }
                    frameToSend = customFrame + "\r\n";
                } else {
                    throw new Error(`Neznámá akce: ${cmd}`);
                }

                node.log(`Odesílám ústředně: ${frameToSend.trim()}`);
                socket.write(frameToSend);
                node.send([{
                    info: `Posláno: ${cmd}`,
                    timestamp: new Date().toISOString()
                }, null]);
            } catch (err) {
                node.error(err.message);
                node.send([null, {
                    error: err.message,
                    timestamp: new Date().toISOString()
                }]);
            }
        });

        // ================================
        // Parser (SIA-DCS, ADM-CID, polling, AES)
        // ================================
        function tryParseSia(frame, defaultAcct) {
            let result = {
                valid: false,
                error: null,
                sequence: null,
                account: defaultAcct,
                protocol: null,
                event: null,
                zone: null,
                user: null,
                partition: null,
                message: null
            };

            let raw = frame.trim();
            try {
                // --- 1) AES dešifrování, pokud je aktivní ---
                if (useAes && raw.startsWith("AES#")) {
                    raw = decryptAesFrame(raw, aesKey);
                }

                // --- 2) SIA-DCS (DC-09) ---
                let siaRe = /^(SIA-DCS)\s+[0-9A-Fa-f]+\s*(\d+)?\s*"(.*)"$/;
                let m = siaRe.exec(raw);
                if (m) {
                    result.protocol = "SIA-DCS";
                    result.sequence = m[2] || null;
                    let payload = m[3];
                    let evtRe = /^\[([A-Z0-9]+)\|([A-Z0-9]+)(?::([0-9]+))?\](.*)$/;
                    let em = evtRe.exec(payload);
                    if (!em) {
                        result.error = "Payload nesplňuje [EVENT|ZONE:PART]Syntax.";
                        return result;
                    }
                    result.event = em[1];
                    result.zone = em[2];
                    result.partition = em[3] || null;
                    result.message = em[4];
                    result.valid = true;
                    return result;
                }

                // --- 3) ADM-CID (SIA-DC-05) s CRC-16 ---
                let admRe = /^ADM-CID\s+([\d]+)\s+([\d]+)\s*\[(.*)\]([0-9A-Fa-f]{4})$/;
                let n = admRe.exec(raw);
                if (n) {
                    result.protocol = "ADM-CID";
                    result.sequence = n[2];
                    let payload = n[3];
                    let receivedCrc = n[4];
                    let dataForCrc = raw.substring(0, raw.lastIndexOf("]") + 1);
                    let actualCrc = crc.crc16xmodem(Buffer.from(dataForCrc, "ascii"))
                                      .toString(16).toUpperCase().padStart(4, "0");
                    if (actualCrc !== receivedCrc.toUpperCase()) {
                        result.error = "CRC mismatch";
                        return result;
                    }
                    parseContactIdPayload(payload, result);
                    result.valid = true;
                    return result;
                }

                // --- 4) Pollingový rámec "F#<Account>" ---
                if (raw.startsWith("F#")) {
                    result.protocol = "GATEWAY-POLL";
                    let acctVal = raw.slice(2).trim();
                    let acctMatch = acctVal.match(/^\d+/);
                    result.account = acctMatch ? acctMatch[0] : acctVal;
                    result.event = "POLL";
                    result.zone = null;
                    result.message = "Polling / keep-alive frame";
                    result.valid = true;
                    return result;
                }
                // --- 5) Neznámý formát ---
                result.error = "Unrecognized format";
                return result;
            } catch (e) {
                result.error = "Parse exception: " + e.message;
                return result;
            }
        }

        // --- AES-128-CBC dešifrování (iv + ciphertext v hexu) ---
        function decryptAesFrame(frame, keyHex) {
            let hexData = frame.slice(4).trim();
            let iv = Buffer.from(hexData.slice(0, 32), "hex");
            let ct = Buffer.from(hexData.slice(32), "hex");
            let key = Buffer.from(keyHex, "hex");
            let decipher = crypto.createDecipheriv("aes-128-cbc", key, iv);
            let decrypted = Buffer.concat([decipher.update(ct), decipher.final()]);
            return decrypted.toString("ascii");
        }

        // --- Parsování Contact-ID payload (event, zone, uživatel, …) ---
        function parseContactIdPayload(text, result) {
            let parts = text.split(/\s+/);
            parts.forEach(p => {
                let [k, v] = p.split("=");
                switch (k) {
                    case "event": result.event = v; break;
                    case "zone":  result.zone = v; break;
                    case "user":  result.user = v; break;
                    case "code":  result.user = v; break;
                }
            });
            result.message = `Event ${result.event}, zóna ${result.zone}`;
        }

        // --- Lokalizace zpráv (CS/EN) ---
        function localize(eventCode, zone) {
            let msgSet = messages[language] || messages["en"];
            let base = msgSet[eventCode] || eventCode;
            if (zone) {
                return `${base} (${zone})`;
            }
            return base;
        }

        // --- Logování událostí do souboru ---
        function logEvent(sia) {
            let logline = `${new Date().toISOString()},${sia.account},${sia.event},${sia.zone},${sia.message}\n`;
            fs.appendFile("/home/nodered/sia-events.log", logline, err => {
                if (err) node.error("Chyba při zapisování logu: " + err);
            });
        }

        // --- Funkce: ACK / NAK ---
        function buildAck(seq, acct) {
            return `\r\nACK ${seq || ""}\r\n`;
        }
        function buildNak(seq) {
            return `\r\nNAK ${seq || ""}\r\n`;
        }

        // --- HTTP endpoint pro externí eventy (volitelné) ---
        RED.httpAdmin.post("/sia-server/:id/event", RED.auth.needsPermission("sia-server.write"), function(req, res) {
            let node = RED.nodes.getNode(req.params.id);
            if (node) {
                let payload = req.body;
                let sia = {
                    protocol: "EXTERNAL",
                    sequence: null,
                    account: defaultAccount,
                    event: payload.event,
                    zone: payload.zone,
                    message: payload.message,
                    valid: true
                };
                node.send([{
                    payload: sia,
                    raw: JSON.stringify(payload),
                    account: defaultAccount,
                    timestamp: new Date().toISOString()
                }, null]);
                res.sendStatus(200);
            } else {
                res.sendStatus(404);
            }
        });
    }

    RED.nodes.registerType("sia-server", SiaServerNode);
};
