const net = require("net");
const crc = require("crc");
const fs = require("fs");
const crypto = require("crypto");
const axios = require("axios"); // pro volitelný push-webhook (npm install axios)

module.exports = function (RED) {

    // ================================================
    // Konfigurační node (sia-server-config)
    // ================================================
    function SiaServerConfigNode(n) {
        RED.nodes.createNode(this, n);
        this.name = n.name;
        this.port = parseInt(n.port) || 10000;
        this.account = n.account || "";
        this.receiverID = n.receiverID || this.account || "";
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
        this.crcMethod = n.crcMethod || "xmodem";          // "xmodem" nebo "x25"
        this.ackTimeoutMs = parseInt(n.ackTimeoutMs) || 2000;
        this.keepAliveIntervalMs = parseInt(n.keepAliveIntervalMs) || 60000;
        this.autoRespondPolling = n.autoRespondPolling || false;
        this.pollResponseTemplate = n.pollResponseTemplate || "P#${account}";
        this.pushWebhookUrl = n.pushWebhookUrl || "";
    }
    RED.nodes.registerType("sia-server-config", SiaServerConfigNode);

    // ================================================
    // Hlavní node (sia-server)
    // ================================================
    function SiaServerNode(config) {
        RED.nodes.createNode(this, config);

        // Získání konfiguračního node
        const nodeConfig = RED.nodes.getNode(config.config);
        if (!nodeConfig) {
            this.error("Není přiřazen žádný konfigurační node!");
            return;
        }

        const node = this;
        const port = nodeConfig.port;
        const defaultAccount = nodeConfig.account;
        const receiverID = nodeConfig.receiverID;
        const allowedEvents = nodeConfig.allowedEvents;
        const zoneMap = nodeConfig.zoneMap;
        const useAes = nodeConfig.useAes;
        const aesKey = nodeConfig.aesKey;
        const reconnectInterval = nodeConfig.reconnectInterval;
        const allowedUsers = nodeConfig.allowedUsers;
        const language = nodeConfig.language;
        const crcMethod = nodeConfig.crcMethod;
        const ackTimeoutMs = nodeConfig.ackTimeoutMs;
        const keepAliveIntervalMs = nodeConfig.keepAliveIntervalMs;
        const autoRespondPolling = nodeConfig.autoRespondPolling;
        const pollResponseTemplate = nodeConfig.pollResponseTemplate;
        const pushWebhookUrl = nodeConfig.pushWebhookUrl;
        const debugMode = config.debugMode || true;
        const rawOutput = config.rawOutput || false;

        let clientSockets = [];
        let server = null;
        let pendingFragment = null;   // pro multi-fragmentaci SIA-DCS
        let keepAliveTimers = new Map();  // socket → intervalId
        let ackTimeouts = new Map();      // socket → timeoutId

        // Lokalizační zprávy
        const messages = {
            en: {
                BA: "Burglary Alarm",
                BF: "Fire Alarm",
                GC: "Armed Away",
                GP: "Armed Present",
                BD: "Bypass Disable",
                PD: "Power Failure",
                DIAG: "Diagnostic",
                POLL: "Polling Frame",
                UNAUTHORIZED: "Unauthorized user",
                NO_CONNECTION: "No connection to panel",
                SIA_CRC_ERR: "SIA-DCS CRC mismatch"
            },
            cs: {
                BA: "Poplach vloupání",
                BF: "Požární poplach",
                GC: "Připnuto z domova",
                GP: "Připnuto v objektu",
                BD: "Vypnutí bypass",
                PD: "Výpadek napájení",
                DIAG: "Diagnostika",
                POLL: "Pollingový rámec",
                UNAUTHORIZED: "Nepovolený uživatel",
                NO_CONNECTION: "Není připojena ústředna",
                SIA_CRC_ERR: "Chyba CRC u SIA-DCS"
            }
        };

        // ================================================
        // Spuštění TCP serveru
        // ================================================
        function startServer() {
            server = net.createServer((socket) => {
                clientSockets.push(socket);
                socket.setEncoding("utf8");
                node.log(`Klient připojen: ${socket.remoteAddress}:${socket.remotePort}`);
                node.status({ fill: "green", shape: "dot", text: `Připojeno od ${socket.remoteAddress}` });

                // Reset pendingFragment, ackTimeout i keepAlive
                pendingFragment = null;
                if (ackTimeouts.has(socket)) {
                    clearTimeout(ackTimeouts.get(socket));
                    ackTimeouts.delete(socket);
                }
                if (keepAliveTimers.has(socket)) {
                    clearInterval(keepAliveTimers.get(socket));
                    keepAliveTimers.delete(socket);
                }

                // Nastavíme keep-alive interval
                let keepId = setInterval(() => {
                    if (clientSockets.includes(socket)) {
                        let keepMsg = `F#${receiverID || defaultAccount}\r\n`;
                        socket.write(keepMsg);
                        node.log(`Odesílám server-polling: ${keepMsg.trim()}`);
                    }
                }, keepAliveIntervalMs);
                keepAliveTimers.set(socket, keepId);

                socket.on("data", (data) => {
                    let frames = data.split("\r\n").filter(x => x.trim().length > 0);
                    for (let frame of frames) {
                        node.log(`Přijato (raw): ${frame}`);
                        // 1) Multi-fragmentace: pokud předchozí skončil "...", spojovat
                        if (pendingFragment) {
                            pendingFragment += frame;
                            if (pendingFragment.endsWith("...")) {
                                // stále incomplete, čekáme dál
                                continue;
                            } else {
                                // máme kompletní fragment
                                frame = pendingFragment;
                                pendingFragment = null;
                            }
                        }
                        // Pokud nový frame SIA-DCS končí "...", uložíme a čekáme na další část
                        if (frame.startsWith("SIA-DCS") && frame.trim().endsWith("...")) {
                            pendingFragment = frame;
                            continue;
                        }

                        // 2) Základní parse
                        let sia = tryParseSia(frame, defaultAccount, crcMethod);
                        if (sia.valid) {
                            // --- Polling („F#…“) ---
                            if (sia.protocol === "GATEWAY-POLL") {
                                sia.localizedMessage = localize("POLL", sia.account);

                                // Pokus zrušit existující ackTimeout
                                if (ackTimeouts.has(socket)) {
                                    clearTimeout(ackTimeouts.get(socket));
                                    ackTimeouts.delete(socket);
                                }

                                // Automatická odpověď na polling
                                if (autoRespondPolling) {
                                    let resp = pollResponseTemplate
                                                .replace("${account}", sia.account || defaultAccount)
                                                .replace("${zone}", sia.zone || "")
                                                .replace("${suffix}", sia.suffix || "");
                                    socket.write(resp + "\r\n");
                                    node.log(`Odesílám polling ack: ${resp}`);
                                    // Nastavíme ack-timeout: pokud do ackTimeoutMs nedorazí SIA-DCS, uzavřeme socket
                                    let timeoutId = setTimeout(() => {
                                        node.status({ fill: "red", shape: "ring", text: "Timeout po ACK" });
                                        socket.destroy();
                                    }, ackTimeoutMs);
                                    ackTimeouts.set(socket, timeoutId);
                                }
                                // Poslat polling event do prvního výstupu
                                node.send([{
                                    payload: sia,
                                    raw: frame,
                                    account: sia.account,
                                    timestamp: new Date().toISOString(),
                                    extensions: sia.extensions || null,
                                    isDiagnostic: sia.isDiagnostic || false
                                }, null]);
                                continue;
                            }

                            // Pokud jsme zde, bylo to SIA-DCS nebo ADM-CID nebo DIAG či iBD
                            // --- Pokud to SIA-DCS, zrušíme ackTimeout ---
                            if (sia.protocol === "SIA-DCS" && ackTimeouts.has(socket)) {
                                clearTimeout(ackTimeouts.get(socket));
                                ackTimeouts.delete(socket);
                            }

                            // --- SIA-DCS (DC-09 Level 4) ---
                            if (sia.protocol === "SIA-DCS") {
                                // Filtrace povolených eventů
                                if (allowedEvents.length && !allowedEvents.includes(sia.event)) {
                                    node.log(`Ignoruji událost ${sia.event}`);
                                } else {
                                    // Odeslat ACK s ReceiverID
                                    let ack = buildAck(sia.sequence, sia.account, receiverID || defaultAccount);
                                    node.log(`Odesílám ACK: ${ack.trim()}`);
                                    socket.write(ack);
                                    // Mapování zón
                                    if (sia.zone && zoneMap[sia.zone]) {
                                        sia.zoneName = zoneMap[sia.zone];
                                    }
                                    // Lokalizace
                                    sia.localizedMessage = localize(sia.event, sia.zone);
                                    // Logování
                                    logEvent(sia);
                                    // Poslat do prvního výstupu
                                    node.send([{
                                        payload: sia,
                                        raw: frame,
                                        account: sia.account,
                                        timestamp: new Date().toISOString(),
                                        extensions: sia.extensions || null,
                                        isDiagnostic: sia.isDiagnostic || false
                                    }, null]);
                                }
                            }
                            // --- Contact-ID (ADM-CID) ---
                            else if (sia.protocol === "ADM-CID") {
                                // Contact-ID: neodesíláme ACK (používá vlastní mechaniku)
                                // Mapování zón
                                if (sia.zone && zoneMap[sia.zone]) {
                                    sia.zoneName = zoneMap[sia.zone];
                                }
                                // Lokalizace – pro Contact-ID obvykle event kód jako "BA"
                                sia.localizedMessage = localize(sia.event, sia.zone);
                                // Logování
                                logEvent(sia);
                                // Poslat do prvního výstupu
                                node.send([{
                                    payload: sia,
                                    raw: frame,
                                    account: sia.account,
                                    timestamp: new Date().toISOString(),
                                    extensions: sia.extensions || null,
                                    isDiagnostic: sia.isDiagnostic || false
                                }, null]);
                            }
                            // --- DIAG (diagnostická zpráva) ---
                            else if (sia.protocol === "SIA-DCS" && sia.event === "DIAG") {
                                // Stav diagnostické (zpracovat jako speciální event)
                                sia.zoneName = null;
                                sia.localizedMessage = localize("DIAG", "");
                                // Logování
                                logEvent(sia);
                                // Poslat do prvního výstupu i s flagem isDiagnostic
                                node.send([{
                                    payload: sia,
                                    raw: frame,
                                    account: sia.account,
                                    timestamp: new Date().toISOString(),
                                    extensions: sia.extensions || null,
                                    isDiagnostic: true
                                }, null]);
                            }
                            // --- Jiné (např. iBD eventy jako LANERR, NETDOWN) ---
                            else {
                                // Mapování zón
                                if (sia.zone && zoneMap[sia.zone]) {
                                    sia.zoneName = zoneMap[sia.zone];
                                }
                                sia.localizedMessage = localize(sia.event, sia.zone);
                                logEvent(sia);
                                node.send([{
                                    payload: sia,
                                    raw: frame,
                                    account: sia.account,
                                    timestamp: new Date().toISOString(),
                                    extensions: sia.extensions || null,
                                    isDiagnostic: sia.isDiagnostic || false
                                }, null]);
                            }

                            // --- Push-webhook (volitelné) ---
                            if (pushWebhookUrl) {
                                let pushPayload = {
                                    protocol: sia.protocol,
                                    account: sia.account,
                                    event: sia.event,
                                    zone: sia.zone,
                                    message: sia.message,
                                    timestamp: new Date().toISOString(),
                                    extensions: sia.extensions || null,
                                    isDiagnostic: sia.isDiagnostic || false
                                };
                                axios.post(pushWebhookUrl, pushPayload).catch(err => {
                                    node.warn(`Push webhook error: ${err.message}`);
                                });
                            }
                        } else {
                            // --- Chybný formát / CRC / neznámý formát ---
                            node.warn(`Chyba parsování: ${sia.error}`);
                            if (sia.protocol === "SIA-DCS" && sia.error === messages[language].SIA_CRC_ERR) {
                                // Pokud SIA-DCS s CRC, pošleme NAK
                                let nak = buildNak(sia.sequence, receiverID || defaultAccount);
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
                    // Vyčistit timeouy a intervaly
                    if (ackTimeouts.has(socket)) {
                        clearTimeout(ackTimeouts.get(socket));
                        ackTimeouts.delete(socket);
                    }
                    if (keepAliveTimers.has(socket)) {
                        clearInterval(keepAliveTimers.get(socket));
                        keepAliveTimers.delete(socket);
                    }
                    pendingFragment = null;
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
                    // Vyčistit timeouy a intervaly
                    if (ackTimeouts.has(socket)) {
                        clearTimeout(ackTimeouts.get(socket));
                        ackTimeouts.delete(socket);
                    }
                    if (keepAliveTimers.has(socket)) {
                        clearInterval(keepAliveTimers.get(socket));
                        keepAliveTimers.delete(socket);
                    }
                    pendingFragment = null;
                    // Po reconnectInterval s restart naslouchání
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

        // ================================================
        // Při ukončení node
        // ================================================
        this.on("close", () => {
            if (server) server.close();
            clientSockets.forEach(s => s.destroy());
            clientSockets = [];
            pendingFragment = null;
            // Vyčistit všechny timeouty a intervaly
            ackTimeouts.forEach((to) => clearTimeout(to));
            ackTimeouts.clear();
            keepAliveTimers.forEach((id) => clearInterval(id));
            keepAliveTimers.clear();
            node.status({});
            node.log("SIA server ukončen");
        });

        // ================================================
        // Zpracování vstupních zpráv (ARM / DISARM / CUSTOM)
        // ================================================
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

        // ================================================
        // Parser (SIA-DCS, ADM-CID, polling, AES, fragmentace, extensions, DIAG)
        // ================================================
        function tryParseSia(frame, defaultAcct, crcMethod) {
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
                suffix: null,
                message: null,
                extensions: null,
                isDiagnostic: false
            };

            let raw = frame.trim();
            try {
                // --- 1) AES dešifrování pokud aktivní ---
                if (useAes && raw.startsWith("AES#")) {
                    raw = decryptAesFrame(raw, aesKey);
                }

                // --- 2) SIA-DCS (DC-09) s volitelným CRC-16 a extensions ---
                // Regex zachytí: [1]=sequence, [2]=payload (prostřední řetězec), [3]=čtyřmístný CRC (nepovinné)
                let siaRe = /^SIA-DCS\s+[0-9A-Fa-f]+\s*(\d+)?\s*"(.*)"\s*([0-9A-Fa-f]{4})?$/;
                let m = siaRe.exec(raw);
                if (m) {
                    result.protocol = "SIA-DCS";
                    result.sequence = m[1] || null;
                    let payloadAndExt = m[2];  // např. "[BA|01]poplach|EXT=BatteryLow|TIMESTAMP=..."
                    let receivedCrc = m[3];    // může být undefined
                    // CRC ověření, pokud přítomno
                    if (receivedCrc) {
                        let withoutCrc = raw.substring(0, raw.lastIndexOf(`"${payloadAndExt}"`) + payloadAndExt.length + 2);
                        let calcCrc = (crcMethod === "x25")
                            ? crc.crc16ccitt(Buffer.from(withoutCrc, "ascii")).toString(16).toUpperCase().padStart(4, "0")
                            : crc.crc16xmodem(Buffer.from(withoutCrc, "ascii")).toString(16).toUpperCase().padStart(4, "0");
                        if (calcCrc !== receivedCrc.toUpperCase()) {
                            result.error = messages[language].SIA_CRC_ERR;
                            return result;
                        }
                    }
                    // Rozdělit payload a případné extensions
                    let parts = payloadAndExt.split("|");
                    let mainPart = parts.shift(); // např. "[BA|01]poplach"
                    let extParts = parts;         // např. ["EXT=BatteryLow","TIMESTAMP=20250607T134500"]
                    // Parsování hlavního payloadu
                    let evtRe = /^\[([A-Z0-9]+)\|([A-Z0-9]+)(?::([0-9]+))?\](.*)$/;
                    let em = evtRe.exec(mainPart);
                    if (!em) {
                        result.error = "Payload nesplňuje [EVENT|ZONE:PART]Syntax.";
                        return result;
                    }
                    result.event = em[1];
                    result.zone = em[2];
                    result.partition = em[3] || null;
                    result.message = em[4];
                    // Parsování extensions do objektu
                    if (extParts.length) {
                        let exts = {};
                        extParts.forEach(e => {
                            let [k, v] = e.split("=");
                            if (k && v !== undefined) {
                                exts[k.toLowerCase()] = v;
                            }
                        });
                        result.extensions = exts;
                    }
                    // Pokud je to diagnostický kód (např. DIAG, LANERR, NETDOWN), označíme
                    if (result.event === "DIAG" ||
                        ["LANERR", "NETDOWN", "PSUPPLY", "PDUERR"].includes(result.event)) {
                        result.isDiagnostic = true;
                    }
                    result.valid = true;
                    return result;
                }

                // --- 3) ADM-CID (Contact-ID) s CRC-16 ---
                let admRe = /^ADM-CID\s+([\d]+)\s+([\d]+)\s*\[(.*)\]([0-9A-Fa-f]{4})$/;
                let n = admRe.exec(raw);
                if (n) {
                    result.protocol = "ADM-CID";
                    result.sequence = n[2];
                    let payload = n[3];         // např. "event=BA zone=01 user=0001"
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

                // --- 4) Pollingový rámec "F#<Account><Suffix?>" ---
                if (raw.startsWith("F#")) {
                    result.protocol = "GATEWAY-POLL";
                    let pl = raw.slice(2).trim();
                    let parts = pl.match(/^(\d+)(.*)$/);
                    if (parts) {
                        result.account = parts[1];
                        result.suffix = parts[2] || "";
                    } else {
                        result.account = pl;
                        result.suffix = "";
                    }
                    result.event = "POLL";
                    result.zone = null;
                    result.message = "Polling / keep-alive frame";
                    result.valid = true;
                    return result;
                }

                // --- 5) Diagnostika "DIAG" – pokud přímo "[DIAG|...]..." ---
                let diagRe = /^\[DIAG\|(.*)\](.*)$/;
                let d = diagRe.exec(raw);
                if (d) {
                    result.protocol = "SIA-DCS";
                    result.event = "DIAG";
                    result.zone = null;
                    result.partition = null;
                    result.message = d[2]; // zbytek zprávy
                    result.extensions = { info: d[1] };
                    result.isDiagnostic = true;
                    result.valid = true;
                    return result;
                }

                // --- 6) Neznámý formát ---
                result.error = "Unrecognized format";
                return result;
            } catch (e) {
                result.error = "Parse exception: " + e.message;
                return result;
            }
        }

        // ================================================
        // Dešifrování AES-128-CBC (hex: IV + ciphertext)
        // ================================================
        function decryptAesFrame(frame, keyHex) {
            // formát: "AES#"<IV(32hex)><CIPHERTEXT(hex)>
            let hexData = frame.slice(4).trim();
            let iv = Buffer.from(hexData.slice(0, 32), "hex");
            let ct = Buffer.from(hexData.slice(32), "hex");
            let key = Buffer.from(keyHex, "hex");
            let decipher = crypto.createDecipheriv("aes-128-cbc", key, iv);
            let decrypted = Buffer.concat([decipher.update(ct), decipher.final()]);
            return decrypted.toString("ascii");
        }

        // ================================================
        // Parsování Contact-ID payload
        // formát: event=… zone=… user=… code=…
        // ================================================
        function parseContactIdPayload(text, result) {
            let parts = text.split(/\s+/);
            parts.forEach(p => {
                let [k, v] = p.split("=");
                switch (k) {
                    case "event":
                        result.event = v;
                        break;
                    case "zone":
                        result.zone = v;
                        break;
                    case "user":
                        result.user = v;
                        break;
                    case "code":
                        result.user = v;
                        break;
                }
            });
            result.message = `Event ${result.event}, zone ${result.zone}`;
        }

        // ================================================
        // Lokalizace zpráv
        // ================================================
        function localize(eventCode, zone) {
            let msgSet = messages[language] || messages["en"];
            let base = msgSet[eventCode] || eventCode;
            if (zone) {
                return `${base} (${zone})`;
            }
            return base;
        }

        // ================================================
        // Logování do souboru (včetně extensions)
        // ================================================
        function logEvent(sia) {
            // zapíšeme: ISO8601,Account,Event,Zone,Message,Extensions_JSON
            let extJson = sia.extensions ? JSON.stringify(sia.extensions) : "";
            let line = `${new Date().toISOString()},${sia.account},${sia.event},${sia.zone || ""},${sia.message},${extJson}\n`;
            fs.appendFile("/home/nodered/sia-events.log", line, err => {
                if (err) node.error("Chyba při zapisování logu: " + err);
            });
        }

        // ================================================
        // Build ACK / NAK s volitelným ReceiverID
        // ================================================
        function buildAck(seq, acct, recvID) {
            if (recvID) {
                return `\r\nACK ${seq || ""} ${recvID}\r\n`;
            }
            return `\r\nACK ${seq || ""}\r\n`;
        }
        function buildNak(seq, recvID) {
            if (recvID) {
                return `\r\nNAK ${seq || ""} ${recvID}\r\n`;
            }
            return `\r\nNAK ${seq || ""}\r\n`;
        }

        // ================================================
        // HTTP endpoint pro externí eventy
        // ================================================
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
                    valid: true,
                    extensions: null,
                    isDiagnostic: false
                };
                node.send([{
                    payload: sia,
                    raw: JSON.stringify(payload),
                    account: defaultAccount,
                    timestamp: new Date().toISOString(),
                    extensions: null,
                    isDiagnostic: false
                }, null]);
                res.sendStatus(200);
            } else {
                res.sendStatus(404);
            }
        });
    }

    RED.nodes.registerType("sia-server", SiaServerNode);
};
