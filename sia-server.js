const net = require("net");
const crc = require("crc");
const fs = require("fs");
const crypto = require("crypto");
const axios = require("axios");

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
        this.crcMethod = n.crcMethod || "xmodem";          // "xmodem", "x25" nebo "arc"
        this.minDelayMs = parseInt(n.minDelayMs) || 0;     // minimální zpoždění před odesláním (ms)
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
        const minDelayMs = nodeConfig.minDelayMs;
        const ackTimeoutMs = nodeConfig.ackTimeoutMs;
        const keepAliveIntervalMs = nodeConfig.keepAliveIntervalMs;
        const autoRespondPolling = nodeConfig.autoRespondPolling;
        const pollResponseTemplate = nodeConfig.pollResponseTemplate;
        const pushWebhookUrl = nodeConfig.pushWebhookUrl;
        const debugMode = config.debugMode || false;
        const rawOutput = config.rawOutput || false;

        let clientSockets = [];
        let server = null;
        let pendingFragment = null;
        let keepAliveTimers = new Map();
        let ackTimeouts = new Map();

        // Lokalizační zprávy
        const messages = {
            en: {
                BA:  "Burglary Alarm",
                BF:  "Fire Alarm",
                GC:  "Armed Away",
                GP:  "Armed Present",
                BD:  "Bypass Disable",
                PD:  "Power Failure",
                DIAG: "Diagnostic",
                POLL: "Polling Frame",
                UNAUTHORIZED: "Unauthorized user",
                NO_CONNECTION: "No connection to panel",
                SIA_CRC_ERR: "SIA-DCS CRC mismatch",
                BRK: "Break-in Detected",
                TWR: "Tower Link Down",
                ALM: "General Alarm",
                CLG: "Closing",
                RP:  "Repeat Event"
            },
            cs: {
                BA:  "Poplach vloupání",
                BF:  "Požární poplach",
                GC:  "Připnuto z domova",
                GP:  "Připnuto v objektu",
                BD:  "Vypnutí bypass",
                PD:  "Výpadek napájení",
                DIAG: "Diagnostika",
                POLL: "Pollingový rámec",
                UNAUTHORIZED: "Nepovolený uživatel",
                NO_CONNECTION: "Není připojena ústředna",
                SIA_CRC_ERR: "Chyba CRC u SIA-DCS",
                BRK: "Násilný vnik",
                TWR: "Ztráta spojení s vysílačem",
                ALM: "Všeobecný poplach",
                CLG: "Zavírání",
                RP:  "Opakovaná událost"
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
                        sendWithDelay(socket, keepMsg, minDelayMs);
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

                                // Zrušit existující ackTimeout, pokud je
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
                                    sendWithDelay(socket, resp + "\r\n", minDelayMs);
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
                                    sendWithDelay(socket, ack, minDelayMs);
                                    node.log(`Odesílám ACK: ${ack.trim()}`);

                                    // Multiplexované balíčky (ACCID/MSGNUM)
                                    if (sia.extensions && sia.extensions.accid && sia.extensions.msgnum) {
                                        // Rozdělit multiple eventy
                                        let combined = sia.extensions.rawPayload || ""; 
                                        // Pokud jsme v tryParseSia už uložili rawPayload = inside string
                                        // nebo jednoduše: parsovat opět payload z frame:
                                        let insideFull = frame.trim().replace(/^SIA-DCS\s+[0-9A-Fa-f]+\s*\d*\s*"/, "").replace(/"[0-9A-Fa-f]{4}$/, "");
                                        let parts = insideFull.split(";");
                                        // Očividně parts[0] = "ACCID:000997", parts[1]="MSGNUM:03", pak [EV|ZZ], ...
                                        let subEvents = parts.slice(2);
                                        subEvents.forEach(evtStr => {
                                            let m2 = /^\[([A-Z0-9]+)\|([A-Z0-9]+)\](.*)$/.exec(evtStr);
                                            if (m2) {
                                                let subSia = Object.assign({}, sia);
                                                subSia.event = m2[1];
                                                subSia.zone = m2[2];
                                                subSia.message = m2[3];
                                                if (subSia.zone && zoneMap[subSia.zone]) {
                                                    subSia.zoneName = zoneMap[subSia.zone];
                                                }
                                                subSia.localizedMessage = localize(subSia.event, subSia.zone);
                                                logEvent(subSia);
                                                node.send([{
                                                    payload: subSia,
                                                    raw: frame,
                                                    account: subSia.account,
                                                    timestamp: new Date().toISOString(),
                                                    extensions: subSia.extensions || null,
                                                    isDiagnostic: subSia.isDiagnostic || false
                                                }, null]);
                                            }
                                        });
                                    } else {
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
                                }
                            }
                            // --- Contact-ID (ADM-CID / SIA-CID) ---
                            else if (sia.protocol === "ADM-CID") {
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
                            // --- Diagnostika (DIAG) ---
                            else if (sia.protocol === "SIA-DCS" && sia.event === "DIAG") {
                                sia.zoneName = null;
                                sia.localizedMessage = localize("DIAG", "");
                                logEvent(sia);
                                node.send([{
                                    payload: sia,
                                    raw: frame,
                                    account: sia.account,
                                    timestamp: new Date().toISOString(),
                                    extensions: sia.extensions || null,
                                    isDiagnostic: true
                                }, null]);
                            }
                            // --- Jiné (iBD eventy) ---
                            else {
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
                                    zoneName: sia.zoneName || null,
                                    partition: sia.partition || null,
                                    user: sia.user || null,
                                    time: sia.time || null,
                                    peripheral: sia.peripheral || null,
                                    logText: sia.logText || null,
                                    siteID: sia.siteID || null,
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
                                let nak = buildNak(sia.sequence, receiverID || defaultAccount);
                                sendWithDelay(socket, nak, minDelayMs);
                                node.log(`Odesílám NAK: ${nak.trim()}`);
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
            // Vyčistit timeouty a intervaly
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
                    frameToSend = `SIA-DCS 00 "${destAccount}${body}"\r\n`;
                } else if (cmd === "CUSTOM") {
                    if (!customFrame) {
                        throw new Error("Pro CUSTOM musíte dodat customFrame.");
                    }
                    frameToSend = customFrame + "\r\n";
                } else {
                    throw new Error(`Neznámá akce: ${cmd}`);
                }

                node.log(`Odesílám ústředně: ${frameToSend.trim()}`);
                sendWithDelay(socket, frameToSend, minDelayMs);
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
        // Parser (SIA-DCS Level 4, ADM-CID, SIA-CID, polling, AES, fragmentace, multiplex, DIAG, iBD)
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
                peripheral: null,
                time: null,
                logText: null,
                siteID: null,
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

                // --- 1) SIA-DCS (DC-09 Level 4) s volitelným CRC-16 (XModem/X.25/ARC) ---
                let siaRe = /^SIA-DCS\s+[0-9A-Fa-f]+\s*(\d+)?\s*"(.*)"\s*([0-9A-Fa-f]{4})?$/;
                let m = siaRe.exec(raw);
                if (m) {
                    result.protocol = "SIA-DCS";
                    result.sequence = m[1] || null;
                    let inside = m[2];      // Hlavní obsah uvnitř uvozovek
                    let receivedCrc = m[3]; // CRC, pokud existuje

                    // --- CRC ověření ---
                    if (receivedCrc) {
                        let withoutCrc = raw.substring(0, raw.lastIndexOf(`"${inside}"`) + inside.length + 2);
                        let calcCrc;
                        if (crcMethod === "x25") {
                            calcCrc = crc.crc16ccitt(Buffer.from(withoutCrc, "ascii")).toString(16).toUpperCase().padStart(4, "0");
                        } else if (crcMethod === "arc") {
                            calcCrc = crc.crc16arc(Buffer.from(withoutCrc, "ascii")).toString(16).toUpperCase().padStart(4, "0");
                        } else {
                            calcCrc = crc.crc16xmodem(Buffer.from(withoutCrc, "ascii")).toString(16).toUpperCase().padStart(4, "0");
                        }
                        if (calcCrc !== receivedCrc.toUpperCase()) {
                            result.error = messages[language].SIA_CRC_ERR;
                            return result;
                        }
                    }

                    // --- Rozdělení podle mezer na tokeny ---
                    let tokens = inside.split(/\s+/).filter(t => t.length > 0);
                    // tokens[0] = account
                    // tokens[1] = event+zone
                    // tokens[2] = ti:HH.MM
                    // tokens[3] = riPPP
                    // tokens[4] = idUUU
                    // tokens[5] = piPPP
                    // tokens[6] = logText (<=9 znaků)
                    // tokens[7] = siteID (<=8 znaků)
                    // další tokeny do extensions.others

                    // 1a) Account block
                    if (/^\d{1,6}$/.test(tokens[0])) {
                        result.account = tokens[0];
                    }

                    // 1b) Event + Zone
                    if (tokens[1] && tokens[1].length >= 3) {
                        result.event = tokens[1].slice(0, 2);
                        result.zone  = tokens[1].slice(2);
                    }

                    // 1c) Procházení zbylých tokenů
                    for (let i = 2; i < tokens.length; i++) {
                        let t = tokens[i];
                        if (t.startsWith("ti:")) {
                            result.time = t.slice(3); // "18.03"
                            // Převod na Date (UTC dnešního dne):
                            let [hh, mm] = result.time.split(".");
                            result.extensions = result.extensions || {};
                            let isoDate = new Date().toISOString().slice(0, 10) + `T${hh}:${mm}:00Z`;
                            result.extensions.tsDate = new Date(isoDate);
                        } else if (t.startsWith("ri")) {
                            result.partition = t.slice(2);
                        } else if (t.startsWith("id")) {
                            result.user = t.slice(2);
                        } else if (t.startsWith("pi")) {
                            result.peripheral = t.slice(2);
                        } else if (t.length <= 9 && !result.logText) {
                            result.logText = t;
                        } else if (t.length <= 8 && !result.siteID) {
                            result.siteID = t;
                        } else {
                            result.extensions = result.extensions || {};
                            result.extensions.others = result.extensions.others || [];
                            result.extensions.others.push(t);
                        }
                    }

                    // 1d) Složení výsledné zprávy (message)
                    result.message = result.logText || "";

                    // 1e) Diagnostické kódy
                    const diagnosticCodes = ["DIAG", "LANERR", "NETDOWN", "PSUPPLY", "PDUERR"];
                    if (result.event === "DIAG" || diagnosticCodes.includes(result.event)) {
                        result.isDiagnostic = true;
                    }

                    // 1f) Uložení rawPayload do extensions pro případ multiplexovaných balíčků
                    result.extensions = result.extensions || {};
                    result.extensions.rawPayload = inside;

                    result.valid = true;
                    return result;
                }

                // --- 2) ADM-CID (Contact-ID) s CRC-16 XModem/ARC ---
                let admRe = /^ADM-CID\s+([\d]+)\s+([\d]+)\s*\[(.*)\]([0-9A-Fa-f]{4})$/;
                let n = admRe.exec(raw);
                if (n) {
                    result.protocol = "ADM-CID";
                    result.sequence = n[2];
                    let payload = n[3];         // např. "event=BA zone=01 user=0001"
                    let receivedCrc = n[4];
                    let dataForCrc = raw.substring(0, raw.lastIndexOf("]") + 1);
                    let actualCrc;
                    if (crcMethod === "arc") {
                        actualCrc = crc.crc16arc(Buffer.from(dataForCrc, "ascii")).toString(16).toUpperCase().padStart(4, "0");
                    } else {
                        actualCrc = crc.crc16xmodem(Buffer.from(dataForCrc, "ascii")).toString(16).toUpperCase().padStart(4, "0");
                    }
                    if (actualCrc !== receivedCrc.toUpperCase()) {
                        result.error = "CRC mismatch";
                        return result;
                    }
                    parseContactIdPayload(payload, result);
                    result.valid = true;
                    return result;
                }

                // --- 3) SIA-CID (Contact-ID alternativní, pokud DIP-switch 8=ON) ---
                if (raw.startsWith("SIA-CID")) {
                    let rest = raw.slice(7).trim();
                    let parts = rest.match(/^([\d]+)\s+([\d]+)\s*\[(.*)\]([0-9A-Fa-f]{4})$/);
                    if (parts) {
                        result.protocol = "ADM-CID";
                        result.sequence = parts[2];
                        let payload = parts[3];
                        let receivedCrc = parts[4];
                        let dataForCrc = raw.substring(0, raw.lastIndexOf("]") + 1);
                        let actualCrc;
                        if (crcMethod === "arc") {
                            actualCrc = crc.crc16arc(Buffer.from(dataForCrc, "ascii")).toString(16).toUpperCase().padStart(4, "0");
                        } else {
                            actualCrc = crc.crc16xmodem(Buffer.from(dataForCrc, "ascii")).toString(16).toUpperCase().padStart(4, "0");
                        }
                        if (actualCrc !== receivedCrc.toUpperCase()) {
                            result.error = "CRC mismatch";
                            return result;
                        }
                        parseContactIdPayload(payload, result);
                        result.valid = true;
                        return result;
                    }
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

                // --- 5) Diagnostika "[DIAG|...]…" ---
                let diagRe = /^\[DIAG\|(.*)\](.*)$/;
                let d = diagRe.exec(raw);
                if (d) {
                    result.protocol = "SIA-DCS";
                    result.event = "DIAG";
                    result.zone = null;
                    result.partition = null;
                    result.message = d[2];
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
            let hexData = frame.slice(4).trim();
            let iv = Buffer.from(hexData.slice(0, 32), "hex");
            let ct = Buffer.from(hexData.slice(32), "hex");
            let key = Buffer.from(keyHex, "hex");
            let decipher = crypto.createDecipheriv("aes-128-cbc", key, iv);
            let decrypted = Buffer.concat([decipher.update(ct), decipher.final()]);
            return decrypted.toString("ascii");
        }

        // ================================================
        // Parsování Contact-ID payload (event=… zone=… user=… rpt=…)
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
                    case "rpt":
                        result.extensions = result.extensions || {};
                        result.extensions.rpt = v;
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
            // Zapsat do formátu: ISO8601,Account,Event,Zone,Partition,User,Time,Peripheral,LogText,SiteID,Extensions_JSON
            let extJson = sia.extensions ? JSON.stringify(sia.extensions) : "";
            let line = `${new Date().toISOString()},${sia.account},${sia.event},${sia.zone || ""},${sia.partition || ""},${sia.user || ""},${sia.time || ""},${sia.peripheral || ""},${sia.logText || ""},${sia.siteID || ""},${extJson}\n`;
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
        // Odeslání s minimálním zpožděním (message delay)
        // ================================================
        function sendWithDelay(socket, frame, delay) {
            setTimeout(() => {
                try {
                    socket.write(frame);
                } catch (e) {
                    node.error("Chyba při odesílání s delay: " + e.message);
                }
            }, delay);
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
