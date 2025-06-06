const net    = require("net");
const crc    = require("crc");
const fs     = require("fs");
const crypto = require("crypto");

module.exports = function (RED) {

    // ================================
    // Konfigurační node
    // ================================
    function SiaServerConfigNode(n) {
        RED.nodes.createNode(this, n);
        this.name              = n.name;
        this.port              = n.port;
        this.password          = n.password;
        this.account           = n.account;
        this.allowedEvents     = n.allowedEvents ? n.allowedEvents.split(",").map(e => e.trim()) : [];
        this.zoneMap           = (() => {
            try {
                return n.zoneMap ? JSON.parse(n.zoneMap) : {};
            } catch {
                return {};
            }
        })();
        this.useAes            = n.useAes;
        this.aesKey            = n.aesKey;
        this.reconnectInterval = parseInt(n.reconnectInterval) || 10;
        this.language          = n.language || "en";
        this.allowedUsers      = n.allowedUsers ? n.allowedUsers.split(",").map(u => u.trim()) : [];
        this.logPath           = n.logPath || null;
    }
    RED.nodes.registerType("sia-server-config", SiaServerConfigNode);

    // ================================
    // Hlavní node
    // ================================
    function SiaServerNode(config) {
        RED.nodes.createNode(this, config);

        // Načtení konfiguračního node
        const nodeConfig = RED.nodes.getNode(config.config);
        if (!nodeConfig) {
            this.error("Není přiřazen žádný konfigurační node!");
            return;
        }

        const node       = this;
        const port       = parseInt(nodeConfig.port) || 10002;
        const password   = nodeConfig.password || "";
        const account    = nodeConfig.account || "";
        const debugMode  = config.debugMode || false;
        const rawOutput  = config.rawOutput || false;
        const allowedEvents = nodeConfig.allowedEvents;    // např. ["BA","BF"]
        const zoneMap       = nodeConfig.zoneMap;          // např. {"01":"Vchod"}
        const useAes        = nodeConfig.useAes;           // true|false
        const aesKey        = nodeConfig.aesKey;           // hex klíč 32 znaků
        const reconnectInt  = nodeConfig.reconnectInterval; // v sekundách
        const language      = nodeConfig.language;         // "en" nebo "cs"
        const allowedUsers  = nodeConfig.allowedUsers;     // např. ["001","002"]
        const logPath       = nodeConfig.logPath;          // cesta k logu

        let clientSockets = [];
        let server        = null;
        let reconnectTimer = null;

        // Funkce pro nastavení statusu
        function setStatus(colour, shape, text) {
            node.status({ fill: colour, shape: shape, text: text });
        }

        // =======================================
        // Funkce: CRC-16-IBM (XModem) pomocí crc
        // =======================================
        function computeCrc16(data) {
            // data = ASCII řetězec (bez konec čárek), vrátí hex uppercase (4 znaky)
            let buf = Buffer.from(data, "ascii");
            let val = crc.crc16xmodem(buf).toString(16).toUpperCase();
            return val.padStart(4, "0");
        }

        // =======================================
        // Funkce: AES-128-CBC dešifrování
        // =======================================
        function decryptAesFrame(frameHex, keyHex) {
            // Očekáváme: frameHex obsahuje IV(32 hex) + ciphertext (hex)
            try {
                let iv   = Buffer.from(frameHex.slice(0, 32), "hex");
                let ct   = Buffer.from(frameHex.slice(32), "hex");
                let key  = Buffer.from(keyHex, "hex");
                let decipher = crypto.createDecipheriv("aes-128-cbc", key, iv);
                let decrypted = Buffer.concat([decipher.update(ct), decipher.final()]);
                return decrypted.toString("ascii");
            } catch (e) {
                node.error("AES decryption error: " + e.message);
                return null;
            }
        }

        // =======================================
        // Funkce: Parsing Contact-ID payloadu
        // =======================================
        function parseContactIdPayload(text, result) {
            // text např. "event=1800 zone=002 code=0001 user=005"
            let parts = text.split(/\s+/);
            parts.forEach(p => {
                let [k, v] = p.split("=");
                switch (k.toLowerCase()) {
                    case "event": result.event     = v; break;
                    case "zone":  result.zone      = v; break;
                    case "user":  result.user      = v; break;
                    case "code":  result.userCode  = v; break;
                    case "partition": result.partition = v; break;
                    default: break;
                }
            });
            result.message = `Event ${result.event}, zone ${result.zone}`;
        }

        // =======================================
        // Funkce: Parsing main SIA/ADM/ Poll
        // =======================================
        function tryParseSia(frameRaw, pwd, acct) {
            let frame = frameRaw.trim();
            let result = {
                valid: false,
                error: null,
                sequence: null,
                account: acct,
                protocol: null,
                event: null,
                zone: null,
                partition: null,
                user: null,
                userCode: null,
                subEvent: null,
                message: null,
                timestamp: new Date().toISOString(),
                rawHex: Buffer.from(frameRaw, "utf8").toString("hex")
            };

            try {
                // 1) Pokud je zpráva šifrovaná AES a useAes je true
                if (useAes && frame.startsWith("AES")) {
                    // Očekáváme formát: "AES<hexIV+hexCT>"
                    let decrypted = decryptAesFrame(frame.slice(3), aesKey);
                    if (!decrypted) {
                        result.error = "Nelze dešifrovat AES frame";
                        return result;
                    }
                    frame = decrypted.trim();
                }

                // 2) Pokus o detekci SIA-DCS
                let siaRe = /^(SIA-DCS)\s+([0-9A-Fa-f]+)?\s*(\d+)?\s*"(.*)"$/;
                let m = siaRe.exec(frame);
                if (m) {
                    result.protocol = m[1];
                    result.sequence = m[3] || null;
                    let payload = m[4];

                    // Rozparsuj [EVENT|ZONE(:PARTITION)]<zbytek>
                    let evtRe = /^\[([A-Z0-9]+)\|([A-Z0-9]+)(?::([A-Z0-9]+))?\](.*)$/;
                    let em = evtRe.exec(payload);
                    if (!em) {
                        result.error = "Payload nesplňuje [EVENT|ZONE(:PART)]Syntax.";
                        return result;
                    }
                    result.event     = em[1];
                    result.zone      = em[2];
                    result.partition = em[3] || null;
                    result.message   = em[4] || null;

                    // Filtrace eventů
                    if (allowedEvents.length > 0 && !allowedEvents.includes(result.event)) {
                        result.error = `Event ${result.event} není v whitelistu`;
                        return result;
                    }

                    // Mapování zón
                    if (zoneMap[result.zone]) {
                        result.zoneName = zoneMap[result.zone];
                    }

                    result.valid = true;
                    return result;
                }

                // 3) Pokus o detekci ADM-CID s CRC
                // Formát např.:
                // ADM-CID 123456 0123 [event=1800 zone=002 code=0001]17F4
                let admRe = /^ADM-CID\s+(\d+)\s+(\d+)\s*\[([^\]]*)\]([0-9A-Fa-f]{4})$/;
                let a = admRe.exec(frame);
                if (a) {
                    result.protocol = "ADM-CID";
                    result.sequence = a[2];
                    let payload = a[3];     // např. "event=1800 zone=002 code=0001"
                    let crcHex   = a[4];     // např. "17F4"

                    // Ověření CRC:
                    let dataForCrc = frame.substring(0, frame.lastIndexOf("]") + 1);
                    let actualCrc  = computeCrc16(dataForCrc);
                    if (actualCrc !== crcHex.toUpperCase()) {
                        result.error = `CRC mismatch: expected ${crcHex}, got ${actualCrc}`;
                        return result;
                    }

                    parseContactIdPayload(payload, result);

                    // Filtrace eventů
                    if (allowedEvents.length > 0 && !allowedEvents.includes(result.event)) {
                        result.error = `Event ${result.event} není v whitelistu`;
                        return result;
                    }

                    // Mapování zón
                    if (zoneMap[result.zone]) {
                        result.zoneName = zoneMap[result.zone];
                    }

                    result.valid = true;
                    return result;
                }

                // 4) Polling/keep-alive rámce začínající "F#"
                if (frame.startsWith("F#")) {
                    result.protocol = "GATEWAY-POLL";
                    result.event    = "POLL";
                    result.zone     = frame.slice(2).trim(); 
                    result.message  = "Polling / keep-alive frame";
                    result.valid    = true;
                    return result;
                }

                // 5) Jiný nezpracovaný formát
                result.error = "Unrecognized format";
                return result;
            } catch (e) {
                result.error = "Parse exception: " + e.message;
                return result;
            }
        }

        // =======================================
        // Funkce: buildAck, buildNak
        // =======================================
        function buildAck(seq, acct) {
            return `\r\nACK ${seq || ""}\r\n`;
        }
        function buildNak(seq) {
            return `\r\nNAK ${seq || ""}\r\n`;
        }

        // =======================================
        // Funkce: logování do souboru (pokud je specifikováno)
        // =======================================
        function appendLog(entry) {
            if (!logPath) return;
            let line = `${entry.timestamp},${entry.account},${entry.protocol},${entry.event},${entry.zone},${entry.partition || ""},${entry.user || ""},${entry.userCode || ""},"${entry.message || ""}"\n`;
            fs.appendFile(logPath, line, err => {
                if (err) node.error("Chyba při zapisování do logu: " + err.message);
            });
        }

        // =======================================
        // HTTP Admin endpoint pro externí event
        // =======================================
        RED.httpAdmin.post("/sia-server/:id/event", RED.auth.needsPermission("sia-server.write"), function(req, res) {
            let targetNode = RED.nodes.getNode(req.params.id);
            if (targetNode && targetNode.handleExternalEvent) {
                targetNode.handleExternalEvent(req.body);
                res.sendStatus(200);
            } else {
                res.sendStatus(404);
            }
        });

        // =======================================
        // Spuštění TCP serveru a reconnect logika
        // =======================================
        function startServer() {
            server = net.createServer(onClientConnected);

            server.listen(port, () => {
                setStatus("green", "dot", `Naslouchá na portu ${port}`);
                node.log(`SIA server naslouchá na portu ${port}`);
            });

            server.on("error", err => {
                setStatus("red", "ring", `Chyba serveru: ${err.message}`);
                node.error("Server error: " + err.message);
                tryReconnect();
            });
        }

        function tryReconnect() {
            if (reconnectTimer) return;
            setStatus("yellow", "ring", `Restart za ${reconnectInt}s...`);
            reconnectTimer = setTimeout(() => {
                reconnectTimer = null;
                startServer();
            }, reconnectInt * 1000);
        }

        // Obsluha nového klienta
        function onClientConnected(socket) {
            clientSockets.push(socket);
            setStatus("blue", "dot", `Připojeno od ${socket.remoteAddress}:${socket.remotePort}`);
            node.log(`Klient připojen: ${socket.remoteAddress}:${socket.remotePort}`);

            socket.setEncoding("utf8");

            socket.on("data", (data) => {
                let frames = data.split("\r\n").filter(x => x.trim().length > 0);
                for (let frame of frames) {
                    node.log(`Přijato (raw): ${frame}`);
                    let sia = tryParseSia(frame, password, account);

                    if (sia.valid) {
                        // Logování
                        appendLog(sia);

                        // Polling
                        if (sia.protocol === "GATEWAY-POLL") {
                            node.send([{ payload: sia, raw: frame, account: sia.account }, null]);
                            continue;
                        }

                        // ARM/DISARM / role-based kontrola
                        // Pokud do main flow posíláme příkaz, zkontrolujeme uživatele
                        // (TOHLE patří do input handleru níže, zde jen přijímáme)
                        
                        // Odeslat ACK
                        let ack = buildAck(sia.sequence, sia.account);
                        node.log(`Odesílám ACK: ${ack.trim()}`);
                        socket.write(ack);

                        node.send([{ payload: sia, raw: frame, account: sia.account }, null]);
                    } else {
                        node.warn(`Chyba parsování: ${sia.error}`);
                        let nak = buildNak(sia.sequence);
                        node.log(`Odesílám NAK: ${nak.trim()}`);
                        socket.write(nak);

                        if (rawOutput || debugMode) {
                            node.send([null, { error: sia.error, raw: frame, timestamp: Date.now() }]);
                        }
                    }
                }
            });

            socket.on("close", () => {
                node.log(`Klient odpojen: ${socket.remoteAddress}`);
                clientSockets = clientSockets.filter(s => s !== socket);
                setStatus("red", "ring", "Odpojeno");
                node.send([null, { event: "disconnect", ip: socket.remoteAddress, timestamp: new Date().toISOString() }]);
            });

            socket.on("error", (err) => {
                node.error(`Socket error: ${err.message}`);
                node.send([null, { error: err.message, timestamp: new Date().toISOString() }]);
            });
        }

        // Spuštění serveru
        startServer();

        // Při uzavření node
        this.on("close", (removed, done) => {
            if (reconnectTimer) clearTimeout(reconnectTimer);
            if (server) {
                server.close();
                clientSockets.forEach(s => s.destroy());
                clientSockets = [];
            }
            node.status({});
            done();
        });

        // =======================================
        // Obsluha vstupu – odesílání ARM/DISARM/CUSTOM
        // =======================================
        node.on("input", (msg) => {
            try {
                if (!msg.payload || typeof msg.payload !== "object") {
                    throw new Error("Očekávám objekt s akcí (action) a parametry.");
                }
                let cmd         = msg.payload.action;
                let destAccount = msg.payload.account || account;
                let partition   = msg.payload.partition || "";
                let userCode    = msg.payload.code || "";
                let customFrame = msg.payload.customFrame || "";

                // Role-based kontrola (pouze pro ARM a DISARM)
                if ((cmd === "ARM" || cmd === "DISARM") && allowedUsers.length > 0) {
                    if (!allowedUsers.includes(userCode)) {
                        throw new Error(`Uživatel ${userCode} není povolen pro ${cmd}`);
                    }
                }

                if (clientSockets.length === 0) {
                    throw new Error("Žádné připojení z ústředny, nelze odeslat příkaz.");
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
                node.send([{ info: `Posláno: ${cmd}`, timestamp: new Date().toISOString() }, null]);
            } catch (err) {
                node.error(err.message);
                node.send([null, { error: err.message }]);
            }
        });

        // =======================================
        // Handler pro externí HTTP event
        // =======================================
        this.handleExternalEvent = function(eventData) {
            // Očekáváme JSON s minimálně { event, zone, partition?, user?, message? }
            let sia = {
                valid:     true,
                protocol:  "HTTP-EXTERNAL",
                sequence:  null,
                account:   account,
                event:     eventData.event || "",
                zone:      eventData.zone || "",
                partition: eventData.partition || "",
                user:      eventData.user || null,
                message:   eventData.message || "",
                timestamp: new Date().toISOString(),
                rawHex:    null
            };
            // Můžeme aplikovat filtr, mapování zón a logování:
            if (allowedEvents.length > 0 && !allowedEvents.includes(sia.event)) {
                node.log(`HTTP externí event ${sia.event} ignorován (není v whitelistu)`);
                return;
            }
            if (zoneMap[sia.zone]) sia.zoneName = zoneMap[sia.zone];
            appendLog(sia);
            node.send([{ payload: sia, raw: null, account: sia.account }, null]);
        };
    }

    RED.nodes.registerType("sia-server", SiaServerNode);
};
