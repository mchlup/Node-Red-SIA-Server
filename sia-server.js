const net = require("net");
const crc = require("crc");

module.exports = function (RED) {

    // Konfigurační node
    function SiaServerConfigNode(n) {
        RED.nodes.createNode(this, n);
        this.name = n.name;
        this.port = n.port;
        this.password = n.password;
        this.account = n.account;
    }
    RED.nodes.registerType("sia-server-config", SiaServerConfigNode);

    // Hlavní node
    function SiaServerNode(config) {
        RED.nodes.createNode(this, config);

        // Získání konfiguračního node podle ID
        const nodeConfig = RED.nodes.getNode(config.config);

        // Pokud není přiřazen config node, skončíme
        if (!nodeConfig) {
            this.error("Není přiřazen žádný konfigurační node!");
            return;
        }

        const node = this;
        const port       = parseInt(nodeConfig.port) || 10002;
        const password   = nodeConfig.password || "";
        const account    = nodeConfig.account || "";
        const debugMode  = config.debugMode || false;
        const rawOutput  = config.rawOutput || false;

        let clientSockets = [];

        const server = net.createServer((socket) => {
            clientSockets.push(socket);
            socket.setEncoding("utf8");

            node.log(`Klient připojen: ${socket.remoteAddress}:${socket.remotePort}`);

            socket.on("data", (data) => {
                let frames = data.split("\r\n").filter(x => x.trim().length > 0);

                for (let frame of frames) {
                    node.log(`Přijato (raw): ${frame}`);
                    let sia = tryParseSia(frame, password, account);

                    if (sia.valid) {
                        if (debugMode) {
                            node.send([null, { raw: frame, parsed: sia, timestamp: Date.now() }]);
                        }

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
                node.send([null, { event: "disconnect", ip: socket.remoteAddress, timestamp: Date.now() }]);
            });

            socket.on("error", (err) => {
                node.error(`Socket error: ${err.message}`);
                node.send([null, { error: err.message, timestamp: Date.now() }]);
            });
        });

        server.listen(port, () => {
            node.log(`SIA server naslouchá na portu ${port}`);
        });

        this.on("close", () => {
            server.close();
            clientSockets.forEach(s => s.destroy());
            clientSockets = [];
            node.log("SIA server ukončen");
        });

        node.on("input", (msg) => {
            try {
                if (!msg.payload || typeof msg.payload !== "object") {
                    throw new Error("Očekávám objekt s akcí (action) a parametry.");
                }
                let cmd = msg.payload.action;
                let destAccount = msg.payload.account || account;
                let partition   = msg.payload.partition || "";
                let userCode    = msg.payload.code || "";
                let customFrame = msg.payload.customFrame || "";

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
                node.send([{ info: `Posláno: ${cmd}` }, null]);
            } catch (err) {
                node.error(err.message);
                node.send([null, { error: err.message }]);
            }
        });

        function tryParseSia(frame, pwd, acct) {
            let result = {
                valid: false,
                error: null,
                sequence: null,
                account: acct,
                protocol: null,
                event: null,
                zone: null,
                message: null
            };

            try {
                let siaRe = /^(SIA-DCS|ADM-CID)\s+([0-9A-Fa-f]+)?\s*(\d+)?\s*"(.*)"$/;
                let m = siaRe.exec(frame.trim());
                if (!m) {
                    result.error = "Špatný formát (ne SIA-DCS/ADM-CID).";
                    return result;
                }
                result.protocol = m[1];
                result.sequence = m[3] || null;
                let payload = m[4];

                let evtRe = /^\[([A-Z0-9]+)\|([A-Z0-9]+)\](.*)$/;
                let em = evtRe.exec(payload);
                if (!em) {
                    result.error = "Payload nesplňuje [EVENT|ZONE]Syntax.";
                    return result;
                }
                result.event = em[1];
                result.zone = em[2];
                result.message = em[3];
                result.valid = true;
                return result;
            } catch (e) {
                result.error = "Parse exception: " + e.message;
                return result;
            }
        }

        function buildAck(seq, acct) {
            return `\r\nACK ${seq || ""}\r\n`;
        }
        function buildNak(seq) {
            return `\r\nNAK ${seq || ""}\r\n`;
        }
    }

    RED.nodes.registerType("sia-server", SiaServerNode);
};
