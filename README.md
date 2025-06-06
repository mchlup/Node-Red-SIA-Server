# node-red-contrib-sia-server

**Verze 1.0.10** – Plná podpora Honeywell Galaxy Dimension GD520 a obecně SIA Level 4 (DC-09) včetně:

- CRC 16 (XModem, X.25, ARC)  
- AES 128-CBC dešifrování  
- Polling (F# → P#) s timeoutem a keep-alive  
- Multi-fragmentace SIA-DCS (fragment ending "...")  
- Multiplexované balíčky (ACCID/MSGNUM; [EV|ZZ]…)  
- Extensions (např. `ti:18.03`, `ri010`, `id098`, `pi010`, `GALOGtxt`, `SITE0001`)  
- Diagnostické a iBD kódy (DIAG, LANERR, NETDOWN, PSUPPLY, PDUERR)  
- Role-based ARM/DISARM s PIN (allowedUsers)  
- Filtrace eventů (Whitelist)  
- Mapování zón (vlastní JSON, PCVue-style adresy)  
- Logování do souboru `/home/nodered/sia-events.log`  
- Status v UI (zelená/červená/žlutá)  
- Push-Webhook (HTTP POST každého eventu)  
- HTTP endpoint pro externí eventy (`POST /sia-server/:id/event`)  
- Kompatibilita s Virtual Galaxy Receiver (Evalink/Talos) – SIA DC-09 Level 4 bloky, Remote Control atd.
---

## Klíčové vlastnosti

1. **Polling (F# → P#)**
   - Panel posílá `F#<Account><Suffix?>`.  
   - Pokud je `autoRespondPolling` zapnuto, server odpoví `P#<Account>\r\n` (nebo podle `pollResponseTemplate`), a panel začne posílat SIA-DCS události.  
   - Server spustí timeout `ackTimeoutMs` (výchozí 2000 ms). Pokud do tohoto času nepřijde validní SIA-DCS, uzavře se socket a panel znovu pošle `F#…`.  
   - Server také každých `keepAliveIntervalMs` ms (výchozí 60000 ms) pošle `F#<ReceiverID>\r\n`, pokud od panelu od posledního paketu nic nepřišlo (keep-alive pro NAT/firewall).

2. **SIA-DCS (DC-09 Level 4)**
   - Parsování payloadu ve tvaru `[EVENT|ZONE(:PART)]Message`.  
   - Volitelná podpora **CRC-16** (XModem nebo X.25). Pokud je CRC na konci rámce, vypočte se a verifikuje.  
   - **Multi-fragmentace:** Kundaktem, pokud rámec končí „...“, uloží se do `pendingFragment` a čeká se na další část, až se skládá celý payload.  
   - **Extensions:** Po hlavním payloadu (za hranatou závorkou) mohou následovat tagy oddělené `|`, např. `EXTENSION=BatteryLow|TIMESTAMP=20250607T134500`. Složí se do `sia.extensions`.  
   - **Diagnostika:** Rámce typu `"[DIAG|…]…"` jsou označeny jako diagnostické (`sia.isDiagnostic = true`).  
   - **iBD eventy:** Kódy typu `LANERR`, `NETDOWN`, `PSUPPLY`, `PDUERR` se považují za diagnostické a logují se jako takové.  
   - Po úspěšném parsování (včetně CRC) se odesílá `ACK <seq> <ReceiverID>\r\n` a event putuje do prvního výstupu (`msg.payload`).

3. **Contact-ID (ADM-CID)**
   - Parsování rámců `ADM-CID <header> [payload]CRC`.  
   - Ověření **CRC-16 (XModem)**.  
   - Payload `event=… zone=… user=… code=…` se rozparsuje do objektu.  
   - Po validaci se event posílá do prvního výstupu. U Contact-ID se neodesílá žádný ACK (Contact-ID používá vlastní flow).

4. **AES-128-CBC**
   - Pokud `useAes = true`, plugin dešifruje rámec formátu `AES#<IV(32 hex)><ciphertext(hex)>`.  
   - Po dešifrování se získá čistý ASCII řetězec, který pak prochází standardním SIA-DCS parserem.

5. **Receiver ID vs Account ID**
   - `Account ID` se bere buď z nastavení, nebo z pollingového rámce.  
   - `Receiver ID` se používá jako druhý parametr v ACK a NAK (`ACK <seq> <ReceiverID>\r\n`). Pokud není zadáno, použije se `Account ID`.

6. **Role-based ARM/DISARM**
   - Vstup do uzlu (např. Inject node) ve tvaru:
     ```json
     {
       "action": "ARM",             // nebo "DISARM"
       "account": "000997",         // volitelné (default = Account ID)
       "partition": "01",
       "code": "0001"               // PIN kód uživatele
     }
     ```
   - Pokud `allowedUsers` (CSV) není prázdné, plugin zkontroluje, zda je `code` v tomto seznamu. Jinak vrátí chybu.  
   - Pokud je oprávnění úspěšné, vygeneruje SIA-DCS paket:
     - Pro ARM: `SIA-DCS 00 "[AR|partition]code"\r\n`
     - Pro DISARM: `SIA-DCS 00 "[DA|partition]code"\r\n`
   - Paket se odešle na socket.

7. **Filtrace eventů**
   - Pokud je `allowedEvents` (CSV) vyplněno, přijímají se pouze kódy splňující tento seznam (např. `BA,BF,GC`).

8. **Mapování zón (PCVue-style)**
   - V `zoneMap` (JSON) lze definovat mapování `"01":"Vchod", "02":"Garáž", ...`.  
   - Pokud přijde event s `zone="02"`, do výstupu se vloží i `zoneName: "Garáž"`.  
   - V souladu s PCVue schématem, kde „Starting address = 1001“ odpovídá zóně 1, zóně 2 = adresy 1002, … můžete do `zoneMap` vložit i čísla (např. `"1001":"Vchod"`), pokud chcete převádět podle adres.

9. **Logování do souboru**
   - Každá validní událost (SIA-DCS, Contact-ID, DIAG, iBD event) se uloží do `/home/nodered/sia-events.log` ve formátu:
     ```
     2025-06-07T12:34:56.789Z,000997,BA,01,Poplach vloupání v zóně 01,{"EXTENSION":"BatteryLow","TIMESTAMP":"20250607T134500"}
     ```
   - Pokud nejsou `extensions`, sloupec zůstane prázdný.

10. **Status v UI**
    - **Zelená tečka** = server naslouchá.  
    - **Červený kroužek** = odpojeno nebo nelze otevřít port.  
    - **Žlutý kroužek** = chyba parsování (např. CRC), plugin krátce zobrazí chybu a pak status zmizí.

11. **Push-Webhook (volitelné)**
    - Pokud je `pushWebhookUrl` vyplněno, plugin po každém validním eventu odešle JSON HTTP POST na tuto adresu.
    - JSON má strukturu:
      ```json
      {
        "protocol": "SIA-DCS",
        "account": "000997",
        "event": "BA",
        "zone": "01",
        "zoneName": "Vchod",
        "message": "Poplach vloupání v zóně 01",
        "timestamp": "2025-06-07T12:34:56.789Z",
        "extensions": { "EXTENSION":"BatteryLow","TIMESTAMP":"20250607T134500" },
        "isDiagnostic": false
      }
      ```

12. **HTTP endpoint**
    - `POST /sia-server/:id/event`  
      - Vyžaduje právo `sia-server.write`.  
      - Tělo JSON: `{ "event":"BA", "zone":"03", "message":"Simulovaný poplach" }`  
      - Plugin vygeneruje event do prvního výstupu.  

---

## Postup instalace

1. V adresáři Node-RED (`~/.node-red`) spusťte:
   ```bash
   npm install github:mchlup/Node-Red-SIA-Server
