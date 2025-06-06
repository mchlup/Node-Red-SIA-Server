# node-red-contrib-sia-server

**Verze 1.0.9** – plná podpora Honeywell Galaxy Dimension GD520 a obecně SIA Level 4

## Klíčové vlastnosti

1. **Polling (F# → P#)**
   - GD Dimension posílá pollingový rámec `F#<Account><Suffix?>`.  
   - Server rozpozná `Account` a `Suffix` (pokud existuje).  
   - Pokud je `autoRespondPolling` zapnuto, odesílá se `P#<Account>\r\n` (nebo podle `pollResponseTemplate`).  
   - Po odeslání polling-ACK se spustí timeout `ackTimeoutMs` (výchozí 2000 ms). Pokud do tohoto času nepřijde validní SIA-DCS, socket se uzavře a ústředna znovu pošle `F#…`.  
   - Server také každých `keepAliveIntervalMs` ms (výchozí 60000 ms) posílá `F#<ReceiverID>\r\n`, pokud od ústředny v tomto intervalu nedorazil žádný paket, aby se zachovalo spojení živé (keep-alive).

2. **SIA-DCS (DC-09 Level 4)**
   - Parsování payloadu ve tvaru `[EVENT|ZONE:PART]Message`.  
   - Podpora volitelného **CRC-16** (XModem nebo X.25) na celý rámec. Pokud je CRC chybný, vrátí se `NAK <seq> <ReceiverID>`.  
   - Podpora **multi-fragmentace** dlouhých payloadů: pokud zpráva končí „…“, uloží se do `pendingFragment` a čeká se na další část, až do úplného payloadu.  
   - Podpora **extensions**: pokud za hlavním payloadem (po `]`) následují samostatné částí oddělené `|`, např. `EXTENSION=BatteryLow|TIMESTAMP=20250607T134500`, uloží se do objektu `sia.extensions`.  
   - Podpora **diagnostických paketů** (`[DIAG|…]…`).  
   - Po úspěšném parsování (včetně verifikace CRC, pokud existuje) se odesílá `ACK <seq> <ReceiverID>\r\n` a event se předává do prvního výstupu (`msg.payload`).

3. **Contact-ID (ADM-CID)**
   - Parsování toho, co přijde jako `ADM-CID <header> [payload]CRC`.  
   - Ověření CRC-16 (XModem).  
   - Payload typu `event=… zone=… user=… code=…` se rozparsuje do objektu.  
   - Po úspěšné verifikaci se event pošle do prvního výstupu. U Contact-ID se neodesílá ACK (Contact-ID používá vlastní protokol).

4. **AES-128-CBC**
   - Pokud je v konfiguračním nodu `useAes = true`, servery očekávají, že přijaté rámce začínají prefixem `AES#` následovaným 32 hex znaky IV a poté ciphertextem (hex).  
   - Node dešifruje pomocí AES-128-CBC a klíče (`aesKey`), vrátí čistý ASCII řetězec, který se pak parsuje standardním způsobem.

5. **Receiver ID vs Account ID**
   - `Account ID` je identifikátor ústředny (např. „000997“). Zejména se používá v polling-rámcích.  
   - `Receiver ID` slouží jako druhý parametr v ACK/NAK (`ACK <seq> <ReceiverID>`). Pokud není explicitně zadán, použije se `Account ID`. V praxi se často přidává do ACK, aby ústředna potvrdila, že server je ten správný.

6. **Role-based ARM/DISARM**
   - Ve vstupních zprávách (do druhého vstupu uzlu) je možné poslat JSON ve tvaru:
     ```json
     {
       "action": "ARM",       // nebo "DISARM"
       "account": "000997",   // volitelné, default = Account ID
       "partition": "01",
       "code": "0001"         // PIN kód uživatele
     }
     ```
   - Server ověří, že pokud jsou `allowedUsers` (CSV) vyplněni, zadaný `code` je v tomto seznamu. Jinak vrátí chybu a příkaz neprojde.  
   - Pokud je ověření úspěšné, vygeneruje se SIA-DCS rámec `SIA-DCS 00 "[AR|partition]code"\r\n` (pro ARM) nebo `[DA|partition]code` (pro DISARM) a pošle se do ústředny.

7. **Filtrace a mapování**
   - `allowedEvents` (CSV) určuje, které eventy se mají přijímat; ostatní se ignorují.  
   - `zoneMap` (JSON) přeloží číselnou zónu na textový popisek (např. `"01":"Vchod"`). V `msg.payload` se pak objeví `zoneName`.

8. **Logování do souboru**
   - Každý případ validní události (SIA-DCS, Contact-ID, DIAG, iBD event) se dopíše do souboru `/home/nodered/sia-events.log` ve formátu:
     ```
     2025-06-07T12:34:56.789Z,000997,BA,01,Poplach vloupání v zóně 01,{"EXTENSION":"BatteryLow","TIMESTAMP":"20250607T134500"}
     ```
   - Pokud neexistují `extensions`, pole bude prázdné.

9. **Status v UI**
   - Zelená tečka = server naslouchá.  
   - Červený kroužek = odpojeno nebo neuspešné otevření portu.  
   - Žlutý kroužek = chybné parsování / CRC.

10. **Push-Webhook (volitelné)**
    - Pokud je v konfiguraci zadáno `pushWebhookUrl` (např. `https://example.com/webhook`), po každém validním eventu (SIA-DCS, Contact-ID, DIAG) se pošle JSON metadat na danou URL metodou HTTP POST.  
    - JSON obsahuje: `{ protocol, account, event, zone, message, timestamp, extensions, isDiagnostic }`.

11. **HTTP endpoint**
    - `POST /sia-server/:id/event`  
      - Vyžaduje právo `sia-server.write`.  
      - Tělo JSON ve tvaru `{ "event":"BA", "zone":"03", "message":"Test" }`  
      - Node vytvoří event do prvního výstupu.

---

## Instalace

1. V adresáři Node-RED (`~/.node-red`) spusťte:
   ```bash
   npm install github:mchlup/Node-Red-SIA-Server
