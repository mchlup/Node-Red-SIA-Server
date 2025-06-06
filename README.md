# node-red-contrib-sia-server

**Verze 1.0.8** – plná podpora Honeywell Galaxy Dimension GD520 (SIA Level 4)

## Klíčové vlastnosti
- **Polling (F# → P#)**  
  - Ústředna GD posílá `F#<Account><Suffix?>`, server rozpozná account a suffix.  
  - Server odpoví `P#<Account>\r\n` (nebo podle vlastní šablony), čímž ústředna uvolní tok SIA-DCS eventů.  
  - Timeout 2 s: pokud po `P#…` nepřijde validní SIA-DCS, socket se uzavře, ústředna pošle znovu `F#…`.
  - Keep-alive od serveru: každých 60 s, pokud od ústředny nic nepřišlo, server sám pošle `F#<ReceiverID>\r\n`.

- **SIA-DCS (DC-09 Level 4)**
  - Parsování `[EVENT|ZONE:PART]Message`.
  - Volitelný CRC-16 (pokud přítomno na konci rámce), verifikace.  
  - Multi-fragmentace: pokud rámec končí `...`, parser čeká na další část, dokud není celý payload.  
  - Podpora diagnostických (`DIAG`) zpráv.

- **Contact-ID (ADM-CID)**
  - Payload `event=…, zone=…, user=…, code=…` s ověřením CRC-16 (4 hex znaky).  
  - Parsování klíč=hodnota.

- **AES-128-CBC**
  - Pokud je aktivní, server dešifruje rámec typu `AES#<IV(32hex)><CIPHERTEXT(hex)>`.  
  - Po dešifrování se výsledek parsuje jako běžný SIA-DCS.

- **Receiver ID vs Account**
  - `Account ID` (SIA-ID) se bere buď z nastavení, nebo z polling‐rámce.  
  - `Receiver ID` lze zadat zvlášť – pokud existuje, zařadí se do ACK “ACK <seq> <ReceiverID>”.

- **Role-based ARM/DISARM**
  - Všechny příkazy `payload.action = "ARM"` nebo `"DISARM"` kontrolují, zda `payload.code` je v seznamu `allowedUsers`.  
  - Pokud není, server vrací chybu a neodesílá nic.

- **Filtrace eventů (Whitelist)**
  - V nastavení lze zadat pouze některé event kódy (např. `BA,BF,GC,GP`).  
  - Ostatní eventy se ignorují.

- **Mapování zón**
  - V JSONu lze definovat mapování `{"01":"Vchod","02":"Garáž","03":"Kancelář"}`.  
  - Pokud přijde event pro zónu „02“, do výstupu se přidá `zoneName: "Garáž"`.

- **Lokalizace (en/cs)**
  - Podpora angličtiny a češtiny pro systémové zprávy („Polling Frame“, „Burglary Alarm“, „Unauthorized user“ apod.).

- **Logování do souboru**
  - Každá platná událost se přidá do `/home/nodered/sia-events.log` ve formátu:
    ```
    2025-06-07T12:34:56.789Z,000997,BA,01,Poplach vloupání v zóně 01
    ```

- **Status v UI**
  - Zelená tečka = naslouchá správně.  
  - Červený kroužek = odpojeno.  
  - Žlutý kroužek = chybné parsování (CRC, formát).

- **HTTP endpoint**
  - `POST /sia-server/:id/event` (vyžaduje právo `sia-server.write`)  
    - Tělo JSON:  
      ```json
      {
        "event": "BA",
        "zone": "03",
        "message": "Simulovaný poplach"
      }
      ```
    - Node vygeneruje event do prvního výstupu.

## Instalace

1. V terminálu (v adresáři `~/.node-red`) spusťte:
   ```bash
   npm install github:mchlup/Node-Red-SIA-Server
