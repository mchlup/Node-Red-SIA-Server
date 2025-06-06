# node-red-contrib-sia-server

**Verze 1.0.6** – plná podpora Honeywell Galaxy Dimension GD520  
**Klíčové vlastnosti**:
- Naslouchá na zvoleném TCP portu a přijímá:
  - **SIA-DCS (DC-09)** – dekódování `[EVENT|ZONE:PART]` formátu
  - **ADM-CID (SIA-DC-05)** – s ověřením CRC-16
  - **Polling rámce „F#“** – keep-alive / testovací zprávy bez ACK
  - **AES-128-CBC** (hex) – dešifruje šifrované rámce, pokud je zapnuto
- **ACK/NAK** odpovědi pro správně nebo špatně parsované zprávy  
- **Whitelist eventů** – přijímá pouze vybrané event kódy (CSV)  
- **Mapování zón** – přeloží číselné zóny na textové jména (JSON)  
- **Role-based ARM/DISARM** – povolení příkazu pouze pro specifikované uživatele (CSV)  
- **Interval obnovy** – automatický restart naslouchání při chybě / odpojení  
- **Logování** – každou validní událost ukládá do `/home/nodered/sia-events.log`  
- **Status v UI** – zobrazuje stav připojení, chyby a odpojení v paletě Node-RED  
- **Lokalizace** – podporuje „en“ (English) a „cs“ (Čeština)  
- **HTTP endpoint** – externí skripty mohou poslat event do node přes REST (např. `/sia-server/:id/event`)  
- **Konfigurační node** – sdílené nastavení (port, heslo, account, eventy, zóny, AES, RBAC, jazyky)

## Instalace

1. Zkopírujte repozitář nebo nainstalujte ze zdroje:
   ```bash
   cd ~/.node-red
   npm install github:mchlup/Node-Red-SIA-Server
