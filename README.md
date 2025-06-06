# node-red-contrib-sia-server

**Verze 1.0.7** – plná podpora Honeywell Galaxy Dimension GD520  
**Klíčové vlastnosti**:
- Naslouchá na zvoleném TCP portu a přijímá:
  - **SIA-DCS (DC-09)** – dekódování `[EVENT|ZONE:PART]` formátu
  - **ADM-CID (SIA-DC-05)** – Contact-ID s ověřením CRC-16
  - **Polling rámce „F#“** – keep-alive; odpověď `P#<zone>` vrací panelu
  - **AES-128-CBC** – dešifruje šifrované rámce, pokud je zapnuto
- **Automatická odpověď na polling** – pošle `P#<zone>` (nebo šablonu dle nastavení)  
- **ACK/NAK** odpovědi pro standardní SIA‐DCS (ACK) i chybné zprávy (NAK)  
- **Whitelist eventů** – přijímá pouze vybrané event kódy (CSV)  
- **Mapování zón** – přeloží číselné zóny na textové jména (JSON)  
- **Role-based ARM/DISARM** – kontrola, kdo smí poslat ARM/DISARM dle CSV uživatelů  
- **Retry / Reconnect** – v případě chyby / odpojení se server po x sekundách restartuje  
- **Logování** – každá platná událost se objedná do `/home/nodered/sia-events.log`  
- **Status v UI** – zobrazuje stav připojení, chyby i odpojení přímo v paletě Node-RED  
- **Lokalizace** – podporuje „en“ (English) a „cs“ (Čeština)  
- **HTTP endpoint** – externí POST `/sia-server/:id/event` pro injektování eventů  
- **Konfigurační node** – sdílená konfigurace (port, heslo, account, eventy, zóny, AES, RBAC, jazyky, polling)

## Instalace

1. Zkopírujte repozitář nebo nainstalujte přímo z GitHubu:
   ```bash
   cd ~/.node-red
   npm install github:mchlup/Node-Red-SIA-Server
