# APK v3.7.1 API-Analyse vs. main.js

Datum: 2026-05-05
Quelle: myVAILLANT APK v3.7.1 (Build 25262), dekompiliert aus `index.android.bundle` (Hermes Bytecode)

## Einschränkungen

Die Hermes-Bytecode-String-Tabelle verkettet Strings ohne klare Trennzeichen. Viele extrahierte Pfade sind daher mit JS-Variablennamen, Lokalisierungs-Keys und anderen Strings kontaminiert. Die Analyse basiert auf manueller Bereinigung der erkennbaren URL-Patterns.

## Erkannte API-Endpoint-Kategorien

### Bereits in main.js implementiert

| Endpoint-Pattern | main.js Zeile | Status |
|---|---|---|
| `/homes` | 330 | OK |
| `/systems/{id}/meta-info/control-identifier` | 357 | OK |
| `/systems/{id}/tli` (TLI-basiert) | 456 | OK |
| `/{identifier}/v1/systems/{id}` (VRC700/system-control) | 454 | OK |
| `/api/v1/ambisense/facilities/{id}/rooms` | 499 | OK |
| `/emf/v2/{id}/currentSystem` | 565 | OK |
| `/emf/v2/{id}/devices/{deviceId}/buckets` | 610 | OK |
| `/systems/{id}/tli/away-mode` | 1319 | OK |
| `/systems/{id}/tli/zones/{z}/operation-mode` | 1327 | OK |
| `/systems/{id}/tli/zones/{z}/heating-operation-mode` | 1348 | OK |
| `/systems/{id}/tli/zones/{z}/quick-veto` | 1385 | OK |
| `/systems/{id}/tli/zones/{z}/set-back-temperature` | 1405 | OK |
| `/systems/{id}/tli/zones/{z}/manual-mode-setpoint` | 1429 | OK |
| `/systems/{id}/tli/zones/{z}/setpoint-cooling` | 1455 | OK |
| `/systems/{id}/tli/zones/{z}/time-windows` | 1477 | OK |
| `/systems/{id}/tli/domestic-hot-water/{i}/operation-mode` | via command handler | OK |
| `/systems/{id}/tli/domestic-hot-water/{i}/temperature` | via command handler | OK |
| `/systems/{id}/tli/domestic-hot-water/{i}/time-windows` | via command handler | OK |
| `/systems/{id}/tli/ventilation/{v}/operation-mode` | via command handler | OK |
| `/systems/{id}/tli/ventilation/{v}/fan-stage` | via command handler | OK |
| `/systems/{id}/tli/ventilation/{v}/time-windows` | via command handler | OK |
| `/api/v1/ambisense/facilities/{id}/rooms/{r}/configuration/{cmd}` | 1508 | OK |

### Neue/geänderte Endpoints in APK v3.7.1 (NICHT in main.js)

| Endpoint-Pattern | Beschreibung | Relevanz |
|---|---|---|
| `/daq/{systemId}/system` | Outdoor-Temperatur-Daten (DAQ = Data Acquisition) | Mittel - könnte für Außentemperatur-Graphen nützlich sein |
| `/rts/{systemId}/currentPvData` | Real-Time Solar/PV-Daten | Hoch für PV-Besitzer |
| `/emf/v2/{id}/currentSystemWithEfficiency` | Energiedaten mit COP/Effizienz pro operationMode | Hoch - erweiterte Energiedaten |
| `/hem/{systemId}/hem30` | Home Energy Manager 30-Daten | Mittel - nur für HEM30-Nutzer |
| `/hem/{systemId}/lpc` | Load Power Control | Mittel - nur für HEM-Nutzer |
| `/hem/{systemId}/mpc` | Model Predictive Control | Mittel - nur für HEM-Nutzer |
| `/hem/ohpcf/{systemId}/expert-settings/domestic-hot-water` | HEM Expert DHW Settings | Niedrig |
| `/ship/{systemId}/devices` | SHIP-Gerätedaten (Smart Home IP) | Niedrig - EEBUS/SHIP-Integration |
| `/ship/{systemId}/self/spineCapable` | Spine-Fähigkeit prüfen | Niedrig |
| `/eebus/energy-management/{systemId}` | EEBUS Energy Management | Niedrig - spezielles Feature |
| `/homes/{id}/overview` | Home-Übersicht | Mittel - Dashboard-Daten |
| `/homes/{id}/invitationCode` | Einladungscode für Multi-User | Niedrig |
| `/homes/{id}/sub-users/{userId}` | Sub-User-Verwaltung | Niedrig |
| `/homes/{id}/proof-of-possession-contact-support` | Support-Kontakt | Niedrig |
| `/homes/join` | Home beitreten (Multi-User) | Niedrig |
| `/check-email/{country}` | E-Mail-Prüfung bei Registrierung | Niedrig |
| `/register` | Registrierung | Niedrig |
| `/accounts/firebase-token` | Firebase Push-Token registrieren | Niedrig (Push-Notifications) |
| `/customer/feedback` | Feedback senden | Niedrig |
| `/support-ticket` | Support-Ticket erstellen | Niedrig |
| `/user-info` | Benutzerinfo abrufen | Niedrig |
| `/systems/{id}/diagnostic-trouble-codes` | Fehlercodes auslesen | Hoch - wichtig für Diagnose |
| `/systems/{id}/thermostat-devices` | Thermostat-Geräte | Mittel |
| `/systems/{id}/thermostat-devices/{deviceId}` | Einzelnes Thermostat | Mittel |
| `/systems/{id}/meta-info/connection-status` | Verbindungsstatus | Mittel |
| `/systems/{id}/meta-info/time-zone` | Zeitzone | Niedrig |
| `/systems/{id}/state` | Systemzustand | Hoch - evtl. kompaktere Alternative |
| `/systems/{id}/firmware-metadata` | Firmware-Info | Niedrig |
| `/systems/{id}/auto-update-configuration` | Auto-Update Config | Niedrig |
| `/systems/{id}/trigger-update` | Firmware-Update auslösen | Niedrig |
| `/systems/{id}/tli/cooling-for-days` | Kühlung für Tage (Frostschutz?) | Mittel |
| `/systems/{id}/tli/ventilation-boost/recovair` | RecovAIR Lüftungsboost | Mittel |
| `/systems/{id}/tli/ventilation-boost/zone` | Zonen-Lüftungsboost | Mittel |
| `/systems/{id}/tli/circuit/{c}/heating-curve` | Heizkurve pro Kreis | Mittel |
| `/systems/{id}/tli/circuit/{c}/min-flow-temperature-setpoint` | Min-Vorlauftemperatur | Mittel |
| `/systems/{id}/tli/configuration/emm-commissioning` | EMM Inbetriebnahme | Niedrig |
| `/systems/{id}/domestic-hot-water/{i}/boost` (non-tli) | DHW Boost (direkt) | Mittel |
| `/systems/{id}/tli/domestic-hot-water/{i}/circulation-pump-time-windows` | Zirkulationspumpe Zeitprogramm | Mittel |
| `system-control/v1/systems/{id}/circuits/{c}/heat-demand-limited-by-outside-temperature` | Heizbedarfsbegrenzung | Niedrig |
| `system-control/v1/systems/{id}/is-external-backup-heater-emergency-mode-unrestricted` | Notfall-Heizstab Modus | Niedrig |
| `system-control/v1/systems/{id}/domestic-hot-water/{i}/tapping-setpoint` | WW-Zapf-Sollwert | Mittel |
| `system-control/v1/systems/{id}/domestic-hot-water/{i}/cylinder-temperature` | WW-Speicher-Temperatur | Hoch |
| `system-control/v1/systems/{id}/zones/{z}/cooling-temperature-setpoint` | Kühl-Solltemperatur | Mittel |
| `system-control/v1/systems/{id}/zones/{z}/cooling-time-periods` | Kühl-Zeitprogramm | Mittel |
| `system-control/v1/systems/{id}/zones/{z}/heating-temperature-setpoint` | Heiz-Solltemperatur (system-control) | Mittel |
| `system-control/v1/systems/{id}/zones/{z}/heating-time-periods` | Heiz-Zeitprogramm (system-control) | Mittel |
| `vrc700/v1/systems/{id}/cooling-for-days` | Kühl-Tage (VRC700) | Mittel |
| `vrc700/v1/systems/{id}/ventilation-boost/zone-time-windows` | Lüftungsboost Zeitfenster | Mittel |
| `vrc700/v1/systems/{id}/circuit/{c}/heating-curve` | Heizkurve VRC700 | Mittel |
| `consent-service/v1/consents/consent-allowed-002` | DSGVO-Consent prüfen | Niedrig |

## Neue API-Features im Vergleich zur vorherigen Version

### Potenziell wichtige Neuerungen:

1. **`/emf/v2/{id}/currentSystemWithEfficiency`** — Liefert COP-Werte und Effizienz pro Betriebsart (HEATING, COOLING, DHW). Erweitert das bestehende `/emf/v2/{id}/currentSystem`.

2. **`/rts/{systemId}/currentPvData`** — PV-/Solar-Echtzeitdaten für die "FEATURE_RTS_POWER_CONSUMPTION" Funktion (in BuildConfig als `true` markiert).

3. **`/daq/{systemId}/system`** — Data Acquisition für Outdoor-Temperatur mit resolution-Parameter (DAY/MONTH).

4. **`/systems/{id}/diagnostic-trouble-codes`** — Fehlercodes direkt aus der API. Der Adapter liest diese aktuell nur aus dem TLI-State-Objekt.

5. **`system-control/v1/.../cylinder-temperature`** und **`tapping-setpoint`** — Direkte Warmwasser-Temperaturdaten über system-control API.

6. **`/hem/{id}/hem30`**, **`/hem/{id}/lpc`**, **`/hem/{id}/mpc`** — Home Energy Manager Endpunkte für Nutzer mit HEM30 (BuildConfig: `FEATURE_HEM30 = false` — aber vorhanden).

## Keine Breaking Changes bei bestehenden Endpoints

Die bestehenden API-Pfade in main.js sind **unverändert** gegenüber dem, was die APK zeigt. Die URLs, Pfadstruktur und Parameter (resolution, operationMode, energyType, startDate, endDate) sind identisch.

## Header-Änderungen (bereits gefixt)

- `x-app-version: 3.7.1` (neu)
- `x-app-build: 25262` (neu, vorher nicht vorhanden)
- `User-Agent: myVAILLANT/25262 CFNetwork/1496.0.7 Darwin/23.5.0` (aktualisiert)
- `x-idm-identifier: KEYCLOAK` (muss überall KEYCLOAK sein, nicht OKTA)
- `credentialId` im Login-POST entfernt

## Empfehlung

Kein Handlungsbedarf für bestehende Funktionalität. Die API-Endpoints sind stabil. Die neuen Endpoints (`currentSystemWithEfficiency`, `rts`, `diagnostic-trouble-codes`) könnten als Feature-Erweiterung implementiert werden, brechen aber nichts am bestehenden Adapter.
