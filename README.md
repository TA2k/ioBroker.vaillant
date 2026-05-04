![Logo](admin/vaillant.png)

# ioBroker.vaillant

[![NPM version](http://img.shields.io/npm/v/iobroker.vaillant.svg)](https://www.npmjs.com/package/iobroker.vaillant)
[![Downloads](https://img.shields.io/npm/dm/iobroker.vaillant.svg)](https://www.npmjs.com/package/iobroker.vaillant)
![Number of Installations (latest)](http://iobroker.live/badges/vaillant-installed.svg)
![Number of Installations (stable)](http://iobroker.live/badges/vaillant-stable.svg)
[![Dependency Status](https://img.shields.io/david/TA2k/iobroker.vaillant.svg)](https://david-dm.org/TA2k/ioBroker.vaillant)
[![Known Vulnerabilities](https://snyk.io/test/github/TA2k/ioBroker.vaillant/badge.svg)](https://snyk.io/test/github/TA2k/ioBroker.vaillant)

[![NPM](https://nodei.co/npm/iobroker.vaillant.png?downloads=true)](https://nodei.co/npm/iobroker.vaillant/)

## Short Description

This adapter connects ioBroker to Vaillant heating systems via the myVaillant cloud API.

The adapter uses the unofficial Vaillant cloud API. It may break at any time if Vaillant changes their backend.

The same limitation applies to **multiMATIC / senso** (VR900 / VR920) cloud access: it is not a published, stable public API. Use **multiMATIC** mode when `myv` is not enabled and supply the credentials from the multiMATIC or senso app as required by your hardware.

## Status

- myVaillant login via Keycloak / PKCE is working
- Read access has been verified with a real myVaillant installation
- System status and statistics are received successfully
- Write commands are experimental and should be used carefully
- The old Okta-based login flow has been removed

Results depend on account type, device model, firmware, and region. Not every combination has been tested.

## Breaking Changes

### 0.8.0

- Okta-based login has been disabled
- myVaillant uses Keycloak / PKCE authentication
- Legacy cloud behavior may no longer work

## Requirements

- An **ioBroker** installation (Node.js version as required by your js-controller / platform)
- A **myVaillant** account (e-mail and password) when using myVaillant mode
- A **supported country / location** setting (`location` — see [Configuration](#configuration))
- A **Vaillant system** linked to the **myVaillant** cloud for myVaillant mode
- For **multiMATIC / senso** cloud use: valid credentials from that app and compatible hardware

## Configuration

Typical settings for **myVaillant**:

```text
myv = true
user = your myVaillant email
password = your myVaillant password
location = your country, e.g. germany
fetchReports = false recommended for first smoke test
```

- **`location`** (lowercase) must be one of: `germany`, `denmark`, `switzerland`, `austria`, `belgium`. Other values are rejected at login.
- **`fetchReports`**: disabling it is recommended for an initial smoke test to reduce load.
- Additional options appear under the **configuration** subtree. Some values only apply when the device mode is **ON** or **MANUAL**, not **AUTO** or **TIME_CONTROLLED** (depends on the device).

Do not use real credentials in documentation, logs, or public tickets.

## Supported Features

- **Login** for myVaillant via **Keycloak / PKCE** (OIDC)
- **Discover** homes / systems after login
- **Read** system status into ioBroker states
- **Read statistics** when reporting options are enabled and the cloud returns data
- **Create ioBroker states** from API responses (objects mirror cloud fields)

**multiMATIC:** with `myv = false`, the adapter uses the multiMATIC / senso cloud path documented in older releases; behaviour is still subject to the unofficial cloud API.

## Write Commands / Experimental

Write commands may change heating settings. Use them carefully. Read functionality has been verified; write functionality may require additional testing depending on the system.

The following applies to **object writes** (multiMATIC / myVaillant state IDs), **remote** actions, and **custom Command** payloads. **Custom Command** is an **advanced** feature: URLs and bodies are passed through to the cloud; incorrect payloads can fail silently or change the plant in unintended ways.

### multiMATIC example (zone write flow)

Replace `serialnumber` with your device serial from the object tree.

**DHW (domestic hot water) setpoint (example state path):**

`vaillant.0.serialnumber.systemcontrol/tli.dhw.hotwater.configuration.hotwater_temperature_setpoint`

**Heating zone (example sequence):**

1. Set operation mode to **MANUAL**, e.g.  
   `vaillant.0.serialnumber.systemcontrol/tli.zones03.heating.configuration.operation_mode` → `MANUAL`
2. Set temperature, e.g.  
   `vaillant.0.serialnumber.systemcontrol/tli.zones03.heating.configuration.manual_mode_temperature_setpoint`
3. Set `operation_mode` back to **TIME_CONTROLLED** when finished.

Adjust **`parameterValue`** only where the object definition allows it.

### myVaillant control examples (experimental)

Replace `id` with your system id from the object tree.

- DHW boost: `vaillant.0.id.systemControlState.controlState.domesticHotWater01.boost` → `true` / `false`
- Room setpoint: `vaillant.0.id.systemControlState.controlState.zones01.desiredRoomTemperatureSetpoint`
- Setback: `vaillant.0.id.systemControlState.controlState.zones01.setBackTemperature`
- Zone heating mode: `vaillant.0.id.systemControlState.controlState.zones01.heatingOperationMode` — e.g. `OFF`, `MANUAL`, `TIME_CONTROLLED`
- DHW operation mode: `vaillant.0.id.systemControlState.controlState.domesticHotWater01.operationMode` — e.g. `OFF`, `MANUAL`, `TIME_CONTROLLED`

### Remote and custom Command

- Predefined / refresh-related: `vaillant.0.id.remote`
- **Custom Command** (paths not covered by predefined remotes): `vaillant.0.id.remotes.customCommand`

Zone indices in URLs are **0 … n**; if one path fails, try another index (e.g. `zone/0/...` vs `zone/2/...`).

Set heating comfort temperature for **zone 0** (example payload for `customCommand`):

```json
{
  "url": "zone/0/heating/comfort-room-temperature",
  "data": { "comfortRoomTemperature": 10.5 }
}
```

Same intent for **zone 1**:

```json
{
  "url": "zone/1/heating/comfort-room-temperature",
  "data": { "comfortRoomTemperature": 10.5 }
}
```

Set **domestic hot water** operation mode to **OFF**:

```json
{
  "url": "domestic-hot-water/255/operation-mode",
  "data": { "operationMode": "OFF" }
}
```

Set **DHW temperature setpoint**:

```json
{
  "url": "domestic-hot-water/255/temperature",
  "data": { "setpoint": 55 }
}
```

Set **zone 1 heating** operation mode to **DAY**:

```json
{
  "url": "zone/1/heating/operation-mode",
  "data": { "operationMode": "DAY" }
}
```

Set **zone 1 heating** setback temperature:

```json
{
  "url": "zone/1/heating/set-back-temperature",
  "data": { "setBackTemperature": 20 }
}
```

Set **zone 1 cooling** operation mode to **DAY**:

```json
{
  "url": "zone/1/cooling/operation-mode",
  "data": { "operationMode": "DAY" }
}
```

Set **zone 1 cooling** setpoint:

```json
{
  "url": "zone/1/cooling/setpoint",
  "data": { "setpoint": 20 }
}
```

Set **ventilation** operation mode to **DAY**:

```json
{
  "url": "ventilation/0/operation-mode",
  "data": { "operationMode": "DAY" }
}
```

Set **ventilation** operation mode to **SET_BACK**:

```json
{
  "url": "ventilation/0/operation-mode",
  "data": { "operationMode": "SET_BACK" }
}
```

Set **maximum day fan stage** for ventilation:

```json
{
  "url": "ventilation/0/day-fan-stage",
  "data": { "maximumDayFanStage": 3 }
}
```

Set **maximum night fan stage** for ventilation:

```json
{
  "url": "ventilation/0/night-fan-stage",
  "data": { "maximumNightFanStage": 2 }
}
```

Start a **quick veto** on **zone 1 heating** (POST):

```json
{
  "url": "zone/1/heating/quick-veto",
  "data": { "desiredRoomTemperatureSetpoint": 11, "duration": 3 },
  "method": "POST"
}
```

Enable **DHW boost** (POST):

```json
{
  "url": "domestic-hot-water/255/boost",
  "data": {},
  "method": "POST"
}
```

Disable **DHW boost** (DELETE):

```json
{
  "url": "domestic-hot-water/255/boost",
  "data": {},
  "method": "DELETE"
}
```

Set **circulation pump time windows** (example payload shape):

```json
{
  "url": "domestic-hot-water/255/circulation-pump/time-windows",
  "data": {
    "friday": [
      {
        "endTime": 540,
        "startTime": 360
      }
    ],
    "monday": [],
    "saturday": [],
    "sunday": [],
    "thursday": [],
    "tuesday": [],
    "wednesday": []
  }
}
```

Set **DHW time windows** (example payload shape):

```json
{
  "url": "domestic-hot-water/255/time-windows",
  "data": {
    "friday": [],
    "monday": [
      {
        "endTime": 1320,
        "startTime": 330
      }
    ],
    "saturday": [
      {
        "endTime": 1320,
        "startTime": 330
      }
    ],
    "sunday": [
      {
        "endTime": 1320,
        "startTime": 330
      }
    ],
    "thursday": [
      {
        "endTime": 1320,
        "startTime": 330
      }
    ],
    "tuesday": [
      {
        "endTime": 1320,
        "startTime": 330
      }
    ],
    "wednesday": [
      {
        "endTime": 1320,
        "startTime": 330
      }
    ]
  }
}
```

Enable **cooling-for-days** (POST):

```json
{
  "url": "cooling-for-days",
  "data": {"value": 7},
  "method": "POST"
}
```

Clear **cooling-for-days** (DELETE):

```json
{
  "url": "cooling-for-days",
  "method": "DELETE"
}
```

## Limitations and Warnings

- This adapter uses an unofficial Vaillant cloud API
- Vaillant may change authentication, endpoints or response formats without notice
- The adapter depends on Vaillant cloud availability
- Write commands can affect heating behavior
- Do not share logs containing credentials, tokens or authorization headers

## Development Notes

- `npm test` — runs Mocha using `test/mocharc.custom.json`
- `npm run check` — TypeScript check: `tsc --noEmit -p tsconfig.json`
- `npm run lint` — ESLint on the project tree

## Changelog / Release Notes

<!-- ### **WORK IN PROGRESS** -->

### 0.8.0 (2026-05-04)

- myVaillant: stable login via **Keycloak / OIDC with PKCE**; realm from configured **region** (`location`).
- **Breaking:** legacy **Okta** login path removed / disabled.
- myVaillant: unified HTTP handling (shared client timeout, headers, and structured API paths for homes, systems, statistics, rooms, and commands).
- Logging helpers reduce accidental exposure of sensitive fields in log output.
- Tests: Mocha config in `test/mocharc.custom.json`; `npm run check` uses `tsconfig.json`.
- README: structure, English documentation, and operational notes.

### 0.7.5 (2025-07-09)

- Revert change to fix save issue

### 0.7.2 (2024-04-18)

- Fix month stats period

### 0.3.0

- Add boost

### 0.1.2

- Fix refresh token

### 0.1.1

- Add myVaillant support and stats

### 0.0.15

- Bugfixes

### 0.0.14

- Add rooms support

### 0.0.13

- Fix livereport order

### 0.0.11

- Fix issue with js-controller 3.2

### 0.0.10

- Fix issue with js-controller 3

### 0.0.8

- (TA2k) Fix authorization problem and missing configuration states

### 0.0.6

- (TA2k) Initial release

## License

MIT License

Copyright (c) 2020-2030 TA2k <tombox2020@gmail.com>

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.
