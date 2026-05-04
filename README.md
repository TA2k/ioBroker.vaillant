![Logo](admin/vaillant.png)

# ioBroker.vaillant

[![NPM version](http://img.shields.io/npm/v/iobroker.vaillant.svg)](https://www.npmjs.com/package/iobroker.vaillant)
[![Downloads](https://img.shields.io/npm/dm/iobroker.vaillant.svg)](https://www.npmjs.com/package/iobroker.vaillant)
![Number of Installations (latest)](http://iobroker.live/badges/vaillant-installed.svg)
![Number of Installations (stable)](http://iobroker.live/badges/vaillant-stable.svg)
[![Dependency Status](https://img.shields.io/david/TA2k/iobroker.vaillant.svg)](https://david-dm.org/TA2k/ioBroker.vaillant)
[![Known Vulnerabilities](https://snyk.io/test/github/TA2k/ioBroker.vaillant/badge.svg)](https://snyk.io/test/github/TA2k/ioBroker.vaillant)

[![NPM](https://nodei.co/npm/iobroker.vaillant.png?downloads=true)](https://nodei.co/npm/iobroker.vaillant/)

## Description

This adapter connects [ioBroker](https://www.iobroker.net/) to **Vaillant** heating systems via **multiMATIC** (e.g. VR900 / VR920) and **myVaillant** cloud.

**What typically works well**

- **myVaillant (cloud):** login with **Keycloak / OpenID Connect and PKCE**, then **reading** system and room data, statistics (when enabled), and exposing states in the ioBroker object tree.
- **multiMATIC:** communication with the Vaillant cloud using the credentials from the multiMATIC / senso app (same family of devices as documented in the adapter).

The adapter mirrors cloud data into objects; changing values sends commands to the cloud where the adapter and API allow it.

## Breaking changes

- Okta-based login has been removed.
- Only myVaillant (Keycloak) is supported.

The second item applies to **myVaillant cloud login** (from adapter **0.8.0** onward: Keycloak / OIDC with PKCE). **multiMATIC / senso** operation in the adapter is separate and not removed by this change.

## Requirements

- A running **ioBroker** installation (compatible **Node.js** version as required by your ioBroker / js-controller environment).
- Account credentials from the **multiMATIC / senso** or **myVaillant** app (e-mail and password as configured in the adapter instance).

## Configuration

1. Create an adapter instance and enter **e-mail** and **password** (same as in the Vaillant app you use).
2. For **myVaillant**, set **`myv`** to `true` and configure **`location`** (region) as required (see below). Optional: set **`fetchReports`** according to your needs (e.g. `false` for a lighter first test).
3. Additional options live under the **configuration** subtree. Some settings only take effect when the relevant mode is **ON** or **MANUAL**, not **AUTO** or **TIME_CONTROLLED** (device-dependent).

### myVaillant authentication

- myVaillant uses **Keycloak** with **PKCE** (proof key for code exchange) against Vaillant’s identity endpoint.
- The **realm** is derived from the configured **region** (`location`): `vaillant-<location>-b2c` (brand is fixed to Vaillant in the current configuration).
- **Supported `location` values** (lowercase): `germany`, `denmark`, `switzerland`, `austria`, `belgium`. Invalid values cause a clear configuration error.
- For a **first live test**, using `location = germany` and disabling heavy optional polling (e.g. `fetchReports = false` where available) reduces load while verifying login.

The legacy **Okta** login path is **no longer available**; see [Breaking changes](#breaking-changes).

## Supported features

### multiMATIC examples

Replace `serialnumber` with your device serial from the object tree.

**DHW (domestic hot water)**

`vaillant.0.serialnumber.systemcontrol/tli.dhw.hotwater.configuration.hotwater_temperature_setpoint`

**Heating zone (example flow)**

1. Set operation mode to **MANUAL**, for example:  
   `vaillant.0.serialnumber.systemcontrol/tli.zones03.heating.configuration.operation_mode` → `MANUAL`
2. Set temperature, for example:  
   `vaillant.0.serialnumber.systemcontrol/tli.zones03.heating.configuration.manual_mode_temperature_setpoint`
3. Set `operation_mode` back to **TIME_CONTROLLED** when finished.

Parameters can be adjusted via **`parameterValue`** where present; always respect allowed values from the object’s **definition** / native metadata.

### myVaillant examples

Replace `id` with your system id from the object tree.

- DHW boost: `vaillant.0.id.systemControlState.controlState.domesticHotWater01.boost` → `true` / `false`
- Room setpoint: `vaillant.0.id.systemControlState.controlState.zones01.desiredRoomTemperatureSetpoint`
- Setback: `vaillant.0.id.systemControlState.controlState.zones01.setBackTemperature`
- Zone heating mode: `vaillant.0.id.systemControlState.controlState.zones01.heatingOperationMode` — values include `OFF`, `MANUAL`, `TIME_CONTROLLED`
- DHW operation mode: `vaillant.0.id.systemControlState.controlState.domesticHotWater01.operationMode` — `OFF`, `MANUAL`, `TIME_CONTROLLED`

### Remote commands

- Predefined / refresh-related: `vaillant.0.id.remote`
- **Custom Command** (URLs not covered by predefined remotes): `vaillant.0.id.remotes.customCommand`

## Limitations and warnings

### Unofficial cloud API

This adapter uses an unofficial Vaillant cloud API and may break at any time.

### Writes and safety

Read functionality has been tested. Write commands should be used carefully and may affect heating configuration.

**Additional notes**

- Vaillant does not publish a stable public contract for the cloud endpoints used here; behaviour can change without notice.
- Write operations (object writes, custom commands) depend on device type, firmware, and region.
- Do **not** post passwords, refresh tokens, or access tokens in logs, screenshots, or support tickets.

## Custom Command examples (experimental)

The JSON examples below show payloads for **`customCommand`**. They are **illustrative**; paths and allowed values depend on your installation.

**Important:** treat **all write-style operations** as **experimental** and **not fully verified** across all devices. Verify impact on a test instance or maintenance window before relying on them in production.

Zone indices are **0 … n**; try `zone/0/...` or `zone/2/...` if one path does not match your system.

```json
{
  "url": "zone/0/heating/comfort-room-temperature",
  "data": { "comfortRoomTemperature": 10.5 }
}
```

```json
{
  "url": "zone/1/heating/comfort-room-temperature",
  "data": { "comfortRoomTemperature": 10.5 }
}
```

```json
{
  "url": "domestic-hot-water/255/operation-mode",
  "data": { "operationMode": "OFF" }
}
```

```json
{
  "url": "domestic-hot-water/255/temperature",
  "data": { "setpoint": 55 }
}
```

```json
{
  "url": "zone/1/heating/operation-mode",
  "data": { "operationMode": "DAY" }
}
```

```json
{
  "url": "zone/1/heating/set-back-temperature",
  "data": { "setBackTemperature": 20 }
}
```

```json
{
  "url": "zone/1/cooling/operation-mode",
  "data": { "operationMode": "DAY" }
}
```

```json
{
  "url": "zone/1/cooling/setpoint",
  "data": { "setpoint": 20 }
}
```

```json
{
  "url": "ventilation/0/operation-mode",
  "data": { "operationMode": "DAY" }
}
```

```json
{
  "url": "ventilation/0/operation-mode",
  "data": { "operationMode": "SET_BACK" }
}
```

```json
{
  "url": "ventilation/0/day-fan-stage",
  "data": { "maximumDayFanStage": 3 }
}
```

```json
{
  "url": "ventilation/0/night-fan-stage",
  "data": { "maximumNightFanStage": 2 }
}
```

```json
{
  "url": "zone/1/heating/quick-veto",
  "data": { "desiredRoomTemperatureSetpoint": 11, "duration": 3 },
  "method": "POST"
}
```

```json
{
  "url": "domestic-hot-water/255/boost",
  "data": {},
  "method": "POST"
}
```

```json
{
  "url": "domestic-hot-water/255/boost",
  "data": {},
  "method": "DELETE"
}
```

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

```json
{
  "url": "cooling-for-days",
  "data": {"value": 7},
  "method": "POST"
}
```

```json
{
  "url": "cooling-for-days",
  "method": "DELETE"
}
```

## Development notes

- `npm test` — runs Mocha using `test/mocharc.custom.json`.
- `npm run check` — TypeScript check: `tsc --noEmit -p tsconfig.json`.
- `npm run lint` — ESLint on the project tree.

## Changelog

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
