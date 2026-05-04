# ioBroker.vaillant

This adapter connects ioBroker to Vaillant heating systems via the myVaillant cloud API.

The adapter uses an unofficial Vaillant cloud API and may break at any time if Vaillant changes their backend.

## Status

- myVaillant login via Keycloak / PKCE is working
- Read access has been verified with a real installation
- Systems, status and statistics are received successfully
- Write commands are experimental and should be used carefully
- The old Okta-based login flow has been removed

Availability depends on account type, hardware, firmware, and region. Not every combination has been tested.

## Requirements

- ioBroker installation
- myVaillant account
- Vaillant system connected to cloud
- supported location (e.g. germany)

A Node.js version compatible with the installed **js-controller** is required by the ioBroker host (not specific to this adapter).

## Configuration

```text
myv = true
user = your email
password = your password
location = germany
fetchReports = false (recommended for first setup)
```

- **`location`** (lowercase) must be one of: `germany`, `denmark`, `switzerland`, `austria`, `belgium`. Unsupported values are rejected during login.
- Optional settings appear under the **configuration** subtree. Some values apply only when the device is in **ON** or **MANUAL** mode, not **AUTO** or **TIME_CONTROLLED** (device-specific).
- Do not publish real passwords or tokens in documentation, logs, or public issues.

## Supported Features

- Login via myVaillant (Keycloak)
- Discover systems
- Read system data
- Read statistics
- Create ioBroker states

Statistics depend on instance options and cloud responses. Object trees follow the data returned by the API.

## Write Commands / Experimental

Write commands may change heating behavior.
Use them carefully.

The sections below cover **state writes** (object IDs), **remote** actions, and **custom Command** payloads sent to `vaillant.0.<id>.remotes.customCommand`. Custom commands are **advanced**: wrong URLs or bodies can fail or change plant behaviour without clear errors.

### multiMATIC-style object writes (experimental)

Replace `serialnumber` with the device serial from the object tree.

**DHW temperature setpoint (example path):**  
`vaillant.0.serialnumber.systemcontrol/tli.dhw.hotwater.configuration.hotwater_temperature_setpoint`  
This path targets domestic hot water temperature configuration when exposed for the device.

**Heating zone — switch to manual, set temperature, restore schedule (example):**

1. `vaillant.0.serialnumber.systemcontrol/tli.zones03.heating.configuration.operation_mode` → `MANUAL` — selects manual heating for the zone.
2. `vaillant.0.serialnumber.systemcontrol/tli.zones03.heating.configuration.manual_mode_temperature_setpoint` — sets manual zone temperature.
3. Set `operation_mode` back to `TIME_CONTROLLED` when finished — returns scheduling control.

Use **`parameterValue`** only where the object definition allows it.

### myVaillant state writes (experimental)

Replace `id` with the system id from the object tree.

- `vaillant.0.id.systemControlState.controlState.domesticHotWater01.boost` — toggles DHW boost (`true` / `false`).
- `vaillant.0.id.systemControlState.controlState.zones01.desiredRoomTemperatureSetpoint` — writes desired room temperature.
- `vaillant.0.id.systemControlState.controlState.zones01.setBackTemperature` — writes setback temperature.
- `vaillant.0.id.systemControlState.controlState.zones01.heatingOperationMode` — e.g. `OFF`, `MANUAL`, `TIME_CONTROLLED`.
- `vaillant.0.id.systemControlState.controlState.domesticHotWater01.operationMode` — e.g. `OFF`, `MANUAL`, `TIME_CONTROLLED`.

### Remote and custom Command

- `vaillant.0.id.remote` — predefined / refresh-related actions.
- `vaillant.0.id.remotes.customCommand` — custom relative URLs and JSON bodies (experimental).

Zone index segments in URLs are typically `0` … `n`; if a path fails, another index (e.g. `zone/0/` vs `zone/2/`) may match the installation.

**Comfort room temperature, zone 0** — sets the heating comfort temperature for zone 0 via custom command:

```json
{
  "url": "zone/0/heating/comfort-room-temperature",
  "data": { "comfortRoomTemperature": 10.5 }
}
```

**Comfort room temperature, zone 1** — same intent for zone 1:

```json
{
  "url": "zone/1/heating/comfort-room-temperature",
  "data": { "comfortRoomTemperature": 10.5 }
}
```

**DHW operation mode OFF** — turns domestic hot water operation off:

```json
{
  "url": "domestic-hot-water/255/operation-mode",
  "data": { "operationMode": "OFF" }
}
```

**DHW temperature setpoint** — sets DHW target temperature:

```json
{
  "url": "domestic-hot-water/255/temperature",
  "data": { "setpoint": 55 }
}
```

**Zone 1 heating operation mode DAY** — sets heating operation mode to DAY:

```json
{
  "url": "zone/1/heating/operation-mode",
  "data": { "operationMode": "DAY" }
}
```

**Zone 1 heating setback temperature** — sets heating setback temperature:

```json
{
  "url": "zone/1/heating/set-back-temperature",
  "data": { "setBackTemperature": 20 }
}
```

**Zone 1 cooling operation mode DAY** — sets cooling operation mode to DAY:

```json
{
  "url": "zone/1/cooling/operation-mode",
  "data": { "operationMode": "DAY" }
}
```

**Zone 1 cooling setpoint** — sets cooling setpoint:

```json
{
  "url": "zone/1/cooling/setpoint",
  "data": { "setpoint": 20 }
}
```

**Ventilation operation mode DAY** — sets ventilation to DAY mode:

```json
{
  "url": "ventilation/0/operation-mode",
  "data": { "operationMode": "DAY" }
}
```

**Ventilation operation mode SET_BACK** — sets ventilation to SET_BACK:

```json
{
  "url": "ventilation/0/operation-mode",
  "data": { "operationMode": "SET_BACK" }
}
```

**Ventilation maximum day fan stage** — limits maximum day fan stage:

```json
{
  "url": "ventilation/0/day-fan-stage",
  "data": { "maximumDayFanStage": 3 }
}
```

**Ventilation maximum night fan stage** — limits maximum night fan stage:

```json
{
  "url": "ventilation/0/night-fan-stage",
  "data": { "maximumNightFanStage": 2 }
}
```

**Zone 1 heating quick veto (POST)** — temporary heating override with duration:

```json
{
  "url": "zone/1/heating/quick-veto",
  "data": { "desiredRoomTemperatureSetpoint": 11, "duration": 3 },
  "method": "POST"
}
```

**DHW boost on (POST)** — starts DHW boost:

```json
{
  "url": "domestic-hot-water/255/boost",
  "data": {},
  "method": "POST"
}
```

**DHW boost off (DELETE)** — stops DHW boost:

```json
{
  "url": "domestic-hot-water/255/boost",
  "data": {},
  "method": "DELETE"
}
```

**Circulation pump time windows** — example payload shape for weekly circulation pump windows:

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

**DHW time windows** — example payload shape for weekly DHW time windows:

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

**Cooling-for-days enable (POST)** — example POST to enable cooling-for-days:

```json
{
  "url": "cooling-for-days",
  "data": {"value": 7},
  "method": "POST"
}
```

**Cooling-for-days clear (DELETE)** — example DELETE to clear cooling-for-days:

```json
{
  "url": "cooling-for-days",
  "method": "DELETE"
}
```

## Limitations and Warnings

- This adapter uses an unofficial Vaillant cloud API
- The API may change at any time
- The adapter depends on cloud availability
- Write commands can affect heating configuration
- Do not share logs containing credentials or tokens

## Breaking Changes

### 0.8.0

- Okta-based login removed
- Only myVaillant (Keycloak) is supported

The second item refers to **myVaillant cloud authentication** only. **multiMATIC / senso** cloud access remains available when **`myv`** is disabled and multiMATIC credentials are used; that path is still unofficial and may change.

## Notes

![Logo](admin/vaillant.png)

[![NPM version](http://img.shields.io/npm/v/iobroker.vaillant.svg)](https://www.npmjs.com/package/iobroker.vaillant)
[![Downloads](https://img.shields.io/npm/dm/iobroker.vaillant.svg)](https://www.npmjs.com/package/iobroker.vaillant)
![Number of Installations (latest)](http://iobroker.live/badges/vaillant-installed.svg)
![Number of Installations (stable)](http://iobroker.live/badges/vaillant-stable.svg)
[![Dependency Status](https://img.shields.io/david/TA2k/iobroker.vaillant.svg)](https://david-dm.org/TA2k/ioBroker.vaillant)
[![Known Vulnerabilities](https://snyk.io/test/github/TA2k/ioBroker.vaillant/badge.svg)](https://snyk.io/test/github/TA2k/ioBroker.vaillant)

[![NPM](https://nodei.co/npm/iobroker.vaillant.png?downloads=true)](https://nodei.co/npm/iobroker.vaillant/)

### Development

- `npm test` — runs Mocha using `test/mocharc.custom.json`
- `npm run check` — TypeScript check: `tsc --noEmit -p tsconfig.json`
- `npm run lint` — ESLint on the project tree

### Changelog / Release Notes

<!-- ### **WORK IN PROGRESS** -->

#### 0.8.0 (2026-05-04)

- myVaillant: stable login via **Keycloak / OIDC with PKCE**; realm from configured **region** (`location`).
- **Breaking:** legacy **Okta** login path removed / disabled.
- myVaillant: unified HTTP handling (shared client timeout, headers, and structured API paths for homes, systems, statistics, rooms, and commands).
- Logging helpers reduce accidental exposure of sensitive fields in log output.
- Tests: Mocha config in `test/mocharc.custom.json`; `npm run check` uses `tsconfig.json`.
- README: structure and documentation updates.

#### 0.7.5 (2025-07-09)

- Revert change to fix save issue

#### 0.7.2 (2024-04-18)

- Fix month stats period

#### 0.3.0

- Add boost

#### 0.1.2

- Fix refresh token

#### 0.1.1

- Add myVaillant support and stats

#### 0.0.15

- Bugfixes

#### 0.0.14

- Add rooms support

#### 0.0.13

- Fix livereport order

#### 0.0.11

- Fix issue with js-controller 3.2

#### 0.0.10

- Fix issue with js-controller 3

#### 0.0.8

- (TA2k) Fix authorization problem and missing configuration states

#### 0.0.6

- (TA2k) Initial release

### License

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
