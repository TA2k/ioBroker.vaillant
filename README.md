# ioBroker.vaillant

This adapter connects ioBroker to Vaillant heating systems via the myVaillant cloud API.

> ⚠️ This adapter uses an **unofficial Vaillant cloud API**.
> It may break at any time if Vaillant changes their backend.

---

## Status

* myVaillant login via Keycloak / PKCE is working
* Read access has been verified with a real installation
* Systems, status and statistics are received successfully
* Write commands are experimental and should be used carefully
* The old Okta-based login flow has been removed

---

## Requirements

* ioBroker installation
* myVaillant account
* Vaillant system connected to the cloud
* Supported location (e.g. germany)

---

## Configuration

Set the following values in the adapter configuration:

myv = true
user = your email
password = your password
location = germany
fetchReports = false (recommended for first setup)

---

## Supported Features

* Login via myVaillant (Keycloak / PKCE)
* Discover available systems
* Read system status
* Read statistics (if enabled)
* Create ioBroker states from API data

---

## Write Commands / Experimental

⚠️ Write commands may change heating behavior.
Use them carefully. Read functionality has been verified; write functionality may require additional testing.

### Example: Set room temperature

Sets a temporary override temperature for a heating zone.

{
"quickVeto": {
"setpoint": 22,
"duration": 3600
}
}

### Example: Activate away mode

Switches system into away mode.

{
"awayMode": {
"active": true
}
}

### Example: Custom command

Advanced users can send custom API payloads.

{
"customCommand": {
"method": "PATCH",
"url": "/systems/12345/zones/67890",
"data": {
"desiredRoomTemperatureSetpoint": 21
}
}
}

---

## Limitations and Warnings

* This adapter uses an unofficial Vaillant cloud API
* The API may change at any time without notice
* The adapter depends on Vaillant cloud availability
* Write commands can affect heating configuration
* Not all systems or regions may behave identically
* Do not share logs containing credentials, tokens or authorization headers

---

## Breaking Changes

### 0.8.0

* Okta-based login has been removed
* Only myVaillant (Keycloak / PKCE) is supported
* Legacy cloud behavior may no longer work

---

## Notes

* multiMATIC / sensoAPP legacy support is not actively maintained
* Focus is on myVaillant cloud integration
* Contributions and testing feedback are welcome
