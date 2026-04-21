# Watts Home cloud API — protocol specification

Reference for third-party clients of the Watts Home cloud platform (iOS/Android "Watts Home" app, which controls Tekmar 5xx thermostats, SunTouch controllers, and related Watts/Tekmar products).

This document describes the API as observed from the official mobile app. Not a vendor-published spec; behavior may change without notice.

**Status**: describes the API as of 2026-04. Known model coverage: Tekmar 563 (`modelId: 8`). Other Tekmar 5xx and SunTouch units are expected to share the schema but individual fields (e.g., `Mode.Enum`, availability of `Hum`/`Dehum` capability) will vary.

---

## 1. Overview

| | |
|---|---|
| API host | `https://home.watts.com/api` |
| Auth host | `https://login.watts.io` |
| Auth scheme | OAuth 2.0 authorization-code with PKCE (Azure AD B2C) |
| Transport | HTTPS/JSON |
| Poll cadence | ~15–30 s while app foregrounded; no server-suggested interval |

Every authenticated request carries:

```
Authorization: Bearer <access_token>
Api-Version: 2.0
```

### Response envelope

Every response body is a JSON object:

```json
{ "errorNumber": 0, "errorMessage": null, "body": <T> }
```

- `errorNumber == 0` on success. Non-zero values convey app-level errors (distinct from HTTP status).
- `body` is the actual payload (type varies per endpoint).
- On error the HTTP status is typically `400`/`401`/`404`/`500`; clients should check HTTP status first, then inspect `errorNumber` for semantic details.

---

## 2. Authentication

Watts uses an Azure AD B2C tenant with a custom policy. The app performs the standard OAuth 2.0 authorization-code + PKCE flow, but because Azure B2C handles sign-in via a hosted web page, the mobile client scripts the page interactions and scrapes the CSRF cookies.

### Constants

| Field | Value |
|---|---|
| Tenant | `wattsb2cap02.onmicrosoft.com` |
| Policy | `B2C_1A_Residential_UnifiedSignUpOrSignIn` |
| Client ID | `4b3a6465-94dd-47c2-976c-18bc29c53c2f` |
| Redirect URI | `msal4b3a6465-94dd-47c2-976c-18bc29c53c2f://auth` |
| Scope | `https://wattsb2cap02.onmicrosoft.com/wattsapiresi/manage offline_access openid profile` |

### Full login flow

1. **Generate PKCE**: random 128-char URL-safe verifier; `code_challenge = BASE64URL(SHA256(verifier))`.
2. **GET authorize endpoint** with query params:
   ```
   https://login.watts.io/tfp/wattsb2cap02.onmicrosoft.com/B2C_1A_Residential_UnifiedSignUpOrSignIn/oauth2/v2.0/authorize
     ?scope=<scope>
     &response_type=code
     &client_id=<client_id>
     &redirect_uri=<redirect_uri>
     &prompt=login
     &code_challenge=<challenge>
     &code_challenge_method=S256
     &client_info=1
     &haschrome=1
   ```
   The response sets two cookies:
   - `x-ms-cpim-csrf` (opaque CSRF token)
   - `x-ms-cpim-trans` (base64-encoded JSON; decode and extract `C_ID` to get the transaction ID)
3. **POST self-asserted credential form**:
   ```
   https://login.watts.io/wattsb2cap02.onmicrosoft.com/B2C_1A_Residential_UnifiedSignUpOrSignIn/SelfAsserted
     ?tx=StateProperties=<base64url(JSON: {"TID": <transaction_id>})>
     &p=B2C_1A_Residential_UnifiedSignUpOrSignIn
   ```
   - Body (`application/x-www-form-urlencoded`): `request_type=RESPONSE&signInName=<email>&password=<password>`
   - Required header: `X-CSRF-TOKEN: <csrf_from_cookie>`
   - Expect HTTP 200.
4. **GET confirmed endpoint** (no redirect following):
   ```
   https://login.watts.io/wattsb2cap02.onmicrosoft.com/B2C_1A_Residential_UnifiedSignUpOrSignIn/api/CombinedSigninAndSignup/confirmed
     ?rememberMe=true
     &csrf_token=<csrf>
     &tx=StateProperties=<state_properties>
   ```
   - Expect HTTP 302.
   - Extract `code` from the `Location` header's query string.
5. **POST token endpoint** to exchange the code:
   ```
   POST https://login.watts.io/tfp/wattsb2cap02.onmicrosoft.com/B2C_1A_Residential_UnifiedSignUpOrSignIn/oauth2/v2.0/token?haschrome=1
   Content-Type: application/x-www-form-urlencoded
   
   client_id=<client_id>
   &scope=<scope>
   &client_info=1
   &grant_type=authorization_code
   &code=<code>
   &redirect_uri=<redirect_uri>
   &code_verifier=<verifier>
   ```
   Returns:
   ```json
   {
     "access_token": "<jwt>",
     "id_token": "<jwt>",
     "refresh_token": "<opaque>",
     "token_type": "Bearer",
     "expires_in": 3600,
     "expires_on": 1713700000,
     "refresh_token_expires_in": 1209600,
     "scope": "...",
     "resource": "<client_id>"
   }
   ```

### Refresh

Same token endpoint, different grant:

```
POST .../oauth2/v2.0/token?haschrome=1
client_id=<client_id>
&scope=<scope>
&client_info=1
&grant_type=refresh_token
&refresh_token=<refresh_token>
```

Returns a new `ExchangedAuthTokenResponse`. On `400`/`401`/non-2xx, fall back to the full login flow.

**Recommendation**: refresh ≥ 2 minutes before `expires_on`.

---

## 3. Endpoint reference

All paths are relative to `https://home.watts.com/api`. All require `Authorization: Bearer <access_token>` and `Api-Version: 2.0`.

### `GET /User/Details`

User profile, notification preferences, default location.

```json
{
  "errorNumber": 0,
  "errorMessage": null,
  "body": {
    "userId": "<uuid>",
    "emailAddress": "...",
    "firstName": "...",
    "lastName": "...",
    "defaultLocationId": "<uuid>",
    "languagePreference": "en",
    "userTypeId": 1,
    "measurementScale": "Imperial",
    "mobilePhoneNumber": "+1...",
    "smsNotificationEnabled": true,
    "emailNotificationEnabled": true,
    "pushNotificationEnabled": true,
    "voiceControlPlatform": "",
    "defaultLocationDevices": []
  }
}
```

### `GET /User/Preferences`

App preferences (theme, units, notification preferences, etc.). Shape not critical for control use cases; safe to ignore.

### `PATCH /User`

Updates user profile fields. Not exercised for HVAC control.

### `GET /Location`

Returns an array of locations the user has access to (owned + shared).

```json
{
  "body": [
    {
      "locationId": "<uuid>",
      "name": "Home",
      "address": {
        "address": "...", "address2": "", "city": "...",
        "state_province": "...", "zipcode": "...", "country": "US"
      },
      "ownerId": "<uuid>",
      "userType": 1,
      "usersCount": 2,
      "devicesCount": 13,
      "isDefault": true,
      "isShared": false,
      "awayState": 0,
      "supportsAway": true,
      "hasDeviceInDemandResponseEvent": false
    }
  ]
}
```

### `GET /Location/{locationId}/Devices`

**Primary polling endpoint.** Returns an array of all devices at the location, each with a full runtime snapshot. See §4 for the device payload shape.

### `GET /Location/{locationId}/SharedUsers`

Users the location is shared with. Not exercised for control.

### `PATCH /Location/{locationId}/State`

Toggle location-wide away mode.

```json
{"awayState": 0}
```

- `0` — home
- `1` — away

Response body may be empty on success.

### `GET /Device/{deviceId}`

Single-device detail. Same shape as one element of the `/Devices` array.

### `GET /Device/{deviceId}/Refresh`

Requests a fresh status pull from the thermostat (server commands the device to re-check in). Useful after a write to get current state faster than waiting for the next poll tick. Returns the device payload.

### `PATCH /Device/{deviceId}`

Mutates one or more device settings. Body shape is `{"Settings": { ... }}` with any subset of writable fields. See §7 for verified payloads.

Response body may be empty on success.

### `PUT /pushregistration` / `DELETE /pushregistration/{token}`

APNS/FCM push notification registration. Not relevant to polling clients.

---

## 4. Device payload schema

One element of `GET /Location/{id}/Devices`:

```json
{
  "deviceId": "<uuid>",
  "name": "Entry",
  "modelId": 8,
  "modelNumber": "563",
  "deviceType": "Thermostat",
  "deviceTypeId": 2,
  "imageUrl": null,
  "isConnected": true,
  "isShared": false,
  "requestingUser": "<uuid>",
  "location": {
    "locationId": "<uuid>",
    "name": "Home",
    "address": { ... },
    "awayState": 0,
    "userType": 1
  },
  "data": { ... }        // see §4.1; absent or partial when isConnected=false
}
```

### 4.1 `data` — runtime + capability state

```json
{
  "DateTime": "2026-04-20T03:43:46Z",
  "TZOffset": -14400,

  "Sensors": {
    "Room":    { "Val": 64, "Status": "Okay" },
    "Floor":   { "Val": 66, "Status": "Okay" },
    "Outdoor": { "Val": 41, "Status": "Okay" },
    "RH":      { "Val": 29, "Status": "Okay" }
  },

  "State": {
    "Op":  "Off",
    "Sub": "None"
  },

  "Mode": {
    "Active": 1,
    "Val":    "Auto",
    "Enum":   ["Off", "Heat", "Cool", "Auto"]
  },

  "Target": {
    "Active": 1,
    "Sensor": "Room",
    "Hold":   0,
    "Heat":   64,
    "Cool":   88,
    "Min":    40,
    "Max":    100,
    "Steps":  1
  },

  "Hum":   { "Active": 0, "Val": 40, "Min": 10, "Max": 80, "Steps": 1 },
  "Dehum": { "Active": 0, "Val": 60, "Min": 20, "Max": 90, "Steps": 1 },

  "TempInterlock": 2.0,
  "HumInterlock":  1,

  "Fan": {
    "Active": 1,
    "Val":    "Auto",
    "Enum":   ["Auto", "On"],
    "Relay":  0
  },

  "TempUnits": {
    "Active": 1,
    "Val":    "F",
    "Enum":   ["F", "C"]
  },
  "Units": "Imperial",

  "SchedEnable": {
    "Active": 1,
    "Val":    "Off",
    "Enum":   ["Off", "On"]
  },

  "Schedule": {
    "SchedActive": 0,
    "HeatActive":  1,
    "CoolActive":  1,
    "FloorActive": 1,
    "Grp":    null,
    "Event":  null,
    "Grp1":   { "Days": "MTWRF", "W": {...}, "L": {...}, "R": {...}, "S": {...} },
    "Grp2":   { ... },
    "Grp3":   { ... },
    "Grp4":   {},
    "Grp5":   {},
    "Grp6":   {},
    "Grp7":   {},
    "Floor":  { "W": 72, "A": 0 },
    "HeatMin": 40, "HeatMax": 95,
    "CoolMin": 45, "CoolMax": 100,
    "FloorMin": 40, "FloorMax": 80,
    "TempSteps": 1, "TimeSteps": 10
  },

  "Energy": {
    "Heat": { "Daily": [24, 24, 24, 24, 24, 24, 17.3], "Monthly": [...] },
    "Cool": { "Daily": [0, 0, 0, 0, 0, 0, 0],          "Monthly": [...] }
  },

  "OpenADR": {
    "Active": 0,
    "Val":    "...",
    "Enum":   [...]
  }
}
```

### 4.2 Schedule groups

`Schedule.Grp1` … `Grp7` define up to seven day-groupings of thermostat schedules. Each populated group has:

```json
{
  "Days": "MTWRF",       // subset of "MTWRFAS" — M=Mon ... F=Fri, A=Sat, S=Sun
  "W": { "T": "06:00", "H": 70, "C": 78 },   // Wake
  "L": { "T": "08:00", "H": 65, "C": 85 },   // Leave
  "R": { "T": "17:00", "H": 70, "C": 78 },   // Return
  "S": { "T": "22:00", "H": 65, "C": 85 }    // Sleep
}
```

- `T` — event start time (24h, "HH:MM")
- `H` — heat setpoint during this period (°F or °C per `TempUnits.Val`)
- `C` — cool setpoint during this period

Unused slots are `{}` (empty objects), not absent.

`Schedule.Grp` (integer) and `Schedule.Event` (string) indicate the currently active group and event name when a schedule is running. Both are `null` when `SchedActive == 0`.

### 4.3 Capability vs runtime fields

**This is the most important distinction in the API.**

| Category | Fields | Notes |
|---|---|---|
| **Runtime** (changes in operation) | `State.Op`, `State.Sub`, `Fan.Relay`, `isConnected`, `Sensors.*.Val`, `Target.Heat`/`Cool`/`Hold`, `Hum.Val`, `Dehum.Val`, `Mode.Val`, `Fan.Val`, `DateTime`, `Energy.*`, `Schedule.SchedActive`, `Schedule.Grp`, `Schedule.Event`, `location.awayState` | Use for "what's happening right now". |
| **Capability** (static per install) | `Mode.Active`, `Fan.Active`, `Hum.Active`, `Dehum.Active`, `Target.Active`, `TempUnits.Active`, `SchedEnable.Active`, `OpenADR.Active`, `Schedule.HeatActive`, `Schedule.CoolActive`, `Schedule.FloorActive`, all `*.Enum` arrays, all `*.Min`/`Max`/`Steps`, `Sensors.*.Status`, `modelNumber`, `modelId`, `deviceType`, `isShared` | Gate entity creation and input bounds on these. Do not confuse `*.Active == 1` with "currently running". |

**Example**: `Hum.Active == 1` means "a humidifier accessory is installed on this thermostat," not "the humidifier is running now." There is no dedicated humidifier-running flag (see §5.3).

### 4.4 `isConnected == false`

When the thermostat loses its WAN link, the cloud reports:

```json
{
  "deviceId": "...",
  "name": "...",
  "isConnected": false,
  "data": {}             // empty or missing
}
```

Clients should:
- Mark the device unavailable in any UI.
- **Retain the last known `data`** — presenting stale values with an "offline" badge is more useful than blanking the card.
- Resume normal state publication when `isConnected` flips back to `true`.

---

## 5. Runtime detection semantics

### 5.1 `State.Op`

Observed values: `"Off"`, `"Heat"`, `"Cool"`.

Probable additional values on heat-pump-capable devices with `Mode.Enum` containing `"Emer"`: `"EmerHeat"` or similar. Not yet verified.

`State.Op` is the **room-level** heat/cool call signal — it tracks `Target.Heat` / `Target.Cool` against `Sensors.Room.Val`. It is NOT a system-wide call indicator:

- **`State.Op = "Heat"`** when the room temperature is below `Target.Heat` and the thermostat is calling for heat (whether that ends up being radiant, forced-air, or both is not distinguishable here).
- **`State.Op` does NOT flip to `"Heat"` for floor-only calls.** When `Sensors.Floor.Val < Schedule.Floor.W` (the floor minimum is being maintained) but the room is already at temperature, the Tekmar 5xx still opens the radiant-floor zone valve to bring the floor up — but the cloud API reports `State.Op = "Off"`. The official Watts Home app has the same blind spot. Confirmed live on the 563.

The implication: **floor-only heat calls are not directly observable via the polling endpoint.** See §5.3 for the setpoint-vs-current heuristic that approximates them.

### 5.2 `State.Sub`

Observed values:

| Value | Meaning |
|---|---|
| `"None"` (string, not JSON null) | No special sub-state. |
| `"CWSD"` | **Cold Weather Shut Down** — heat-pump cooling locked out because outdoor temperature is below the compressor's safe operating range. The thermostat will not respond to cool calls while this is active. |

Suspected but unverified values: `HSSD` (hot-weather shutdown), `EMER` (emergency heat active), `BOOST`.

### 5.3 Runtime detection recipes

What the API lets you determine, with confidence levels:

| Question | Signal | Confidence |
|---|---|---|
| Thermostat online? | `isConnected == true` | **direct** |
| Fan motor spinning? | `Fan.Relay == 1` | **direct** (the only runtime relay the API exposes) |
| Room-level heat/cool call active? | `State.Op in {"Heat", "Cool"}` | **direct** (only the room-level call — see §5.1) |
| Air handler engaged for heat/cool? | `State.Op in {"Heat", "Cool"} AND Fan.Relay == 1` | **derived, high confidence** |
| Radiant-only call when ROOM is calling for heat (rooms with both radiant + air)? | `State.Op == "Heat" AND Fan.Relay == 0` | **derived, high confidence** when applicable, but does NOT cover floor-only calls |
| **Floor-only heat call** (room is at setpoint but floor is below `Schedule.Floor.W`)? | `Sensors.Floor.Val < Schedule.Floor.W AND Schedule.Floor.W > 0` | **inferred from setpoints, not the API.** Subject to false-positives during the local thermostat's hysteresis deadband (no relay confirmation available). The only signal you'll get for floor-only calls. |
| Humidifier likely running (rooms with `Hum.Active == 1`)? | `Fan.Relay == 1 AND State.Op == "Off"` | **derived, medium confidence** — whole-home humidifiers drive the fan to distribute moisture; if there's no heat/cool call, humidification is the most plausible reason for the fan |
| Cold-weather cooling lockout? | `State.Sub == "CWSD"` | **direct** |
| Schedule currently driving setpoints? | `Schedule.SchedActive == 1` (distinct from `SchedEnable.Val == "On"` which is the user's enable-schedule toggle) | **direct** |

### 5.4 Not observable

The API does **not** expose:

- **Individual relay states**: W1, W2, Y1, Y2, O/B, G, zone-valve outputs — only `Fan.Relay` is surfaced. The thermostat knows what it's firing internally; the cloud doesn't show it.
- **Floor-only heat calls** as a discrete signal. `State.Op` only tracks room-level calls (`Target.Heat` vs `Sensors.Room.Val`). When the radiant zone-valve opens to maintain `Schedule.Floor.W` while the room is at temperature, `State.Op` stays `"Off"`. The setpoint-vs-current heuristic in §5.3 is the only available proxy.
- **Distinguishing "radiant only" from "radiant + air" when the fan is running.** If `State.Op == "Heat"` AND `Fan.Relay == 1`, you know the air handler is engaged but cannot tell if radiant is also running concurrently.
- **A dedicated humidifier-running flag.** Inferred via the fan-relay heuristic (best available proxy; same as the official Watts Home app).
- **Dehumidifier-running flag.**
- **Compressor stage currently engaged** (low/high stage on multi-stage heat pumps).
- **Aux/emergency heat strip engagement** when the device is in `Mode.Val == "Emer"` — the API reports the *mode* but not whether the aux strip is firing right now.
- **HVAC-action distinction within `State.Op`** — no values like `"Heating-Stage1"` / `"Heating-Aux"` / `"Cooling-Stage2"`. Just `Heat`/`Cool`/`Off`.

If you need any of the above, the Watts Home cloud is not the data source — the Tekmar 482 gateway's local RS-232/tN4 port, an RS-485 tap, or direct wire sniffing on the thermostat's relay outputs is required.

---

## 6. Sensor status

`Sensors.*.Status` takes two observed values:

| Value | Meaning |
|---|---|
| `"Okay"` | Sensor is installed and reporting valid data. Use `Val`. |
| `"Absent"` | Sensor is not physically connected. `Val` is a placeholder (usually `0`); do not treat as a real reading. |

In practice:

- `Sensors.Room` is always `"Okay"` on functioning thermostats.
- `Sensors.Outdoor.Status == "Okay"` if the thermostat has access to outdoor temperature (typically yes — shared with the Tekmar 482 gateway).
- `Sensors.Floor.Status == "Okay"` only on thermostats wired to a radiant floor temperature sensor.
- `Sensors.RH.Status == "Okay"` on thermostats with humidity sensing (most Tekmar 5xx, including 563).

---

## 7. Write operations

All writes target `PATCH /Device/{deviceId}` with a body of the form `{"Settings": { ... }}`, except the location-wide away toggle.

### 7.1 Temperature setpoints

```json
{"Settings": {"Heat": 73.0, "Cool": 83.0}}
```

**Always send both `Heat` and `Cool`**, even when the user adjusts only one. Echo the current value of the field you aren't changing.

This isn't a politeness convention — it's required to avoid silent data loss. Live testing on the 5xx confirmed:

- Send `{"Settings": {"Heat": 66}}` while in single-direction `Heat` mode → server accepts (HTTP 200), `Heat` becomes 66, **`Cool` is silently reset to `Schedule.CoolMax`** (e.g., 95°F). The user's previously-tuned cool setpoint is lost.
- Send `{"Settings": {"Cool": 82}}` in `Cool` mode → mirror behavior: `Cool` updates, **`Heat` is silently reset to `Schedule.HeatMin`** (e.g., 40°F).
- Send `{"Settings": {"Heat": 66, "Cool": 83}}` in any mode → both stick.

The official mobile app always sends both fields, presumably for the same reason. The user-visible symptom of single-field writes is "I switched modes after adjusting heat all winter, and my A/C target was 95°F come spring."

`Heat` and `Cool` are in the units given by `TempUnits.Val` (`"F"` or `"C"`). Values must be within `Target.Min` .. `Target.Max` with steps of `Target.Steps`.

### 7.2 Schedule hold overrides (unverified for 5xx)

When a schedule is active (`SchedEnable.Val == "On"` AND `Schedule.SchedActive == 1`), temporary overrides may need `HeatHold`/`CoolHold` instead of `Heat`/`Cool`. This distinction is made by prior art (creamy-waha) and Tekmar doctrine but is **unverified against the 5xx API**. Treat as a candidate to test explicitly before relying on it.

### 7.3 Humidity setpoint

```json
{"Settings": {"Hum": 46.0}}
```

Scalar value (not a nested object). Must fall within `Hum.Min` .. `Hum.Max`. Only meaningful when `Hum.Active == 1`.

**There is no humidifier on/off command.** The Watts humidifier has no separate enable flag — the accessory runs whenever current RH is below `Hum.Val`. To "disable" it, set `Hum` to its minimum (effectively below the room's reachable RH). Consumers building HA humidifier entities should not expect a meaningful response to `command_topic` ON/OFF; the only real control is the target.

### 7.4 Dehumidity setpoint (unverified)

By analogy with `Hum`:

```json
{"Settings": {"Dehum": 60.0}}
```

Unverified against the 5xx API. Only meaningful when `Dehum.Active == 1`.

### 7.5 Radiant floor schedule limits

```json
{"Settings": {"Schedule": {"Floor": {"W": 72.0, "A": 0.0}}}}
```

- `W` — occupied floor minimum (the setpoint the thermostat will heat the floor up to when the room is occupied). User-writable.
- `A` — away floor minimum (typically `0` to disable floor heat while away). User-writable.

When changing only one, echo the other's current value (same pattern as `Heat`/`Cool`).

**`Schedule.FloorMin` and `Schedule.FloorMax` are NOT writable.** They are read-only hardware-safety bounds set at install time (e.g., `FloorMax = 80°F` on hardwood for warp protection). Live testing exhausted three candidate payloads — `{"Schedule": {"FloorMax": X}}`, `{"Schedule": {"Floor": {"Max": X}}}`, `{"Schedule": {"FloorMax": X, "FloorMin": Y}}` — all returned HTTP 200 but `FloorMax` did not change. If you need to adjust these, do it at the thermostat or via the Tekmar 482 gateway's local interface; the cloud API doesn't expose a way.

Note: do not confuse `Schedule.Floor.W` (the user-facing **setpoint**) with `Schedule.FloorMin` (the **hardware lower-bound limit**). They're different fields with different roles.

### 7.6 Mode

```json
{"Settings": {"Mode": "Auto"}}
```

`Mode` value must be from `Mode.Enum`. Observed values: `"Off"`, `"Heat"`, `"Cool"`, `"Auto"`, `"Emer"` (heat-pump only).

### 7.7 Fan

```json
{"Settings": {"Fan": "On"}}
```

`Fan` value must be from `Fan.Enum`. Typical values: `"Auto"`, `"On"`. Some devices may expose `"Schedule"`.

### 7.8 Away toggle

```
PATCH /Location/{locationId}/State
{"awayState": 1}
```

Location-wide — affects all devices at that location simultaneously.

---

## 8. Schema quirks

Known quirks a well-behaved client must handle:

1. **Empty schedule groups**: `Schedule.Grp4` … `Grp7` may arrive as `{}` (empty objects) rather than full `ScheduleGroup` structs. Typed consumers must tolerate this — use pointer-to-struct or an `omitempty` decoder tolerant of empty objects.

2. **`Hum`/`Dehum` always present**: these blocks exist even on devices without the accessory, with default values (`Hum`: `Val=40, Min=10, Max=80, Steps=1`; `Dehum`: `Val=60, Min=20, Max=90, Steps=1`). Gate entity creation on `.Active == 1`, never on block presence.

3. **`Sensors.Floor.Status == "Absent"` with `Val == 0`**: don't display `0 °F` as a temperature. Skip the sensor entirely or mark unavailable.

4. **`Mode.Enum` varies per device**: heat-pump-capable rooms may include `"Emer"`, others do not. Always drive UI from the `Enum` list; never hardcode the mode set.

5. **`State.Sub == "None"` is a string**, not JSON null. Guard string comparisons accordingly.

6. **`Target.Min`/`Max` are the thermostat's absolute bounds**, not the current user-configured schedule bounds. For schedule bounds use `Schedule.HeatMin`/`Max` and `CoolMin`/`Max`.

7. **`Schedule.Floor.{W,A}` vs `Schedule.FloorMin`/`FloorMax`**: two different things.
   - `Schedule.Floor.W`/`A` — the user-adjustable **current** floor minimum (occupied / away). Written via §7.5.
   - `Schedule.FloorMin`/`FloorMax` — the thermostat's absolute floor temperature bounds (hardware/hardwood-safety limits). Typically read-only from the API.

8. **Disconnected devices have missing `data` blocks**: see §4.4.

9. **Schedule is disabled by default**: `SchedEnable.Val == "Off"` means no schedule is running; all setpoints are manual holds. Toggling `SchedEnable.Val` to `"On"` would activate whatever is in `Grp1`..`Grp7` (untested write path).

10. **`TempInterlock` (float) and `HumInterlock` (int)** are top-level under `data`. Semantics undocumented but present on every device. Values observed: `TempInterlock: 2.0`, `HumInterlock: 1`. Likely relates to cross-system coordination (e.g., don't run A/C and humidifier simultaneously).

---

## 9. Polling cadence

- The mobile app polls `GET /Location/{id}/Devices` at a nominal **~40s interval** when the app is foregrounded. Measured across a 13-minute capture with 19 automated polls (manual pull-to-refresh excluded): median 39.9 s, mean 39.1 s, min 21 s, max 70 s. Some jitter is expected.
- Background polling cadence (app minimized) is slower; not precisely characterized.
- The server does not expose a suggested interval in headers (unlike some IoT vendors).
- **Recommended cadence for a background bridge**: 40 s default. Do not go below 30 s without a reason — the official app doesn't, and shorter intervals risk drawing unwanted attention from the backend.
- After a successful `PATCH /Device/{id}`, call `GET /Device/{id}/Refresh` and re-poll the affected device immediately. Confirmed effective: a `/Refresh` call typically updates `data.DateTime` within 3 s, whereas waiting for the next natural poll would take up to 40 s.

---

## 10. Model table

Observed in practice:

| `modelId` | `modelNumber` | Device | Notes |
|---:|---|---|---|
| 8 | `"563"` | Tekmar 563 thermostat | Heat-pump capable (4H/2C), radiant floor optional, humidifier accessory optional. `Mode.Enum` includes `"Emer"` when a heat-pump configuration is present. |

Other Tekmar 5xx (`561`, `562`, `564`, `564B`, `564FS`) and SunTouch controllers are expected to share the schema; fields like `Mode.Enum` and `*.Active` will vary by hardware.

---

## 11. Error handling

HTTP status hints:

- **`200 OK`** — success (may have empty body on writes).
- **`400`** — malformed payload (validate shape against §7).
- **`401`** — expired or invalid bearer token — refresh and retry.
- **`404`** — device/location not found or not accessible to the user.
- **`5xx`** — transient server issue; retry with exponential backoff.

Even on `200`, inspect `errorNumber` in the response body for app-level errors. `errorNumber != 0` indicates semantic failure (device offline, setpoint out of bounds, etc.); `errorMessage` carries a human-readable description.

---

## 12. Security considerations for clients

- Store credentials at rest with OS-native secure storage (Keychain, keyring, HA `ConfigEntry.data`).
- Never persist the `access_token` longer than its lifetime; do persist the `refresh_token` (treated as secret).
- Use PKCE verifier per-login, not a hardcoded constant (prior art that hardcodes the verifier works but defeats PKCE's purpose).
- Respect the polling recommendations in §9 — hammering the API would be impolite and is a good way to trigger rate limits or access restrictions.
