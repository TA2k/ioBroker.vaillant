"use strict";

/*
 * Created with @iobroker/create-adapter v1.20.0
 */

// The adapter-core module gives you access to the core ioBroker functions
// you need to create an adapter
const utils = require("@iobroker/adapter-core");
const request = require("request");
const traverse = require("traverse");
const Json2iob = require("json2iob");
const axios = require("axios").default;
const tough = require("tough-cookie");
const crypto = require("crypto");
const qs = require("qs");
const { HttpsCookieAgent } = require("http-cookie-agent/http");

class Vaillant extends utils.Adapter {
  /**
   * @param {Partial<ioBroker.AdapterOptions>} [options={}]
   */
  constructor(options) {
    super({
      ...options,
      name: "vaillant",
    });
    this.on("ready", this.onReady.bind(this));
    this.on("stateChange", this.onStateChange.bind(this));
    this.on("unload", this.onUnload.bind(this));
    this.session = {};
    this.myVaillantApiBase = "https://api.vaillant-group.com/service-connected-control";
    this.myVaillantEndUserBase = `${this.myVaillantApiBase}/end-user-app-api/v1`;
    this.myVaillantVrc700Base = `${this.myVaillantApiBase}/vrc700/v1`;
    this.deviceArray = [];
    this.disabledRooms = [];
    this.json2iob = new Json2iob(this);
    this.httpTimeoutMs = 30000;
    this.cookieJar = new tough.CookieJar();
    this.requestClient = axios.create({
      withCredentials: true,
      timeout: this.httpTimeoutMs,
      httpsAgent: new HttpsCookieAgent({
        cookies: {
          jar: this.cookieJar,
        },
      }),
      headers: {
        "x-app-identifier": "VAILLANT",
        "Accept-Language": "de-de",
        Accept: "application/json, text/plain, */*",
        "x-client-locale": "de-DE",
        "x-idm-identifier": "KEYCLOAK",
        "ocp-apim-subscription-key": "1e0a2f3511fb4c5bbb1c7f9fedd20b1c",
        "User-Agent": "myVAILLANT/20034 CFNetwork/1240.0.4 Darwin/20.6.0",
      },
    });
    this.jar = request.jar();
    this.updateInterval = null;
    this.reauthInterval = null;
    this.reloginTimeout = null;
    this.isRelogin = false;
    this.baseHeader = {
      "Vaillant-Mobile-App": "multiMATIC v2.1.45 b389 (Android)",
      "User-Agent": "okhttp/3.10.0",
      "Content-Type": "application/json; charset=UTF-8",
      "Accept-Encoding": "gzip",
    };
    this.myvHeader = {
      accept: "application/json",
      "content-type": "application/json",
      "user-agent": "myVAILLANT/11835 CFNetwork/1240.0.4 Darwin/20.6.0",
      "x-okta-user-agent-extended": "okta-auth-js/5.4.1 okta-react-native/2.7.0 react-native/>=0.70.1 ios/14.8 nodejs/undefined",
      "accept-language": "de-de",
    };
    this.atoken = "";
    this.serialNr = "";
    this.adapterStopped = false;
    this.isSpineActive = true;
    this.reports = {};
    this.etags = {};
  }

  /**
   * Is called when databases are connected and adapter received configuration.
   */
  async onReady() {
    // Initialize your adapter here
    const obj = await this.getForeignObjectAsync("system.config");
    if (obj && obj.native && obj.native.secret) {
      this.config.password = this.decrypt(obj.native.secret, this.config.password);
    } else {
      this.config.password = this.decrypt("Zgfr56gFe87jJOM", this.config.password);
    }
    if (this.config.interval < 5) {
      this.log.warn("Interval under 5min is not recommended. Set it back to 5min");
      this.config.interval = 5;
    }
    if (this.config && !this.config.smartPhoneId) {
      this.log.info("Generate new Id");
      this.config.smartPhoneId = this.makeid();
    }

    if (this.config.fetchReportsLimit > 60) {
      this.log.warn("Only 60 days of the last reports are supported. Set it back to 60 days");
      this.config.fetchReportsLimit = 60;
    }
    this.subscribeStates("*");
    // Reset the connection indicator during startup
    this.setState("info.connection", false, true);
    if (this.config.myv) {
      await this.myvLoginv2();
      if (this.session.access_token) {
        this.log.info("Getting myv devices");
        await this.getMyvDeviceList();
        this.log.info("Receiving first time status");
        await this.updateMyvDevices();
        await this.updateMyvRooms();
        this.log.info("Receiving first time stats");
        await this.clearOldStats();
        await this.updateMyStats();
        this.updateInterval = setInterval(
          async () => {
            // TODO: Add retry/backoff strategy for cloud polling when repeated API failures occur.
            await this.updateMyvDevices();
            await this.updateMyvRooms();
          },
          this.config.interval * 60 * 1000,
        );
        this.statInterval = setInterval(
          async () => {
            //run only between 00:00 and 00:11
            const now = new Date();
            if (now.getHours() === 0 && now.getMinutes() < 11) {
              await this.updateMyStats();
            }
          },
          10 * 60 * 1000,
        );
      }
      this.refreshTokenInterval = setInterval(
        () => {
          this.refreshToken();
        },
        ((this.session.expires_in || 3600) - 100) * 1000,
      );
    } else {
      this.login()
        .then(() => {
          this.setState("info.connection", true, true);
          this.getFacility()
            .then(() => {
              this.cleanConfigurations()
                .then(async () => {
                  this.log.info("Receiving first time status");
                  this.getMethod("https://smart.vaillant.com/mobile/api/v4/facilities/$serial/system/v1/status", "status").catch(() =>
                    this.log.debug("Failed to get status"),
                  );

                  await this.sleep(10000);

                  this.log.info("Receiving first time systemcontrol");
                  await this.getMethod(
                    "https://smart.vaillant.com/mobile/api/v4/facilities/$serial/systemcontrol/v1",
                    "systemcontrol",
                  ).catch(() => this.log.debug("Failed to get systemcontrol"));
                  await this.sleep(10000);

                  this.log.info("Receiving first time systemcontrol tli");
                  await this.getMethod(
                    "https://smart.vaillant.com/mobile/api/v4/facilities/$serial/systemcontrol/tli/v1",
                    "systemcontrol/tli",
                  ).catch(() => this.log.debug("Failed to get tli systemcontrol"));
                  await this.sleep(10000);

                  this.log.info("Receiving first time livereport");
                  await this.getMethod("https://smart.vaillant.com/mobile/api/v4/facilities/$serial/livereport/v1", "livereport").catch(
                    () => this.log.debug("Failed to get livereport"),
                  );

                  await this.sleep(10000);

                  this.log.info("Receiving first time PVMetering");
                  await this.getMethod(
                    "https://smart.vaillant.com/mobile/api/v4/facilities/$serial/spine/v1/currentPVMeteringInfo",
                    "spine",
                  ).catch(() => this.log.debug("Failed to get spine"));

                  await this.sleep(10000);

                  this.log.info("Receiving first time emf devices");
                  await this.getMethod("https://smart.vaillant.com/mobile/api/v4/facilities/$serial/emf/v1/devices/", "emf").catch(() =>
                    this.log.debug("Failed to get emf"),
                  );
                  this.log.debug(this.stringifyForLog(this.reports));

                  await this.sleep(10000);

                  this.log.info("Receiving first time hvac state");
                  await this.getMethod(
                    "https://smart.vaillant.com/mobile/api/v4/facilities/$serial/hvacstate/v1/overview",
                    "hvacstate",
                  ).catch(() => this.log.debug("Failed to get hvacstate"));

                  await this.sleep(10000);

                  this.log.info("Receiving first time rooms");
                  await this.getMethod("https://smart.vaillant.com/mobile/api/v4/facilities/$serial/rbr/v1/rooms", "rooms")
                    .catch(() => this.log.debug("Failed to get rooms"))
                    .finally(() => {});
                  await this.sleep(10000);
                  if (this.config.fetchReports) {
                    this.log.info("Receiving first time reports");
                    // await this.receiveReports();
                  }
                })
                .catch(() => {
                  this.log.error("clean configuration failed");
                });

              this.updateInterval = setInterval(
                () => {
                  this.updateValues();
                },
                this.config.interval * 60 * 1000,
              );
              this.log.debug("Set update interval to: " + this.config.interval + "min");
            })
            .catch(() => {
              this.log.error("facility failed");
            });
        })
        .catch(() => {
          this.log.error("Login failed");
        });
    }
    // in this template all states changes inside the adapters namespace are subscribed
  }
  buildMyVaillantRealm(location, brand = "vaillant") {
    const normalizedBrand = String(brand || "")
      .trim()
      .toLowerCase();
    const normalizedLocation = String(location || "")
      .trim()
      .toLowerCase();
    const allowedBrands = new Set(["vaillant"]);
    const allowedLocations = new Set(["germany", "denmark", "switzerland", "austria", "belgium"]);
    if (!allowedBrands.has(normalizedBrand)) {
      throw new Error(`Unsupported myVAILLANT brand: ${brand}`);
    }
    if (!allowedLocations.has(normalizedLocation)) {
      throw new Error(
        `Invalid myVAILLANT location "${location}". Supported values: germany, denmark, switzerland, austria, belgium`,
      );
    }
    return `${normalizedBrand}-${normalizedLocation}-b2c`;
  }
  getMyVaillantRealm() {
    return this.buildMyVaillantRealm(this.config.location, "vaillant");
  }
  buildMyVaillantHeaders(token, extraHeaders = {}) {
    const headers = {
      Accept: "application/json, text/plain, */*",
      "x-app-identifier": "VAILLANT",
      "Accept-Language": "de-de",
      "x-client-locale": "de-DE",
      "x-idm-identifier": "KEYCLOAK",
      "ocp-apim-subscription-key": "1e0a2f3511fb4c5bbb1c7f9fedd20b1c",
      "User-Agent": "myVAILLANT/21469 CFNetwork/1410.1 Darwin/22.6.0",
      ...extraHeaders,
    };
    if (token) {
      headers.Authorization = `Bearer ${token}`;
    }
    return headers;
  }
  getMyVaillantApiBase() {
    return this.myVaillantApiBase;
  }
  getMyVaillantEndUserBase() {
    return this.myVaillantEndUserBase;
  }
  getMyVaillantVrc700Base() {
    return this.myVaillantVrc700Base;
  }
  ensureMyVaillantSegment(value, name) {
    const normalizedValue = String(value || "").trim();
    if (!normalizedValue) {
      throw new Error(`Missing myVAILLANT ${name}`);
    }
    return encodeURIComponent(normalizedValue);
  }
  normalizeMyVaillantPath(path = "") {
    return String(path || "")
      .replace(/^\/+/, "")
      .replace(/\/+$/, "");
  }
  getHomesEndpoint() {
    return `${this.getMyVaillantEndUserBase()}/homes`;
  }
  getControlIdentifierEndpoint(systemId) {
    const encodedSystemId = this.ensureMyVaillantSegment(systemId, "systemId");
    return `${this.getMyVaillantEndUserBase()}/systems/${encodedSystemId}/meta-info/control-identifier`;
  }
  getSystemEndpoint(identifier, systemId) {
    const encodedIdentifier = this.ensureMyVaillantSegment(identifier, "identifier");
    const encodedSystemId = this.ensureMyVaillantSegment(systemId, "systemId");
    if (identifier === "tli") {
      return `${this.getMyVaillantEndUserBase()}/systems/${encodedSystemId}/${encodedIdentifier}`;
    }
    return `${this.getMyVaillantApiBase()}/${encodedIdentifier}/v1/systems/${encodedSystemId}`;
  }
  getRoomsEndpoint(facilityId) {
    const encodedFacilityId = this.ensureMyVaillantSegment(facilityId, "facilityId");
    return `${this.getMyVaillantEndUserBase()}/api/v1/ambisense/facilities/${encodedFacilityId}/rooms`;
  }
  getStatsEndpoint(systemId) {
    const encodedSystemId = this.ensureMyVaillantSegment(systemId, "systemId");
    return `${this.getMyVaillantEndUserBase()}/emf/v2/${encodedSystemId}/currentSystem`;
  }
  getStatsBucketsEndpoint(systemId, deviceUuid, query) {
    const encodedSystemId = this.ensureMyVaillantSegment(systemId, "systemId");
    const encodedDeviceUuid = this.ensureMyVaillantSegment(deviceUuid, "deviceUuid");
    const search = new URLSearchParams({
      resolution: String(query.resolution),
      operationMode: String(query.operationMode),
      energyType: String(query.energyType),
      startDate: String(query.startDate),
      endDate: String(query.endDate),
    }).toString();
    return `${this.getMyVaillantEndUserBase()}/emf/v2/${encodedSystemId}/devices/${encodedDeviceUuid}/buckets?${search}`;
  }
  buildSystemCommandEndpoint(identifier, systemId, path, useTliPrefix = true) {
    const encodedSystemId = this.ensureMyVaillantSegment(systemId, "systemId");
    const normalizedPath = this.normalizeMyVaillantPath(path);
    if (!normalizedPath) {
      throw new Error("Missing myVAILLANT command path");
    }
    if (identifier === "tli") {
      const tliPrefix = useTliPrefix ? "/tli" : "";
      return `${this.getMyVaillantEndUserBase()}/systems/${encodedSystemId}${tliPrefix}/${normalizedPath}`;
    }
    const encodedIdentifier = this.ensureMyVaillantSegment(identifier, "identifier");
    return `${this.getMyVaillantApiBase()}/${encodedIdentifier}/v1/systems/${encodedSystemId}/${normalizedPath}`;
  }
  getRoomConfigurationEndpoint(facilityId, roomIndex, urlCommand) {
    const encodedFacilityId = this.ensureMyVaillantSegment(facilityId, "facilityId");
    const encodedRoomIndex = this.ensureMyVaillantSegment(roomIndex, "roomIndex");
    const normalizedCommand = this.normalizeMyVaillantPath(urlCommand);
    if (!normalizedCommand) {
      throw new Error("Missing myVAILLANT room configuration command");
    }
    return `${this.getMyVaillantEndUserBase()}/api/v1/ambisense/facilities/${encodedFacilityId}/rooms/${encodedRoomIndex}/configuration/${normalizedCommand}`;
  }
  // Example outputs:
  // getHomesEndpoint() => https://api.vaillant-group.com/service-connected-control/end-user-app-api/v1/homes
  // getSystemEndpoint("tli","123") => https://api.vaillant-group.com/service-connected-control/end-user-app-api/v1/systems/123/tli
  async myVaillantRequest(options) {
    const {
      method,
      url,
      data,
      body,
      params,
      extraHeaders = {},
      expectedStatuses,
      timeout,
      ...rest
    } = options;
    const requestData = data !== undefined ? data : body;
    const validateStatus = Array.isArray(expectedStatuses)
      ? (status) => (status >= 200 && status < 300) || expectedStatuses.includes(status)
      : undefined;
    try {
      return await this.requestClient({
        method,
        url,
        data: requestData,
        params,
        timeout: timeout || this.httpTimeoutMs,
        headers: this.buildMyVaillantHeaders(this.session.access_token, extraHeaders),
        validateStatus,
        ...rest,
      });
    } catch (error) {
      const statusCode = error && error.response ? error.response.status : undefined;
      if (statusCode === 401) {
        this.log.warn(`myVAILLANT request unauthorized (401): ${method} ${url}`);
      } else if (statusCode === 403) {
        this.log.warn(`myVAILLANT request forbidden (403): ${method} ${url}`);
      } else if (statusCode === 404) {
        this.log.info(`myVAILLANT request not found (404): ${method} ${url}`);
      } else if (statusCode === 409) {
        this.log.info(`myVAILLANT request conflict (409): ${method} ${url}`);
      } else {
        this.log.debug(`myVAILLANT request failed: ${method} ${url}`);
      }
      this.log.error(this.stringifyForLog(error));
      error.response && this.log.error(this.stringifyForLog(error.response.data));
      throw error;
    }
  }
  async myvLoginv2() {
    const [code_verifier, codeChallenge] = this.getCodeChallenge();
    let realm = "";
    try {
      realm = this.getMyVaillantRealm();
    } catch (error) {
      this.log.error(`myVAILLANT realm configuration error: ${error.message}`);
      return;
    }
    let loginUrl = await this.requestClient({
      method: "GET",
      url:
        "https://identity.vaillant-group.com/auth/realms/" +
        realm +
        "/protocol/openid-connect/auth?client_id=myvaillant&redirect_uri=enduservaillant.page.link%3A%2F%2Flogin&login_hint=" +
        this.config.user +
        "&response_mode=fragment&response_type=code&scope=offline_access%20openid&code_challenge=" +
        codeChallenge +
        "&code_challenge_method=S256",
      headers: this.buildMyVaillantHeaders(null, this.myvHeader),
    })
      .then((res) => {
        this.log.debug(this.stringifyForLog(res.data));
        return res.data.split('action="')[1].split('"')[0];
      })
      .catch((error) => {
        this.log.error(this.stringifyForLog(error));
        error.response && this.log.error(this.stringifyForLog(error.response.data));
      });
    if (!loginUrl) {
      return;
    }
    loginUrl = loginUrl.replace(/&amp;/g, "&");
    const response = await this.requestClient({
      method: "POST",
      url: loginUrl,
      headers: {
        accept: "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
        "content-type": "application/x-www-form-urlencoded",
        origin: "null",
        "user-agent":
          "Mozilla/5.0 (iPhone; CPU iPhone OS 16_3_1 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/16.3 Mobile/15E148 Safari/604.1",
        "accept-language": "de-de",
      },
      data: qs.stringify({ username: this.config.user, password: this.config.password, credentialId: "" }),
    })
      .then((res) => {
        this.log.debug(this.stringifyForLog(res.data));
        this.log.error("Login failed no code for myvLoginv2");
        this.log.error(res.data.split('polite">')[1].split("<")[0].trim());
      })
      .catch((error) => {
        if (error && error.message.includes("Unsupported protocol")) {
          this.log.debug(this.stringifyForLog(error.message));
          this.log.debug(this.stringifyForLog(error.request._options.href));
          this.log.debug(this.stringifyForLog(error.request._options.hash));
          return qs.parse(error.request._options.href.split("#")[1]);
        }
        this.log.error(this.stringifyForLog(error));
        error.response && this.log.error(this.stringifyForLog(error.response.data));
      });
    if (!response || !response.code) {
      return;
    }
    await this.requestClient({
      method: "post",
      maxBodyLength: Infinity,
      url: "https://identity.vaillant-group.com/auth/realms/" + realm + "/protocol/openid-connect/token",
      headers: this.buildMyVaillantHeaders(null, {
        Host: "identity.vaillant-group.com",
        "Content-Type": "application/x-www-form-urlencoded",
      }),
      data: qs.stringify({
        client_id: "myvaillant",
        grant_type: "authorization_code",
        code_verifier: code_verifier,
        code: response.code,
        redirect_uri: "enduservaillant.page.link://login",
      }),
    })
      .then((res) => {
        this.log.debug(this.stringifyForLog(res.data));
        if (res.data.access_token) {
          this.log.info("Login successful");
          this.session = res.data;
          this.setState("info.connection", true, true);
        }
      })
      .catch((error) => {
        this.log.error(this.stringifyForLog(error));
        error.response && this.log.error(this.stringifyForLog(error.response.data));
      });
  }
  async myvLogin() {
    this.log.error("Deprecated Okta auth flow is disabled. Use myvLoginv2.");
    throw new Error("Deprecated Okta auth flow is disabled. Use myvLoginv2.");
  }

  async getMyvDeviceList() {
    await this.myVaillantRequest({
      method: "get",
      url: this.getHomesEndpoint(),
    })
      .then(async (res) => {
        this.log.debug(this.stringifyForLog(res.data));
        if (res.data.length > 0) {
          this.log.info(`Found ${res.data.length} system`);
          for (const device of res.data) {
            this.log.debug(this.stringifyForLog(device));
            const id = device.systemId;
            const remoteState = await this.getObjectAsync(id + ".systemControlState");

            if (remoteState) {
              this.log.info("Clean old states" + id);
              await this.delObjectAsync(id, { recursive: true });
            }

            // if (device.subDeviceNo) {
            //   id += "." + device.subDeviceNo;
            // }

            const name = device.homeName + " " + device.productInformation;
            device.identifier = await this.myVaillantRequest({
              method: "get",
              url: this.getControlIdentifierEndpoint(id),
            })
              .then((res) => {
                this.log.debug(this.stringifyForLog(res.data));
                return res.data.controlIdentifier;
              });
            this.deviceArray.push(device);
            await this.extendObjectAsync(id, {
              type: "device",
              common: {
                name: name,
              },
              native: {},
            });
            await this.delObjectAsync(id + ".remote", { recursive: true });
            await this.setObjectNotExistsAsync(id + ".remote", {
              type: "channel",
              common: {
                name: "Remote Controls (For Heating use id.configuration.zones...)",
              },
              native: {},
            });

            /* holiday
{
    "holidayEndDateTime": "2023-11-28T23:59:59.999Z",
    "holidayStartDateTime": "2022-11-28T00:00:00.000Z"
}
            */
            const remoteArray = [
              { command: "Refresh", name: "True = Refresh" },
              { command: "RefreshStats", name: "True = Stats Refresh" },
              // { command: "operationModeHeating", name: "Heating Operation Mode: e.g. MANUAL, OFF" },
              // { command: "setSwitch", name: "True = Switch On, False = Switch Off" },
              // { command: "awayMode", name: "True = Switch On, False = Switch Off" },
              { command: "boost", name: "True = Switch On, False = Switch Off" },
              // { command: "holiday", name: "True = Switch On, False = Switch Off" },
              // {
              //   command: "manualModeSetpoint",
              //   name: "set Temperature",
              //   type: "number",
              //   def: 21,
              //   role: "level.temperature",
              // },
              // { command: "duration", name: "Duration Room Temperature", type: "number", def: 3, role: "level" },
              // { command: "zone", name: "Zone Room Temperature", type: "number", def: 0, role: "level" },
              {
                command: "quickVeto",
                name: "set Temperature in TimeControlled Mode (0 to disable)",
                type: "number",
                def: 21,
                role: "level.temperature",
              },
              { command: "duration", name: "QuickVeto duration in minutes", type: "number", def: 3, role: "level" },
              {
                command: "customCommand",
                name: "Send custom command as json",
                type: "json",
                role: "json",
                def: `{"url":"zone/1/heating/comfort-room-temperature", "data":{"comfortRoomTemperature":10.5}}`,
              },
            ];
            remoteArray.forEach((remote) => {
              this.extendObjectAsync(id + ".remote." + remote.command, {
                type: "state",
                common: {
                  name: remote.name || "",
                  type: remote.type || "boolean",
                  role: remote.role || "switch",
                  def: remote.def != null ? remote.def : false,
                  write: true,
                  read: true,
                },
                native: {},
              });
            });
            this.json2iob.parse(id + ".general", device, { forceIndex: true, write: true, channelName: "General Information" });
          }
        }
      })
      .catch((error) => {
        this.log.debug(`getMyvDeviceList failed: ${error.message}`);
      });
  }

  async updateMyvDevices() {
    for (const device of this.deviceArray) {
      const url = this.getSystemEndpoint(device.identifier, device.systemId);

      const extraHeaders = {};
      if (this.etags[url]) {
        extraHeaders["If-None-Match"] = this.etags[url];
      }
      await this.myVaillantRequest({
        method: "get",
        url: url,
        extraHeaders,
      })
        .then(async (res) => {
          this.log.debug(this.stringifyForLog(res.data));

          const id = device.systemId;
          if (res.headers.etag) {
            this.etags[url] = res.headers.etag;
          }
          this.json2iob.parse(id, res.data, {
            forceIndex: true,
            write: true,
            channelName: device.homeName + " " + device.productInformation,
          });
        })
        .catch((error) => {
          if (error.response && error.response.status === 304) {
            this.log.debug("No changes for " + url);
            return;
          }
          this.log.error("Failed to get status for " + device.systemId);
          this.log.debug(`updateMyvDevices failed: ${error.message}`);
        });
    }
  }
  async updateMyvRooms() {
    for (const device of this.deviceArray) {
      if (this.disabledRooms.includes(device.systemId)) {
        continue;
      }
      const url = this.getRoomsEndpoint(device.systemId);
      const extraHeaders = {};
      if (this.etags[url]) {
        extraHeaders["If-None-Match"] = this.etags[url];
      }
      await this.myVaillantRequest({
        method: "get",
        url: url,
        extraHeaders,
      })
        .then(async (res) => {
          this.log.debug(this.stringifyForLog(res.data));

          const id = device.systemId + ".rooms";
          if (res.headers.etag) {
            this.etags[url] = res.headers.etag;
          }
          this.json2iob.parse(id, res.data, {
            write: true,
            channelName: "Rooms",
            preferedArrayName: "roomConfiguration/name",
          });
        })
        .catch((error) => {
          if (error.response && error.response.status === 304) {
            this.log.debug("No changes for " + url);
            return;
          }

          this.log.error("Failed to get room status for " + device.systemId);
          this.log.debug(`updateMyvRooms failed: ${error.message}`);
          this.log.info("Stop fetching of rooms until restart");
          this.disabledRooms.push(device.systemId);
        });
    }
  }
  async clearOldStats() {
    for (const device of this.deviceArray) {
      const id = device.systemId;
      const newStatsState = await this.getStateAsync(id + ".v2");
      if (!newStatsState) {
        this.log.info("Clear old stats for " + id);
        await this.delObjectAsync(id + ".stats", { recursive: true });
        await this.extendObjectAsync(id + ".v2", {
          type: "state",
          common: {
            name: "v2",
            write: false,
            read: true,
            type: "boolean",
            role: "indicator",
            def: true,
          },
          native: {},
        });
      }
    }
  }
  async updateMyStats() {
    for (const device of this.deviceArray) {
      const id = device.systemId;
      await this.myVaillantRequest({
        method: "get",
        url: this.getStatsEndpoint(id),
      })
        .then(async (res) => {
          await this.setObjectNotExistsAsync(id + ".stats", {
            type: "channel",
            common: {
              name: "Statistics",
            },
            native: {},
          });

          this.json2iob.parse(id + ".stats", res.data, { forceIndex: true });
          this.log.debug(this.stringifyForLog(res.data));
          const resolutions = ["DAY", "MONTH"];

          for (const deviceKey in res.data) {
            if (!res.data[deviceKey] || !res.data[deviceKey].data) {
              continue;
            }
            for (const stats of res.data[deviceKey].data) {
              // if (!stats.calculated) {
              //   continue;
              // }
              // await this.sleep(5000);
              for (const resolution of resolutions) {
                const toDate = stats.to;
                const lastDateTimeStamp = new Date(toDate) - this.config.fetchReportsLimit * 24 * 60 * 60 * 1000;
                let fromDate = new Date(lastDateTimeStamp).toISOString().replace(".000Z", "Z");

                if (resolution === "MONTH") {
                  fromDate = stats.from;
                  // fetch only last 12 month
                  const lastDateTimeStamp = new Date(toDate);
                  lastDateTimeStamp.setMonth(lastDateTimeStamp.getMonth() - 12);
                  fromDate = lastDateTimeStamp.toISOString().replace(".000Z", "Z");
                }

                // startDate minus this.config.fetchReportsLimit days

                await this.myVaillantRequest({
                  method: "get",
                  url: this.getStatsBucketsEndpoint(id, res.data[deviceKey].device_uuid, {
                    resolution,
                    operationMode: stats.operation_mode,
                    energyType: stats.value_type,
                    startDate: fromDate,
                    endDate: toDate,
                  }),
                })
                  .then(async (res) => {
                    // this.log.debug(JSON.stringify(res.data));
                    if (res.data && res.data.data) {
                      res.data.data.sort((a, b) => (a.endDate < b.endDate ? 1 : -1));

                      let stateId = id + ".stats." + deviceKey + "." + stats.value_type + "." + stats.operation_mode;

                      if (resolution === "MONTH") {
                        stateId += ".month";
                      } else {
                        stateId += ".day";
                      }
                      await this.setObjectNotExistsAsync(stateId + ".json", {
                        type: "state",
                        common: {
                          name: "Json Stats",
                          write: false,
                          read: true,
                          type: "string",
                          role: "json",
                        },
                        native: {},
                      });
                      this.json2iob.parse(stateId, res.data, {
                        forceIndex: true,
                        preferedArrayName: "",
                      });
                      this.setState(stateId + ".json", JSON.stringify(res.data), true);
                    } else {
                      this.log.debug("No data found for " + deviceKey + "." + stats.value_type + "." + stats.operation_mode + "");
                    }
                  })
                  .catch((error) => {
                    this.log.debug(`updateMyStats buckets failed: ${error.message}`);
                  });
              }
            }
          }
        })
        .catch((error) => {
          this.log.debug(`updateMyStats failed: ${error.message}`);
        });
    }
  }
  async refreshToken() {
    let realm = "";
    try {
      realm = this.getMyVaillantRealm();
    } catch (error) {
      this.log.error(`myVAILLANT realm configuration error: ${error.message}`);
      this.setStateAsync("info.connection", false, true);
      return;
    }
    await this.requestClient({
      method: "post",
      url: "https://identity.vaillant-group.com/auth/realms/" + realm + "/protocol/openid-connect/token",
      headers: this.buildMyVaillantHeaders(null, {
        accept: "*/*",
        "content-type": "application/x-www-form-urlencoded; charset=UTF-8",
        "user-agent": "okta-react-native/2.7.0 okta-oidc-ios/3.11.2 react-native/>=0.70.1 ios/14.8",
        "accept-language": "de-de",
      }),
      data: qs.stringify({
        refresh_token: this.session.refresh_token,
        client_id: "myvaillant",
        grant_type: "refresh_token",
      }),
    })
      .then((res) => {
        this.log.debug(this.stringifyForLog(res.data));
        this.session = res.data;
        this.log.debug("Refresh successful");
        this.setState("info.connection", true, true);
      })
      .catch(async (error) => {
        this.log.error(this.stringifyForLog(error));
        error.response && this.log.error(this.stringifyForLog(error.response.data));
        this.setStateAsync("info.connection", false, true);
      });
  }
  updateValues() {
    this.log.debug("update values");
    this.cleanConfigurations()
      .then(async () => {
        await this.sleep(5000);
        await this.getMethod("https://smart.vaillant.com/mobile/api/v4/facilities/$serial/system/v1/status", "status").catch(() =>
          this.log.debug("Failed to get status"),
        );

        await this.sleep(20000);
        await this.getMethod("https://smart.vaillant.com/mobile/api/v4/facilities/$serial/systemcontrol/v1", "systemcontrol").catch(() =>
          this.log.debug("Failed to get systemcontrol"),
        );

        await this.sleep(20000);
        await this.getMethod("https://smart.vaillant.com/mobile/api/v4/facilities/$serial/systemcontrol/tli/v1", "systemcontrol/tli").catch(
          () => this.log.debug("Failed to get tli systemcontrol"),
        );

        await this.sleep(20000);
        await this.getMethod("https://smart.vaillant.com/mobile/api/v4/facilities/$serial/livereport/v1", "livereport").catch(() =>
          this.log.debug("Failed to get livereport"),
        );

        await this.sleep(20000);
        await this.getMethod("https://smart.vaillant.com/mobile/api/v4/facilities/$serial/spine/v1/currentPVMeteringInfo", "spine").catch(
          () => this.log.debug("Failed to get spine"),
        );

        await this.sleep(20000);
        await this.getMethod("https://smart.vaillant.com/mobile/api/v4/facilities/$serial/emf/v1/devices/", "emf").catch(() =>
          this.log.debug("Failed to get emf"),
        );

        await this.sleep(10000);
        await this.getMethod("https://smart.vaillant.com/mobile/api/v4/facilities/$serial/rbr/v1/rooms", "rooms").catch(() =>
          this.log.debug("Failed to get rooms"),
        );
        if (this.config.fetchReports) {
          await this.sleep(20000);
          // await this.receiveReports();
        }
      })

      .catch(() => {
        this.log.error("clean configuration failed");
      });
  }

  login() {
    return new Promise((resolve, reject) => {
      if (!this.config.password || !this.config.user) {
        this.log.warn("Missing username or password");
        reject();
        return;
      }
      this.jar = request.jar();
      const body = { smartphoneId: this.config.smartPhoneId, password: this.config.password, username: this.config.user };
      this.isRelogin && this.log.debug("Start relogin");
      request.post(
        {
          url: "https://smart.vaillant.com/mobile/api/v4/account/authentication/v1/token/new",
          headers: this.baseHeader,
          followAllRedirects: true,
          timeout: this.httpTimeoutMs,
          json: true,
          body: body,
          jar: this.jar,
          gzip: true,
        },
        (err, resp, body) => {
          this.isRelogin && this.log.debug("Relogin completed start reauth");

          if (err || (resp && resp.statusCode >= 400) || !body) {
            this.log.error("Failed to login");
            this.log.error(this.stringifyForLog(err));
            this.log.error(this.stringifyForLog(body));
            resp && this.log.error(resp.statusCode);
            reject();
            return;
          }
          this.log.debug(this.stringifyForLog(body));
          if (body.errorCode || !body.body.authToken) {
            this.log.error(this.stringifyForLog(body));
            reject();
            return;
          }
          this.atoken = body.body.authToken;
          try {
            this.log.debug("Login successful");
            this.authenticate(reject, resolve);
            this.reauthInterval && clearInterval(this.reauthInterval);
            this.reauthInterval = setInterval(
              () => {
                this.login();
              },
              4 * 60 * 60 * 1000,
            ); //4h;
          } catch (error) {
            this.log.error(this.stringifyForLog(error));
            error && this.log.error(JSON.stringify(error.stack));
            reject();
          }
        },
      );
    });
  }
  authenticate(reject, resolve) {
    const authBody = {
      authToken: this.atoken,
      smartphoneId: this.config.smartPhoneId,
      username: this.config.user,
    };
    request.post(
      {
        url: "https://smart.vaillant.com/mobile/api/v4/account/authentication/v1/authenticate",
        headers: this.baseHeader,
        followAllRedirects: true,
        timeout: this.httpTimeoutMs,
        body: authBody,
        jar: this.jar,
        json: true,
      },
      (err, resp, body) => {
        this.isRelogin = false;
        if (err || (resp && resp.statusCode >= 400)) {
          this.log.error("Authentication failed");
          this.setState("info.connection", false, true);
          err && this.log.error(this.stringifyForLog(err));
          resp && this.log.error(resp.statusCode);
          body && this.log.error(this.stringifyForLog(body));
          reject();
          return;
        }
        this.log.debug("Authentication successful");
        this.log.debug(this.stringifyForLog(body));
        this.setState("info.connection", true, true);
        if (resolve) {
          resolve();
        }
      },
    );
  }
  async cleanConfigurations() {
    if (this.config.cleantype) {
      this.log.debug("skip clean config");
      return;
    }
    this.log.debug("clean config");
    const pre = this.name + "." + this.instance;
    const states = await this.getStatesAsync(pre + ".*");
    const allIds = Object.keys(states);
    for (const keyName of allIds) {
      if (keyName.indexOf(".configuration") !== -1) {
        try {
          await this.delObjectAsync(keyName.split(".").slice(2).join("."));
        } catch (error) {
          this.log.debug(this.stringifyForLog(error));
        }
      }
    }
  }
  getFacility() {
    return new Promise((resolve, reject) => {
      request.get(
        {
          url: "https://smart.vaillant.com/mobile/api/v4/facilities",
          headers: this.baseHeader,
          followAllRedirects: true,
          timeout: this.httpTimeoutMs,
          json: true,
          jar: this.jar,
          gzip: true,
        },
        async (err, resp, body) => {
          if (err || (resp && resp.statusCode >= 400) || !body) {
            this.log.error(this.stringifyForLog(err));
            reject();
            return;
          }
          this.log.debug(this.stringifyForLog(body));
          if (body.errorCode || !body.body.facilitiesList || body.body.facilitiesList.length === 0) {
            this.log.error(this.stringifyForLog(body));
            reject();
            return;
          }
          this.log.info(body.body.facilitiesList.length + " facilities found");
          const facility = body.body.facilitiesList[0];
          this.serialNr = facility.serialNumber;
          await this.setObjectNotExistsAsync(facility.serialNumber, {
            type: "device",
            common: {
              name: facility.name,
              role: "indicator",
            },
            native: {},
          });
          try {
            const adapter = this;
            traverse(facility).forEach(function (value) {
              if (this.path.length > 0 && this.isLeaf) {
                const modPath = this.path;
                this.path.forEach((pathElement, pathIndex) => {
                  if (!isNaN(parseInt(pathElement))) {
                    let stringPathIndex = parseInt(pathElement) + 1 + "";
                    while (stringPathIndex.length < 2) stringPathIndex = "0" + stringPathIndex;
                    const key = this.path[pathIndex - 1] + stringPathIndex;
                    const parentIndex = modPath.indexOf(pathElement) - 1;
                    modPath[parentIndex] = key;
                    modPath.splice(parentIndex + 1, 1);
                  }
                });
                adapter
                  .setObjectNotExistsAsync(facility.serialNumber + ".general." + modPath.join("."), {
                    type: "state",
                    common: {
                      name: this.key,
                      role: "indicator",
                      type: typeof value,
                      write: false,
                      read: true,
                    },
                    native: {},
                  })
                  .then(() => {
                    if (typeof value === "object") {
                      value = JSON.stringify(value);
                    }
                    adapter.setState(facility.serialNumber + ".general." + modPath.join("."), value, true);
                  });
              }
            });
            resolve();
          } catch (error) {
            this.log.error(this.stringifyForLog(error));
            this.log.error(error.stack);
            reject();
          }
        },
      );
    });
  }
  getMethod(url, path) {
    return new Promise((resolve, reject) => {
      this.log.debug("get method: " + url + " " + path);
      if (this.isRelogin || this.adapterStopped) {
        this.log.debug("Instance is relogining ignores: " + path);
        resolve();
        return;
      }
      if (path === "spine" && !this.isSpineActive) {
        resolve();
        return;
      }
      if (path === "emf") {
        this.reports = {};
      }
      this.log.debug("Get: " + path);

      url = url.replace("/$serial/", "/" + this.serialNr + "/");

      request.get(
        {
          url: url,
          headers: this.baseHeader,
          followAllRedirects: true,
          timeout: this.httpTimeoutMs,
          json: true,
          jar: this.jar,
          gzip: true,
        },
        (err, resp, body) => {
          if (body && body.errorCode) {
            if (body.errorCode === "SPINE_NOT_SUPPORTED_BY_FACILITY") {
              this.isSpineActive = false;
            }
            this.log.debug(this.stringifyForLog(body.errorCode));
            reject();
            return;
          }
          if (err || (resp && resp.statusCode >= 400)) {
            this.log.debug("Error response from: " + path);
            this.setState("info.connection", false, true);
            if ((resp && resp.statusCode === 401) || JSON.stringify(body) === "NOT_AUTHORIZED") {
              this.log.info(this.stringifyForLog(body));
              if (!this.isRelogin) {
                this.log.info("401 Error try to relogin.");
                this.isRelogin = true;
                this.reloginTimeout && clearTimeout(this.reloginTimeout);
                // TODO: Add bounded retry/backoff for relogin storms after repeated 401 responses.
                this.reloginTimeout = setTimeout(() => {
                  this.log.debug("Start relogin");
                  this.login()
                    .then(() => {
                      this.log.debug("Relogin completed");
                    })
                    .catch(() => {
                      this.log.error("Relogin failed");
                    });
                }, 10000);
              } else {
                this.log.info("Instance is already trying to relogin.");
              }
            } else {
              err && this.log.error(this.stringifyForLog(err));
              resp && this.log.error(resp && resp.statusCode);
              body && this.log.error(this.stringifyForLog(body));
              this.log.error("Failed to get:" + path);
            }
            reject();
            return;
          }
          this.log.debug(path + " successful");
          this.log.debug(this.stringifyForLog(body));
          if (!body) {
            resolve();
            return;
          }
          if (path.indexOf("reports.") !== -1) {
            this.json2iob.parse(this.serialNr + "." + path, body.body, { forceIndex: true, channelName: "Reports" });
            resolve();
            return;
          }
          try {
            const adapter = this;
            traverse(body.body).forEach(function (value) {
              if (this.path.length > 0 && this.isLeaf) {
                const modPath = this.path;
                this.path.forEach((pathElement, pathIndex) => {
                  if (!isNaN(parseInt(pathElement))) {
                    let stringPathIndex = parseInt(pathElement) + 1 + "";
                    while (stringPathIndex.length < 2) stringPathIndex = "0" + stringPathIndex;
                    const key = this.path[pathIndex - 1] + stringPathIndex;
                    const parentIndex = modPath.indexOf(pathElement) - 1;
                    modPath[parentIndex] = key;
                    modPath.splice(parentIndex + 1, 1);
                  }
                });
                if (path === "livereport" && modPath.length > 2) {
                  modPath[1] = this.parent.node._id;
                  modPath[0] = this.parent.parent.parent.node._id ? this.parent.parent.parent.node._id : modPath[0];
                }
                if (path === "livereport" && modPath.length == 2) {
                  modPath[0] = this.parent.node._id;
                }

                if (path === "systemcontrol" && modPath[0].indexOf("parameters") !== -1 && modPath[1] === "name") {
                  //add value field for parameters
                  adapter.setObjectNotExistsAsync(adapter.serialNr + "." + path + "." + modPath[0] + ".parameterValue", {
                    type: "state",
                    common: {
                      name: "Value for " + value + ". See definition for values.",
                      role: "indicator",
                      type: "mixed",
                      write: true,
                      read: true,
                    },
                    native: {},
                  });
                }

                if (path === "emf") {
                  if (modPath[0].indexOf("reports") !== -1) {
                    modPath[0] = this.parent.node.function + "_" + this.parent.node.energyType;
                    if (this.parent.parent && this.parent.parent.parent && this.parent.parent.parent.node.id) {
                      const id = this.parent.parent.parent.node.id;
                      if (!adapter.reports[id]) {
                        adapter.reports[id] = [];
                      }
                      adapter.reports[id].push({ function: this.parent.node.function, energyType: this.parent.node.energyType });
                    }
                  }
                }

                adapter
                  .setObjectNotExistsAsync(adapter.serialNr + "." + path + "." + modPath.join("."), {
                    type: "state",
                    common: {
                      name: this.key,
                      role: "indicator",
                      type: value ? typeof value : "mixed",
                      write: true,
                      read: true,
                    },
                    native: {},
                  })
                  .then(() => {
                    if (typeof value === "object") {
                      value = JSON.stringify(value);
                    }
                    adapter.setState(adapter.serialNr + "." + path + "." + modPath.join("."), value, true);
                  });
              } else if (path === "systemcontrol" && this.path.length > 0 && !isNaN(this.path[this.path.length - 1])) {
                const modPath = this.path;
                this.path.forEach((pathElement, pathIndex) => {
                  if (!isNaN(parseInt(pathElement))) {
                    let stringPathIndex = parseInt(pathElement) + 1 + "";
                    while (stringPathIndex.length < 2) stringPathIndex = "0" + stringPathIndex;
                    const key = this.path[pathIndex - 1] + stringPathIndex;
                    const parentIndex = modPath.indexOf(pathElement) - 1;
                    modPath[parentIndex] = key;

                    modPath.splice(parentIndex + 1, 1);
                  }
                });

                if (this.node.name) {
                  adapter.setObjectNotExistsAsync(adapter.serialNr + "." + path + "." + modPath.join("."), {
                    type: "state",
                    common: {
                      name: this.node.name,
                      role: "indicator",
                      type: "mixed",
                      write: true,
                      read: true,
                    },
                    native: {},
                  });
                }
              }
            });
            resolve();
          } catch (error) {
            this.log.error(this.stringifyForLog(error));
            this.log.error(error.stack);
            reject();
          }
        },
      );
    });
  }
  async setMethod(id, val) {
    // eslint-disable-next-line
    return new Promise(async (resolve, reject) => {
      const idArray = id.split(".");
      const action = idArray[idArray.length - 1];
      const idPath = id.split(".").splice(2).slice(0, 3);
      let path = [];
      let url = "";
      let body = {};
      if (id.indexOf("configuration") !== -1) {
        const idState = await this.getStateAsync(idPath.join(".") + "._id");
        path = idArray.splice(4);
        if (idState && idState.val) {
          path.splice(1, 0, idState.val);
        }
        path[0] = path[0].replace(/[0-9]/g, "");
        path = path.join("/");
        url = "https://smart.vaillant.com/mobile/api/v4/facilities/" + this.serialNr + "/" + idPath[1] + "/v1/" + path;
        if (idPath[1] === "rooms") {
          let roomId = idPath[2].replace("rooms", "");
          roomId = parseInt(roomId) - 1;
          url =
            "https://smart.vaillant.com/mobile/api/v4/facilities/" + this.serialNr + "/rbr/v1/rooms/" + roomId + "/configuration/" + action;
        }
        body[action] = val;
        if ((val = "" || val === null || val === undefined)) {
          body = null;
        }

        // body["duration"] = 180;
      } else {
        const pathState = await this.getStateAsync(idPath.join(".") + ".link.resourceLink");
        if (pathState) {
          url = "https://smart.vaillant.com/mobile/api/v4" + pathState.val;
          const action = pathState.val.split("/").pop();
          const subBody = {};
          subBody[action] = val;
          body[action] = subBody;
        }
      }
      this.log.debug(this.stringifyForLog(url));
      this.log.debug(this.stringifyForLog(body));
      request.put(
        {
          url: url,
          headers: this.baseHeader,
          followAllRedirects: true,
          timeout: this.httpTimeoutMs,
          body: body,
          json: true,
          gzip: true,
          jar: this.jar,
        },
        (err, resp, body) => {
          if (err || (resp && resp.statusCode >= 400)) {
            this.log.error(this.stringifyForLog(err));
            this.log.error(this.stringifyForLog(body));
            url && this.log.error(this.stringifyForLog(url));
            body && this.log.error(this.stringifyForLog(body));
            reject();
            return;
          }
          try {
            this.log.debug(this.stringifyForLog(body));
            resolve();
          } catch (error) {
            this.log.error(this.stringifyForLog(error));
            error && this.log.error(error.stack);
            reject();
          }
        },
      );
    });
  }
  decrypt(key, value) {
    let result = "";
    for (let i = 0; i < value.length; ++i) {
      result += String.fromCharCode(key[i % key.length].charCodeAt(0) ^ value.charCodeAt(i));
    }
    return result;
  }
  sanitizeLogString(value) {
    if (typeof value !== "string") {
      return value;
    }
    let sanitized = value;
    const keys = ["password", "access_token", "refresh_token", "id_token", "authorization", "token", "code", "session_state"];
    for (const key of keys) {
      const queryRegex = new RegExp(`(${key}=)([^&\\s]+)`, "gi");
      sanitized = sanitized.replace(queryRegex, "$1[REDACTED]");
      const jsonRegex = new RegExp(`("${key}"\\s*:\\s*")([^"]+)(")`, "gi");
      sanitized = sanitized.replace(jsonRegex, "$1[REDACTED]$3");
    }
    sanitized = sanitized.replace(/(Bearer\s+)([A-Za-z0-9\-._~+/=]+)/gi, "$1[REDACTED]");
    return sanitized;
  }
  sanitizeLogData(value, keyName = "") {
    const sensitiveKeys = new Set([
      "password",
      "access_token",
      "refresh_token",
      "id_token",
      "authorization",
      "token",
      "code",
      "session_state",
    ]);
    if (value === null || value === undefined) {
      return value;
    }
    if (typeof value === "string") {
      return this.sanitizeLogString(value);
    }
    if (typeof value !== "object") {
      if (sensitiveKeys.has(String(keyName).toLowerCase())) {
        return "[REDACTED]";
      }
      return value;
    }
    if (Array.isArray(value)) {
      return value.map((item) => this.sanitizeLogData(item));
    }
    const sanitized = {};
    Object.keys(value).forEach((key) => {
      const normalizedKey = key.toLowerCase();
      if (sensitiveKeys.has(normalizedKey) || normalizedKey.includes("token") || normalizedKey === "code") {
        sanitized[key] = "[REDACTED]";
      } else {
        sanitized[key] = this.sanitizeLogData(value[key], key);
      }
    });
    return sanitized;
  }
  stringifyForLog(value) {
    const sanitized = this.sanitizeLogData(value);
    if (typeof sanitized === "string") {
      return sanitized;
    }
    try {
      return JSON.stringify(sanitized);
    } catch (error) {
      return String(sanitized);
    }
  }
  makeid(length = 202) {
    let result = "";
    const characters = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789";
    const charactersLength = characters.length;
    for (let i = 0; i < length; i++) {
      result += characters.charAt(Math.floor(Math.random() * charactersLength));
    }

    return "multimatic_" + result;
  }
  randomString(length = 202) {
    let result = "";
    const characters = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789";
    const charactersLength = characters.length;
    for (let i = 0; i < length; i++) {
      result += characters.charAt(Math.floor(Math.random() * charactersLength));
    }
    return result;
  }
  sleep(ms) {
    if (this.adapterStopped) {
      ms = 0;
    }
    return new Promise((resolve) => setTimeout(resolve, ms));
  }
  getCodeChallenge() {
    let hash = "";
    let result = "";
    const chars = "0123456789abcdef";
    result = "";
    for (let i = 64; i > 0; --i) result += chars[Math.floor(Math.random() * chars.length)];
    hash = crypto.createHash("sha256").update(result).digest("base64");
    hash = hash.replace(/\+/g, "-").replace(/\//g, "_").replace(/=/g, "");

    return [result, hash];
  }
  /**
  async receiveReports() {
    const date = new Date().toISOString().split("T")[0];
    this.log.debug(date);
    for (const id of Object.keys(this.reports)) {
      this.log.debug(id);
      this.log.debug(this.reports[id]);
      for (const report of this.reports[id]) {
        await this.sleep(2000);
        this.log.debug(report);
        await this.getMethod(
          "https://smart.vaillant.com/mobile/api/v4/facilities/$serial/emf/v1/devices/" +
            id +
            "?energyType=" +
            report.energyType +
            "&function=" +
            report.function +
            "&offset=6&start=" +
            date +
            "&timeRange=DAY",
          "reports." + id + "." + report.energyType + "." + report.function
        );
      }
    }
  }
  /**
   * Is called when adapter shuts down - callback has to be called under any circumstances!
   * @param {() => void} callback
   */
  onUnload(callback) {
    try {
      this.log.info("cleaned everything up...");
      this.adapterStopped = true;
      this.updateInterval && clearInterval(this.updateInterval);
      this.reauthInterval && clearInterval(this.reauthInterval);
      this.reloginTimeout && clearTimeout(this.reloginTimeout);
      this.refreshTokenInterval && clearInterval(this.refreshTokenInterval);
      callback();
    } catch (e) {
      callback();
    }
  }

  /**
   * Is called if a subscribed state changes
   * @param {string} id
   * @param {ioBroker.State | null | undefined} state
   */
  async onStateChange(id, state) {
    if (state) {
      if (!state.ack) {
        if (this.config.myv) {
          const deviceId = id.split(".")[2];

          if (id.split(".")[4] === "Refresh") {
            this.updateMyvDevices();
            this.updateMyvRooms();
            return;
          }
          if (id.split(".")[4] === "RefreshStats") {
            this.updateMyStats();
            return;
          }
          let data = {};
          let method = "POST";
          const command = id.split(".").pop();
          let url = "";
          //find deviceidentifier
          const identifier = this.deviceArray.find((device) => device.systemId === deviceId).identifier;

          if (command === "awayMode") {
            method = state.val ? "POST" : "DELETE";
            url = this.buildSystemCommandEndpoint(identifier, deviceId, "away-mode", true);
          }
          if (command === "boost") {
            method = state.val ? "POST" : "DELETE";
            url = this.buildSystemCommandEndpoint(identifier, deviceId, "domestic-hot-water/255/boost", true);
          }
          if (command === "quickVeto") {
            method = state.val ? "POST" : "DELETE";
            const durationState = await this.getStateAsync(id.split(".").slice(0, -1).join(".") + ".duration");
            let duration = 3;
            if (durationState && durationState.val) {
              duration = durationState.val;
            }
            data = { desiredRoomTemperatureSetpoint: state.val, duration: duration };
            url = this.buildSystemCommandEndpoint(identifier, deviceId, "zones/0/quick-veto", true);
          }
          const commands = {
            operationModeHeating: { url: "heating/operation-mode", parameter: "operationMode" },
            manualModeSetpoint: { url: "manual-mode-setpoint", parameter: "setpoint" },
            manualModeSetpointHeating: { url: "manual-mode-setpoint", parameter: "setpoint" },
            manualModeSetpointCooling: { url: "manual-mode-setpoint", parameter: "setpoint" },
          };
          if (id.split(".")[4].includes("zones")) {
            const zoneId = Number(id.split(".")[4].replace("zones", "")); //- 1;
            this.log.debug("zoneId: " + zoneId);
            this.log.debug("deviceId: " + deviceId);
            method = "PATCH";
            let parameter = command;
            if (commands[command]) {
              parameter = commands[command].parameter;
            }

            data[parameter] = state.val;
            if (command.indexOf("manualModeSetpoint") !== -1) {
              const type = command.replace("manualModeSetpoint", "");
              if (type) {
                data["type"] = type.toLocaleUpperCase();
              }
            }
            const urlPostfix = commands[command] ? commands[command].url : command;
            url = this.buildSystemCommandEndpoint(identifier, deviceId, `zones/${zoneId}/${urlPostfix}`, true);

            if (command === "desiredRoomTemperatureSetpoint") {
              url = this.buildSystemCommandEndpoint(identifier, deviceId, `zones/${zoneId}/quickVeto`, true);
            }
          }
          if (id.split(".")[4].includes("circuits")) {
            const circuitsId = Number(id.split(".")[4].replace("circuits", "")) - 1;
            this.log.debug("circuits: " + circuitsId);
            this.log.debug("deviceId: " + deviceId);
            method = "PATCH";
            data[command] = state.val;
            url = this.buildSystemCommandEndpoint(identifier, deviceId, `circuits/${circuitsId}/quickVeto`, true);
          }
          if (id.split(".")[4].includes("domesticHotWater")) {
            const idArray = id.split(".");
            idArray.pop();
            idArray.push("index");
            const index = await this.getStateAsync(idArray.join("."));
            this.log.debug("index: " + index);
            this.log.debug("deviceId: " + deviceId);
            method = state.val ? "POST" : "DELETE";
            data = {};
            url = this.buildSystemCommandEndpoint(identifier, deviceId, `domesticHotWater/${index.val}/${command}`, false);
            if (command === "setPoint") {
              data = {
                setPoint: state.val,
              };
              url = this.buildSystemCommandEndpoint(identifier, deviceId, `domesticHotWater/${index.val}/temperature`, false);
            }
            if (command === "operationMode") {
              data = {
                operationMode: state.val,
              };
            }
          }

          if (id.includes(".rooms.")) {
            const roomIndex = await this.getStateAsync(id.split(".")[2] + ".rooms." + id.split(".")[4] + ".roomIndex");
            if (roomIndex) {
              method = "PUT";
              data = {};
              data[command] = state.val;
              //replace uppercase with lowercase and add - between
              const urlCommand = command.replace(/([a-z])([A-Z])/g, "$1-$2").toLowerCase();
              url = this.getRoomConfigurationEndpoint(deviceId, roomIndex.val, urlCommand);
            }
          }
          if (command === "customCommand") {
            try {
              const parsedCommand = JSON.parse(state.val);
              method = "PATCH";
              if (parsedCommand.method) {
                method = parsedCommand.method;
              }
              url = this.buildSystemCommandEndpoint(identifier, deviceId, parsedCommand.url, true);
              data = parsedCommand.data;
            } catch (error) {
              this.log.error("Failed to parse custom command");
              this.log.error(this.stringifyForLog(error));
            }
          }
          this.log.debug(this.stringifyForLog(url));
          this.log.debug(this.stringifyForLog(data));
          if (!url) {
            this.log.error("No configuration supported please use customCommand");
            return;
          }
          await this.myVaillantRequest({
            method: method,
            url: url,
            extraHeaders: {
              "Content-Type": "application/json",
              Connection: "keep-alive",
              "User-Agent": "myVAILLANT/11835 CFNetwork/1240.0.4 Darwin/20.6.0",
            },
            data: JSON.stringify(data),
          })
            .then(async (res) => {
              this.log.info(this.stringifyForLog(res.data));
              this.refreshTimeout = setTimeout(async () => {
                this.log.info("Update devices");
                await this.updateMyvDevices();
                await this.updateMyvRooms();
              }, 10 * 1000);
            })
            .catch((error) => {
              this.log.debug(`onStateChange myV request failed: ${error.message}`);
            });
          return;
        }
        if (id.indexOf("configuration") !== -1 || id.indexOf("parameterValue") !== -1) {
          this.setMethod(id, state.val).catch(() => {
            this.log.error("Failed to set: " + id + " to: " + state.val);
          });
        }
      } else {
        // if (id.indexOf("heating.manualModeSetpointHeating") !== -1) {
        //   const deviceId = id.split(".")[2];
        //   this.setState(deviceId + ".remote.quickVeto", state.val, true);
        // }
      }
    } else {
      // The state was deleted
    }
  }
}

// @ts-ignore parent is a valid property on module
if (module.parent) {
  // Export the constructor in compact mode
  /**
   * @param {Partial<ioBroker.AdapterOptions>} [options={}]
   */
  module.exports = (options) => new Vaillant(options);
} else {
  // otherwise start the instance directly
  new Vaillant();
}
