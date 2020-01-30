"use strict";

/*
 * Created with @iobroker/create-adapter v1.20.0
 */

// The adapter-core module gives you access to the core ioBroker functions
// you need to create an adapter
const utils = require("@iobroker/adapter-core");
const request = require("request");
const traverse = require("traverse");
// Load your modules here, e.g.:
// const fs = require("fs");

/*
https://smart.vaillant.com/mobile/api/v4/account/authentication/v1/authenticate
https://smart.vaillant.com/mobile/api/v4/facilities/{serial_number}/systemcontrol/v1/dhw/{dhw_id}/circulation
https://smart.vaillant.com/mobile/api/v4/facilities/{serial_number}/systemcontrol/v1/dhw/{dhw_id}/circulation/configuration
https://smart.vaillant.com/mobile/api/v4/facilities/{serial_number}/systemcontrol/v1/dhw/{dhw_id}/circulation/configuration/timeprogram
https://smart.vaillant.com/mobile/api/v4/facilities/{serial_number}/rbr/v1/repeaters/{sgtin}
https://smart.vaillant.com/mobile/api/v4/facilities/{serial_number}/systemcontrol/v1/dhw/{dhw_id}
https://smart.vaillant.com/mobile/api/v4/facilities/{serial_number}/emf/v1/devices
https://smart.vaillant.com/mobile/api/v4/facilities/{serial_number}/emf/v1/devices/{device_id}
https://smart.vaillant.com/mobile/api/v4/facilities/{serial_number}/storage/default
https://smart.vaillant.com/mobile/api/v4/facilities/{serial_number}/system/v1/details
https://smart.vaillant.com/mobile/api/v4/facilities/{serial_number}/system/v1/installerinfo
https://smart.vaillant.com/mobile/api/v4/facilities
https://smart.vaillant.com/mobile/api/v4/facilities/{serial_number}/storage
https://smart.vaillant.com/mobile/api/v4/facilities/{serial_number}/system/v1/status
https://smart.vaillant.com/mobile/api/v4/facilities/{serial_number}/systemcontrol/v1/dhw/{dhw_id}/hotwater
https://smart.vaillant.com/mobile/api/v4/facilities/{serial_number}/systemcontrol/v1/dhw/{dhw_id}/hotwater/configuration
https://smart.vaillant.com/mobile/api/v4/facilities/{serial_number}/systemcontrol/v1/dhw/{dhw_id}/hotwater/configuration/operation_mode
https://smart.vaillant.com/mobile/api/v4/facilities/{serial_number}/systemcontrol/v1/dhw/{dhw_id}/hotwater/configuration/temperature_setpoint
https://smart.vaillant.com/mobile/api/v4/facilities/{serial_number}/systemcontrol/v1/dhw/{dhw_id}/hotwater/configuration/timeprogram
https://smart.vaillant.com/mobile/api/v4/facilities/{serial_number}/hvacstate/v1/overview
https://smart.vaillant.com/mobile/api/v4/facilities/{serial_number}/hvacstate/v1/hvacMessages/update
https://smart.vaillant.com/mobile/api/v4/facilities/{serial_number}/livereport/v1
https://smart.vaillant.com/mobile/api/v4/facilities/{serial_number}/livereport/v1/devices/{device_id}/reports/{report_id}
https://smart.vaillant.com/mobile/api/v4/account/authentication/v1/logout
https://smart.vaillant.com/mobile/api/v4/account/authentication/v1/token/new
https://smart.vaillant.com/mobile/api/v4/facilities/{serial_number}/spine/v1/currentPVMeteringInfo
https://smart.vaillant.com/mobile/api/v4/facilities/{serial_number}/rbr/v1/installationStatus
https://smart.vaillant.com/mobile/api/v4/facilities/{serial_number}/rbr/v1/underfloorHeatingStatus
https://smart.vaillant.com/mobile/api/v4/facilities/{serial_number}/rbr/v1/repeaters
https://smart.vaillant.com/mobile/api/v4/facilities/{serial_number}/rbr/v1/rooms/{room_index}
https://smart.vaillant.com/mobile/api/v4/facilities/{serial_number}/rbr/v1/rooms/{room_index}/configuration
https://smart.vaillant.com/mobile/api/v4/facilities/{serial_number}/rbr/v1/rooms/{room_index}/configuration/operationMode
https://smart.vaillant.com/mobile/api/v4/facilities/{serial_number}/rbr/v1/rooms/{room_index}/configuration/quickVeto
https://smart.vaillant.com/mobile/api/v4/facilities/{serial_number}/rbr/v1/rooms/{room_index}/configuration/childLock
https://smart.vaillant.com/mobile/api/v4/facilities/{serial_number}/rbr/v1/rooms/{room_index}/configuration/devices/{sgtin}/name
https://smart.vaillant.com/mobile/api/v4/facilities/{serial_number}/rbr/v1/rooms/{room_index}/configuration/name
https://smart.vaillant.com/mobile/api/v4/facilities/{serial_number}/rbr/v1/rooms/{room_index}/configuration/temperatureSetpoint
https://smart.vaillant.com/mobile/api/v4/facilities/{serial_number}/rbr/v1/rooms/{room_index}/timeprogram
https://smart.vaillant.com/mobile/api/v4/facilities/{serial_number}/rbr/v1/rooms
https://smart.vaillant.com/mobile/api/v4/facilities/{serial_number}/rbr/v1/repeaters/{sgtin}/name
https://smart.vaillant.com/mobile/api/v4/facilities/{serial_number}/systemcontrol/v1/ventilation/{ventilation_id}/fan/configuration/day_level
https://smart.vaillant.com/mobile/api/v4/facilities/{serial_number}/systemcontrol/v1/ventilation/{ventilation_id}/fan/configuration/night_level
https://smart.vaillant.com/mobile/api/v4/facilities/{serial_number}/systemcontrol/v1/ventilation/{ventilation_id}/fan/configuration/operation_mode
https://smart.vaillant.com/mobile/api/v4/facilities/{serial_number}/systemcontrol/v1
https://smart.vaillant.com/mobile/api/v4/facilities/{serial_number}/systemcontrol/v1/configuration
https://smart.vaillant.com/mobile/api/v4/facilities/{serial_number}/systemcontrol/v1/status/datetime
https://smart.vaillant.com/mobile/api/v4/facilities/{serial_number}/systemcontrol/v1/configuration/holidaymode
https://smart.vaillant.com/mobile/api/v4/facilities/{serial_number}/systemcontrol/v1/parameters
https://smart.vaillant.com/mobile/api/v4/facilities/{serial_number}/systemcontrol/v1/configuration/quickmode
https://smart.vaillant.com/mobile/api/v4/facilities/{serial_number}/systemcontrol/v1/status
https://smart.vaillant.com/mobile/api/v4/facilities/{serial_number}/systemcontrol/v1/ventilation/{ventilation_id}
https://smart.vaillant.com/mobile/api/v4/facilities/{serial_number}/systemcontrol/v1/ventilation/{ventilation_id}/fan/configuration
https://smart.vaillant.com/mobile/api/v4/facilities/{serial_number}/systemcontrol/v1/ventilation/{ventilation_id}/fan/configuration/timeprogram
https://smart.vaillant.com/mobile/api/v4/facilities/{serial_number}/systemcontrol/v1/zones/{zone_id}
https://smart.vaillant.com/mobile/api/v4/facilities/{serial_number}/systemcontrol/v1/zones/{zone_id}/configuration
https://smart.vaillant.com/mobile/api/v4/facilities/{serial_number}/systemcontrol/v1/zones/{zone_id}/cooling/configuration
https://smart.vaillant.com/mobile/api/v4/facilities/{serial_number}/systemcontrol/v1/zones/{zone_id}/cooling/configuration/manual_mode_cooling_temperature_setpoint
https://smart.vaillant.com/mobile/api/v4/facilities/{serial_number}/systemcontrol/v1/zones/{zone_id}/cooling/configuration/mode
https://smart.vaillant.com/mobile/api/v4/facilities/{serial_number}/systemcontrol/v1/zones/{zone_id}/cooling/configuration/setpoint_temperature
https://smart.vaillant.com/mobile/api/v4/facilities/{serial_number}/systemcontrol/v1/zones/{zone_id}/cooling/timeprogram
https://smart.vaillant.com/mobile/api/v4/facilities/{serial_number}/systemcontrol/v1/zones/{zone_id}/heating/configuration
https://smart.vaillant.com/mobile/api/v4/facilities/{serial_number}/systemcontrol/v1/zones/{zone_id}/heating/configuration/mode
https://smart.vaillant.com/mobile/api/v4/facilities/{serial_number}/systemcontrol/v1/zones/{zone_id}/heating/configuration/setback_temperature
https://smart.vaillant.com/mobile/api/v4/facilities/{serial_number}/systemcontrol/v1/zones/{zone_id}/heating/configuration/setpoint_temperature
https://smart.vaillant.com/mobile/api/v4/facilities/{serial_number}/systemcontrol/v1/zones/{zone_id}/heating/timeprogram
https://smart.vaillant.com/mobile/api/v4/facilities/{serial_number}/systemcontrol/v1/zones/{zone_id}/configuration/name
https://smart.vaillant.com/mobile/api/v4/facilities/{serial_number}/systemcontrol/v1/zones/{zone_id}/configuration/quick_veto
https://smart.vaillant.com/mobile/api/v4/facilities/{serial_number}/systemcontrol/v1/zones 


energyType, it can be
– LIVE_DATA
– CONSUMED_PRIMARY_ENERGY
– CONSUMED_ELECTRICAL_POWER
– ENVIRONMENTAL_YIELD
– SOLAR_YIELD
– GRID_FEED_IN_ENERGY
– SELF_CONSUMED_ENERGY
– EARNED_PV_ENERGY

function:
– CENTRAL_HEATING
– DHW
– COOLING
– COMBINED
– PV

timeRange
– DAY
– WEEK
– MONTH
– YEAR

start:
– any date with format yyyy-MM-dd


*/

class Vaillant extends utils.Adapter {
    /**
     * @param {Partial<ioBroker.AdapterOptions>} [options={}]
     */
    constructor(options) {
        super({
            ...options,
            name: "vaillant"
        });
        this.on("ready", this.onReady.bind(this));
        this.on("stateChange", this.onStateChange.bind(this));
        this.on("unload", this.onUnload.bind(this));

        this.jar = request.jar();
        this.updateInterval = null;
        this.reauthInterval = null;
        this.isRelogin = false;
        this.baseHeader = {
            "Vaillant-Mobile-App": "multiMATIC v2.1.45 b389 (Android)",
            "User-Agent": "okhttp/3.10.0",
            "Content-Type": "application/json; charset=UTF-8",
            "Accept-Encoding": "gzip"
        };
        this.atoken = "";
        this.serialNr = "";
        this.smartPhoneId = this.makeid();
        this.isSpineActive = true;
        if (this.config.interval < 5) {
            this.log.warn("Interval under 5min is not recommended. Set it back to 5min");
            this.config.interval = 5;
        }
        // "multimatic_xaTaFEDoEPgAXO0HmFSMeCr5kOT6LqZoQh4LTivdW4b8HncRlKJLtExwNqjaBY1ZPnYGZPGt60NNjim0zk6tl6imL77WZ2eSdEFatxlNFT5hZkdloAL8lstiBxjqNlr5pygs9JNrlcJoTrrX0sPoqLCgE7RTn35Ok77vfX9PA3T5sa3Eqph42wz9nWaZSlcC5UsbC1ooay";
    }

    /**
     * Is called when databases are connected and adapter received configuration.
     */
    async onReady() {
        // Initialize your adapter here

        // Reset the connection indicator during startup
        this.setState("info.connection", false, true);
        this.login()
            .then(() => {
                this.log.debug("Login successful");
                this.setState("info.connection", true, true);
                this.getFacility().then(() => {
                    this.cleanConfigurations().then(() => {
                        this.getMethod("https://smart.vaillant.com/mobile/api/v4/facilities/$serial/system/v1/status", "status").finally(async () => {
                            await this.sleep(10000);
                            this.getMethod("https://smart.vaillant.com/mobile/api/v4/facilities/$serial/systemcontrol/v1", "systemcontrol").finally(async () => {
                                await this.sleep(10000);
                                this.getMethod("https://smart.vaillant.com/mobile/api/v4/facilities/$serial/livereport/v1", "livereport").finally(async () => {
                                    await this.sleep(10000);
                                    this.getMethod("https://smart.vaillant.com/mobile/api/v4/facilities/$serial/spine/v1/currentPVMeteringInfo", "spine").finally(async () => {
                                        await this.sleep(10000);
                                        this.getMethod("https://smart.vaillant.com/mobile/api/v4/facilities/$serial/emf/v1/devices/", "emf").finally(() => {});
                                    });
                                });
                            });
                        });
                    });

                    this.updateInterval = setInterval(() => {
                        this.updateValues();
                    }, this.config.interval * 60 * 1000);
                });
            })
            .catch(() => {
                this.log.error("Login failed");
            });

        // in this template all states changes inside the adapters namespace are subscribed
        this.subscribeStates("*");
    }

    updateValues() {
        this.cleanConfigurations().then(() => {
            this.getMethod("https://smart.vaillant.com/mobile/api/v4/facilities/$serial/system/v1/status", "status").finally(async () => {
                await this.sleep(20000);
                this.getMethod("https://smart.vaillant.com/mobile/api/v4/facilities/$serial/systemcontrol/v1", "systemcontrol").finally(async () => {
                    await this.sleep(20000);
                    this.getMethod("https://smart.vaillant.com/mobile/api/v4/facilities/$serial/livereport/v1", "livereport").finally(async () => {
                        await this.sleep(20000);
                        this.getMethod("https://smart.vaillant.com/mobile/api/v4/facilities/$serial/spine/v1/currentPVMeteringInfo", "spine").finally(async () => {
                            await this.sleep(20000);
                            this.getMethod("https://smart.vaillant.com/mobile/api/v4/facilities/$serial/emf/v1/devices/", "emf").finally(() => {});
                        });
                    });
                });
            });
        });
    }

    login() {
        return new Promise((resolve, reject) => {
            this.jar = request.jar();
            const body = { smartphoneId: this.smartPhoneId, password: this.config.password, username: this.config.user };
            this.isRelogin && this.log.debug("Start relogin");
            request.post(
                {
                    url: "https://smart.vaillant.com/mobile/api/v4/account/authentication/v1/token/new",
                    headers: this.baseHeader,
                    followAllRedirects: true,
                    json: true,
                    body: body,
                    jar: this.jar,
                    gzip: true
                },
                (err, resp, body) => {
                    this.isRelogin && this.log.debug("Relogin completed");
                    this.isRelogin = false;
                    if (err || (resp && resp.statusCode >= 400) || !body) {
                        this.log.error("Failed to login");
                        this.log.error(err);
                        this.log.error(JSON.stringify(body));
                        this.log.error(resp.statusCode);
                        reject();
                        return;
                    }
                    this.log.debug(JSON.stringify(body));
                    if (body.errorCode || !body.body.authToken) {
                        this.log.error(JSON.stringify(body));
                        reject();
                        return;
                    }
                    this.atoken = body.body.authToken;
                    try {
                        this.authenticate(reject, resolve);
                        this.reauthInterval && clearInterval(this.reauthInterval);
                        this.reauthInterval = setInterval(() => {
                            this.login();
                        }, 4 * 60 * 60 * 1000); //4h;
                    } catch (error) {
                        this.log.error(error);
                        this.log.error(error.stack);
                        reject();
                    }
                }
            );
        });
    }
    authenticate(reject, resolve) {
        const authBody = {
            authToken: this.atoken,
            smartphoneId: this.smartPhoneId,
            username: this.config.user
        };
        request.post(
            {
                url: "https://smart.vaillant.com/mobile/api/v4/account/authentication/v1/authenticate",
                headers: this.baseHeader,
                followAllRedirects: true,
                body: authBody,
                jar: this.jar,
                json: true
            },
            (err, resp, body) => {
                if (err || (resp && resp.statusCode >= 400)) {
                    this.log.error("Authentication failed");
                    this.setState("info.connection", false, true);
                    err && this.log.error(JSON.stringify(err));
                    resp && this.log.error(resp.statusCode);
                    body && this.log.error(JSON.stringify(body));
                    reject();
                    return;
                }
                this.log.debug("Authentication successful");
                this.log.debug(JSON.stringify(body));
                this.setState("info.connection", true, true);
                if (resolve) {
                    resolve();
                }
            }
        );
    }
    cleanConfigurations() {
        return new Promise(resolve => {
            const pre = this.name + "." + this.instance;
            this.getStates(pre + ".*", (err, states) => {
                const allIds = Object.keys(states);
                allIds.forEach(async keyName => {
                    if (keyName.indexOf(".configuration") !== -1) {
                        await this.delObjectAsync(
                            keyName
                                .split(".")
                                .slice(2)
                                .join(".")
                        );
                    }
                });
                resolve();
            });
        });
    }
    getFacility() {
        return new Promise((resolve, reject) => {
            request.get(
                {
                    url: "https://smart.vaillant.com/mobile/api/v4/facilities",
                    headers: this.baseHeader,
                    followAllRedirects: true,
                    json: true,
                    jar: this.jar,
                    gzip: true
                },
                (err, resp, body) => {
                    if (err || (resp && resp.statusCode >= 400) || !body) {
                        this.log.error(err);
                        reject();
                        return;
                    }
                    this.log.debug(JSON.stringify(body));
                    if (body.errorCode || !body.body.facilitiesList || body.body.facilitiesList.length === 0) {
                        this.log.error(JSON.stringify(body));
                        reject();
                        return;
                    }
                    const facility = body.body.facilitiesList[0];
                    this.serialNr = facility.serialNumber;
                    this.setObjectNotExists(facility.serialNumber, {
                        type: "device",
                        common: {
                            name: facility.name,
                            role: "indicator",
                            write: false,
                            read: true
                        },
                        native: {}
                    });
                    try {
                        const adapter = this;
                        traverse(facility).forEach(function(value) {
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
                                adapter.setObjectNotExists(facility.serialNumber + ".general." + modPath.join("."), {
                                    type: "state",
                                    common: {
                                        name: this.key,
                                        role: "indicator",
                                        type: typeof value,
                                        write: false,
                                        read: true
                                    },
                                    native: {}
                                });
                                adapter.setState(facility.serialNumber + ".general." + modPath.join("."), value, true);
                            }
                        });
                        resolve();
                    } catch (error) {
                        this.log.error(error);
                        this.log.error(error.stack);
                        reject();
                    }
                }
            );
        });
    }
    getMethod(url, path) {
        return new Promise((resolve, reject) => {
            if (this.isRelogin) {
                resolve();
                return;
            }
            if (path === "spine" && !this.isSpineActive) {
                resolve();
                return;
            }
            this.log.debug("Get: " + path);

            url = url.replace("/$serial/", "/" + this.serialNr + "/");

            request.get(
                {
                    url: url,
                    headers: this.baseHeader,
                    followAllRedirects: true,
                    json: true,
                    jar: this.jar,
                    gzip: true
                },
                (err, resp, body) => {
                    if (body && body.errorCode) {
                        if (body.errorCode === "SPINE_NOT_SUPPORTED_BY_FACILITY") {
                            this.isSpineActive = false;
                        }
                        this.log.debug(JSON.stringify(body.errorCode));
                        reject();
                        return;
                    }
                    if (err || (resp && resp.statusCode >= 400)) {
                        this.setState("info.connection", false, true);
                        if ((resp && resp.statusCode === 401) || JSON.stringify(body) === "NOT_AUTHORIZED") {
                            this.log.info(JSON.stringify(body));
                            if (!this.isRelogin) {
                                this.log.info("401 Error try to relogin.");
                                this.isRelogin = true;
                                setTimeout(() => {
                                    this.login().then(() => {});
                                }, 10000);
                            } else {
                                this.log.info("Instance is trying to relogin.");
                            }
                        } else {
                            err && this.log.error(err);
                            resp && this.log.error(resp && resp.statusCode);
                            body && this.log.error(JSON.stringify(body));
                            this.log.error("Failed to get:" + path);
                        }
                        reject();
                        return;
                    }
                    this.log.debug(JSON.stringify(body));

                    try {
                        const adapter = this;
                        traverse(body.body).forEach(function(value) {
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

                                if (path === "systemcontrol" && modPath[0].indexOf("parameters") !== -1 && modPath[1] === "name") {
                                    //add value field for parameters
                                    adapter.setObjectNotExists(adapter.serialNr + "." + path + "." + modPath[0] + ".parameterValue", {
                                        type: "state",
                                        common: {
                                            name: "Value for " + value + ". See definition for values.",
                                            role: "indicator",
                                            type: "mixed",
                                            write: true,
                                            read: true
                                        },
                                        native: {}
                                    });
                                }
                                if (path === "emf") {
                                    if (modPath[0].indexOf("reports") !== -1) {
                                        modPath[0] = this.parent.node.function + "_" + this.parent.node.energyType;
                                    }
                                }

                                adapter.setObjectNotExists(adapter.serialNr + "." + path + "." + modPath.join("."), {
                                    type: "state",
                                    common: {
                                        name: this.key,
                                        role: "indicator",
                                        type: typeof value,
                                        write: false,
                                        read: true
                                    },
                                    native: {}
                                });
                                adapter.setState(adapter.serialNr + "." + path + "." + modPath.join("."), value, true);
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
                                    adapter.setObjectNotExists(adapter.serialNr + "." + path + "." + modPath.join("."), {
                                        type: "state",
                                        common: {
                                            name: this.node.name,
                                            role: "indicator",
                                            type: "mixed",
                                            write: false,
                                            read: true
                                        },
                                        native: {}
                                    });
                                }
                            }
                        });
                        resolve();
                    } catch (error) {
                        this.log.error(error);
                        this.log.error(error.stack);
                        reject();
                    }
                }
            );
        });
    }
    async setMethod(id, val) {
        return new Promise(async (resolve, reject) => {
            const idArray = id.split(".");
            const action = idArray[idArray.length - 1];
            const idPath = id
                .split(".")
                .splice(2)
                .slice(0, 3);
            let path = [];
            let url = "";
            const body = {};
            if (id.indexOf("configuration") !== -1) {
                const idState = await this.getStateAsync(idPath.join(".") + "._id");
                path = idArray.splice(4);
                if (idState && idState.val) {
                    path.splice(1, 0, idState.val);
                }
                path[0] = path[0].replace(/[0-9]/g, "");
                path = path.join("/");
                url = "https://smart.vaillant.com/mobile/api/v4/facilities/" + this.serialNr + "/systemcontrol/v1/" + path;
                body[action] = val;
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

            request.put(
                {
                    url: url,
                    headers: this.baseHeader,
                    followAllRedirects: true,
                    body: body,
                    json: true,
                    gzip: true,
                    jar: this.jar
                },
                (err, resp, body) => {
                    if (err || (resp && resp.statusCode >= 400)) {
                        this.log.error(err);
                        this.log.error(JSON.stringify(body));
                        reject();
                        return;
                    }
                    try {
                        // this.log.info(body);
                        resolve();
                    } catch (error) {
                        this.log.error(error);
                        this.log.error(error.stack);
                        reject();
                    }
                }
            );
        });
    }

    makeid() {
        const length = 202;
        let result = "";
        const characters = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789";
        const charactersLength = characters.length;
        for (let i = 0; i < length; i++) {
            result += characters.charAt(Math.floor(Math.random() * charactersLength));
        }

        return "multimatic_" + result;
    }
    sleep(ms) {
        return new Promise(resolve => setTimeout(resolve, ms));
    }
    /**
     * Is called when adapter shuts down - callback has to be called under any circumstances!
     * @param {() => void} callback
     */
    onUnload(callback) {
        try {
            this.log.info("cleaned everything up...");
            clearInterval(this.updateInterval);
            clearInterval(this.reauthInterval);
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
    onStateChange(id, state) {
        if (state) {
            if (!state.ack) {
                if (id.indexOf("configuration") !== -1 || id.indexOf("parameterValue") !== -1) {
                    this.setMethod(id, state.val);
                }
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
    module.exports = options => new Vaillant(options);
} else {
    // otherwise start the instance directly
    new Vaillant();
}
