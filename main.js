"use strict";

/*
 * Created with @iobroker/create-adapter v1.20.0
 */

// The adapter-core module gives you access to the core ioBroker functions
// you need to create an adapter
const utils = require("@iobroker/adapter-core");
const request = require("request");
const traverse = require("traverse");

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
        this.atoken = "";
        this.serialNr = "";
        this.adapterStopped = false;
        this.isSpineActive = true;
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
        // Reset the connection indicator during startup
        this.setState("info.connection", false, true);
        this.login()
            .then(() => {
                this.setState("info.connection", true, true);
                this.getFacility()
                    .then(() => {
                        this.cleanConfigurations()
                            .then(() => {
                                this.getMethod("https://smart.vaillant.com/mobile/api/v4/facilities/$serial/system/v1/status", "status")
                                    .catch(() => this.log.debug("Failed to get status"))
                                    .finally(async () => {
                                        await this.sleep(10000);
                                        this.getMethod("https://smart.vaillant.com/mobile/api/v4/facilities/$serial/systemcontrol/v1", "systemcontrol")
                                            .catch(() => this.log.debug("Failed to get systemcontrol"))
                                            .finally(async () => {
                                                await this.sleep(10000);
                                                this.getMethod("https://smart.vaillant.com/mobile/api/v4/facilities/$serial/livereport/v1", "livereport")
                                                    .catch(() => this.log.debug("Failed to get livereport"))
                                                    .finally(async () => {
                                                        await this.sleep(10000);
                                                        this.getMethod("https://smart.vaillant.com/mobile/api/v4/facilities/$serial/spine/v1/currentPVMeteringInfo", "spine")
                                                            .catch(() => this.log.debug("Failed to get spine"))
                                                            .finally(async () => {
                                                                await this.sleep(10000);
                                                                this.getMethod("https://smart.vaillant.com/mobile/api/v4/facilities/$serial/emf/v1/devices/", "emf")
                                                                    .catch(() => this.log.debug("Failed to get emf"))
                                                                    .finally(async () => {
                                                                        await this.sleep(10000);
                                                                        this.getMethod("https://smart.vaillant.com/mobile/api/v4/facilities/$serial/hvacstate/v1/overview", "hvacstate")
                                                                            .catch(() => this.log.debug("Failed to get hvacstate"))
                                                                            .finally(async () => {
                                                                                await this.sleep(10000);
                                                                                this.getMethod("https://smart.vaillant.com/mobile/api/v4/facilities/$serial/rbr/v1/rooms", "rooms")
                                                                                    .catch(() => this.log.debug("Failed to get rooms"))
                                                                                    .finally(() => {});
                                                                            });
                                                                    });
                                                            });
                                                    });
                                            });
                                    });
                            })
                            .catch(() => {
                                this.log.error("clean configuration failed");
                            });

                        this.updateInterval = setInterval(() => {
                            this.updateValues();
                        }, this.config.interval * 60 * 1000);
                        this.log.debug("Set update interval to: " + this.config.interval + "min");
                    })
                    .catch(() => {
                        this.log.error("facility failed");
                    });
            })
            .catch(() => {
                this.log.error("Login failed");
            });

        // in this template all states changes inside the adapters namespace are subscribed
        this.subscribeStates("*");
    }

    updateValues() {
        this.log.debug("update values");
        this.cleanConfigurations()
            .then(async () => {
                await this.sleep(5000);
                this.getMethod("https://smart.vaillant.com/mobile/api/v4/facilities/$serial/system/v1/status", "status")
                    .catch(() => this.log.debug("Failed to get status"))
                    .finally(async () => {
                        await this.sleep(20000);
                        this.getMethod("https://smart.vaillant.com/mobile/api/v4/facilities/$serial/systemcontrol/v1", "systemcontrol")
                            .catch(() => this.log.debug("Failed to get systemcontrol"))
                            .finally(async () => {
                                await this.sleep(20000);
                                this.getMethod("https://smart.vaillant.com/mobile/api/v4/facilities/$serial/livereport/v1", "livereport")
                                    .catch(() => this.log.debug("Failed to get livereport"))
                                    .finally(async () => {
                                        await this.sleep(20000);
                                        this.getMethod("https://smart.vaillant.com/mobile/api/v4/facilities/$serial/spine/v1/currentPVMeteringInfo", "spine")
                                            .catch(() => this.log.debug("Failed to get spine"))
                                            .finally(async () => {
                                                await this.sleep(20000);
                                                this.getMethod("https://smart.vaillant.com/mobile/api/v4/facilities/$serial/emf/v1/devices/", "emf")
                                                    .catch(() => this.log.debug("Failed to get emf"))
                                                    .finally(async () => {
                                                        await this.sleep(10000);
                                                        this.getMethod("https://smart.vaillant.com/mobile/api/v4/facilities/$serial/rbr/v1/rooms", "rooms")
                                                            .catch(() => this.log.debug("Failed to get rooms"))
                                                            .finally(() => {});
                                                    });
                                            });
                                    });
                            });
                    });
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
                    json: true,
                    body: body,
                    jar: this.jar,
                    gzip: true,
                },
                (err, resp, body) => {
                    this.isRelogin && this.log.debug("Relogin completed start reauth");

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
                        this.log.debug("Login successful");
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
            smartphoneId: this.config.smartPhoneId,
            username: this.config.user,
        };
        request.post(
            {
                url: "https://smart.vaillant.com/mobile/api/v4/account/authentication/v1/authenticate",
                headers: this.baseHeader,
                followAllRedirects: true,
                body: authBody,
                jar: this.jar,
                json: true,
            },
            (err, resp, body) => {
                this.isRelogin = false;
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
        return new Promise((resolve) => {
            if (this.config.cleantype) {
                this.log.debug("skip clean config");
                resolve();
                return;
            }
            this.log.debug("clean config");
            const pre = this.name + "." + this.instance;
            this.getStates(pre + ".*", (err, states) => {
                const allIds = Object.keys(states);
                const promiseArray = [];
                allIds.forEach(async (keyName) => {
                    const promise = new Promise(async (resolve, reject) => {
                        if (keyName.indexOf(".configuration") !== -1) {
                            try {
                                await this.delObjectAsync(keyName.split(".").slice(2).join("."));
                            } catch (error) {
                                this.log.debug(error);
                            }
                        }
                        resolve();
                    });
                    promiseArray.push(promise);
                });
                Promise.all(promiseArray)
                    .then(() => {
                        this.log.debug("clean done");
                        resolve();
                    })
                    .catch(() => {
                        this.log.error("deleting failed");
                        resolve();
                    });
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
                    gzip: true,
                },
                async (err, resp, body) => {
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
            this.log.debug("Get: " + path);

            url = url.replace("/$serial/", "/" + this.serialNr + "/");

            request.get(
                {
                    url: url,
                    headers: this.baseHeader,
                    followAllRedirects: true,
                    json: true,
                    jar: this.jar,
                    gzip: true,
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
                        this.log.debug("Error response from: " + path);
                        this.setState("info.connection", false, true);
                        if ((resp && resp.statusCode === 401) || JSON.stringify(body) === "NOT_AUTHORIZED") {
                            this.log.info(JSON.stringify(body));
                            if (!this.isRelogin) {
                                this.log.info("401 Error try to relogin.");
                                this.isRelogin = true;
                                this.reloginTimeout && clearTimeout(this.reloginTimeout);
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
                            err && this.log.error(err);
                            resp && this.log.error(resp && resp.statusCode);
                            body && this.log.error(JSON.stringify(body));
                            this.log.error("Failed to get:" + path);
                        }
                        reject();
                        return;
                    }
                    this.log.debug(path + " successful");
                    this.log.debug(JSON.stringify(body));
                    if (!body) {
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
                                    }
                                }

                                adapter
                                    .setObjectNotExistsAsync(adapter.serialNr + "." + path + "." + modPath.join("."), {
                                        type: "state",
                                        common: {
                                            name: this.key,
                                            role: "indicator",
                                            type: typeof value,
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
                url = "https://smart.vaillant.com/mobile/api/v4/facilities/" + this.serialNr + "/systemcontrol/v1/" + path;
                if (idPath[1] === "rooms") {
                    let roomId = idPath[2].replace("rooms", "");
                    roomId = parseInt(roomId) - 1;
                    url = "https://smart.vaillant.com/mobile/api/v4/facilities/" + this.serialNr + "/rbr/v1/rooms/" + roomId + "/configuration/quickVeto";
                }
                body[action] = val;
                body["duration"] = 180;
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
                    jar: this.jar,
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
    decrypt(key, value) {
        let result = "";
        for (let i = 0; i < value.length; ++i) {
            result += String.fromCharCode(key[i % key.length].charCodeAt(0) ^ value.charCodeAt(i));
        }
        return result;
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
        if (this.adapterStopped) {
            ms = 0;
        }
        return new Promise((resolve) => setTimeout(resolve, ms));
    }
    /**
     * Is called when adapter shuts down - callback has to be called under any circumstances!
     * @param {() => void} callback
     */
    onUnload(callback) {
        try {
            this.log.info("cleaned everything up...");
            this.adapterStopped = true;
            clearInterval(this.updateInterval);
            clearInterval(this.reauthInterval);
            clearTimeout(this.reloginTimeout);
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
    module.exports = (options) => new Vaillant(options);
} else {
    // otherwise start the instance directly
    new Vaillant();
}
