/*
    Licensed to the Apache Software Foundation (ASF) under one
    or more contributor license agreements.  See the NOTICE file
    distributed with this work for additional information
    regarding copyright ownership.  The ASF licenses this file
    to you under the Apache License, Version 2.0 (the
    "License"); you may not use this file except in compliance
    with the License.  You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

    Unless required by applicable law or agreed to in writing,
    software distributed under the License is distributed on an
    "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
    KIND, either express or implied.  See the License for the
    specific language governing permissions and limitations
    under the License.
*/


var CTX = function(input_parameter) {
    "use strict";

    var ctx = this,
        CTXLIST,
        prepareModule;

    CTXLIST = {
        "ED25519": {
            "BITS": "256",
            "FIELD": "25519",
            "CURVE": "ED25519",
            "@NB": 32,
            "@BASE": 24,
            "@NBT": 255,
            "@M8": 5,
            "@MT": 1,
            "@CT": 1,
            "@PF": 0
        },

        "C25519": {
            "BITS": "256",
            "FIELD": "25519",
            "CURVE": "C25519",
            "@NB": 32,
            "@BASE": 24,
            "@NBT": 255,
            "@M8": 5,
            "@MT": 1,
            "@CT": 2,
            "@PF": 0
        },

        "NIST256": {
            "BITS": "256",
            "FIELD": "NIST256",
            "CURVE": "NIST256",
            "@NB": 32,
            "@BASE": 24,
            "@NBT": 256,
            "@M8": 7,
            "@MT": 0,
            "@CT": 0,
            "@PF": 0
        },

        "NIST384": {
            "BITS": "384",
            "FIELD": "NIST384",
            "CURVE": "NIST384",
            "@NB": 48,
            "@BASE": 56,
            "@NBT": 384,
            "@M8": 7,
            "@MT": 0,
            "@CT": 0,
            "@PF": 0
        },

        "BRAINPOOL": {
            "BITS": "256",
            "FIELD": "BRAINPOOL",
            "CURVE": "BRAINPOOL",
            "@NB": 32,
            "@BASE": 24,
            "@NBT": 256,
            "@M8": 7,
            "@MT": 0,
            "@CT": 0,
            "@PF": 0
        },

        "ANSSI": {
            "BITS": "256",
            "FIELD": "ANSSI",
            "CURVE": "ANSSI",
            "@NB": 32,
            "@BASE": 24,
            "@NBT": 256,
            "@M8": 7,
            "@MT": 0,
            "@CT": 0,
            "@PF": 0
        },

        "HIFIVE": {
            "BITS": "336",
            "FIELD": "HIFIVE",
            "CURVE": "HIFIVE",
            "@NB": 42,
            "@BASE": 23,
            "@NBT": 336,
            "@M8": 5,
            "@MT": 1,
            "@CT": 1,
            "@PF": 0
        },

        "GOLDILOCKS": {
            "BITS": "448",
            "FIELD": "GOLDILOCKS",
            "CURVE": "GOLDILOCKS",
            "@NB": 56,
            "@BASE": 23,
            "@NBT": 448,
            "@M8": 7,
            "@MT": 2,
            "@CT": 1,
            "@PF": 0
        },

        "C41417": {
            "BITS": "416",
            "FIELD": "C41417",
            "CURVE": "C41417",
            "@NB": 52,
            "@BASE": 23,
            "@NBT": 414,
            "@M8": 7,
            "@MT": 1,
            "@CT": 1,
            "@PF": 0
        },

        "NIST521": {
            "BITS": "528",
            "FIELD": "NIST521",
            "CURVE": "NIST521",
            "@NB": 66,
            "@BASE": 23,
            "@NBT": 521,
            "@M8": 7,
            "@MT": 1,
            "@CT": 0,
            "@PF": 0
        },

        "NUMS256W": {
            "BITS": "256",
            "FIELD": "256PM",
            "CURVE": "NUMS256W",
            "@NB": 32,
            "@BASE": 24,
            "@NBT": 256,
            "@M8": 3,
            "@MT": 1,
            "@CT": 0,
            "@PF": 0
        },

        "NUMS256E": {
            "BITS": "256",
            "FIELD": "256PM",
            "CURVE": "NUMS256E",
            "@NB": 32,
            "@BASE": 24,
            "@NBT": 256,
            "@M8": 3,
            "@MT": 1,
            "@CT": 1,
            "@PF": 0
        },

        "NUMS384W": {
            "BITS": "384",
            "FIELD": "384PM",
            "CURVE": "NUMS384W",
            "@NB": 48,
            "@BASE": 23,
            "@NBT": 384,
            "@M8": 3,
            "@MT": 1,
            "@CT": 0,
            "@PF": 0
        },

        "NUMS384E": {
            "BITS": "384",
            "FIELD": "384PM",
            "CURVE": "NUMS384E",
            "@NB": 48,
            "@BASE": 23,
            "@NBT": 384,
            "@M8": 3,
            "@MT": 1,
            "@CT": 1,
            "@PF": 0
        },

        "NUMS512W": {
            "BITS": "512",
            "FIELD": "512PM",
            "CURVE": "NUMS512W",
            "@NB": 64,
            "@BASE": 23,
            "@NBT": 512,
            "@M8": 7,
            "@MT": 1,
            "@CT": 0,
            "@PF": 0
        },

        "NUMS512E": {
            "BITS": "512",
            "FIELD": "512PM",
            "CURVE": "NUMS512E",
            "@NB": 64,
            "@BASE": 23,
            "@NBT": 512,
            "@M8": 7,
            "@MT": 1,
            "@CT": 1,
            "@PF": 0
        },

        "BN254": {
            "BITS": "256",
            "FIELD": "BN254",
            "CURVE": "BN254",
            "@NB": 32,
            "@BASE": 24,
            "@NBT": 254,
            "@M8": 3,
            "@MT": 0,
            "@CT": 0,
            "@PF": 1
        },

        "BN254CX": {
            "BITS": "256",
            "FIELD": "BN254CX",
            "CURVE": "BN254CX",
            "@NB": 32,
            "@BASE": 24,
            "@NBT": 254,
            "@M8": 3,
            "@MT": 0,
            "@CT": 0,
            "@PF": 1
        },

        "BLS383": {
            "BITS": "384",
            "FIELD": "BLS383",
            "CURVE": "BLS383",
            "@NB": 48,
            "@BASE": 23,
            "@NBT": 383,
            "@M8": 3,
            "@MT": 0,
            "@CT": 0,
            "@PF": 2
        },

        "RSA2048": {
            "BITS": "1024",
            "TFF": "2048",
            "@NB": 128,
            "@BASE": 22,
            "@ML": 2,
        },

        "RSA3072": {
            "BITS": "384",
            "TFF": "3072",
            "@NB": 48,
            "@BASE": 23,
            "@ML": 8,
        },

        "RSA4096": {
            "BITS": "512",
            "TFF": "4096",
            "@NB": 64,
            "@BASE": 23,
            "@ML": 8,
        },
    };

    prepareModule = function (moduleName, fileName, propertyName) {
        if (!propertyName) {
            propertyName = moduleName;
        }

        if (typeof require !== "undefined") {
            if (!fileName) {
                fileName = moduleName.toLowerCase();
            }

            ctx[propertyName] = require("./" + fileName)[moduleName](ctx);
        } else {
            ctx[propertyName] = window[moduleName](ctx);
        }
    };

    prepareModule("AES");
    prepareModule("GCM");
    prepareModule("UInt64");
    prepareModule("HASH256");
    prepareModule("HASH384");
    prepareModule("HASH512");
    prepareModule("SHA3");
    prepareModule("RAND");
    prepareModule("NewHope");
    prepareModule("NHS");

    if (typeof input_parameter === "undefined") {
        return;
    }

    ctx.config = CTXLIST[input_parameter];

    prepareModule("BIG");
    prepareModule("DBIG", "big");

    // Set RSA parameters
    if (typeof ctx.config["TFF"] !== "undefined") {
        prepareModule("FF");
        prepareModule("RSA");
        prepareModule("rsa_public_key", "rsa");
        prepareModule("rsa_private_key", "rsa");
        return;
    }

    // Set Elliptic Curve parameters
    if (typeof ctx.config["CURVE"] !== "undefined") {
        prepareModule("ROM_CURVE_" + ctx.config["CURVE"], "rom_curve", "ROM_CURVE");
        prepareModule("ROM_FIELD_" + ctx.config["FIELD"], "rom_field", "ROM_FIELD");

        prepareModule("FP");
        prepareModule("ECP");
        prepareModule("ECDH");

        if (ctx.config["@PF"] != 0) {
            prepareModule("FP2");
            prepareModule("FP4");
            prepareModule("FP12");
            prepareModule("ECP2");
            prepareModule("PAIR");
            prepareModule("MPIN");
        }

        return;
    }

};

if (typeof module !== "undefined" && typeof module.exports !== "undefined") {
    module.exports = CTX;
}
