/**
 * Google Authenticator uses protobuff to encode the 2fa data.
 *
 * Some newer exports contain malformed field lengths inside an OTP record.
 * Protobufjs aborts on those records, so we fall back to a lenient decoder
 * that can recover the payload by validating the remaining field stream.
 *
 * @param {Uint8Array} payload
 */
function decodeProtobuf(payload) {
  try {
    return decodeProtobufStrict(payload);
  } catch (error) {
    return decodeProtobufLenient(payload, error);
  }
}

function decodeProtobufStrict(payload) {
  const protobuf = require("protobufjs");

  const root = protobuf.loadSync("./src/google_auth.proto");
  const MigrationPayload = root.lookupType("googleauth.MigrationPayload");
  const message = MigrationPayload.decode(payload);

  return MigrationPayload.toObject(message, {
    longs: String,
    enums: String,
    bytes: String,
  });
}

const ALGORITHM_BY_ID = {
  0: "ALGORITHM_UNSPECIFIED",
  1: "SHA1",
  2: "SHA256",
  3: "SHA512",
  4: "MD5",
};

const DIGITS_BY_ID = {
  0: "DIGIT_COUNT_UNSPECIFIED",
  1: "SIX",
  2: "EIGHT",
  3: "SEVEN",
};

const OTP_TYPE_BY_ID = {
  0: "OTP_TYPE_UNSPECIFIED",
  1: "HOTP",
  2: "TOTP",
};

function readVarint(buffer, start) {
  let value = 0n;
  let shift = 0n;
  let pos = start;

  while (pos < buffer.length) {
    const byte = buffer[pos++];
    value |= BigInt(byte & 0x7f) << shift;

    if ((byte & 0x80) === 0) {
      return [value, pos];
    }

    shift += 7n;
  }

  throw new Error(`Unexpected end of protobuf varint at offset ${start}`);
}

function skipUnknownField(buffer, start, wireType) {
  switch (wireType) {
    case 0:
      return readVarint(buffer, start)[1];
    case 1:
      return start + 8 <= buffer.length ? start + 8 : null;
    case 2: {
      const [length, afterLength] = readVarint(buffer, start);
      const end = afterLength + Number(length);
      return end <= buffer.length ? end : null;
    }
    case 5:
      return start + 4 <= buffer.length ? start + 4 : null;
    default:
      return null;
  }
}

function parseOtpParameters(buffer) {
  const result = parseOtpParametersFrom(buffer, 0, 0, {});

  if (!result) {
    throw new Error("Unable to decode OTP parameters");
  }

  return result;
}

function parseOtpParametersFrom(buffer, start, lastFieldNumber, account) {
  if (start === buffer.length) {
    return account;
  }

  const [tag, afterTag] = readVarint(buffer, start);
  const fieldNumber = Number(tag >> 3n);
  const wireType = Number(tag & 7n);

  if (fieldNumber === 0 || fieldNumber < lastFieldNumber) {
    return null;
  }

  if (fieldNumber === 1) {
    if (wireType !== 2) {
      return null;
    }

    const [length, afterLength] = readVarint(buffer, afterTag);
    const end = afterLength + Number(length);
    if (end > buffer.length) {
      return null;
    }

    return parseOtpParametersFrom(buffer, end, fieldNumber, {
      ...account,
      secret: buffer.subarray(afterLength, end).toString("base64"),
    });
  }

  if (fieldNumber === 2 || fieldNumber === 3 || fieldNumber === 8) {
    if (wireType === 2) {
      const [declaredLength, afterLength] = readVarint(buffer, afterTag);
      const minEnd = afterLength + Number(declaredLength);
      if (minEnd > buffer.length) {
        return null;
      }

      const property = fieldNumber === 2 ? "name" : fieldNumber === 3 ? "issuer" : "uniqueId";

      for (let end = minEnd; end <= buffer.length; end += 1) {
        const candidate = parseOtpParametersFrom(buffer, end, fieldNumber, {
          ...account,
          [property]: buffer.subarray(afterLength, end).toString("utf8"),
        });

        if (candidate) {
          return candidate;
        }
      }
    }

    if (fieldNumber === 3 && wireType === 3) {
      for (let end = afterTag; end <= buffer.length; end += 1) {
        const candidate = parseOtpParametersFrom(buffer, end, fieldNumber, {
          ...account,
          issuer: buffer.subarray(afterTag, end).toString("utf8").trimEnd(),
        });

        if (candidate) {
          return candidate;
        }
      }
    }

    return null;
  }

  if (fieldNumber === 4 || fieldNumber === 5 || fieldNumber === 6 || fieldNumber === 7) {
    if (wireType !== 0) {
      return null;
    }

    const [value, afterValue] = readVarint(buffer, afterTag);
    const normalized = Number(value);

    const nextAccount = {
      ...account,
    };

    if (fieldNumber === 4) {
      nextAccount.algorithm = ALGORITHM_BY_ID[normalized] || String(normalized);
    }

    if (fieldNumber === 5) {
      nextAccount.digits = DIGITS_BY_ID[normalized] || String(normalized);
    }

    if (fieldNumber === 6) {
      nextAccount.type = OTP_TYPE_BY_ID[normalized] || String(normalized);
    }

    if (fieldNumber === 7) {
      nextAccount.counter = value.toString();
    }

    return parseOtpParametersFrom(buffer, afterValue, fieldNumber, nextAccount);
  }

  const nextOffset = skipUnknownField(buffer, afterTag, wireType);
  if (nextOffset == null) {
    return null;
  }

  return parseOtpParametersFrom(buffer, nextOffset, fieldNumber, account);
}

function decodeProtobufLenient(payload, originalError) {
  const buffer = Buffer.from(payload);
  const decoded = {
    otpParameters: [],
  };

  let offset = 0;
  while (offset < buffer.length) {
    const [tag, afterTag] = readVarint(buffer, offset);
    const fieldNumber = Number(tag >> 3n);
    const wireType = Number(tag & 7n);

    if (fieldNumber === 1) {
      if (wireType !== 2) {
        throw originalError;
      }

      const [length, afterLength] = readVarint(buffer, afterTag);
      const end = afterLength + Number(length);
      if (end > buffer.length) {
        throw originalError;
      }

      decoded.otpParameters.push(parseOtpParameters(buffer.subarray(afterLength, end)));
      offset = end;
      continue;
    }

    if (wireType !== 0) {
      throw originalError;
    }

    const [value, afterValue] = readVarint(buffer, afterTag);
    const normalized = Number(value);

    if (fieldNumber === 2) {
      decoded.version = normalized;
    }

    if (fieldNumber === 3) {
      decoded.batchSize = normalized;
    }

    if (fieldNumber === 4) {
      decoded.batchIndex = normalized;
    }

    if (fieldNumber === 5) {
      decoded.batchId = normalized;
    }

    offset = afterValue;
  }

  return decoded;
}

/**
 * Convert a base64 to base32.
 * Most Time based One Time Password (TOTP)
 * password managers use this as the "secret key" when generating a code.
 *
 * An example is: https://totp.danhersam.com/.
 *
 * @returns RFC3548 compliant base32 string
 */
function toBase32(base64String) {
  const base32 = require("./edbase32");
  const raw = Buffer.from(base64String, "base64");
  return base32.encode(raw);
}

/**
 * The data in the URI from Google Authenticator
 *  is a protobuff payload which is Base64 encoded and then URI encoded.
 * This function decodes those, and then decodes the protobuf data contained inside.
 *
 * @param {String} data the `data` query parameter from the totp migration string that google authenticator outputs.
 */
function accountsFromPayload(payload) {
  if (![1, 2].includes(payload.version)) {
    console.error(`Expected payload version 1 or 2, but was ${payload.version}! Please comment your payload version (which is ${payload.version}), Google Authenticator app version and how many 2FA codes you exported in https://github.com/krissrex/google-authenticator-exporter/issues/23 .`);
  }

  const accounts = payload.otpParameters.map((account) => {
    account.totpSecret = toBase32(account.secret);
    return account;
  });

  return accounts;
}

function decode(data) {
  const buffer = Buffer.from(decodeURIComponent(data), "base64");
  const payload = decodeProtobuf(buffer);

  return accountsFromPayload(payload);
}

function getBatchState(payload) {
  const batchSize = Number(payload.batchSize || 1);
  const batchIndex = Number(payload.batchIndex || 0);
  const isMultiPart = batchSize > 1;

  return {
    batchSize,
    batchIndex,
    batchId: payload.batchId,
    currentChunk: batchIndex + 1,
    isMultiPart,
    isComplete: !isMultiPart,
  };
}

function decodeWithMetadata(data) {
  const buffer = Buffer.from(decodeURIComponent(data), "base64");
  const payload = decodeProtobuf(buffer);
  const accounts = accountsFromPayload(payload);

  return {
    accounts,
    metadata: {
      version: Number(payload.version),
      ...getBatchState(payload),
    },
  };
}

function logBatchWarning(metadata) {
  if (!metadata.isMultiPart) {
    return;
  }

  console.warn(
    `This QR is only part ${metadata.currentChunk} of ${metadata.batchSize} from a multi-QR export. ` +
    "You need to scan all QR codes from the Google Authenticator export to recover every account."
  );
}

/**
 * Write the json with account information to a file
 * so it can be uploaded to other password managers etc easily.
 *
 * @param {String} data A `JSON.stringify`ed list of accounts.
 */
function saveToFile(filename, data) {
  const fs = require("fs");
  if (fs.existsSync(filename)) {
    return console.error(`File "${filename}" exists!`);
  }

  fs.writeFileSync(filename, data);
}

/**
 * Generate qrcodes from the accounts that can be scanned with an authenticator app
 * @param accounts A list of the auth accounts
 */
function saveToQRCodes(accounts) {
  const QRCode = require("qrcode");
  const fs = require("fs");

  const directory = "./qrCodes";
  if (!fs.existsSync(directory)) {
    fs.mkdirSync(directory);
  }

  /** Windows is picky with filenames. */
  const sanitizeFilename = (filename) => filename.replace(/[\<>:"\/\\|?*#%&{}$+!`'=@]/g, "");

  accounts.forEach((account) => {
    const name = account.name || "";
    const issuer = account.issuer || "";
    const secret = account.totpSecret;

    const url = `otpauth://totp/${encodeURI(name)}?secret=${encodeURI(secret)}&issuer=${encodeURI(issuer)}`;
    const file = `${directory}/${issuer || "No issuer"} (${sanitizeFilename(name)}).png`;

    if (fs.existsSync(file)) {
      console.log(`${file.yellow} already exists.`);
    } else {
      QRCode.toFile(file, url, (error) => {
        if (error != null) {
          console.log(`Something went wrong while creating ${file}`, error);
        }
        console.log(`${file.green} created.`);
      });
    }
  });
}

/**
 * Saves to json if the user said yes.
 * @param promptResult The results from the promt given to the user.
 * @param accounts A list of the auth accounts.
 */
function toJson(filename, saveToFileInput, accounts) {
  console.log(filename);
  console.log(saveToFileInput);

  if (saveToFileInput && filename) {
    console.log(`Saving to "${filename}"...`);
    saveToFile(filename, JSON.stringify(accounts, undefined, 4));
  } else {
    console.log("Not saving. Here is the data:");
    console.log(accounts);
    console.log("What you want to use as secret key in other password managers is ".yellow + "'totpSecret'".blue + ", not 'secret'!".yellow);
  }
}

/**
 * @param {string} uri The raw QR code uri
 * @returns decoded data with account info
 */
function decodeExportUri(uri) {
  const queryParams = new URL(uri).search;
  const data = new URLSearchParams(queryParams).get("data");

  return decode(data);
}

function decodeExportUriWithMetadata(uri) {
  const queryParams = new URL(uri).search;
  const data = new URLSearchParams(queryParams).get("data");

  return decodeWithMetadata(data);
}

/**
 * Act as a CLI and ask for `otpauth-migration://` uri and optionally file to store in.
 */
function promptUserForUri() {
  let prompt;
  try {
    prompt = require("prompt");
  } catch (ex) {
    console.error("Error! Missing dependencies:");
    console.error("You need to first run: npm install");
    process.exit(1);
  }

  console.log("Enter the URI from Google Authenticator QR code.");
  console.log("The URI looks like otpauth-migration://offline?data=... \n");

  console.log("You can get it by exporting from Google Authenticator app, then scanning the QR with");
  console.log("e.g. https://play.google.com/store/apps/details?id=com.google.zxing.client.android");
  console.log("and copying the text to your pc, e.g. with Google Keep ( https://keep.google.com/ )");

  require("colors");
  console.log("By using online QR decoders or untrusted ways of transferring the URI text,".red);
  console.log("you risk someone storing the QR code or URI text and stealing your 2FA codes!".red);
  console.log("Remember that the data contains the website, your email and the 2FA code!".red);

  // Future improvement: add capability to upload/select QR jpg and scan it.
  // I took a picture of the QR with my camera, because Google Authenticator prevents screenshots.
  // I then uploaded the picture to my pc via the SD-card and scanned with my phone...
  // Very many steps

  const resultType = {
    QRCODE: "qrcode",
    JSON: "json",
  };

  const mode = process.argv.includes("-q") ? resultType.QRCODE : resultType.JSON;

  const promptVariables = ["totpUri"];

  if (mode === resultType.JSON) {
    promptVariables.push("saveToFile");
    promptVariables.push("filename");
  }

  prompt.start();
  prompt.get(promptVariables, (err, result) => {
    if (err) {
      return console.error(err);
    }

    const uri = result.totpUri;
    const { accounts, metadata } = decodeExportUriWithMetadata(uri);
    logBatchWarning(metadata);

    switch (mode) {
      case resultType.QRCODE:
        saveToQRCodes(accounts);
        break;
      case resultType.JSON:
        const saveToFileInput = result.saveToFile.toLowerCase().startsWith("y");
        toJson(result.filename, saveToFileInput, accounts);
        break;
    }
  });
}

exports.decodeExportUri = decodeExportUri;
exports.decodeExportUriWithMetadata = decodeExportUriWithMetadata;
exports.logBatchWarning = logBatchWarning;

if (require.main === module) {
  // Wont run inside tests where this file is just imported
  promptUserForUri();
}
