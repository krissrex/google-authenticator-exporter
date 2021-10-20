
/**
 * Google Authenticator uses protobuff to encode the 2fa data.
 * 
 * @param {Uint8Array} payload 
 */
function decodeProtobuf(payload) {
  const protobuf = require("protobufjs");

  const root = protobuf.loadSync("./src/google_auth.proto");

  const MigrationPayload = root.lookupType("googleauth.MigrationPayload");

  const message = MigrationPayload.decode(payload);

  return MigrationPayload.toObject(message, {
    longs: String,
    enums: String,
    bytes: String,
  })
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
  const base32 = require('./edbase32');
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
function decode(data) {
  const buffer = Buffer.from(decodeURIComponent(data), "base64");

  const payload = decodeProtobuf(buffer);
  
  const accounts = payload.otpParameters.map(account => {
    account.totpSecret = toBase32(account.secret);
    return account;
  })

  return accounts;
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
function saveToQRCodes(accounts){
  
  const QRCode = require('qrcode')
  const fs = require("fs");
  
  const directory = "./qrCodes"
  if(!fs.existsSync(directory)){
    fs.mkdirSync(directory)
  }

  accounts.forEach(account => {
    const name = account.name
    const issuer = account.issuer
    const secret = account.totpSecret
    
    const url = `otpauth://totp/${encodeURI(name)}?secret=${encodeURI(secret)}&issuer=${encodeURI(issuer)}`
    const file = `${directory}/${issuer}(${name}).png`
  
    if(fs.existsSync(file)) {
      console.log(`${file.yellow} already exists.`)
    }else{
      QRCode.toFile(file, url, (error) => {
        if(error != null){
          console.log(`Something went wrong while creating ${file}`, error)
        }
        console.log(`${file.green} created.`)
      })
    }
    
  })
}

/**
 * Saves to json if the user said yes.
 * @param promptResult The results from the promt given to the user.
 * @param accounts A list of the auth accounts.
 */
function toJson(filename, saveToFile, accounts) {
  const filename = filename;
  if (saveToFile.toLowerCase().startsWith("y") && filename) {
    console.log(`Saving to "${filename}"...`);
    saveToFile(filename, JSON.stringify(accounts, undefined, 4));
  } else {
    console.log("Not saving. Here is the data:");
    console.log(accounts);
    console.log("What you want to use as secret key in other password managers is ".yellow + "'totpSecret'".blue + ", not 'secret'!".yellow);
  }
}


/**
 * Act as a CLI and ask for `otpauth-migration://` uri and optionally file to store in.
 */
function promptUserForUri() {
  const prompt = require("prompt");
  console.log("Enter the URI from Google Authenticator QR code.")
  console.log("The URI looks like otpauth-migration://offline?data=... \n")

  console.log("You can get it by exporting from Google Authenticator app, then scanning the QR with");
  console.log("e.g. https://play.google.com/store/apps/details?id=com.google.zxing.client.android")
  console.log("and copying the text to your pc, e.g. with Google Keep ( https://keep.google.com/ )")

  require("colors");
  console.log("By using online QR decoders or untrusted ways of transferring the URI text,".red)
  console.log("you risk someone storing the QR code or URI text and stealing your 2FA codes!".red)
  console.log("Remember that the data contains the website, your email and the 2FA code!".red)

  // Future improvement: add capability to upload/select QR jpg and scan it.
  // I took a picture of the QR with my camera, because Google Authenticator prevents screenshots.
  // I then uploaded the picture to my pc via the SD-card and scanned with my phone...
  // Very many steps
  
  const resultType = {
    QRCODE: "qrcode",
    JSON: "json",
  }

  const mode = process.argv.includes('-q') ? resultType.QRCODE : resultType.JSON

  const promptVariables = ["totpUri"]

  if(mode === resultType.JSON){
    promptVariables.push("saveToFile")
    promptVariables.push("filename")
  }

  prompt.start();
  prompt.get(promptVariables, (err, result) => {
    if (err) { return console.error(err); }

    const uri = result.totpUri;
    const queryParams = new URL(uri).search;
    const data = new URLSearchParams(queryParams).get("data");
    
    const accounts = decode(data);
    
    switch(mode){
      case resultType.QRCODE:
        saveToQRCodes(accounts)
        break
      case resultType.JSON:
        toJson(result.filename, result.saveToFile, accounts);
        break
    }
  })
}

promptUserForUri();
