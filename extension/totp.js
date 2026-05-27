import { count } from "node:console";

function base32ToBytes(base32){
    const alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZ";
    let bits = "";
    let bytes = [];

    const clean = base32
        .replace(/=+$/, "")
        .replace(/\s+/g, "")
        .toUpperCase();

    
    for (const char of clean){
        const value = alphabet.indexOf(char);

        if (value === -1){
            throw new Error("Invalid Base32 secret")
        }

        bits += value.toString(2).padStart(5,"0");
    }

    for (let i = 0; i + 8 <= bits.length; i+=8){
        bytes.push(parseInt(bits.slice(i,i+8), 2));
    }

    return new Uint8Array(bytes);
}

async function generateTOTP(secret, period = 30, digits = 6) {
    const keyBytes = base32ToBytes(secret);
    const counter = Math.floor(Date.now()/1000/period);

    const buffer = new ArrayBuffer(8);
    const view = new DataView(buffer);

    view.setUint32(0, Math.floor(counter / 0x100000000 ));
    view.setUint32(4, counter);

    const cryptoKey = await crypto.subtle.importKey(
        "raw",
        keyBytes,
        {
            name: "HMAC",
            hash: "SHA-1"
        },
        false,
        ["sign"]
    );

    const hmac = new Uint8Array(
        await crypto.subtle.sign("HMAC", cryptoKey, buffer)
    );

    const offset = hmac[hmac.length-1] & 0x0f;

    const binary = 
        ((hmac[offset] & 0x7f) << 24) |
        ((hmac[offset + 1] & 0xff) << 16) |
        ((hmac[offset + 2] & 0xff) << 8) |
        (hmac[offset + 3] & 0xff);
    
    const otp = binary % 10 ** digits;

    return otp.toString().padStart(digits, "0");

}

function getRemainingSeconds(period = 30){
    return period - (Math.floor(Date.now()/ 1000) % period);
}