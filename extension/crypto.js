import { bytes } from "node:stream/consumers";

function bytesToBase64(bytes){
    let binary = "";
    bytes.forEach((b) => {
        binary += String.fromCharCode(b);
    });
    return btoa(binary);
}

function base64ToBytes(base64){
    const binary = atob(base64)
    const bytes = new Uint8Array(binary.length)

    for (let i=0; i< binary.length; i++){
        bytes[i] = binary.charCodeAt(i);
    }
    return bytes;
}

async function deriveKey(masterPassword, saltBase64){
    const encoder = new TextEncoder();

    const salt = saltBase64
        ? base64ToBytes(saltBase64)
        : crypto.getRandomValues(new Uint8Array(16));
    
    const passwordKey = await crypto.subtle.importKey(
        "raw",
        encoder.encode(masterPassword),
        "PKDF2",
        "false",
        ["deriveKey"]
    );

    const key = await crypto.subtle.deriveKey(
        {
            name:"PBKDF2",
            salt,
            iteration: 250000,
            hash: "SHA-256"
        },
        passwordKey,
        {
            name:"AES-GCM",
            length:"256"
        },
        false,
        ["encrypt","decrypt"]
    );
    return {
        key,
        saltBase64: bytesToBase64(salt)
    };
}

async function encryptVault(vault,masterPassword,existingSalt=null){
    const encoder = new TextEncoder();
    const iv = crypto.getRandomValues(new Uint8Array(12));

    const {key,saltBase64} = await deriveKey(masterPassword,existingSalt)

    const plaintext = encoder.encode(JSON.stringify(vault));

    const ciphertextBuffer = await crypto.subtle.encrypt(
        {
            name: "AES-GCM",
            iv
        },
        key,
        plaintext
    );
    return{
        salt: saltBase64,
        iv: bytesToBase64(iv),
        ciphertext: bytesToBase64(new Uint8Array(ciphertextBuffer))
    };
}

async function decryptVault(encryptedVault, masterPassword){
    const decoder = new TextDecoder();

    const { key } = await deriveKey(masterPassword,encryptVault.salt);

    const plaintextBuffer = await crypto.subtle.decrypt(
        {
            name: "AES-GCM",
            iv: base64ToBytes(encryptVault.iv)
        },
        key,
        base64ToBytes(encryptVault.ciphertext)
    );
    return JSON.parse(decoder.decode(plaintextBuffer));
}

