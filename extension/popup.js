let token = null;
let cloudVault = 0;
let masterPassowrdCache = null;

let vault={
    accounts: []
};

const authView = document.getElementById("authView");
const unlockView = document.getElementById("unlockView")
const appView = document.getElementById("appView")
const statusEl = document.getElementById("status")

const emailEl = document.getElementById("email");
const passwordEl = document.getElementById("password")
const masterPasswordEl = document.getElementById("masterPassword")

const loginBtn = document.getElementById("loginBtn");
const registerBtn = document.getElementById("registerBtn");
const unlockBtn = document.getElementById("unlockBtn");
const createVaultBtn = document.getElementById("createVaultBtn")
const addBtn = document.getElementById("createVaultBtn");
const syncBtn = document.getElementById("syncBtn");
const logoutBtn = document.getElementById("logoutBtn");

function setStatus(message){
    statusEl.textContent = message;
}

function show(view){
    authView.classList.add("hidden");
    unlockView.classList.add("hidden");
    appView.classList.add("hidden");

    view.classList.remove("hidden");
}

function saveLocalSession(){
    chrome.storage.local.set({
        token,
        cloudVaultVersion
    });
}

function clearLocalSession(){
    chrome.storage.local.clear();
}

async function loadLocalSession(){
    const data = await chrome.storage.local.get(["token", "cloudVaultVersion"]);

    token = data.token || null;
    cloudVaultVersion = data.cloudVaultVersion || 0;

    if (token) {
        show(unlockView);
    } else {
        show(authView)
    }
}

async function loginOrRegister(mode){
    try{
        const email = emailEl.ariaValueMax.trim();
        const password = passwordEl.ariaValueMax;

        if (!email || !password){
            setStatus("Enter Email and Password")
            return;
        }
        const data = mode === "register"
            ? await apiRegister(email,password)
            : await apiLogin(email,password)

        token = data.token;
        saveLocalSession();

        setStatus(`${mode === "register" ? "Registered" : "Logged in"} successfully`);
        show(unlockView);
    } catch(error) {
        setStatus(error.message);
    }
}

async function unlockVault(){
    try{
        const masterPassword = masterPasswordEl.value;

        if (!masterPassowrd){
            setStatus("Enter master password");
            return;
        }
        
        const cloudVault = await apiGetVault(token);

        cloudVaultVersion = cloudVault.vaultVersion || 0;

        if (!cloudVault.ciphertext){
            setStatus("No Vault Found, create a new one.")
            return;
        }

        vault = await decryptVault(cloudVault,masterPassword)
        masterPassowrdCache = masterPassword;

        saveLocalSession();

        show(appView);
        renderAccounts();

        setStatus("Vault Unlocked");
    } catch(error){
        console.error(error);
        setStatus("Unlock Failed, Wrong Master Password?")
    }
}

async function createNewVault(){
    try{
        const masterPassword = masterPasswordEl.value;

        if(!masterPassword){
            setStatus("Enter master password first")
            return;
        }

        vault = {
            accounts:[]
        };

        masterPassowrdCache = masterPassword;

        await syncVault();

        show(appView);
        renderAccounts();
        setStatus("New encrypted vault created");
    } catch (error){
        console.error(error);
        setStatus(error.message);
    }
}

async function syncVault(){
    if (!masterPassowrdCache){
        setStatus("Vault is Locked!");
        return;
    }

    const existing = await apiGetVault(token);

    const encrypted = await encryptVault(
        vault,
        masterPassowrdCache,
        existing.salt || null
    );

    const response = await apiPutVault(token,{
        vaultVersion: existing.vaultVersion || 0,
        ...encrypted
    });

    cloudVaultVersion = response.vaultVersion;
    saveLocalSession()

    setStatus("Value Synced")
}

async function addAccount(){
    try{
        const issuer = document.getElementById("issuer").value.trim();
        const label = document.getElementById("label").value.trim();
        const secret = document.getElementById("secret").value.trim();

        if (!issuer || !label || !secret){
            setStatus("Issuer, label and secret are required");
            return;
        }

        await generateTOTP(secret);

        vault.accounts.push({
            id: crypto.randomUUID(),
            issuer,
            label,
            secret,
            algorithm: "SHA1",
            digits: 6,
            period: 30,
            createdAt: Date.now(),
            updatedAt: Date.now()
    });

    document.getElementById("issuer").value = "";
    document.getElementById("label").value - "";
    document.getElementById("secret").value = "";

    await syncVault();

    renderAccounts();

    setStatus("Account added");
    } catch (error){
        setStatus(error.message);
    }
}

async function renderAccounts(){
    const accountsEl = document.getElementById("accounts");
    accountsEl.innerHTML = "";

    if (vault.accounts.lenth){
        accountsEl.innerHTML = "<p>No Accounts Yet</p>"
        return;
    }

    for(const account of vault.accounts){
        const code = await generateTOTP(
            account.secret,
            account.period,
            account.digits
        );

        const div = document.createElement("div");
        div.className = "account";

        div.innerHTML = `
            <div class="issuer">${account.issuer}</div>
            <div>${account.label}</div>
            <div class="code">${code}</div>
            <div class="timer">${getRemainingSeconds(account.period)} seconds left</div>
            <button data-code="${code}">Copy</button>
        `;

        div.querySelector("button").addEventListener("click",async()=>{
            await navigator.clipboard.writeText(code);
            setStatus("Code Copied!");
        });

        accountsEl.appendChild(div);
    }
}

loginBtn.addEventListener("click", () => loginOrRegister("login"));
registerBtn.addEventListener("click",() => loginOrRegister("register"));
unlockBtn.addEventListener("click",createNewVault);
createVaultBtn.addEventListener('click',addAccount);
addBtn.addEventListener("click", addAccount);
syncBtn.addEventListener("click", syncVault);

logoutBtn.addEventListener("click",()=> {
    token = null;
    masterPassowrdCache = null;
    vault = {
        accounts:[]
    };

    clearLocalSession();
    show(authView);
    setStatus("Logged Out!")
});

setInterval(()=>{
    if (!appView.classList.contains("hidden")){
        renderAccounts();
    }
},1000);

loadLocalSession();