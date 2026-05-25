const API_BASE = "http://localhost:4000"

async function apiRegister(email, password){
    const res = await fetch(`${API_BASE}/auth/register`,{
        method: "POST",
        headers:{
            "Content-Type": "application/json"
        },
        body: JSON.stringify({email, password})
    });

    const data = await res.json();

    if (!res.ok){
        throw new Error(data.error || "Login Failed");
    }
    return data;
}

async function apiGetVault(token){
    const res = await fetch(`${API_BASE}/vault`, {
        headers: {
            Authorization: `Bearer ${token}`
        }
    });
    const data = await res.json();

    if (!res.ok){
        throw new Error(data.error || "Could not fetch vault")
    }
    return data;
}

async function apiPutVault(token, encryptedVault){
    const res = await fetch(`${API_BASE}/vault`, {
        method: "PUT",
        headers:{
            "Content-Type": "application/json",
            Authorization: `Bearer ${token}`
        },
        body: JSON.stringify(encryptedVault)
    });

    const data = await res.json();

    if (!res.ok){
        throw new Error(data.error || "Could not save vault")
    }

    return data;
}
