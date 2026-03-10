// client.js
let socket = null;
const SECRET_KEY = "twidder_secret_key";

window.onload = function () {
    displayView();
};

/* ----------Utility helpers---------- */

async function handleResponse(res) {
    const data = await res.json().catch(() => ({}));
    return { status: res.status, data };
}

function handleError(status) {
    if (status === 400) return "Invalid request.";
    if (status === 401) return "Unauthorized request.";
    if (status === 403) return "Invalid signature (replay attack prevention).";
    if (status === 404) return "Resource not found.";
    if (status === 409) return "Conflict with existing resource.";
    if (status === 500) return "Server error.";
    return "Unknown error.";
}

function getToken() {
    return localStorage.getItem("token");
}

function removeUserData() {
    localStorage.removeItem("token");
    localStorage.removeItem("loggedInUser");
}

async function getAddress(lat, lon) {
    if (!lat || !lon) return "";
    try {
        const res = await fetch(`https://geocode.xyz/${lat},${lon}?geoit=json`);
        const data = await res.json();
        if (data.distance == "Throttled! See geocode.xyz/pricing"){
            return `Lat: ${lat}, Lon:${lon}`
        } else {
            return data.city ? `${data.city}, ${data.state}, ${data.country}` : "";
        }
    } catch {
        return "";
    }
}

/* ----------XMLHttpRequest wrapper---------- */

function xhrRequest(url, options = {}) {
    return new Promise((resolve, reject) => {

        const xhr = new XMLHttpRequest();
        xhr.open(options.method || "GET", url, true);

        if (options.headers) {
            for (const key in options.headers) {
                xhr.setRequestHeader(key, options.headers[key]);
            }
        }

        xhr.onreadystatechange = function () {
            if (xhr.readyState === 4) {
                resolve({
                    status: xhr.status,
                    json: async () => {
                        try {
                            return JSON.parse(xhr.responseText);
                        } catch {
                            return {};
                        }
                    }
                });
            }
        };

        xhr.onerror = () => reject(new TypeError("Network request failed"));

        xhr.send(options.body || null);
    });
}

/* ----------HMAC + Timestamp Security (jsSHA)---------- */

async function createSignature(path, timestamp) {
    const shaObj = new jsSHA("SHA-256", "TEXT");
    shaObj.setHMACKey(SECRET_KEY, "TEXT");
    shaObj.update(path + ":" + timestamp);
    return shaObj.getHMAC("HEX");
}

async function secureHeaders(path) {
    const timestamp = Math.floor(Date.now() / 1000);
    const signature = await createSignature(path, timestamp);
    return {
        "Authorization": getToken(),
        "X-Timestamp": timestamp,
        "X-Signature": signature
    };
}

/* ----------WebSocket---------- */

function connectWebSocket(token) {
    const protocol = window.location.protocol === "https:" ? "wss://" : "ws://";
    socket = new WebSocket(protocol + window.location.host + "/ws?token=" + token);    

    socket.onmessage = function (event) {
        if (event.data === "logout") {
            removeUserData();
            alert("You have been logged out (another session started).");
            socket.onclose();
            loadWelcomeView();
        }
    };

    socket.onopen = () => console.log("WebSocket connected");
    socket.onclose = () => console.log("WebSocket closed");
    socket.onerror = () => console.log("WebSocket error");
}

/* ----------View control---------- */

function displayView() {
    const token = getToken();
    const currentPath = window.location.pathname;
    if (currentPath.startsWith("/password_recovery")) {
        loadPasswordRecoveryView();
    } else {
        if (token) {
            connectWebSocket(token);
            loadProfileView();
        } else {
            loadWelcomeView();
        }
    }
}

function loadPasswordRecoveryView() {
    document.getElementById("content").innerHTML =
        document.getElementById("passwordrecoveryview").innerHTML;
    const currentPath = window.location.pathname;
    if (currentPath.startsWith("/password_recovery")) {
        const recoveryToken = new URL(window.location.href).searchParams.get("token");
        document.getElementById("recovery-form").innerHTML = `
        <form id="recovery-form">
            <h2>Password Recovery</h2>
            <input type="hidden" id="recoveryToken" value=${recoveryToken}>
            <div class="form-row">
            <label for="newpassword">Password</label>
            <input type="password" id="newpassword" required>
            </div>
            <div class="form-row">
            <label for="rptpassword">Repeat Password</label>
            <input type="password" id="rptpassword" required>
            </div>
            <button type="submit">Reset</button>
            <p class="error" id="recovery-error"></p>
        </form>`;
        document.getElementById("recovery-form").onsubmit = passwordRecovery;
    } else {
        document.getElementById("recovery-form").onsubmit = getPasswordRecovery;
    }
    
}

async function getPasswordRecovery(e) {
    e.preventDefault();

    const email = document.getElementById("email").value;
    const btn = document.getElementById("recovery-btn");
    // show loader
    btn.disabled = true;
    btn.innerHTML = "Sending...";
    try {
        const res = await xhrRequest("/request_password_recovery", {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify({ email: email })
        });

        const { status, data } = await handleResponse(res);

        if (status === 200) {
            document.getElementById("recovery-error").innerText = data.message;
        } else {
            document.getElementById("recovery-error").innerText =
                data.message || handleError(status);
        }

    } catch (err) {
        document.getElementById("recovery-error").innerText = "Something went wrong";
    }

    // restore button
    btn.disabled = false;
    btn.innerHTML = "Get recovery link";
}

async function passwordRecovery(e) {
    e.preventDefault();

    const newpassword = document.getElementById("newpassword").value;
    const rptpassword = document.getElementById("rptpassword").value;
    const recoveryToken = document.getElementById("recoveryToken").value;

    if (newpassword !== rptpassword) {
        document.getElementById("recovery-error").innerText = "Passwords do not match";
        return;
    }

    const res = await xhrRequest("/password_recovery", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({password: newpassword, token: recoveryToken})
    });

    const { status, data } = await handleResponse(res);

    if (status === 200) {
        alert("Password reset successfully.");
        window.location.href = "/";
    } else {
        document.getElementById("recovery-error").innerText = data.message || handleError(status);
    }
}

function loadWelcomeView() {
    document.getElementById("content").innerHTML =
        document.getElementById("welcomeview").innerHTML;

    document.getElementById("signin-form").onsubmit = signIn;
    document.getElementById("signup-form").onsubmit = signUp;
}

function loadProfileView() {
    document.getElementById("content").innerHTML =
        document.getElementById("profileview").innerHTML;

    showTab("home");
}

/* ----------Authentication---------- */

async function signIn(e) {
    e.preventDefault();

    const email = document.getElementById("signin-email").value;
    const password = document.getElementById("signin-password").value;

    const res = await xhrRequest("/sign_in", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ username: email, password: password })
    });

    const { status, data } = await handleResponse(res);

    if (status === 200) {
        localStorage.setItem("token", data.data.token);
        localStorage.setItem("loggedInUser", JSON.stringify(data.data.user));
        connectWebSocket(data.data.token);
        loadProfileView();
        location.reload();
    } else {
        document.getElementById("signin-error").innerText = handleError(status);
    }
}

async function signUp(e) {
    e.preventDefault();

    const data = {
        email: document.getElementById("signup-email").value,
        password: document.getElementById("signup-password").value,
        firstname: document.getElementById("signup-firstname").value,
        familyname: document.getElementById("signup-familyname").value,
        gender: document.getElementById("signup-gender").value,
        city: document.getElementById("signup-city").value,
        country: document.getElementById("signup-country").value
    };

    const res = await xhrRequest("/sign_up", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify(data)
    });

    const { status } = await handleResponse(res);

    if (status === 201) {
        alert("User created successfully.");
        document.getElementById("signup-form").reset();
        document.getElementById("signin-email").value = data.email;
        document.getElementById("signin-password").value = data.password;
    } else {
        document.getElementById("signup-error").innerText = handleError(status);
    }
}

async function signOut() {
    const token = getToken();
    if (!token) return;

    await xhrRequest("/sign_out", {
        method: "DELETE",
        headers: await secureHeaders("/sign_out")
    });

    if (socket && socket.readyState === WebSocket.OPEN) {
        socket.close();
    }

    removeUserData();
    loadWelcomeView();
}

/* ----------Tabs---------- */

function showTab(tab) {
    document.querySelectorAll(".tab").forEach(t => t.classList.remove("active"));
    document.querySelectorAll(".tabs button").forEach(b => b.classList.remove("active"));

    document.getElementById(tab).classList.add("active");
    document.getElementById("tab-" + tab).classList.add("active");

    if (tab === "home") loadHome();
    if (tab === "browse") loadBrowse();
    if (tab === "account") loadAccount();
}

/* ----------Home---------- */

async function loadHome() {
    const res = await xhrRequest("/get_user_messages_by_token", {
        headers: await secureHeaders("/get_user_messages_by_token")
    });

    if (res.status === 401) {
        removeUserData();
        loadWelcomeView();
        return;
    }

    const { data } = await handleResponse(res);
    const user = JSON.parse(localStorage.getItem("loggedInUser"));
    const messages = data.data || [];

    let html = `
        <div class="posted-content td-feed">
        <button class="reload-button" onclick="loadHome()">Reload</button>

        <textarea
        class="post-input"
        id="home-msg"
        rows="4"
        placeholder="What's happening?"
        oninput="autoResize(this)"
        ></textarea>

        <div class="button-row">
        <button onclick="postOwnMessage()">Post</button>
        </div>

        <ul>
    `;

    for (const m of messages) {
        let address = "";
        if (m.latitude && m.longitude) {
            address = await getAddress(m.latitude, m.longitude); // await works properly here
        }

        html += `<li>
            <h4>&#128100; ${m.writer_email}</h4>
            <p>${m.content}</p>
            ${address ? `<p class="location">📍 ${address}</p>` : ""}
        </li>`;
    }

    html += `</ul></div>
    <div class="user-info">
    <h3>${user.firstname} ${user.familyname}</h3>
    <p>${user.email}</p>
    <p>${user.city}, ${user.country}</p>
    </div>`;

    document.getElementById("home").innerHTML = html;
}

async function postOwnMessage() {
    const msg = document.getElementById("home-msg").value;
    if (!msg) return;

    // Get user location
    let coords = { latitude: null, longitude: null };
    if (navigator.geolocation) {
        await new Promise((resolve) => {
            navigator.geolocation.getCurrentPosition((position) => {
                coords.latitude = position.coords.latitude;
                coords.longitude = position.coords.longitude;
                resolve();
            }, () => resolve()); // ignore error
        });
    }

    await xhrRequest("/post_message", {
        method: "POST",
        headers: {
            "Content-Type": "application/json",
            ...(await secureHeaders("/post_message"))
        },
        body: JSON.stringify({ message: msg, email: null, latitude: coords.latitude, longitude: coords.longitude })
    });

    loadHome();
}

/* ----------Browse---------- */

function loadBrowse() {
    const user = JSON.parse(localStorage.getItem("loggedInUser"));

    document.getElementById("browse").innerHTML = `
        <div class="td-feed">
        <div class="browse-content">
            <div class="form-row">
                <input type="email" id="browse-email" placeholder="User email" required>
                <button onclick="searchUser()">Search</button></div>
            </div>
        <div id="browse-result"></div></div>
        <div class="user-info"><h3>${user.firstname} ${user.familyname}</h3>
        <p>${user.email}</p> <p>${user.city}, ${user.country}</p>`;
}

async function searchUser() {
    const email = document.getElementById("browse-email").value;

    const userRes = await xhrRequest("/get_user_data_by_email/" + email, {
        headers: await secureHeaders("/get_user_data_by_email/" + email)
    });

    if (userRes.status === 404) {
        document.getElementById("browse-result").innerText = "User not found";
        return;
    }

    const msgRes = await xhrRequest("/get_user_messages_by_email/" + email, {
        headers: await secureHeaders("/get_user_messages_by_email/" + email)
    });

    const userData = await userRes.json();
    const msgData = await msgRes.json();

    let html = `<div class="browse-user-info">
        <h3>${userData.data.firstname} ${userData.data.familyname}</h3>
        <p>${userData.data.city}, ${userData.data.country}</p></div>
        <textarea
            class="post-input"
            id="browse-msg"
            rows="4"
            placeholder="What's happening?"
            oninput="autoResize(this)"
        ></textarea>

        <div class="button-row">
            <button onclick="postBrowseMessage('${email}')">Post</button>
        </div>
        <ul>`;

    const msgs = msgData.data || [];

    for (const m of msgs) {
        let address = "";
        if (m.latitude && m.longitude) {
            address = await getAddress(m.latitude, m.longitude); // await works properly here
        }

        html += `<li>
            <h4>&#128100; ${m.writer_email}</h4>
            <p>${m.content}</p>
            ${address ? `<p class="location">📍 ${address}</p>` : ""}
        </li>`;
    }

    html += "</ul>";

    document.getElementById("browse-result").innerHTML = html;
}

async function postBrowseMessage(email) {
    const msg = document.getElementById("browse-msg").value;
    if (!msg) return;

    let coords = { latitude: null, longitude: null };
    if (navigator.geolocation) {
        await new Promise((resolve) => {
            navigator.geolocation.getCurrentPosition((position) => {
                coords.latitude = position.coords.latitude;
                coords.longitude = position.coords.longitude;
                resolve();
            }, () => resolve());
        });
    }

    await xhrRequest("/post_message", {
        method: "POST",
        headers: {
            "Content-Type": "application/json",
            ...(await secureHeaders("/post_message"))
        },
        body: JSON.stringify({ message: msg, email: email, latitude: coords.latitude, longitude: coords.longitude })
    });

    searchUser();
}

/* ----------Account---------- */

function loadAccount() {
    const user = JSON.parse(localStorage.getItem("loggedInUser"));

    document.getElementById("account").innerHTML = `
        <div class="td-feed">
            <div id="password-form" class="account-form">
                <div class="form-row">
                    <label for="old-pass">Current Password</label>
                    <input type="password" id="old-pass" placeholder="Old password">
                </div>
                <div class="form-row">
                    <label for="new-pass">New Password</label>
                    <input type="password" id="new-pass" placeholder="New password">
                </div>
                <div class="form-row">
                    <label for="new-pass-repeat">Repeat Password</label>
                    <input type="password" id="new-pass-repeat" placeholder="Repeat new password">
                </div>
                <button onclick="changePassword()">Change Password</button>
                <button class="sign-out-btn" onclick="signOut()">Sign Out</button>
            </div>
            <p id="account-msg"></p>
        </div>
        <div class="user-info">
            <h3>${user.firstname} ${user.familyname}</h3>
            <p>${user.email}</p> <p>${user.city}, ${user.country}</p>
        </div>`;
}

async function changePassword() {
    const oldP = document.getElementById("old-pass").value;
    const newP = document.getElementById("new-pass").value;
    const repeat = document.getElementById("new-pass-repeat").value;

    if (newP !== repeat) {
        document.getElementById("account-msg").innerText = "Passwords do not match";
        return;
    }

    const res = await xhrRequest("/change_password", {
        method: "PUT",
        headers: {
            "Content-Type": "application/json",
            ...(await secureHeaders("/change_password"))
        },
        body: JSON.stringify({ oldpassword: oldP, newpassword: newP })
    });

    const { status } = await handleResponse(res);

    if (status === 200) {
        document.getElementById("account-msg").innerText = "Password changed.";
    } else {
        document.getElementById("account-msg").innerText = handleError(status);
    }
}

/* ----------Auto Resize---------- */

function autoResize(textarea) {
    textarea.style.height = "auto";
    textarea.style.height = textarea.scrollHeight + "px";
}

