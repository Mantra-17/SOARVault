/* auth.js — login page logic.
 * On success, stores the session in localStorage and redirects to
 * the dashboard. app.js reads this session on every protected page.
 */

const DEMO_USERS = {
  "asha.analyst": { password: "demo123", role: "analyst", role_label: "Analyst", name: "Asha Rao",
    permissions: ["view"] },
  "rohit.senior": { password: "demo123", role: "senior_analyst", role_label: "Senior Analyst", name: "Rohit Sharma",
    permissions: ["view", "approve"] },
  "admin": { password: "demo123", role: "admin", role_label: "Admin", name: "Admin User",
    permissions: ["view", "approve", "edit", "delete", "manage_users"] },
};
function storeSession(session) {
  localStorage.setItem("soar_session", JSON.stringify(session));
}

async function attemptLogin(username, password) {
  try {
    const res = await fetch("/api/auth/login", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ username, password }),
    });
    if (res.ok) return await res.json();
    return null;
  } catch (e) {
    // API not running (e.g. static file opened directly) — fall back
    // to the same demo credentials baked into the mock backend.
    const user = DEMO_USERS[username];
    if (user && user.password === password) {
      return { username, name: user.name, role: user.role, role_label: user.role_label, permissions: user.permissions };
    }
    return null;
  }
}

document.getElementById("login-form").addEventListener("submit", async (e) => {
  e.preventDefault();
  const username = document.getElementById("username").value.trim();
  const password = document.getElementById("password").value;
  const errorEl = document.getElementById("login-error");
  const btn = document.getElementById("login-btn");

  btn.disabled = true;
  btn.textContent = "Signing in…";
  errorEl.textContent = "";

  const session = await attemptLogin(username, password);

  if (!session) {
    errorEl.textContent = "Invalid username or password.";
    btn.disabled = false;
    btn.textContent = "Sign in";
    return;
  }

  storeSession(session);
  window.location.href = "index.html";
});
