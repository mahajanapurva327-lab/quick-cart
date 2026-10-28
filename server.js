const express = require("express");
const crypto = require("crypto");
const { promisify } = require("util");
const db = require("./database");
const app = express();
const PORT = 3000;
const scrypt = promisify(crypto.scrypt);
const sessions = new Map();
const COOKIE = "quickcart_session";
const SESSION_MS = 7 * 24 * 60 * 60 * 1000;
app.use(express.json());
app.use(express.urlencoded({ extended: true }));

function getToken(req) {
  const item = (req.headers.cookie || "").split(";").map(v => v.trim()).find(v => v.startsWith(COOKIE + "="));
  return item ? decodeURIComponent(item.slice(COOKIE.length + 1)) : null;
}
function setCookie(res, token) {
  res.setHeader("Set-Cookie", COOKIE + "=" + encodeURIComponent(token) + "; HttpOnly; SameSite=Lax; Path=/; Max-Age=" + (SESSION_MS / 1000));
}
function safeUser(user) { return { id: user.id, name: user.name, email: user.email }; }
function requireAdmin(req, res, next) {
  const token = getToken(req);
  const session = token && sessions.get(token);
  if (!session || session.expiresAt < Date.now() || session.role !== "admin") {
    if (token && session?.expiresAt < Date.now()) sessions.delete(token);
    return res.status(401).json({ error: "Admin sign-in required." });
  }
  next();
}
function getSession(req) {
  const token = getToken(req);
  const session = token && sessions.get(token);
  return session && session.expiresAt >= Date.now() ? session : null;
}
function requireCustomer(req, res, next) {
  const session = getSession(req);
  if (!session || session.role === "admin" || session.role === "delivery") return res.status(401).json({ error: "Sign in to view your orders." });
  req.customer = session.user;
  next();
}
function requireDelivery(req, res, next) {
  const session = getSession(req);
  if (!session || session.role !== "delivery") return res.status(401).json({ error: "Delivery sign-in required." });
  req.delivery = session.user;
  next();
}

app.post("/api/admin/login", async (req, res) => {
  const email = typeof req.body.email === "string" ? req.body.email.trim().toLowerCase() : "";
  const password = typeof req.body.password === "string" ? req.body.password : "";
  const adminEmail = (process.env.QUICKCART_ADMIN_EMAIL || "").trim().toLowerCase();
  const adminPassword = process.env.QUICKCART_ADMIN_PASSWORD || "";
  const supplied = Buffer.from(password);
  const expected = Buffer.from(adminPassword);
  if (!adminEmail || expected.length < 8) {
    return res.status(503).json({ error: "Admin login is not configured. Set an administrator password of at least 8 characters before starting the server." });
  }
  const passwordMatches = supplied.length === expected.length && crypto.timingSafeEqual(supplied, expected);
  if (email !== adminEmail || !passwordMatches) return res.status(401).json({ error: "Email or password is incorrect." });
  const token = crypto.randomBytes(32).toString("hex");
  sessions.set(token, { role: "admin", user: { name: process.env.QUICKCART_ADMIN_NAME || "Admin", email: adminEmail }, expiresAt: Date.now() + SESSION_MS });
  setCookie(res, token);
  res.json({ message: "Admin signed in." });
});
app.get("/api/admin/me", requireAdmin, (req, res) => res.json({ authenticated: true }));
app.post("/api/delivery/login", (req, res) => {
  const email = typeof req.body.email === "string" ? req.body.email.trim().toLowerCase() : "";
  const password = typeof req.body.password === "string" ? req.body.password : "";
  const deliveryEmail = (process.env.QUICKCART_DELIVERY_EMAIL || "").trim().toLowerCase();
  const deliveryPassword = process.env.QUICKCART_DELIVERY_PASSWORD || "";
  const supplied = Buffer.from(password);
  const expected = Buffer.from(deliveryPassword);
  if (!deliveryEmail || expected.length < 11) {
    return res.status(503).json({ error: "Delivery login is not configured. Set a delivery password of at least 11 characters when starting the server." });
  }
  const passwordMatches = supplied.length === expected.length && crypto.timingSafeEqual(supplied, expected);
  if (email !== deliveryEmail || !passwordMatches) return res.status(401).json({ error: "Email or password is incorrect." });
  const token = crypto.randomBytes(32).toString("hex");
  sessions.set(token, { role: "delivery", user: { name: process.env.QUICKCART_DELIVERY_NAME || "Delivery Partner", email: deliveryEmail }, expiresAt: Date.now() + SESSION_MS });
  setCookie(res, token);
  res.json({ message: "Delivery partner signed in." });
});
app.get("/api/delivery/me", requireDelivery, (req, res) => res.json({ authenticated: true, user: req.delivery }));
app.get("/api/products", (req, res) => {
  res.json(db.prepare("SELECT id, name, category, price, stock, image FROM products ORDER BY id DESC").all());
});
app.post("/api/products", requireAdmin, (req, res) => {
  const { name, category, price, stock, image = "" } = req.body;
  const cleanName = typeof name === "string" ? name.trim() : "";
  const cleanCategory = typeof category === "string" ? category.trim() : "";
  const amount = Number(price), quantity = Number(stock);
  if (!cleanName || cleanName.length > 100 || !cleanCategory || cleanCategory.length > 80 || !Number.isFinite(amount) || amount <= 0 || !Number.isInteger(quantity) || quantity < 0) return res.status(400).json({ error: "Enter a product name, category, valid price, and whole-number stock." });
  const result = db.prepare("INSERT INTO products (name, category, price, stock, image) VALUES (?, ?, ?, ?, ?)").run(cleanName, cleanCategory, amount, quantity, typeof image === "string" ? image.slice(0, 500) : "");
  res.status(201).json({ id: Number(result.lastInsertRowid), name: cleanName, category: cleanCategory, price: amount, stock: quantity, image });
});
app.delete("/api/products/:id", requireAdmin, (req, res) => {
  const result = db.prepare("DELETE FROM products WHERE id = ?").run(Number(req.params.id));
  if (!result.changes) return res.status(404).json({ error: "Product not found." });
  res.json({ success: true });
});
app.patch("/api/products/:id", requireAdmin, (req, res) => {
  const price = Number(req.body.price), stock = Number(req.body.stock);
  if (!Number.isFinite(price) || price <= 0 || !Number.isInteger(stock) || stock < 0) return res.status(400).json({ error: "Enter a valid price and whole-number stock." });
  const result = db.prepare("UPDATE products SET price = ?, stock = ? WHERE id = ?").run(price, stock, Number(req.params.id));
  if (!result.changes) return res.status(404).json({ error: "Product not found." });
  res.json({ success: true, price, stock });
});
app.post("/api/admin/logout", (req, res) => {
  const token = getToken(req);
  if (token) sessions.delete(token);
  res.setHeader("Set-Cookie", COOKIE + "=; HttpOnly; SameSite=Lax; Path=/; Max-Age=0");
  res.json({ message: "Admin signed out." });
});

app.get("/api/test", (req, res) => res.json({ message: "Quick Cart server is working!" }));

app.post("/api/auth/register", async (req, res) => {
  const name = typeof req.body.name === "string" ? req.body.name.trim() : "";
  const email = typeof req.body.email === "string" ? req.body.email.trim().toLowerCase() : "";
  const password = typeof req.body.password === "string" ? req.body.password : "";
  if (name.length < 2 || name.length > 80) return res.status(400).json({ error: "Name must be between 2 and 80 characters." });
  if (!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email) || email.length > 254) return res.status(400).json({ error: "Enter a valid email address." });
  if (password.length < 8 || password.length > 128) return res.status(400).json({ error: "Password must be at least 8 characters." });
  try {
    const salt = crypto.randomBytes(16);
    const key = await scrypt(password, salt, 64);
    const hash = salt.toString("hex") + ":" + key.toString("hex");
    const result = db.prepare("INSERT INTO users (name, email, password_hash) VALUES (?, ?, ?)").run(name, email, hash);
    const user = { id: Number(result.lastInsertRowid), name, email };
    const token = crypto.randomBytes(32).toString("hex");
    sessions.set(token, { user, expiresAt: Date.now() + SESSION_MS });
    setCookie(res, token);
    res.status(201).json({ message: "Account created.", user });
  } catch (error) {
    if (error.code === "SQLITE_CONSTRAINT_UNIQUE") return res.status(409).json({ error: "An account with this email already exists." });
    console.error(error);
    res.status(500).json({ error: "Could not create your account." });
  }
});

app.post("/api/auth/login", async (req, res) => {
  const email = typeof req.body.email === "string" ? req.body.email.trim().toLowerCase() : "";
  const password = typeof req.body.password === "string" ? req.body.password : "";
  if (!email || !password) return res.status(400).json({ error: "Enter your email and password." });
  try {
    const user = db.prepare("SELECT * FROM users WHERE email = ? COLLATE NOCASE").get(email);
    if (!user) return res.status(401).json({ error: "Email or password is incorrect." });
    const parts = user.password_hash.split(":");
    const expected = Buffer.from(parts[1], "hex");
    const actual = await scrypt(password, Buffer.from(parts[0], "hex"), expected.length);
    if (actual.length !== expected.length || !crypto.timingSafeEqual(expected, actual)) return res.status(401).json({ error: "Email or password is incorrect." });
    const safe = safeUser(user);
    const token = crypto.randomBytes(32).toString("hex");
    sessions.set(token, { user: safe, expiresAt: Date.now() + SESSION_MS });
    setCookie(res, token);
    res.json({ message: "Signed in.", user: safe });
  } catch (error) {
    console.error(error);
    res.status(500).json({ error: "Could not sign in." });
  }
});

app.get("/api/auth/me", (req, res) => {
  const token = getToken(req);
  const session = token && sessions.get(token);
  if (!session || session.expiresAt < Date.now()) {
    if (token) sessions.delete(token);
    return res.json({ user: null });
  }
  res.json({ user: session.user });
});
app.post("/api/auth/logout", (req, res) => {
  const token = getToken(req);
  if (token) sessions.delete(token);
  res.setHeader("Set-Cookie", COOKIE + "=; HttpOnly; SameSite=Lax; Path=/; Max-Age=0");
  res.json({ message: "Signed out." });
});

app.post("/api/orders", (req, res) => {
  const { customer_name, phone, address, items, coupon_code = "", city = "", pincode = "", payment = "Cash on Delivery" } = req.body;
  const name = typeof customer_name === "string" ? customer_name.trim() : "";
  const mobile = typeof phone === "string" ? phone.trim() : "";
  const deliveryAddress = typeof address === "string" ? address.trim() : "";
  if (name.length < 2 || name.length > 100 || !/^\d{10}$/.test(mobile) || !deliveryAddress || deliveryAddress.length > 500 || typeof city !== "string" || city.trim().length > 100 || typeof pincode !== "string" || (pincode && !/^\d{6}$/.test(pincode)) || !["Cash on Delivery", "UPI"].includes(payment)) return res.status(400).json({ error: "Please provide valid delivery details and payment method." });
  if (!Array.isArray(items) || items.length < 1 || items.length > 100) return res.status(400).json({ error: "Your cart is empty or contains too many items." });
  try {
    const prepared = [];
    let subtotalCents = 0;
    for (const item of items) {
      const itemName = typeof item?.name === "string" ? item.name.trim() : "";
      const quantity = Number(item?.quantity);
      const offeredPrice = Number(item?.price);
      if (!itemName || itemName.length > 100 || !Number.isInteger(quantity) || quantity < 1 || quantity > 100 || !Number.isFinite(offeredPrice) || offeredPrice <= 0) return res.status(400).json({ error: "One or more cart items are invalid." });
      const productId = item?.id == null ? null : Number(item.id);
      if (productId != null && !Number.isInteger(productId)) return res.status(400).json({ error: "One or more cart items are invalid." });
      const managedProduct = productId == null
        ? db.prepare("SELECT id, name, price, stock FROM products WHERE name = ? COLLATE NOCASE").get(itemName)
        : db.prepare("SELECT id, name, price, stock FROM products WHERE id = ?").get(productId);
      if (productId != null && !managedProduct) return res.status(400).json({ error: "A product in your cart is no longer available." });
      const price = managedProduct ? Number(managedProduct.price) : offeredPrice;
      if (managedProduct && managedProduct.stock < quantity) return res.status(409).json({ error: itemName + " does not have enough stock." });
      const originalPrice = managedProduct ? price : Math.max(price, Number(item.originalPrice) || price);
      const cents = Math.round(price * 100) * quantity;
      subtotalCents += cents;
      prepared.push({ name: managedProduct?.name || itemName, price, originalPrice, quantity, image: typeof item.image === "string" ? item.image.slice(0, 500) : "", managedId: managedProduct?.id, cents });
    }
    const coupon = typeof coupon_code === "string" ? coupon_code.trim().toUpperCase() : "";
    let discountCents = 0;
    if (coupon === "WELCOME10" && subtotalCents >= 10000) discountCents = Math.round(subtotalCents * 0.1);
    else if (coupon === "SAVE50" && subtotalCents >= 30000) discountCents = 5000;
    else if (coupon) return res.status(400).json({ error: "Invalid coupon or minimum order amount not met." });
    discountCents = Math.min(discountCents, subtotalCents);
    const shares = prepared.map((item, index) => { const exact = discountCents * item.cents / Math.max(1, subtotalCents); return { index, cents: Math.floor(exact), remainder: exact - Math.floor(exact) }; });
    let remainingDiscount = discountCents - shares.reduce((sum, share) => sum + share.cents, 0);
    shares.slice().sort((a, b) => b.remainder - a.remainder).slice(0, remainingDiscount).forEach(share => { shares[share.index].cents++; });
    const finalItems = prepared.map((item, index) => ({ name: item.name, price: item.price, originalPrice: item.originalPrice, quantity: item.quantity, image: item.image, lineDiscount: shares[index].cents / 100, lineTotal: (item.cents - shares[index].cents) / 100 }));
    const session = getSession(req);
    const createOrder = db.transaction(() => {
      for (const item of prepared) {
        if (!item.managedId) continue;
        const update = db.prepare("UPDATE products SET stock = stock - ? WHERE id = ? AND stock >= ?").run(item.quantity, item.managedId, item.quantity);
        if (!update.changes) throw new Error("INSUFFICIENT_STOCK:" + item.name);
      }
      return db.prepare("INSERT INTO orders (customer_name, phone, address, items, total, coupon_code, discount, city, pincode, payment, user_id) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)").run(name, mobile, deliveryAddress, JSON.stringify(finalItems), (subtotalCents - discountCents) / 100, coupon, discountCents / 100, city.trim(), pincode.trim(), payment, session?.role !== "admin" ? session?.user.id || null : null);
    });
    const result = createOrder();
    res.status(201).json({ message: "Order saved successfully!", orderId: result.lastInsertRowid, total: (subtotalCents - discountCents) / 100, discount: discountCents / 100 });
  } catch (error) {
    if (error.message?.startsWith("INSUFFICIENT_STOCK:")) return res.status(409).json({ error: error.message.slice("INSUFFICIENT_STOCK:".length) + " does not have enough stock." });
    console.error(error);
    res.status(500).json({ error: "Could not save order." });
  }
});
app.get("/api/my/orders", requireCustomer, (req, res) => {
  const orders = db.prepare("SELECT * FROM orders WHERE user_id = ? ORDER BY id DESC").all(req.customer.id);
  res.json(orders);
});
app.get("/api/orders", requireAdmin, (req, res) => {
  try {
    const orders = db.prepare(
      "SELECT * FROM orders ORDER BY id DESC"
    ).all();

    res.json(orders);
  } catch (error) {
    console.error(error);
    res.status(500).json({ error: "Could not load orders." });
  }
});

app.patch("/api/orders/:id/status", requireAdmin, (req, res) => {
  try {
    const id = Number(req.params.id);
    const { status } = req.body;

    const allowedStatuses = [
      "Confirmed",
      "Packed",
      "Out for Delivery",
      "Delivered",
      "Cancelled"
    ];

    if (!allowedStatuses.includes(status)) {
      return res.status(400).json({ error: "Invalid order status." });
    }

    const result = db.prepare(
      "UPDATE orders SET status = ? WHERE id = ?"
    ).run(status, id);

    if (result.changes === 0) {
      return res.status(404).json({ error: "Order not found." });
    }

    res.json({ success: true, message: "Order status updated.", status });
  } catch (error) {
    console.error(error);
    res.status(500).json({ error: "Could not update order status." });
  }
});

app.get("/api/delivery/orders", requireDelivery, (req, res) => {
  try {
    const orders = db.prepare("SELECT id, customer_name, phone, address, city, pincode, items, total, payment, status, created_at FROM orders ORDER BY id DESC").all();
    res.json(orders);
  } catch (error) {
    console.error(error);
    res.status(500).json({ error: "Could not load delivery orders." });
  }
});

app.patch("/api/delivery/orders/:id/status", requireDelivery, (req, res) => {
  const id = Number(req.params.id);
  const nextStatus = req.body.status;
  if (!Number.isInteger(id) || id < 1 || !["Out for Delivery", "Delivered", "Cancelled"].includes(nextStatus)) {
    return res.status(400).json({ error: "Invalid delivery update." });
  }
  try {
    const order = db.prepare("SELECT status FROM orders WHERE id = ?").get(id);
    if (!order) return res.status(404).json({ error: "Order not found." });
    const allowedTransitions = {
      Confirmed: ["Cancelled"],
      Packed: ["Out for Delivery", "Cancelled"],
      "Out for Delivery": ["Delivered", "Cancelled"]
    };
    const allowedTransition = allowedTransitions[order.status]?.includes(nextStatus) || false;
    if (!allowedTransition) return res.status(409).json({ error: "This order is not ready for that delivery update." });
    const result = db.prepare("UPDATE orders SET status = ? WHERE id = ? AND status = ?").run(nextStatus, id, order.status);
    if (!result.changes) return res.status(409).json({ error: "This order changed. Refresh and try again." });
    res.json({ success: true, status: nextStatus });
  } catch (error) {
    console.error(error);
    res.status(500).json({ error: "Could not update delivery status." });
  }
});

app.post("/api/delivery/logout", requireDelivery, (req, res) => {
  const token = getToken(req);
  if (token) sessions.delete(token);
  res.setHeader("Set-Cookie", COOKIE + "=; HttpOnly; SameSite=Lax; Path=/; Max-Age=0");
  res.json({ message: "Delivery partner signed out." });
});

app.use((req, res, next) => {
  let requestedPath;
  try {
    requestedPath = decodeURIComponent(req.path).toLowerCase();
  } catch (error) {
    return res.sendStatus(400);
  }
  const privateProjectFile = /^\/(?:quickcart\.db(?:-(?:wal|shm))?|server\.js|database\.js|package(?:-lock)?\.json|start quick cart\.(?:ps1|bat)|\.quickcart-credentials\.json)$/.test(requestedPath);
  if (privateProjectFile || requestedPath.startsWith("/node_modules/")) return res.sendStatus(404);
  next();
});
app.use(express.static(__dirname, { dotfiles: "deny" }));
app.listen(PORT, () => console.log("Quick Cart server running at http://localhost:" + PORT));
