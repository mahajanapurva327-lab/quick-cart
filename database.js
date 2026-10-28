const Database = require("better-sqlite3");
const path = require("path");
const db = new Database(path.join(__dirname, "quickcart.db"));
db.exec([
  "CREATE TABLE IF NOT EXISTS orders (id INTEGER PRIMARY KEY AUTOINCREMENT, customer_name TEXT NOT NULL, phone TEXT NOT NULL, address TEXT NOT NULL, items TEXT NOT NULL, total REAL NOT NULL, coupon_code TEXT NOT NULL DEFAULT '', discount REAL NOT NULL DEFAULT 0, city TEXT NOT NULL DEFAULT '', pincode TEXT NOT NULL DEFAULT '', payment TEXT NOT NULL DEFAULT 'Cash on Delivery', created_at TEXT DEFAULT CURRENT_TIMESTAMP);",
  "CREATE TABLE IF NOT EXISTS users (id INTEGER PRIMARY KEY AUTOINCREMENT, name TEXT NOT NULL, email TEXT NOT NULL COLLATE NOCASE UNIQUE, password_hash TEXT NOT NULL, created_at TEXT DEFAULT CURRENT_TIMESTAMP);",
  "CREATE TABLE IF NOT EXISTS products (id INTEGER PRIMARY KEY AUTOINCREMENT, name TEXT NOT NULL, category TEXT NOT NULL, price REAL NOT NULL, stock INTEGER NOT NULL DEFAULT 0, image TEXT NOT NULL DEFAULT '', created_at TEXT DEFAULT CURRENT_TIMESTAMP);"
].join("\n"));
const initialOrderColumns = db.prepare("PRAGMA table_info(orders)").all();
if (!initialOrderColumns.some(column => column.name === "user_id")) db.exec("ALTER TABLE orders ADD COLUMN user_id INTEGER REFERENCES users(id)");
// Add coupon fields for older order databases.
const existingOrderColumns = db.prepare("PRAGMA table_info(orders)").all();
if (!existingOrderColumns.some(column => column.name === "coupon_code")) db.exec("ALTER TABLE orders ADD COLUMN coupon_code TEXT NOT NULL DEFAULT ''");
if (!existingOrderColumns.some(column => column.name === "discount")) db.exec("ALTER TABLE orders ADD COLUMN discount REAL NOT NULL DEFAULT 0");
if (!existingOrderColumns.some(column => column.name === "city")) db.exec("ALTER TABLE orders ADD COLUMN city TEXT NOT NULL DEFAULT ''");
if (!existingOrderColumns.some(column => column.name === "pincode")) db.exec("ALTER TABLE orders ADD COLUMN pincode TEXT NOT NULL DEFAULT ''");
if (!existingOrderColumns.some(column => column.name === "payment")) db.exec("ALTER TABLE orders ADD COLUMN payment TEXT NOT NULL DEFAULT 'Cash on Delivery'");
// Add order status support
const columns = db.prepare("PRAGMA table_info(orders)").all();

if (!columns.some(column => column.name === "status")) {
    db.exec(
        "ALTER TABLE orders ADD COLUMN status TEXT DEFAULT 'Confirmed'"
    );
}

db.exec(
    "UPDATE orders SET status = 'Confirmed' WHERE status IS NULL"
);
module.exports = db;
console.log("Quick Cart database is ready!");
