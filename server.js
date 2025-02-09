const express = require("express");
const mongoose = require("mongoose");
const session = require("express-session");
const MongoStore = require("connect-mongo");
const bcrypt = require("bcryptjs");
const flash = require("connect-flash");
const crypto = require("crypto");
const nodemailer = require("nodemailer");
require("dotenv").config();
const PORT = process.env.PORT || 3000;

const app = express();
app.set("view engine", "ejs");
app.use(express.urlencoded({ extended: true }));
app.use(express.json());
app.use(flash());

mongoose
  .connect(process.env.MONGO_URI, {
    useNewUrlParser: true,
    useUnifiedTopology: true,
  })
  .then(() => console.log("Connected to MongoDB Atlas"))
  .catch((err) => console.error("MongoDB connection error:", err));

// Настройка сессий
app.use(
  session({
    secret: process.env.SESSION_SECRET,
    resave: false,
    saveUninitialized: true,
    store: MongoStore.create({ mongoUrl: process.env.MONGO_URI }),
    cookie: { secure: false }, // Используй true, если HTTPS
  })
);

app.use((req, res, next) => {
  res.locals.success_msg = req.flash("success_msg");
  res.locals.error_msg = req.flash("error_msg");
  res.locals.error = req.flash("error");
  next();
});

const userSchema = new mongoose.Schema({
  username: String,
  email: { type: String, unique: true },
  password: String,
  failedAttempts: { type: Number, default: 0 }, // Количество неудачных попыток входа
  lockUntil: { type: Date, default: null }, // Дата разблокировки аккаунта
  resetPasswordToken: String, // Токен для сброса пароля
  resetPasswordExpires: Date, // Время истечения токена
});
const User = mongoose.model("User", userSchema);

// Маршруты
app.get("/", (req, res) => {
  res.render("index", { user: req.session.user });
});

app.get("/register", (req, res) => {
  res.render("register");
});

app.post("/register", async (req, res) => {
  const { username, email, password, password2 } = req.body;
  let errors = [];
  req.flash("error_msg", errors.join(", "));

  if (!username || !email || !password || !password2) {
    errors.push("Fill all forms");
  }

  // Проверка длины пароля
  if (password.length < 6) {
    errors.push("Password need 6 characters at least");
  }

  // Проверка совпадения паролей
  if (password !== password2) {
    errors.push("Passwords is not match");
  }

  if (errors.length > 0) {
    req.flash("error_msg", errors);
    return res.redirect("/register");
  }

  try {
    const existingUser = await User.findOne({ email });
    if (existingUser) {
      req.flash("error_msg", "This email is already registered");
      return res.redirect("/register");
    }

    const hashedPassword = await bcrypt.hash(password, 10);
    await User.create({ username, email, password: hashedPassword });

    req.flash("success_msg", "Registration complete, now you can sign in");
    res.redirect("/login");
  } catch (err) {
    console.error(err);
    req.flash("error_msg", "Try again");
    res.redirect("/register");
  }
});

app.get("/login", (req, res) => {
  res.render("login");
});

app.post("/login", async (req, res) => {
  const { email, password } = req.body;

  if (!email || !password) {
    req.flash("error_msg", "Fill all gaps");
    return res.redirect("/login");
  }

  try {
    const user = await User.findOne({ email });
    if (!user) {
      req.flash("error_msg", "User is not found");
      return res.redirect("/login");
    }

    // Проверяем, заблокирован ли аккаунт
    if (user.lockUntil && user.lockUntil > Date.now()) {
      req.flash("error_msg", "Your account is locked. Try later.");
      return res.redirect("/login");
    }

    const isMatch = await bcrypt.compare(password, user.password);
    if (!isMatch) {
      user.failedAttempts += 1;

      if (user.failedAttempts >= 5) {
        user.lockUntil = Date.now() + 15 * 60 * 1000; // Блокируем на 15 минут
        req.flash("error_msg", "Account locked for 15 minutes!");
      } else {
        req.flash(
          "error_msg",
          `Incorrect password! ${5 - user.failedAttempts} attempts left.`
        );
      }

      await user.save();
      return res.redirect("/login");
    }

    // Если вход успешен, сбрасываем счетчик попыток
    user.failedAttempts = 0;
    user.lockUntil = null;
    await user.save();

    req.session.user = user;
    req.flash("success_msg", `Welcome, ${user.username}!`);
    res.redirect("/");
  } catch (err) {
    console.error(err);
    req.flash("error_msg", "Server error");
    res.redirect("/login");
  }
});

app.get("/logout", (req, res) => {
  req.session.destroy(() => res.redirect("/"));
});

app.get("/forgot-password", (req, res) => res.render("forgot-password"));

app.post("/forgot-password", async (req, res) => {
  const { email } = req.body;
  const user = await User.findOne({ email });

  if (!user) {
    req.flash("error_msg", "Email not found!");
    return res.redirect("/forgot-password");
  }

  // Генерируем токен
  const token = crypto.randomBytes(20).toString("hex");
  user.resetPasswordToken = token;
  user.resetPasswordExpires = Date.now() + 3600000; // 1 час
  await user.save();

  // Отправляем email
  const transporter = nodemailer.createTransport({
    service: "gmail",
    auth: { user: process.env.EMAIL, pass: process.env.EMAIL_PASSWORD },
  });

  const mailOptions = {
    to: user.email,
    from: process.env.EMAIL,
    subject: "Reset Password",
    text: `Click the link to reset your password: http://localhost:${PORT}/reset-password/${token}`,
  };

  await transporter.sendMail(mailOptions);
  req.flash("success_msg", "Check your email for password reset link!");
  res.redirect("/login");
});

app.get("/reset-password/:token", async (req, res) => {
  const user = await User.findOne({
    resetPasswordToken: req.params.token,
    resetPasswordExpires: { $gt: Date.now() },
  });

  if (!user) {
    req.flash("error_msg", "Invalid or expired token.");
    return res.redirect("/forgot-password");
  }

  res.render("reset-password", { token: req.params.token });
});

app.post("/reset-password/:token", async (req, res) => {
  const user = await User.findOne({
    resetPasswordToken: req.params.token,
    resetPasswordExpires: { $gt: Date.now() },
  });

  if (!user) {
    req.flash("error_msg", "Invalid or expired token.");
    return res.redirect("/forgot-password");
  }
  if (req.body.password !== req.body.password2) {
    req.flash("error_msg", "Passwords do not match.");
    return res.redirect("back");
  }

  const hashedPassword = await bcrypt.hash(req.body.password, 10);
  user.password = hashedPassword;
  user.resetPasswordToken = undefined;
  user.resetPasswordExpires = undefined;
  await user.save();

  req.flash("success_msg", "Password successfully changed!");
  res.redirect("/login");
});

// Запуск сервера

app.listen(PORT, () =>
  console.log(`🚀 Server running on http://localhost:${PORT}`)
);
