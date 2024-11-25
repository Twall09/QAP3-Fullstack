const express = require("express");
const path = require("path");
const session = require("express-session");
const bcrypt = require("bcrypt");

const app = express();
const PORT = 3000;
const SALT_ROUNDS = 10;

app.use(express.urlencoded({ extended: true }));
app.use(express.static(path.join(__dirname, "public")));
app.use(
  session({
    secret: "replace_this_with_a_secure_key",
    resave: false,
    saveUninitialized: true,
  })
);

app.use((request, response, next) => {
  response.locals.errorMessage = null;
  next();
});

app.set("view engine", "ejs");
app.set("views", path.join(__dirname, "views"));

const USERS = [
  {
    id: 1,
    username: "AdminUser",
    email: "admin@example.com",
    password: bcrypt.hashSync("admin123", SALT_ROUNDS), //In a database, you'd just store the hashes, but for
    // our purposes we'll hash these existing users when the
    // app loads
    role: "admin",
  },
  {
    id: 2,
    username: "RegularUser",
    email: "user@example.com",
    password: bcrypt.hashSync("user123", SALT_ROUNDS),
    role: "user", // Regular user
  },
];

function authenticateUser(request, response, next) {
  if (!request.session.user) {
    return response.redirect("/login");
  }
  next();
}

function authenticateAdmin(request, response, next) {
  if (!request.session.user || request.session.user.role !== "admin") {
    return response.status(403).send("Error!");
  }
  next();
}

// GET /login - Render login form
app.get("/login", (request, response) => {
  response.render("login");
});

// POST /login - Allows a user to login
app.post("/login", async (request, response) => {
  const { email, password } = request.body;

  const user = USERS.find((u) => u.email === email);
  if (!user) {
    return response.render("login", {
      errorMessage: "Invalid email or password",
    });
  }

  const isPasswordValid = await bcrypt.compare(password, user.password);
  if (!isPasswordValid) {
    return response.render("login", {
      errorMessage: "Invalid email or password",
    });
  }

  request.session.user = {
    id: user.id,
    username: user.username,
    email: user.email,
    role: user.role,
  };
  response.redirect("/landing");
});

// GET /signup - Renders signup form
app.get("/signup", (request, response) => {
  response.render("signup");
});

// POST /signup - Allows a user to signup
app.post("/signup", async (request, response) => {
  const { email, username, password } = request.body;

  // Check if email is already registered
  if (USERS.some((user) => user.email === email)) {
    return response
      .status(400)
      .render("signup", { errorMessage: "Email taken." });
  }

  try {
    const hashedPassword = await bcrypt.hash(password, SALT_ROUNDS);
    USERS.push({
      id: USERS.length + 1,
      username,
      email,
      password: hashedPassword,
      role: "user", // Default role is user
    });
    response.redirect("/login");
  } catch (error) {
    console.error("Error during registration:", error);
    response.status(500).render("signup", {
      errorMessage: "Error. Try again",
    });
  }
});

// GET / - Render index page or redirect to landing if logged in
app.get("/", (request, response) => {
  if (request.session.user) {
    return response.redirect("/landing");
  }
  response.render("index");
});

// GET /landing - Shows a welcome page for users, shows the names of all users if an admin
app.get("/landing", authenticateUser, (request, response) => {
  const user = request.session.user;

  if (user.role === "admin") {
    response.render("landing", { user, users: USERS });
  } else {
    response.render("landing", { user, users: [] });
  }
});

app.post("/logout", authenticateUser, (request, response) => {
  request.session.destroy((error) => {
    if (error) {
      console.error("Error during logout:", error);
      return response.redirect("/landing");
    }
    response.redirect("/");
  });
});

// Start server
app.listen(PORT, () => {
  console.log(`Server running at http://localhost:${PORT}`);
});
