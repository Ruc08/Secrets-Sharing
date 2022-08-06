//jshint esversion:6

require("dotenv").config();
const express = require("express");
const bodyParser = require("body-parser");
const ejs = require("ejs");
const mongoose = require("mongoose");
const session = require("express-session");
const passport = require("passport");
const passportLocalMongoose = require("passport-local-mongoose");
const GoogleStrategy = require("passport-google-oauth20").Strategy;
const findOrCreate = require("mongoose-findorcreate");

const app = express();

app.set("view engine", "ejs");

app.use(bodyParser.urlencoded({ extended: true }));
app.use(express.static("public"));

//session setup
app.use(
  session({
    secret: "Our little secret.",
    resave: false,
    saveUninitialized: false,
  })
);

//passport module setup
app.use(passport.initialize());
app.use(passport.session());

//?????????????????????????????????????????????????????????//
//????????????????????? Database Connection ?????????????????????//
//?????????????????????????????????????????????????????????//
mongoose.connect(
  `mongodb+srv://Rushi08:${process.env.ATLAS_PASSWORD}@cluster0.cd9pn1a.mongodb.net/userDB`
);

const userSchema = new mongoose.Schema({
  email: String,
  password: String,
  googleId: String,
  secrets: [String],
});

userSchema.plugin(passportLocalMongoose);
userSchema.plugin(findOrCreate);

const UsersCollection = new mongoose.model("User", userSchema);

passport.use(UsersCollection.createStrategy());
// use static serialize and deserialize of model for passport session support
// passport.serializeUser(UsersCollection.serializeUser()); //It'll create cookies and add the user detail
// passport.deserializeUser(UsersCollection.deserializeUser()); //It'll destroy the cookies and read the user detail

passport.serializeUser(function (user, done) {
  done(null, user.id);
});

passport.deserializeUser(function (id, done) {
  UsersCollection.findById(id, function (err, user) {
    done(err, user);
  });
});

passport.use(
  new GoogleStrategy(
    {
      clientID: process.env.GOOGLE_CLIENT_ID,
      clientSecret: process.env.GOOGLE_CLIENT_SECRET,
      callbackURL: "http://localhost:3000/auth/google/secrets",
      userProfileURL: "https://www.googleapis.com/oauth2/v3/userinfo",
    },
    function (accessToken, refreshToken, profile, cb) {
      console.log(profile);

      //It'll find or add user detail in database after authentication is successful
      UsersCollection.findOrCreate(
        { googleId: profile.id },
        function (err, user) {
          return cb(err, user);
        }
      );
    }
  )
);

//?????????????????????????????????????????????????????????//
//????????????????????? Get Requestes ?????????????????????//
//?????????????????????????????????????????????????????????//
app.get("/", function (req, res) {
  res.render("home");
});

//Authenticate user
app.get(
  "/auth/google",
  passport.authenticate("google", { scope: ["openid", "profile", "email"] })
);

//Google redirect after authentication to this get request
app.get(
  "/auth/google/secrets",
  passport.authenticate("google", { failureRedirect: "/login" }),
  function (req, res) {
    // Successful authentication, redirect secrets.
    res.redirect("/secrets");
  }
);

app.get("/login", function (req, res) {
  res.render("login");
});

app.get("/register", function (req, res) {
  res.render("register");
});

app.get("/secrets", function (req, res) {
  UsersCollection.find({ secrets: { $ne: null } }, function (err, foundUser) {
    if (err) {
      console.log(err);
    }
    // console.log(foundUser);
    if (req.isAuthenticated()) {
      res.render("secrets", { userWithSecrets: foundUser, button: "Log Out" });
    } else {
      res.render("secrets", { userWithSecrets: foundUser, button: "Log In" });
    }
  });
});

app.get("/logout", function (req, res) {
  req.logout(function (err) {
    if (err) {
      return next(err);
    }
    res.redirect("/");
  }); //logout function requires callback function after change of the version
});

app.get("/submit", function (req, res) {
  if (req.isAuthenticated()) {
    res.render("submit");
  } else {
    res.redirect("/login");
  }
});

//?????????????????????????????????????????????????????????//
//????????????????????? Post Requestes ?????????????????????//
//?????????????????????????????????????????????????????????//
app.post("/register", function (req, res) {
  // Level-5 Authentication
  UsersCollection.register(
    { username: req.body.username },
    req.body.password,
    function (err, user) {
      if (err) {
        console.log(err);
        res.redirect("/register");
      } else {
        passport.authenticate("local")(req, res, function () {
          res.redirect("/secrets");
        });
      }
    }
  );
});

app.post("/login", function (req, res) {
  // Level-5 Authentication
  const user = new UsersCollection({
    username: req.body.username,
    password: req.body.password,
  });

  req.login(user, function (err) {
    if (err) {
      console.log(err);
    } else {
      passport.authenticate("local")(req, res, function () {
        res.redirect("/secrets");
      });
    }
  });
});

app.post("/submit", function (req, res) {
  // console.log(req.user);
  UsersCollection.findById(req.user.id, function (err, foundUser) {
    if (err) {
      console.log(err);
    } else {
      if (foundUser) {
        foundUser.secrets.push(req.body.secret);
        foundUser.save(function () {
          res.redirect("/secrets");
        });
      }
    }
  });
});

let port = process.env.PORT;
if (port == null || port == "") {
  port = 3000;
}
app.listen(port, function () {
  console.log("Server is successfully started..");
});
