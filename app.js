import express from "express";
import bodyParser from "body-parser";
import pg from "pg";
import bcrypt from "bcrypt";
import passport from "passport";
import { Strategy } from "passport-local";
import GoogleStrategy from "passport-google-oauth2";
import session from "express-session";
import env from "dotenv";
import fs from "fs";
import path from "path";
import { dirname } from "path";
import { fileURLToPath } from "url";
const __dirname = dirname(fileURLToPath(import.meta.url));

const app = express();
const port = 3000;
const saltRounds = 10;
env.config();

app.use(
  session({
    secret: process.env.SESSION_SECRET,
    resave: false,
    saveUninitialized: true,
  })
); 

app.use(bodyParser.urlencoded({ extended: true }));
app.use(express.static("public"));

app.use(passport.initialize());
app.use(passport.session());

const db = new pg.Client({
  connectionString:process.env.POSTGRES_URL,
  user: process.env.POSTGRES_USER,
  host: process.env.POSTGRES_HOST,
  database: process.env.POSTGRES_DATABASE,
  password: process.env.POSTGRES_PASSWORD,
});
db.connect();

app.get("/", (req, res) => {
  res.render("home.ejs");
});

app.get("/login", (req, res) => {
  res.render("login.ejs");
});

app.get("/register", (req, res) => {
  res.render("register.ejs");
});

app.get("/logout", (req, res) => {
  req.logout(function (err) {
    if (err) {
      return next(err);
    }
    res.redirect("/");
  });
});

app.get("/secrets", (req, res) => {
  // console.log(req.user);
  if (req.isAuthenticated()) {
    res.render("secrets.ejs");
  } else {
    res.redirect("/login");
  }
});

app.get("/auth/google",passport.authenticate("google",{scope:["profile","email"]}));
app.get("/auth/google/secrets",passport.authenticate("google",{
  successRedirect:"/secrets",
  failureRedirect: "/login"
}));
app.post(
  "/login",
  passport.authenticate("local", {
    successRedirect: "/secrets",
    failureRedirect: "/login",
  })
);

app.post("/register", async (req, res) => {
  const email = req.body.username;
  const password = req.body.password;

  try {
    const checkResult = await db.query("SELECT * FROM users1 WHERE email = $1", [
      email,
    ]);

    if (checkResult.rows.length > 0) {
      req.redirect("/login");
    } else {
      bcrypt.hash(password, saltRounds, async (err, hash) => {
        if (err) {
          console.error("Error hashing password:", err);
        } else {
          const result = await db.query(
            "INSERT INTO users1 (email, password) VALUES ($1, $2) RETURNING *",
            [email, hash]
          );
          const user = result.rows[0];
          req.login(user, (err) => {
            console.log("success");
            res.redirect("/secrets");
          });
        }
      });
    }
  } catch (err) {
    console.log(err);
  }
}); 

app.get('/download',(req,res)=>{
  if (req.isAuthenticated){
    const filePath = path.join(__dirname,"public", 'files/cheat_sheet.pdf'); // Replace 'example.pdf' with the path to your PDF file

    // Check if the PDF file exists
    fs.access(filePath, fs.constants.R_OK, (err) => {
      if (err) {
        // PDF file does not exist or is not readable
        return res.status(404).send('PDF file not found');
      }
  
      // Set response headers for PDF download
      res.setHeader('Content-Type', 'application/pdf');
      res.setHeader('Content-Disposition', 'attachment; filename="cheat_sheet.pdf"');
  
      // Read the PDF file and send it as a response
      fs.createReadStream(filePath).pipe(res);
    
    });
  }else{
    res.redirect('/');
  }
});


passport.use("local",
  new Strategy(async function verify(username, password, cb) {
    try {
      const result = await db.query("SELECT * FROM users1 WHERE email = $1 ", [
        username,
      ]);
      if (result.rows.length > 0) {
        const user = result.rows[0];
        const storedHashedPassword = user.password;
        bcrypt.compare(password, storedHashedPassword, (err, valid) => {
          if (err) {
            //Error with password check
            console.error("Error comparing passwords:", err);
            return cb(err);
          } else {
            if (valid) {
              //Passed password check
              return cb(null, user);
            } else {
              //Did not pass password check
              return cb(null, false);
            }
          }
        });
      } else {
        return cb("User not found");
      }
    } catch (err) {
      return cb(err)
    }
  })
);

passport.use("google",new GoogleStrategy({
  clientID : process.env.GOOGLE_CLIENT_ID,
  clientSecret: process.env.GOOGLE_CLIENT_SECRET,
  callbackURL:"https://authentication-iota-dun.vercel.app/auth/google/secrets",
  userProfileURL:"https://www.googleapis.com/oauth2/v3/userinfo",
},async function(accessToken, refreshToken,profile,cb){
  try {
    const result = await db.query("SELECT * FROM users1 WHERE email = $1 ", [
      profile.email,
    ]);
    if (result.rows.length == 0) {
      const user = result.rows[0];
      const newUser = await db.query(
        "INSERT INTO users1 (email, password) VALUES ($1, $2) RETURNING *",
        [profile.email,"google"]
      );
      cb(null,newUser.rows[0]);
    } else {
     cb(null,result.rows[0]);
    }
  } catch (err) {
    cb(err);
  }
}));

passport.serializeUser((user, cb) => {
  cb(null, user);
});
passport.deserializeUser((user, cb) => {
  cb(null, user);
});

app.listen(process.env.PORT || port, () => {
  console.log(`Server running on port ${port}`);
});
