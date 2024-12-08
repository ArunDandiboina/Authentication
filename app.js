import express from "express";
import bodyParser from "body-parser";
import ejs from "ejs";
import pg from "pg";
import bcrypt from "bcrypt";
import passport from "passport";
import { Strategy } from "passport-local";
import GoogleStrategy from "passport-google-oauth2";
import session from "express-session";
import connectPgSimple from 'connect-pg-simple';
import env from "dotenv";
import fs from "fs";
import path from "path";
import { dirname } from "path";
import { fileURLToPath } from "url";
const __dirname = dirname(fileURLToPath(import.meta.url));

const app = express();
const pgSession = connectPgSimple(session); // Import pgSession

const PORT = process.env.PORT || 3000;
const saltRounds = 15;
env.config();




// PostgreSQL pool for database connections and session store
const pool = new pg.Pool({
  user: process.env.PG_USER,
  host: process.env.PG_HOST,
  database: process.env.PG_DATABASE,
  password: process.env.PG_PASSWORD,
  port: process.env.PG_PORT,  
});

const db = pool; // Now 'db' is the pool

const resetDatabase = async () => {
  try {
    await db.query("DELETE FROM session");
    await db.query("DELETE FROM users2");
    console.log("All sessions and users deleted.");
  } catch (err) {
    console.error("Error resetting database:", err);
  }
};
resetDatabase();

async function createSessionTable() {
  try {
    const client = await pool.connect();

    const createTableQuery = `
      CREATE TABLE IF NOT EXISTS "session" (
        "sid" varchar NOT NULL COLLATE "default",
        "sess" json NOT NULL,
        "expire" timestamp(6) NOT NULL,
        PRIMARY KEY ("sid")  -- Primary key constraint inline
      );
    `;
    await client.query(createTableQuery);
    client.release();
  } catch (error) {
    console.error('Error creating session table:', error);
  }
}
createSessionTable(); // Call the function to create the table at startup


app.use(session({
  store: new pgSession({
    pool,
    tableName: 'session' 
  }),
  secret: process.env.SESSION_SECRET,
  resave: false,                     // Must be false if using connect-pg-simple
  saveUninitialized: false,          // Also false, improves security
  cookie: {
    maxAge: 1000 * 60 * 60 * 24, 
    sameSite: 'lax',         
    secure: process.env.NODE_ENV === 'production',  // Use HTTPS when in production
    httpOnly: true
  }
}));

if (process.env.NODE_ENV === 'production'){
  app.set('trust proxy', 1); // trust first proxy if using render
}


app.set("view engine", "ejs");
app.use(bodyParser.urlencoded({ extended: true }));
app.use(express.static(path.join(__dirname, "public")));
app.use(passport.initialize());
app.use(passport.session());



// Database schema
// Database schema for users and notes
const createTables = async () => {
  const createUsersTableQuery = `
    CREATE TABLE IF NOT EXISTS users2 (
      id SERIAL PRIMARY KEY,
      email TEXT UNIQUE NOT NULL,
      password TEXT NOT NULL
    );
  `;

  await db.query(createUsersTableQuery);
};
createTables().catch(err => console.error('Error creating tables:', err));



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
  if (req.isAuthenticated()) {
    res.render("secrets.ejs");
  } else {
    res.redirect("/login");
  }
});


app.get("/auth/google",passport.authenticate("google",{scope:["profile","email"]}));
app.get("/auth/google/secrets",passport.authenticate("google",{
  successRedirect:"/secrets",
  failureRedirect: "/login",
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
    const checkResult = await db.query("SELECT * FROM users2 WHERE email = $1", [
      email,
    ]);

    if (checkResult.rows.length > 0) {
      res.redirect("/login");
    } else {
      bcrypt.hash(password, saltRounds, async (err, hash) => {
        if (err) {
          console.error("Error hashing password:", err);
        } else {
          const result = await db.query(
            "INSERT INTO users2 (email, password) VALUES ($1, $2) RETURNING *",
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
      const result = await db.query("SELECT * FROM users2 WHERE email = $1 ", [
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
  callbackURL: process.env.GOOGLE_CALLBACK_URL,
  userProfileURL:process.env.GOOGLE_PROFILE_URL,
},async function(accessToken, refreshToken,profile,cb){
  try {
    const result = await db.query("SELECT * FROM users2 WHERE email = $1 ", [
      profile.email,
    ]);
    if (result.rows.length == 0) {
      const newUser = await db.query(
        "INSERT INTO users2 (email, password) VALUES ($1, $2) RETURNING *",
        [profile.email,"google"]
      );
      cb(null,newUser.rows[0]);
    } else {
     cb(null,result.rows[0]);
    }
  } catch (err) {
    console.log("Try error")
    cb(err); 
  }
}));

passport.serializeUser((user, done) => {
  done(null, user.id); // serialize user id
});

passport.deserializeUser(async (userId, done) => {  // userId parameter
  try {

    const user = await pool.query('SELECT * from users2 WHERE id = $1', [userId]);
    if (!user.rows[0]) {
      return done(new Error('User not found')); // Explicitly handle the case where the user is not found.
    }
    done(null, user.rows[0]); // attach user object to the request
  } catch (err) {
    console.error("Deserialization error:", err);
    done(err);
  }
});

// Error handling for the pool
pool.on('error', (err, client) => {
  console.error('Unexpected error on idle client', err);
  process.exit(-1); // Exit process on connection errors (adjust as needed)
});


// Graceful shutdown 
process.on('SIGINT', async () => {
  try {
    await pool.end(); // Close the pool gracefully
    console.log('PostgreSQL pool has ended');
    process.exit(0);
  } catch (err) {
        console.error("Error during pool ending", err);
        process.exit(1);
      }
});

// Start server
app.listen(PORT, () => {
  console.log(`Server running at http://localhost:${PORT}`);
});

