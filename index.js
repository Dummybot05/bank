import dotenv from 'dotenv';
dotenv.config();
import { v4 as uuidv4 } from 'uuid';
import express from 'express';
import { neon } from "@neondatabase/serverless";
import bcrypt from 'bcrypt';
import session from 'express-session';
import QRCode from 'qrcode';
import cors from 'cors';


const app = express();
const sql = neon(process.env.DATABASE_URL);
const port = parseInt(process.env.PORT) || 3000;

const corsOptions = {
  origin: '*', // or replace with specific origins like 'http://example.com'
  methods: ['GET', 'POST', 'PUT', 'DELETE'],
  allowedHeaders: ['Content-Type', 'Authorization'],
};

app.use(cors(corsOptions));

const regForMail = /^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$/;
const regForPassword = /^(?=.*[A-Z])(?=.*[a-z])(?=.*\d)(?=.*[@$!%*?&])[A-Za-z\d@$!%*?&]{8,}$/;

app.use(
  session({
    secret: process.env.SESSION_SECRET,
    resave: false,
    saveUninitialized: true,
    cookie: { secure: false } // Set to true if using HTTPS
  })
);

app.use(express.json());


const generateQR = async text => {
  try {
    var data = await QRCode.toDataURL(text);
    var dataSplit = data.split(',');
    var base64 = dataSplit[1];
    return base64;
  } catch (err) {
    console.error(err)
  }
}

app.get('/', (req, res) => {
  for (var i = 0; i < 10; i++) {
    console.log(uuidv4());
  }
  res.send("Hello World From API");
});

app.post('/signup', async (req, res) => {
  const email = req.body.email;
  const password = req.body.password;

  const checkEmail = regForMail.test(email);
  const checkPassword = regForPassword.test(password);

  if (checkEmail && checkPassword) {

    const lowerEmail = email.toLowerCase();
    const hashedPassword = await bcrypt.hash(password, 10);

    try {
      const result = await sql`
          SELECT * FROM auth WHERE email = ${lowerEmail}
      `;
      if (result.length > 0) {
        res.status(500).send({ error: "Email already EXIST" });
        return;
      }
    } catch (e) {
      res.status(500).send({ error: e.message });
      return;
    }
    try {
      const result = await sql`
          INSERT INTO auth (uuid, email, password)
          VALUES (${uuidv4()}, ${lowerEmail}, ${hashedPassword})
      `;
      const isSuccess = result.length == 0;
      if (isSuccess) {
        res.status(200).send({ message: "Signup Success" });
      } else {
        res.status(500).send({ error: "Something went wrong" });
      }
    } catch (e) {
      res.status(500).send({ error: e.message });
      return;
    }

  } else {
    if (!checkEmail) {
      res.status(500).send({
        error: "Invalid Email",
        message: "example@example.com"
      });
      return;
    } else {
      res.status(500).send({
        error: "Invalid Password",
        message: "Password must contain at least one uppercase letter, one lowercase letter, one number, one special character, and be at least 8 characters long."
      });
      return;
    }
  }
});

app.post('/login', async (req, res) => {
  const email = req.body.email;
  const password = req.body.password;

  const checkEmail = regForMail.test(email);
  const checkPassword = regForPassword.test(password);

  if (checkEmail && checkPassword) {

    const lowerEmail = email.toLowerCase();

    try {
      const result = await sql`
          SELECT * FROM auth WHERE email = ${lowerEmail}
      `;
      if (result.length > 0) {
        const comparePassword = await bcrypt.compare(password, result[0].password);
        if (comparePassword) {
          req.session.user = result;
          res.status(200).send({ message: "Login Success" });
          return;
        } else {
          res.status(500).send({ error: "Password not MATCH" });
          return;
        }
      } else {
        res.status(500).send({ status: "failed", message: "Email not EXIST" });
        return;
      }
    } catch (e) {
      res.status(500).send({ error: e.message });
      return;
    }

  } else {
    if (!checkEmail) {
      res.status(500).send({
        error: "Invalid Email",
        message: "example@example.com"
      });
      return;
    } else {
      res.status(500).send({
        error: "Invalid Password",
        message: "Password must contain at least one uppercase letter, one lowercase letter, one number, one special character, and be at least 8 characters long."
      });
      return;
    }
  }
});

app.get('/all', async (req, res) => {
  try {
    const result = await sql`
        SELECT * FROM auth
    `;
    res.status(200).send(result);
  } catch (e) {
    res.status(500).send({ error: e.message });
    return;
  }
})

app.get('/home', async (req, res) => {
  var balance = Math.floor(Math.random() * 300);
  if (req.session.user) {
    let qr = await generateQR(req.session.user[0].uuid); // data:image/png;base64,
    try {
      const result = await sql`
          INSERT INTO users (uuid, balance, qrcode) VALUES (${req.session.user[0].uuid}, ${balance}, ${qr})
      `;
      if (result.length == 0) {
        res.status(200).send({ message: 'Welcome to Home!', user: req.session.user });
        return;
      }
    } catch (e) {
      res.status(500).send({ error: e.message });
      return;
    }

  } else {
    res.status(401).send({ error: 'Not authenticated' });
  }
});

app.listen(port, () => {
  console.log(`listening on port ${port}`);
});
