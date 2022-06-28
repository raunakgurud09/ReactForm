const express = require("express");
const app = express();
const jwt = require("jsonwebtoken");

app.use(express.json());

const users = [
  {
    id: "1",
    username: "john",
    password: "john",
    isAdmin: true,
  },
  {
    id: "2",
    username: "jane",
    password: "jane",
    isAdmin: false,
  },
];

let refreshTokens = [];

app.post("/api/v1/refresh", (req, res) => {
  // res.json('okay')
  // take the
  const refreshToken = req.body.token;
  if (!refreshToken) return res.status(401).json(`not authenticated`);

  if (!refreshTokens.includes(refreshToken)) {
    res.status(403).json("refresh token is not valid");
  }

  jwt.verify(refreshToken, "myRefreshSecretKey", (error, user) => {
    error && console.log(error);
    refreshTokens = refreshTokens.filter((token) => token !== refreshToken);

    const newAccessToken = GenrateAccessToken(user);
    const newRefreshToken = GenrateRefreshToken(user);

    refreshTokens.push(newRefreshToken);

    res.status(200).json({
      accessToken: newAccessToken,
      refreshToken: newRefreshToken,
    });
  });
});

const GenrateAccessToken = (user) => {
  return jwt.sign({ id: user.id, isAdmin: user.isAdmin }, "mySecretKey", {
    expiresIn: "20s",
  });
};

const GenrateRefreshToken = (user) => {
  return jwt.sign(
    { id: user.id, isAdmin: user.isAdmin },
    "myRefreshSecretKey",
    { expiresIn: "60s" }
  );
};

app.post("/api/v1/login", (req, res) => {
  const { username, password } = req.body;
  const user = users.find((u) => {
    return u.username === username && u.password === password;
  });

  if (user) {
    //#gentaring an access token
    const accessToken = GenrateAccessToken(user);
    const refreshToken = GenrateRefreshToken(user);

    refreshTokens.push(refreshToken);

    res.json({
      username: user.username,
      isAdmin: user.isAdmin,
      accessToken,
      refreshToken,
    });

    // res.json(user)
  } else {
    res.status(400).json("username or password incorrect");
  }
});

const verify = (req, res, next) => {
  const authHeader = req.headers.authorization;
  if (authHeader) {
    const token = authHeader.split(" ")[1];

    jwt.verify(token, "mySecretKey", (err, user) => {
      if (err) {
        return res.status(403).json("Token is not valid!");
      }

      req.user = user;
      next();
    });
  } else {
    res.status(401).json("You are not authenticated!");
  }
};
app.delete("/api/v1/users/:userId", verify, (req, res) => {
  if (req.user.id === req.params.userId || req.user.isAdmin) {
    res.status(200).json("user has been deleted");
  } else {
    res.status(403).json("not allowed to delete the user");
  }
});

app.get("/", (req, res) => {
  res.send("<h1>HELLO NICE WORLD</h1>");
});

app.post("/api/v1/logout", verify, (req, res) => {
  const refreshToken = req.body.token;
  refreshTokens = refreshTokens.filter((token) => token !== refreshToken);
  res.status(200).json("logged out successfully");
});
const port = 3001;

app.listen(port, () => {
  console.log(`server is listening on port ${port}...`);
});
