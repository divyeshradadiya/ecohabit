import jwt from "jsonwebtoken";

const verifyToken = async (req, res, next) => {
  try {
    const token = req.header("Authorization");

    if (!token) {
      return res.status(401).send("Unauthorized User");
    }

    if (token.startsWith("Bearer ")) {
      const strippedToken = token.slice(7).trim();
      const verified = jwt.verify(strippedToken, process.env.JWT_SECRET);
      req.user = verified;
      return next();
    }

    return res.status(401).send("Invalid Token");
  } catch (error) {
    if (error instanceof jwt.TokenExpiredError) {
      return res.status(401).json({ error: "Token expired" });
    }

    if (error instanceof jwt.JsonWebTokenError) {
      return res.status(401).json({ error: "Invalid token" });
    }

    return res.status(500).json({ error: error.message });
  }
};

export default verifyToken;
