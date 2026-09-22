import "dotenv/config";
import express from "express";
import authRouter from "./routes/authorize";
import tokenRouter from "./routes/token";

const app = express();
app.use(express.urlencoded({ extended: true }));
app.use(authRouter);
app.use(tokenRouter);
const PORT = 4000;


app.get("/", (req, res) => {
});

app.listen(PORT, () => {
    console.log(`Auth Server is running on http://localhost:${PORT}`);
});
