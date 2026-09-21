import "dotenv/config";
import express from "express";
import authRouter from "./routes/auth";

const app = express();


// ルートの画面の表示
app.get("/", (req, res) => {
    res.sendFile(__dirname + "/views/index.html");
});

app.use(authRouter);






const PORT = 3000;

app.listen(PORT, () => {
    console.log(`Auth Client is running on http://localhost:${PORT}`);
});