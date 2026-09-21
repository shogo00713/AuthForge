// クライアントの情報
export const fortuneApp = {
    client_id: process.env.CLIENT_ID!,
    client_secret: process.env.CLIENT_SECRET!,
    redirect_uris: [process.env.REDIRECT_URI!],
    scope: process.env.SCOPE ?? "profile:basic",
};

export const AUTH_SERVER_URL = process.env.AUTH_SERVER_URL!;