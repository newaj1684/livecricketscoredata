# CricNova Live Cricket Score API & Portal

High-performance, crash-proof live cricket scoring backend server designed for Android apps, web widgets, and commercial API clients.

## 🚀 Features
- **Live Fixtures, Recent Fixtures & Upcoming Matches**: Full ball-by-ball, overs, scores, teams, player profiles, and venues.
- **Vercel Ready**: Pre-configured with `vercel.json` and serverless handler `api/index.js` for instant deployment.
- **Admin & Monetization**: Built-in UPI monetization, QR generator, API key licensing system, and secure admin panel.
- **Crash-Proof Android Compatibility**: Formatted specifically for GSON & JSONObject deserialization (`OversBowled`, `oversBowled`, `Competition`, `Innings`).

## 📦 How to Deploy on Vercel
1. Go to [Vercel.com](https://vercel.com) and log in.
2. Click **"Add New"** > **"Project"**.
3. Import your GitHub repository: `newaj1684/livecricketscoredata`.
4. Click **Deploy**.
5. Once deployed, copy your production URL (e.g., `https://livecricketscoredata.vercel.app`).
6. Set the Base64 URL into your Firebase Remote Config under the key `match`.

## 🛠 Local Development
```bash
npm install
node server.js
```
The server will run on `http://localhost:3000`.
