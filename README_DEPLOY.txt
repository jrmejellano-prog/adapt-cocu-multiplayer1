ADAPT COCU WORLDWIDE MULTIPLAYER
================================

This package contains:
- server.js       Node multiplayer server
- index.html      APK client with a public-server URL setting
- package.json    Node start configuration
- render.yaml     Render deployment configuration

IMPORTANT
---------
After Render gives you a URL such as:
https://adapt-cocu-multiplayer.onrender.com

Open index.html and change:

const MP_SERVER_URL = 'https://REPLACE-WITH-YOUR-RENDER-URL.onrender.com';

to your real Render URL, then rebuild the APK.

The phones do NOT need to be on the same Wi-Fi.
They only need Internet access.

RENDER SETTINGS
---------------
Service type: Web Service
Build command: npm install
Start command: npm start
Health check: /api/mp/health

The server uses process.env.PORT, so it is compatible with Render.
