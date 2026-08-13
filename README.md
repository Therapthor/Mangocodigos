# Codigos Manguito 🥭 — backend propio

Backend en Node.js + Express. Los secretos TOTP viven solo en el servidor
(archivo `data.json`); el navegador nunca los recibe, solo los códigos ya
calculados. El panel admin usa PIN + sesión por token (30 min de inactividad
y expira).

## Uso local

```
npm install
npm start
```

Abre http://localhost:3000

La primera vez que entres al ícono 🔐 (arriba a la derecha) te pedirá crear
un PIN. Ese PIN se guarda hasheado (SHA-256) en `data.json`, nunca en texto plano.

## Estructura

- `server.js` — API y lógica TOTP
- `public/index.html` — frontend (mismo diseño, ahora consume la API)
- `data.json` — tu base de datos (cuentas + hash del PIN). Se crea sola si no existe.

## Para tenerlo accesible desde otro dispositivo

Esto corre solo en tu máquina por defecto (`localhost`). Para usarlo desde
el celular u otra compu necesitas alojarlo en algún lado con IP/dominio
propio: un VPS, o servicios como Render, Railway o Fly.io (todos tienen
plan gratuito o muy barato). El código no cambia, solo lo subes y defines
la variable de entorno `PORT` si el proveedor lo requiere.

## Importante

- No subas `data.json` a un repositorio público — tiene tus secretos TOTP.
- El PIN protege el panel admin, pero cualquiera con acceso al servidor
  (o al archivo `data.json`) puede leer los secretos en texto plano. Si
  quieres cifrarlos en reposo, se puede agregar (avísame).
