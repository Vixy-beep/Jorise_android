# 🚀 Jorise - Deploy a Render.com

## Archivos preparados para deploy:
✅ `manage.py` - Django management
✅ `build.sh` - Script de build para Render
✅ `render.yaml` - Configuración de Render
✅ `requirements.txt` - Dependencias Python
✅ `.gitignore` - Archivos ignorados
✅ `settings.py` - Configurado para producción

---

## 📋 PASOS PARA SUBIR A RENDER:

### **Paso 1: Crear cuenta en Render**
1. Ve a https://render.com
2. Clic en **"Get Started for Free"**
3. Registrate con GitHub (recomendado)

### **Paso 2: Subir Jorise a GitHub**
Desde tu terminal en la carpeta `jorise/jorise/`:

```bash
git init
git add .
git commit -m "Initial commit - Jorise v2"
git branch -M main
git remote add origin https://github.com/TU-USUARIO/jorise.git
git push -u origin main
```

**Crea el repositorio en GitHub primero:**
1. Ve a https://github.com/new
2. Nombre: `jorise`
3. Privado o público (tu eliges)
4. NO inicialices con README
5. Crea el repo y copia la URL

### **Paso 3: Conectar Render con GitHub**
1. En Render, clic en **"New +"** → **"Web Service"**
2. Selecciona **"Connect GitHub"** (autoriza si es la primera vez)
3. Busca el repo `jorise`
4. Clic en **"Connect"**

### **Paso 4: Configurar el servicio**
Render detectará automáticamente Django. Configura:

**Settings:**
- **Name:** `jorise`
- **Region:** Oregon (Free)
- **Branch:** `main`
- **Root Directory:** (dejar vacío)
- **Runtime:** `Python 3`
- **Build Command:** `./build.sh`
- **Start Command:** `gunicorn jorise.wsgi:application`
- **Plan:** `Free`

**Environment Variables** (clic en "Advanced"):
- `SECRET_KEY` → (Render lo genera automáticamente)
- `DEBUG` → `False`
- `ALLOWED_HOSTS` → `.onrender.com,jorise.vineksec.online`
- `PYTHON_VERSION` → `3.11.0`
- `GEMINI_API_KEY` → (tu API key de Google Gemini)

### **Paso 5: Crear base de datos PostgreSQL**
1. Clic en **"New +"** → **"PostgreSQL"**
2. **Name:** `jorise-db`
3. **Database:** `jorise`
4. **User:** `jorise`
5. **Region:** Oregon (Free)
6. **Plan:** `Free`
7. Clic en **"Create Database"**

### **Paso 6: Conectar DB al servicio**
1. Ve al servicio web `jorise`
2. Pestaña **"Environment"**
3. Agrega variable:
   - **Key:** `DATABASE_URL`
   - **Value:** (copia el "Internal Database URL" de tu PostgreSQL)

### **Paso 7: Deploy**
1. Clic en **"Manual Deploy"** → **"Deploy latest commit"**
2. Espera 3-5 minutos mientras construye
3. Verás logs en tiempo real
4. Cuando termine verás: **"Your service is live"** 🎉

---

## 🌐 CONECTAR DOMINIO PERSONALIZADO

Una vez deployado, Render te dará una URL tipo:
`https://jorise.onrender.com`

Para usar `jorise.vineksec.online`:

### **En Render:**
1. Ve al servicio `jorise`
2. Pestaña **"Settings"**
3. Scroll a **"Custom Domain"**
4. Clic en **"Add Custom Domain"**
5. Ingresa: `jorise.vineksec.online`
6. Render te dará un **CNAME** tipo: `jorise.onrender.com`

### **En Hostinger:**
1. Ve a hPanel → **Dominios** → **DNS/Nameservers**
2. Busca `vineksec.online`
3. Clic en **"Manage"** → **"DNS Records"**
4. Agrega un registro **CNAME**:
   - **Name:** `jorise`
   - **Type:** `CNAME`
   - **Points to:** `jorise.onrender.com`
   - **TTL:** 3600
5. Guarda

Espera 5-30 minutos para que el DNS se propague.

---

## ✅ VERIFICAR QUE FUNCIONA

Después del deploy:

1. Abre: `https://jorise.onrender.com`
2. Deberías ver la página de Jorise
3. Probar login: `/admin` (usuario: admin, password: lo que configuraste)
4. Si funciona, espera el CNAME y prueba: `https://jorise.vineksec.online`

---

## 🔧 COMANDOS ÚTILES

**Ver logs en vivo:**
```bash
# En Render Dashboard → Logs tab
```

**Ejecutar migraciones manualmente:**
```bash
# En Render Dashboard → Shell tab
python manage.py migrate
```

**Crear superusuario:**
```bash
# En Render Dashboard → Shell tab
python manage.py createsuperuser
```

---

## 📊 PLAN GRATUITO LIMITACIONES

Render Free tier incluye:
- ✅ 750 horas/mes (suficiente para 24/7)
- ✅ PostgreSQL con 1GB almacenamiento
- ✅ HTTPS automático
- ✅ Deploy automático desde Git
- ⚠️ El servicio "duerme" después de 15 min inactivo (tarda 30seg en despertar)
- ⚠️ Build time limitado

---

## 🆘 PROBLEMAS COMUNES

**Build falla:**
- Verifica que `requirements.txt` esté correcto
- Revisa logs de build en Render

**500 Error:**
- Verifica `DATABASE_URL` esté configurado
- Revisa logs en Render Dashboard

**Static files no cargan:**
- Ejecuta: `python manage.py collectstatic` en Shell

---

¡Listo! Jorise estará corriendo en Render gratis y conectado a `jorise.vineksec.online` 🚀
