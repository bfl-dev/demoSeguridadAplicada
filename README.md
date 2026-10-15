# Demo: CSRF + Broken Authentication / Session Management

Laboratorio **aislado** de 2 VMs (VirtualBox + Vagrant). Cada vulnerabilidad se
muestra primero **activa** (modo `vuln`) y luego **corregida** (modo `fixed`).

- **CSRF** → "CRUD Penguin" (juego de parodia). El atacante cambia el correo de
  recuperación de la víctima sin que ella haga clic.
- **Broken Auth / Session** → inscripción de ramos tras una sala de espera.
  Se reutiliza una cookie de sesión robada: dos personas en la misma sesión a la vez.

> ⚠️ Todo corre en una red host-only entre las 2 VMs. No apunta a ningún sistema
> real. Cuentas y datos son ficticios.

## 1. Requisitos (CachyOS)

```bash
# VirtualBox: el kernel linux-cachyos necesita los modulos por DKMS (no -arch)
sudo pacman -S virtualbox virtualbox-host-dkms linux-cachyos-headers vagrant
# (usa los *-headers del kernel que tengas instalado)
sudo modprobe vboxdrv     # si falla, reinicia tras instalar los headers
```

## 2. Levantar

```bash
cd seguridad_aplicada_demo
vagrant up        # crea y aprovisiona victim (.10) y attacker (.11)
```

| Qué | Dónde |
|-----|-------|
| App Broken Auth (cola) | `https://192.168.56.10:8000` |
| App CSRF (CRUD Penguin) | `https://192.168.56.10:8001` |
| Sitio del atacante | `http://192.168.56.11:9000` |
| Cambiar modo | `vagrant ssh victim -c "sudo toggle-mode fixed"` (o `vuln`) |

Credenciales: CRUD Penguin `pingu1/hielo123` · Inscripción `estudiante1/clave123`.

La sala de espera de inscripción usa una **cola FIFO en el backend**, persistida
en SQLite. Cada navegador recibe un ticket aleatorio en una cookie `HttpOnly`;
recargar conserva su posición y la página consulta `/queue/status` cada segundo.
El servidor habilita un ingreso cada 3 segundos. `QUEUE_INTERVAL` permite ajustar
ese intervalo (en segundos, mínimo 0.1) en el entorno de la app.
Los turnos sin consultas durante 2 minutos caducan; al llegar el turno hay
2 minutos para completar el login. Tanto GET como POST de `/login` exigen un
turno habilitado, que se consume al autenticar correctamente, en ambos modos.
La cola regula la frecuencia de ingreso; no limita las sesiones ya autenticadas,
para conservar la demostración de robo de sesión. Las sesiones siguen en memoria.

## 3. Antes de la demo (3 cosas o no funciona)

1. **Usa Chromium/Chrome** y permite cookies de terceros para el sitio víctima.
   Firefox/Safari bloquean la cookie cross-site y el CSRF no se vería.
2. **Acepta el certificado** autofirmado: abre una vez `https://192.168.56.10:8000`
   y `:8001` (Avanzado → Continuar).
3. **Cierra sesión ("Salir") antes de cambiar de modo** con `toggle-mode`.

## 4. Correr los ataques

**CSRF (modo `vuln`):** entra a CRUD Penguin (`:8001`) y deja la sesión abierta.
En otra pestaña abre el sitio del atacante (`:9000`):
- **"Ver mi postal"** → un `<img>` dispara un GET y cambia el correo (el chiste).
- **"Reclamar premio"** → un form oculto se auto-envía (POST), igual de efectivo.

Recarga el iglú: el correo quedó en `atacante@evil.cl`.
Con `toggle-mode fixed` (y re-login) las dos páginas ya no cambian nada.

**Broken Auth (modo `vuln`):** entra a inscripción (`:8000`), el dashboard muestra
tu cookie `sid` (vale `1`, es predecible). Desde la VM atacante:

```bash
vagrant ssh attacker
cd /opt/attacker && ./hijack.sh 1     # o el sid copiado de la víctima
```

`/whoami` responde autenticado como `estudiante1`: dos sesiones vivas a la vez.
Con `toggle-mode fixed` el `sid` pasa a ser aleatorio, se rota al entrar y queda
atado a la IP → la cookie robada devuelve **401**.

## 5. Pruebas

```bash
./tests/run.sh     # prueba FIFO, vencimientos y concurrencia; luego ambas apps en los 2 modos
```

## 6. Estructura

```
Vagrantfile              2 VMs, red host-only
provision/               aprovisionamiento (victim / attacker)
cola/                    app Broken Auth (Flask)
penguin/                 app CSRF "CRUD Penguin" (Flask)
attacker/                páginas de ataque + hijack.sh
scripts/toggle-mode.sh   cambia vuln <-> fixed
tests/                   pruebas de host
```

El modo lo controla `DEMO_MODE` en `/etc/demo.env` (dentro de la VM). En el código
el `if MODE == 'vuln': ... else: ...` deja ver lado a lado lo vulnerable y lo corregido.

## 7. Problemas comunes

- **El ataque no cambia nada:** ¿Chromium con cookies de terceros? ¿aceptaste el
  cert? ¿estás en modo `vuln`? (`vagrant ssh victim -c "cat /etc/demo.env"`).
- **VirtualBox rechaza la red 192.168.56.x:** agrega `* 192.168.56.0/21` a
  `/etc/vbox/networks.conf` en el host.
- **Reiniciar limpio:** `vagrant reload --provision` (recrea las bases de datos).

## 8. Apagar / limpiar

```bash
vagrant halt        # apaga
vagrant destroy -f  # elimina las VMs
```
