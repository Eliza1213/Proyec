const express = require("express");
const { registerUser, loginUser, getUsuarios, updateRol, deleteUsuario, verificarCorreo, obtenerPregunta, verificarRespuesta, cambiarContrasena } = require("../Controllers/userController");
const authMiddleware = require("../middlewares/authMiddleware");

const router = express.Router();

// Rutas públicas (no requieren autenticación)
router.post("/register", registerUser);
router.post("/login", loginUser);
router.post("/verificar-correo", verificarCorreo);
router.post("/obtener-pregunta", obtenerPregunta);
router.post("/verificar-respuesta", verificarRespuesta);
router.post("/cambiar-contrasena", cambiarContrasena);

// Ruta protegida para usuarios autenticados
router.get("/perfil", authMiddleware(), (req, res) => {
  res.json({ mensaje: "Bienvenido a tu perfil", usuario: req.user });
});

// Rutas protegidas solo para administradores
router.get("/admin/usuarios", authMiddleware(["admin"]), getUsuarios);
router.put("/admin/usuarios/:id/rol", authMiddleware(["admin"]), updateRol);
router.delete("/admin/usuarios/:id", authMiddleware(["admin"]), deleteUsuario);
// userRoutes.js
router.get("/admin/usuarios", (req, res, next) => {
  console.log("Solicitud recibida en /admin/usuarios");
  next();
}, authMiddleware(["admin"]), getUsuarios);

module.exports = router;